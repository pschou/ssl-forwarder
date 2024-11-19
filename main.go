// Intended to help with linking two apps together and expanded to be a
// general open source software for use to link apps together that usually
// don't do mTLS (mutual TLS)
package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pschou/go-params"
)

type DNS struct {
	Addr string
	Time time.Time
}

var target_addr = ""
var DNSCache = make(map[string]DNS, 0)
var keyFile = ""
var certFile = ""
var keypair *tls.Certificate
var keypair_count = 0
var keypair_mu sync.RWMutex
var rootFile = ""
var root_count = 0
var rootpool *x509.CertPool
var certs_loaded = make(map[string]bool, 0)
var debug = false
var version = "not set"

func loadKeys() {
	keypair_mu.RLock()
	defer keypair_mu.RUnlock()
	var err error

	tmp_key, err_k := tls.LoadX509KeyPair(certFile, keyFile)
	if err_k != nil {
		if keypair == nil {
			log.Fatalf("failed to loadkey pair, check that the cert file has a public key and the key file has a private key.\npublic: %s\nprivate: %s", certFile, keyFile)
		}
		keypair_count++
		log.Println("WARNING: Cannot load keypair (cert/key)", certFile, keyFile, "attempt:", keypair_count)
		if keypair_count > 10 {
			log.Fatalf("failed to loadkey pair, check that the cert file has a public key and the key file has a private key.\npublic: %s\nprivate: %s", certFile, keyFile)
		}
	} else {
		if debug {
			log.Println("Loaded keypair", certFile, keyFile)
		}
		keypair = &tmp_key
		keypair_count = 0
	}

	err_r := LoadCertficatesFromFile(rootFile)
	if err_r != nil {
		if rootpool == nil {
			log.Fatalf("failed to load CA: %s", err)
		}
		root_count++
		log.Println("WARNING: Cannot load CA file", rootFile, "attempt:", root_count)
		if root_count > 10 {
			log.Fatalf("failed to CA: %s", err)
		}
	} else {
		if debug {
			log.Println("Loaded CA", rootFile)
		}
		root_count = 0
	}

}

func main() {
	params.Usage = func() {
		fmt.Fprintf(os.Stderr, "Simple SSL forwarder (github.com/pschou/ssl-forwarder) December 2020\nAll rights reserved, personal use only, provided AS-IS -- not responsible for loss.\nUsage implies agreement.  Version: %s\n\nUsage: %s [options...]\n\n", version, os.Args[0])
		params.PrintDefaults()
	}
	var tls_enabled = params.Bool("tls", true, "Enable listener TLS", "BOOL")
	var verbose = params.Pres("debug", "Verbose output")
	params.GroupingSet("Listener")
	var listen = params.String("listen", ":7443", "Listen address for forwarder", "HOST:PORT")
	var verify_server = params.Bool("verify-server", true, "Verify server, do certificate checks", "BOOL")
	var secure_server = params.Bool("secure-server", true, "Enforce minimum of TLS 1.2 on server side", "BOOL")
	params.GroupingSet("Target")
	var target = params.String("target", "127.0.0.1:443", "Sending address for forwarder", "HOST:PORT")
	var verify_client = params.Bool("verify-client", true, "Verify client, do certificate checks", "BOOL")
	var secure_client = params.Bool("secure-client", true, "Enforce minimum of TLS 1.2 on client side", "BOOL")
	var tls_host = params.String("host", "", "Hostname to verify outgoing connection with", "FQDN")
	params.GroupingSet("Certificate")
	var cert_file = params.String("cert", "/etc/pki/server.pem", "File to load with CERT - automatically reloaded every minute\n", "FILE")
	var key_file = params.String("key", "/etc/pki/server.pem", "File to load with KEY - automatically reloaded every minute\n", "FILE")
	var root_file = params.String("ca", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "File to load with ROOT CAs - reloaded every minute by adding any new entries\n", "FILE")
	params.CommandLine.Indent = 2
	params.Parse()

	var err error
	debug = *verbose

	keyFile = *key_file
	certFile = *cert_file
	rootFile = *root_file
	rootpool = x509.NewCertPool()

	loadKeys()
	go func() {
		ticker := time.NewTicker(time.Minute)
		for {
			select {
			case <-ticker.C:
				loadKeys()
			}
		}
	}()

	var l net.Listener
	if *tls_enabled {
		var config tls.Config
		if *secure_server {
			config = tls.Config{RootCAs: rootpool,
				Certificates: []tls.Certificate{},
				ClientCAs:    rootpool, InsecureSkipVerify: *verify_server == false,
				MinVersion:               tls.VersionTLS12,
				CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
				Renegotiation:            tls.RenegotiateOnceAsClient,
				PreferServerCipherSuites: true,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
			}
		} else {
			config = tls.Config{RootCAs: rootpool,
				ClientCAs: rootpool, InsecureSkipVerify: *verify_server == false}
		}
		config.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if debug {
				log.Println("  Get Cert Returning keypair")
			}
			return keypair, nil
		}

		config.Rand = rand.Reader
		if debug {
			fmt.Println("TLS Listening on", *listen)
		}
		if l, err = tls.Listen("tcp", *listen, &config); err != nil {
			log.Fatal(err)
		}
	} else {
		var err error
		if debug {
			fmt.Println("Listening on", *listen)
		}
		if l, err = net.Listen("tcp", *listen); err != nil {
			log.Fatal(err)
		}
	}

	if debug {
		fmt.Println("Target set to", *target)
	}
	target_addr = *target

	defer l.Close()
	for {
		conn, err := l.Accept() // Wait for a connection.
		if err != nil {
			fmt.Println("Error on accept", err)
			continue
		}
		if debug {
			fmt.Println("New connection from", conn.RemoteAddr())
		}

		go func(c net.Conn) {
			defer conn.Close()
			defer c.Close()
			var tlsConfig *tls.Config
			if *secure_client {
				tlsConfig = &tls.Config{Certificates: []tls.Certificate{*keypair}, RootCAs: rootpool,
					ClientCAs: rootpool, InsecureSkipVerify: *verify_client == false, ServerName: *tls_host,
					MinVersion:               tls.VersionTLS12,
					CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
					PreferServerCipherSuites: true,
					CipherSuites: []uint16{
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					},
				}
			} else {
				tlsConfig = &tls.Config{Certificates: []tls.Certificate{*keypair}, RootCAs: rootpool,
					ClientCAs: rootpool, InsecureSkipVerify: *verify_client == false, ServerName: *tls_host}
			}

			tlsConfig.Rand = rand.Reader

			if debug {
				log.Println("dialing endpoint:", target_addr)
			}
			remote, err := tls.Dial("tcp", target_addr, tlsConfig)
			if err != nil {
				log.Println("error dialing endpoint:", target_addr, "error:", err)
				return
			}
			if debug {
				log.Println("connected!", target_addr)
			}

			go io.Copy(remote, c)
			io.Copy(c, remote)
		}(conn)
	}
}

func LoadCertficatesFromFile(path string) error {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				fmt.Println("warning: error parsing CA cert", err)
				continue
			}
			t := fmt.Sprintf("%v%v", cert.SerialNumber, cert.Subject)
			if _, ok := certs_loaded[t]; !ok {
				if debug {
					fmt.Println(" Adding CA:", cert.Subject)
				}
				rootpool.AddCert(cert)
				certs_loaded[t] = true
			}
		}
		raw = rest
	}

	return nil
}
