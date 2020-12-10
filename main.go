package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"
)

type DNS struct {
	Addr string
	Time time.Time
}

var target_addr = ""
var DNSCache = make(map[string]DNS, 0)
var keypair tls.Certificate
var rootpool *x509.CertPool

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Very simple SSL forwarder, written by Paul Schou github@paulschou.com\n\n Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	var listen = flag.String("listen", ":7443", "Listen address for forwarder")
	var target = flag.String("target", "127.0.0.1:443", "Sending address for forwarder")
	var cert_file = flag.String("cert", "/etc/pki/server.pem", "File to load with CERT")
	var key_file = flag.String("key", "/etc/pki/server.pem", "File to load with KEY")
	var root = flag.String("ca", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "File to load with ROOT CAs")
	var tls_enabled = flag.Bool("tls", true, "Enable listener TLS")
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*cert_file, *key_file)
	if err != nil {
		log.Fatalf("failed to loadkey pair: %s", err)
	}
	rootpool, err = LoadCertficatesFromFile(*root)
	if err != nil {
		log.Fatalf("failed to load CA: %s", err)
	}

	var l net.Listener
	if *tls_enabled {
		config := tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: rootpool}
		config.Rand = rand.Reader
		if l, err = tls.Listen("tcp", *listen, &config); err != nil {
			log.Fatal(err)
		}
	} else {
		var err error
		if l, err = net.Listen("tcp", *listen); err != nil {
			log.Fatal(err)
		}
	}

	target_addr = *target

	defer l.Close()
	for {
		conn, err := l.Accept() // Wait for a connection.
		if err != nil {
			continue
		}

		go func(c net.Conn) {
			defer c.Close()
			config := tls.Config{Certificates: []tls.Certificate{keypair}, RootCAs: rootpool}
			remote, err := tls.Dial("tcp", target_addr, &config)
			if err != nil {
				log.Println("dialing endpoint:", target_addr, "error:", err)
				return
			}

			go io.Copy(remote, c)
			io.Copy(c, remote)
		}(conn)
	}
}

func LoadCertficatesFromFile(path string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			pool.AppendCertsFromPEM(block.Bytes)
		}
		raw = rest
	}

	return pool, nil
}
