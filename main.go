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
	var cert = flag.String("cert", "/etc/pki/server.pem", "File to load with CERT")
	var key = flag.String("key", "/etc/pki/server.pem", "File to load with KEY")
	var root = flag.String("ca", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "File to load with ROOT CAs")
	flag.Parse()

	target_addr = *target
	var l net.Listener
	var err error
	keypair, err = tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatalf("failed to loadkeys: %s", err)
	}
	rootpool, err = LoadCertficatesFromFile(*root)
	if err != nil {
		log.Fatalf("failed to load CA: %s", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{keypair}, RootCAs: rootpool}
	config.Rand = rand.Reader
	if l, err = tls.Listen("tcp", *listen, &config); err != nil {
		log.Fatal(err)
	}

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
