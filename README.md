# SSL Forwarder
Super simple ssl forwarder that does one thing, exposes and end point, establishes a connection, then creates a new ssl connection going into the infrastructure.

# Why would I care to use this?
* Need to sign the connection with a client certificate
* Need to inter-connect IPv4 to IPv6 or vice versa


# Usage
To run the forwarder, listening on the default port :8080 use
```
ssl-forwarder
```

Else if you want to specify a port use
```
ssl-forwarder --listen :2000
```

Or listen on a specific port and host:
```
ssl-forwarder --listen 1.2.3.4:2000
```

The corresponding pre-built container can be pulled here:
```
docker pull pschou/ssl-forwarder:0.1
```

Help context
```
$ ./ssl-forwarder  -h
Very simple SSL forwarder, written by Paul Schou github@paulschou.com

 Usage of ./ssl-forwarder:
  -ca string
        File to load with ROOT CAs (default "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
  -cert string
        File to load with CERT (default "/etc/pki/server.pem")
  -host string
        Hostname to verify outgoing connection with
  -key string
        File to load with KEY (default "/etc/pki/server.pem")
  -listen string
        Listen address for forwarder (default ":7443")
  -target string
        Sending address for forwarder (default "127.0.0.1:443")
  -tls
        Enable listener TLS (default true)
  -tls_verify
        Verify TLS or disable all checks (default true)
```
