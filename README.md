# SSL Forwarder
Super simple ssl forwarder that does one thing, exposes and end point, establishes a connection, then creates a new ssl connection going into the infrastructure.

# Why would I care to use this?  Should you need to...
* Sign a connection with a client certificate, mutual TLS, without rewriting an app
* Inter-connect IPv4 to IPv6 or vice versa - listen on ":443" and point to your IPv4/6 service
* Upgrade a client to a newer version of TLS or enable TLS on an app without TLS support - point the app to this app configured as an HTTP endpoint and outgoing becomes TLS
* Fix MTU issues across network boundary / boundaries - repackage the packets on the fly without the client needing to "find" the correct MTU, allow the network interface to dictate this
* Improve latency in long distance connections when a local link (such as WiFi) has packet loss - place this on the boundary on the immediate other side
* Automate certificate rotations on outgoing connections when the client apps cannot be taken offline / continuity of operations - make a self signed long term cert and then rotate the cert with this

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
$ ./ssl-forwarder -h
Simple SSL forwarder, written by Paul Schou (github.com/pschou/ssl-forwarder) in December 2020
All rights reserved, personal use only, provided AS-IS -- not responsible for loss.
Usage implies agreement.

Usage: ./ssl-forwarder [options...]

Options:
  --debug                 Verbose output
  --tls BOOL              Enable listener TLS  (Default: true)
Listener options:
  --listen HOST:PORT      Listen address for forwarder  (Default: ":7443")
  --secure-server BOOL    Enforce minimum of TLS 1.2 on server side  (Default: true)
  --verify-server BOOL    Verify server, do certificate checks  (Default: true)
Target options:
  --host FQDN             Hostname to verify outgoing connection with  (Default: "")
  --secure-client BOOL    Enforce minimum of TLS 1.2 on client side  (Default: true)
  --target HOST:PORT      Sending address for forwarder  (Default: "127.0.0.1:443")
  --verify-client BOOL    Verify client, do certificate checks  (Default: true)
Certificate options:
  --ca FILE               File to load with ROOT CAs - reloaded every minute by adding any new entries
                            (Default: "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
  --cert FILE             File to load with CERT - automatically reloaded every minute
                            (Default: "/etc/pki/server.pem")
  --key FILE              File to load with KEY - automatically reloaded every minute
                            (Default: "/etc/pki/server.pem")
```
