ARG ARCH="amd64"
ARG OS="linux"
FROM scratch
LABEL description="Very simple reliable ssl forwarder, built in golang" owner="dockerfile@paulschou.com"

EXPOSE      8080
ADD ./LICENSE /LICENSE
ADD ./ssl-forwarder "/ssl-forwarder"
ENTRYPOINT  [ "/ssl-forwarder" ]
