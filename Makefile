PROG_NAME := "ssl-forwarder"
IMAGE_NAME := "pschou/ssl-forwarder"
VERSION := "0.1"


build:
	CGO_ENABLED=0 go build -o ${PROG_NAME} main.go

docker:
	docker build -f Dockerfile --tag ${IMAGE_NAME}:${VERSION} .
	docker push ${IMAGE_NAME}:${VERSION}; \
	docker save -o pschou_${PROG_NAME}.tar ${IMAGE_NAME}:${VERSION}
