#FROM registry.svc.ci.openshift.org/openshift/release:golang-1.10 AS builder
#WORKDIR  /go/src/github.com/openshift/elasticsearch-proxy
#COPY ../. .
#RUN make clean && make && make test

FROM library/fedora:latest
RUN dnf -y install golang make git
RUN mkdir -p /root/go/src/github.com/openshift && \
    cd /root/go/src/github.com/openshift && \
	git clone https://github.com/jcantrill/elasticsearch-proxy
WORKDIR /root/go/src/github.com/openshift/elasticsearch-proxy
RUN make test