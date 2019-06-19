FROM registry.svc.ci.openshift.org/openshift/release:golang-1.10 AS builder
WORKDIR  /go/src/github.com/openshift/elasticsearch-proxy
COPY ../. .
RUN make clean && make && make test