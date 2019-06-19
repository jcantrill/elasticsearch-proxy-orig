FROM registry.svc.ci.openshift.org/openshift/release:golang-1.10 AS builder
WORKDIR  /go/src/github.com/openshift/elasticsearch-proxy
COPY . .
RUN make

FROM registry.svc.ci.openshift.org/openshift/origin-v4.0:base
COPY --from=builder /go/src/github.com/openshift/elasticsearch-proxy/_output/bin/elasticsearch-proxy /usr/bin/elasticsearch-proxy
ENTRYPOINT ["/usr/bin/elasticsearch-proxy"]
