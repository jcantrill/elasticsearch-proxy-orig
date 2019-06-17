CURPATH=$(PWD)
GOFLAGS?=
BIN_NAME=elasticsearch-proxy
IMAGE_REPOSITORY_NAME ?=github.com/openshift/$(BIN_NAME)
MAIN_PKG=cmd/proxy/main.go
TARGET_DIR=$(CURPATH)/_output
TARGET=$(TARGET_DIR)/bin/$(BIN_NAME)
BUILD_GOPATH=$(TARGET_DIR):$(TARGET_DIR)/vendor:$(CURPATH)/cmd

#inputs to 'run' which may need to change
TLS_CERTS_BASEDIR=_output
CLIENT_SECRET?=SzVEeEQwYmRFcVRpb3VaWVpFUmdKbjN3bnZweWxrR3FRU1RWY01BSWNTdDRPRk9wYkdaMjB4cWN6ODRhMElFUg==
COOKIE_SECRET?=3bM3IXYGSivKBWW+xE1uQg==

PKGS=$(shell go list ./... | grep -v -E '/vendor/')
TEST_OPTIONS?=

all: build

fmt:
	@gofmt -l -w cmd && \
	gofmt -l -w pkg
.PHONY: fmt

build: fmt
	@mkdir -p $(TARGET_DIR)/src/$(IMAGE_REPOSITORY_NAME)
	@cp -ru $(CURPATH)/pkg $(TARGET_DIR)/src/$(IMAGE_REPOSITORY_NAME)
	@cp -ru $(CURPATH)/vendor/* $(TARGET_DIR)/src
	@GOPATH=$(BUILD_GOPATH) go build  $(LDFLAGS) -o $(TARGET) $(MAIN_PKG)
.PHONY: build

images:
	imagebuilder -f Dockerfile -t $(IMAGE_REPOSITORY_NAME)/$(BIN_NAME) .
.PHONY: images

clean:
	rm -rf $(TARGET_DIR)
	rm -rf $(TLS_CERTS_BASEDIR)
.PHONY: clean

test:
	@go test $(TEST_OPTIONS) $(PKGS)
.PHONY: test

prep-for-run:
	mkdir -p ${TLS_CERTS_BASEDIR}||:  && \
	for n in "ca" "cert" "key" ; do \
		oc -n openshift-logging get secret elasticsearch -o jsonpath={.data.admin-$$n} | base64 -d > _output/admin-$$n ; \
	done && \
	oc -n openshift-logging  get pod -l component=elasticsearch -o jsonpath={.items[0].metadata.name} > _output/espod && \
	oc -n openshift-logging exec -c elasticsearch $$(cat _output/espod) -- cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt > _output/ca.crt && \
	oc -n openshift-logging serviceaccounts get-token elasticsearch > _output/sa-token && \
	echo openshift-logging > _output/namespace && \
	mkdir -p /var/run/secrets/kubernetes.io/serviceaccount/||:  && \
	sudo ln -sf $${PWD}/_output/ca.crt /var/run/secrets/kubernetes.io/serviceaccount/ca.crt && \
	sudo ln -sf $${PWD}/_output/sa-token /var/run/secrets/kubernetes.io/serviceaccount/token && \
	sudo ln -sf $${PWD}/_output/namespace /var/run/secrets/kubernetes.io/serviceaccount/namespace
	
.PHONY: prep-for-run

run:
	$(TARGET) --https-address=':60000' \
        --upstream=https://127.0.0.1:9200 \
        --tls-cert=$(TLS_CERTS_BASEDIR)/admin-cert \
        --tls-key=$(TLS_CERTS_BASEDIR)/admin-key \
        --upstream-ca=$(TLS_CERTS_BASEDIR)/admin-ca \
		--ssl-insecure-skip-verify
.PHONY: run
