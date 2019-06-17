package config

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	log "github.com/sirupsen/logrus"
)

// Configuration Options that can be set by Command Line Flag, or Config File
type Options struct {
	ProxyWebSockets bool          `flag:"proxy-websockets" cfg:"proxy_websockets"`
	HttpsAddress    string        `flag:"https-address" cfg:"https_address"`
	DebugAddress    string        `flag:"debug-address" cfg:"debug_address"`
	UpstreamFlush   time.Duration `flag:"upstream-flush" cfg:"upstream_flush"`
	TLSCertFile     string        `flag:"tls-cert" cfg:"tls_cert_file"`
	TLSKeyFile      string        `flag:"tls-key" cfg:"tls_key_file"`
	TLSClientCAFile string        `flag:"tls-client-ca" cfg:"tls_client_ca"`
	OpenShiftCAs    []string      `flag:"openshift-ca" cfg:"openshift_ca"`

	Upstreams             []string `flag:"upstream" cfg:"upstreams"`
	SSLInsecureSkipVerify bool     `flag:"ssl-insecure-skip-verify" cfg:"ssl_insecure_skip_verify"`

	RequestLogging bool `flag:"request-logging" cfg:"request_logging"`

	UpstreamCAs []string `flag:"upstream-ca" cfg:"upstream_ca"`
	ProxyURLs   []*url.URL
}

func NewOptions() *Options {
	return &Options{
		ProxyWebSockets: true,
		HttpsAddress:    ":443",
		UpstreamFlush:   time.Duration(5) * time.Millisecond,
		RequestLogging:  true,
	}
}

func (o *Options) Validate() error {
	log.Tracef("Validating options: %v", o)
	msgs := make([]string, 0)

	if len(o.Upstreams) < 1 {
		msgs = append(msgs, "missing setting: upstream")
	}

	o.ProxyURLs = nil
	log.Trace("Validating Upstreams...")
	for _, u := range o.Upstreams {
		log.Tracef("Parsing %q", u)
		upstreamURL, err := url.Parse(u)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf(
				"error parsing upstream=%q %s",
				upstreamURL, err))
			continue
		}
		if upstreamURL.Path == "" {
			upstreamURL.Path = "/"
		}
		log.Tracef("Adding %q to ProxyURLs", u)
		o.ProxyURLs = append(o.ProxyURLs, upstreamURL)
	}

	if len(o.TLSClientCAFile) > 0 && len(o.TLSKeyFile) == 0 && len(o.TLSCertFile) == 0 {
		msgs = append(msgs, "tls-client-ca requires tls-key-file or tls-cert-file to be set to listen on tls")
	}

	if o.SSLInsecureSkipVerify {
		insecureTransport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		http.DefaultClient = &http.Client{Transport: insecureTransport}
	}

	return nil
}
