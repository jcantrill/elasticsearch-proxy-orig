package config

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mreiferson/go-options"
	log "github.com/sirupsen/logrus"
)

// Configuration Options that can be set by Command Line Flag, or Config File
type Options struct {
	ProxyWebSockets bool     `flag:"proxy-websockets"`
	HTTPSAddress    string   `flag:"https-address"`
	TLSCertFile     string   `flag:"tls-cert"`
	TLSKeyFile      string   `flag:"tls-key"`
	TLSClientCAFile string   `flag:"tls-client-ca"`
	OpenShiftCAs    []string `flag:"openshift-ca"`

	UpstreamFlush time.Duration `flag:"upstream-flush"`
	Upstreams     []string      `flag:"upstream"`
	UpstreamCAs   []string      `flag:"upstream-ca"`

	SSLInsecureSkipVerify bool `flag:"ssl-insecure-skip-verify"`
	RequestLogging        bool `flag:"request-logging"`
	ProxyURLs             []*url.URL
}

//Init the configuration options based on the values passed via the CLI
func Init(flagSet *flag.FlagSet) *Options {
	opts := newOptions()

	options.Resolve(opts, flagSet, envConfig)

	if opts.SSLInsecureSkipVerify {
		insecureTransport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		http.DefaultClient = &http.Client{Transport: insecureTransport}
	}

	return opts
}

func newOptions() *Options {
	return &Options{
		ProxyWebSockets: true,
		HTTPSAddress:    ":443",
		UpstreamFlush:   time.Duration(5) * time.Millisecond,
		RequestLogging:  false,
	}
}

//Validate the configuration options and return errors
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

	if len(msgs) != 0 {
		return fmt.Errorf("Invalid configuration:\n  %s",
			strings.Join(msgs, "\n  "))
	}

	return nil
}
