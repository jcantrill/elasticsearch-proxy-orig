package main

import (
	"flag"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"time"

	"github.com/openshift/elasticsearch-proxy/pkg/config"
	ext "github.com/openshift/elasticsearch-proxy/pkg/handlers"
	auth "github.com/openshift/elasticsearch-proxy/pkg/handlers/authentication"
	cl "github.com/openshift/elasticsearch-proxy/pkg/handlers/clusterlogging"
	"github.com/openshift/elasticsearch-proxy/pkg/proxy"
	"github.com/openshift/elasticsearch-proxy/pkg/util"
	log "github.com/sirupsen/logrus"
)

const (
	serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

func main() {
	initLogging()

	flagSet := flag.NewFlagSet("elasticsearch-proxy", flag.ExitOnError)

	upstreams := util.StringArray{}
	openshiftCAs := util.StringArray{}
	upstreamCAs := util.StringArray{}

	flagSet.String("https-address", ":8443", "<addr>:<port> to listen on for HTTPS clients")

	flagSet.String("tls-cert", "", "path to certificate file")
	flagSet.String("tls-key", "", "path to private key file")
	flagSet.String("tls-client-ca", "", "path to a CA file for admitting client certificates.")

	flagSet.Bool("ssl-insecure-skip-verify", false, "skip validation of certificates presented when using HTTPS")
	flagSet.Bool("proxy-websockets", true, "enables WebSocket proxying")
	flagSet.Var(&openshiftCAs, "openshift-ca", "paths to CA roots for the OpenShift API (may be given multiple times, defaults to /var/run/secrets/kubernetes.io/serviceaccount/ca.crt).")
	flagSet.Bool("request-logging", false, "Log requests to stdout")

	flagSet.Var(&upstreams, "upstream", "the http url(s) of the upstream endpoint")
	flagSet.Duration("upstream-flush", time.Duration(5)*time.Millisecond, "force flush upstream responses after this duration(useful for streaming responses). 0 to never force flush. Defaults to 5ms")
	flagSet.Var(&upstreamCAs, "upstream-ca", "paths to CA roots for the Upstream (target) Server (may be given multiple times, defaults to system trust store).")

	flagSet.Parse(os.Args[1:])

	opts := config.Init(flagSet)
	err := opts.Validate()
	if err != nil {
		log.Printf("%s", err)
		os.Exit(1)
	}

	proxyServer := proxy.NewProxyServer(opts)

	extOptions := &ext.Options{
		OpenshiftCAs:          openshiftCAs,
		TLSCertFile:           opts.TLSCertFile,
		TLSKeyFile:            opts.TLSKeyFile,
		UpstreamURL:           opts.ProxyURLs[0],
		SSLInsecureSkipVerify: opts.SSLInsecureSkipVerify,
	}

	extOptions.ServiceAccountToken = readServiceAccountToken()
	log.Printf("Registering Handlers....")
	proxyServer.RegisterRequestHandlers(auth.NewHandlers(extOptions))
	proxyServer.RegisterRequestHandlers(cl.NewHandlers(extOptions))

	var h http.Handler = proxyServer
	if opts.RequestLogging {
		h = proxy.LoggingHandler(os.Stdout, h, true)
	}
	s := &proxy.Server{
		Handler: h,
		Opts:    opts,
	}
	s.ListenAndServe()
}

func initLogging() {
	logLevel := os.Getenv("LOGLEVEL")
	if logLevel == "" {
		logLevel = "warn"
	}
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		level = log.WarnLevel
		log.Infof("Setting loglevel to 'warn' as unable to parse %s", logLevel)
	}
	log.SetLevel(level)
}

func readServiceAccountToken() string {
	log.Debug("Reading ServiceAccount token...")
	var data []byte
	var err error
	if data, err = ioutil.ReadFile(serviceAccountTokenPath); err != nil || len(data) == 0 {
		log.Fatalf("Unable to load serviceaccount token from %q", serviceAccountTokenPath)
	}
	return strings.TrimSpace(string(data))
}
