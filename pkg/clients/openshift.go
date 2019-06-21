package clients

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	neturl "net/url"
	"os"
	"strings"

	"github.com/bitly/go-simplejson"

	"github.com/openshift/elasticsearch-proxy/pkg/config"
	"github.com/openshift/elasticsearch-proxy/pkg/util"
	log "github.com/sirupsen/logrus"
)

type OpenShiftClient interface {
	Get(path, token string) (*simplejson.Json, error)

	//TokenReview performs a tokenreview for a given token submitting to the apiserver
	//using the serviceaccount token. It returns a simplejson object of the response
	TokenReview(token string) (*TokenReview, error)
	SubjectAccessReview(user, namespace, verb, resource, resourceAPIGroup string) (bool, error)
}

type DefaultOpenShiftClient struct {
	//TODO Replace me with kubeclient
	httpClient *http.Client
	token      string
}

type TokenReview struct {
	*simplejson.Json
}

func (t *TokenReview) UserName() string {
	name, err := t.GetPath("status", "user", "username").String()
	if err != nil {
		log.Errorf("user information was not found: %v", err)
	}
	return name
}

func (t *TokenReview) Groups() []string {
	return t.GetPath("status", "user", "groups").MustStringArray([]string{})
}

func (c *DefaultOpenShiftClient) Get(path, token string) (*simplejson.Json, error) {
	if token == "" {
		return nil, fmt.Errorf("Unable to perform GET (%s) with empty token", path)
	}
	req, err := http.NewRequest("GET", getKubeAPIURLWithPath(path).String(), nil)
	if err != nil {
		return nil, err
	}
	return request(c.httpClient, req, token)
}

//TokenReview performs a tokenreview for a given token submitting to the apiserver
//using the serviceaccount token. It returns a simplejson object of the response
func (c *DefaultOpenShiftClient) TokenReview(token string) (*TokenReview, error) {
	log.Debug("Performing TokenReview...")
	spec := simplejson.New()
	spec.Set("token", token)
	json := simplejson.New()
	json.Set("kind", "TokenReview")
	json.Set("apiVersion", "authentication.k8s.io/v1")
	json.Set("spec", spec)
	payload, err := json.MarshalJSON()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", getKubeAPIURLWithPath("/apis/authentication.k8s.io/v1/tokenreviews").String(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	resp, err := request(c.httpClient, req, c.token)
	if err != nil {
		return nil, err
	}
	return &TokenReview{resp}, nil
}

func (c *DefaultOpenShiftClient) SubjectAccessReview(user, namespace, verb, resource, resourceAPIGroup string) (bool, error) {
	log.Debug("Performing SubjectAccessReview...")
	resourceAttributes := simplejson.New()
	resourceAttributes.Set("verb", verb)
	spec := simplejson.New()
	spec.Set("user", user)
	resourceAttr := simplejson.New()
	if strings.HasPrefix(resource, "/") {
		resourceAttr.Set("path", resource)
		spec.Set("nonResourceAttributes", resourceAttr)
	} else {
		resourceAttr.Set("resource", resource)
		resourceAttr.Set("namespace", namespace)
		resourceAttr.Set("group", resourceAPIGroup)
		spec.Set("resourceAttributes", resourceAttr)
	}
	json := simplejson.New()
	json.Set("kind", "SubjectAccessReview")
	json.Set("apiVersion", "authorization.k8s.io/v1")
	json.Set("spec", spec)
	payload, err := json.MarshalJSON()
	if err != nil {
		return false, err
	}
	req, err := http.NewRequest("POST", getKubeAPIURLWithPath("/apis/authorization.k8s.io/v1/subjectaccessreviews").String(), bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	resp, err := request(c.httpClient, req, c.token)
	if err != nil {
		return false, err
	}
	return resp.GetPath("status", "allowed").Bool()
}

func request(client *http.Client, req *http.Request, token string) (*simplejson.Json, error) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Accept", "application/json")
	if client == nil {
		log.Trace("Using http.DefaultClient as the given client is nil")
		client = http.DefaultClient
	}
	log.Tracef("Executing request: %v", req)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("%s %s %s", req.Method, req.URL, err)
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	log.Tracef("Raw Response: %d %s %s %s", resp.StatusCode, req.Method, req.URL, body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("got %d %s", resp.StatusCode, body)
	}
	data, err := simplejson.NewJson(body)
	if err != nil {
		return nil, err
	}
	log.Tracef("Returning %v", data)
	return data, nil
}

// copy of same function in provider.go
func getKubeAPIURLWithPath(path string) *neturl.URL {
	ret := &neturl.URL{
		Scheme: "https",
		Host:   "kubernetes.default.svc",
		Path:   path,
	}

	if host := os.Getenv("KUBERNETES_SERVICE_HOST"); len(host) > 0 {
		ret.Host = host
	}
	if port := os.Getenv("KUBERNETES_SERVICE_PORT"); len(port) > 0 {
		ret.Host = fmt.Sprintf("%s:%s", ret.Host, port)
	}

	return ret
}

// NewOpenShiftClient returns a client for connecting to the master.
func NewOpenShiftClient(opt config.Options) (OpenShiftClient, error) {
	log.Tracef("Creating new OpenShift client with: %+v", opt)
	//defaults
	capaths := []string{"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"}
	systemRoots := true
	if len(opt.OpenShiftCAs) != 0 {
		capaths = opt.OpenShiftCAs
		systemRoots = false
	}
	pool, err := util.GetCertPool(capaths, systemRoots)
	if err != nil {
		return nil, err
	}

	return &DefaultOpenShiftClient{
		&http.Client{
			Jar: http.DefaultClient.Jar,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{
					RootCAs:            pool,
					InsecureSkipVerify: opt.SSLInsecureSkipVerify,
				},
			},
		},
		opt.ServiceAccountToken,
	}, nil
}
