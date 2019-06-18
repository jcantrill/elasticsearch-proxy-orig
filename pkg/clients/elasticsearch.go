package clients

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/bitly/go-simplejson"
	"github.com/oliveagle/jsonpath"
	log "github.com/sirupsen/logrus"
)

var (
	errorLookup, _ = jsonpath.Compile("$.error")
)

const (
	contentTypeJSON = "application/json"
)

//ElasticsearchClient is an admin client to query a local instance of Elasticsearch
type ElasticsearchClient interface {
	Get(path string) (string, error)
	Delete(path string) (string, error)
	Put(path string, body string) (string, error)
	Post(path string, body string) (string, error)
}

//DefaultElasticsearchClient is an admin client to query a local instance of Elasticsearch
type DefaultElasticsearchClient struct {
	serverURL string
	client    *http.Client
}

//NewElasticsearchClient is the initializer to create an instance of ES client
func NewElasticsearchClient(skipVerify bool, serverURL, adminCert, adminKey string, adminCA []string) (ElasticsearchClient, error) {
	caCertPool := x509.NewCertPool()
	for _, ca := range adminCA {
		caCert, err := ioutil.ReadFile(ca)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}

	cert, err := tls.LoadX509KeyPair(adminCert, adminKey)
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: skipVerify,
			},
		},
	}
	return &DefaultElasticsearchClient{serverURL, client}, nil
}

func url(elasticsearchURL, path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return elasticsearchURL + path
}

//Get the content at the path
func (es *DefaultElasticsearchClient) Get(path string) (string, error) {
	url := url(es.serverURL, path)
	log.Tracef("Get: %v", url)
	resp, err := es.client.Get(url)
	if err != nil {
		log.Tracef("Error executing Elasticsearch GET %v", err)
		return "", err
	}
	log.Tracef("Response code: %v", resp.StatusCode)
	body, err := readBody(resp)
	if err != nil {
		return "", err
	}
	return body, nil
}

func readBody(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	body, err := simplejson.NewFromReader(resp.Body)
	if err != nil {
		return "", err
	}
	log.Tracef("Response body: %v", body)
	result, err := body.String()
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		log.Trace("Additionally inspecting result of non 200 response...")
		errorBody := body.Get("error")
		log.Tracef("errBody: %v", errorBody)
		result, err = errorBody.String()
		if err != nil {
			log.Tracef("Error trying to decode json response %q", err)
			return "", err
		}
	}
	return result, nil
}

//Put submits a PUT request to ES assuming the given body is of type 'application/json'
func (es *DefaultElasticsearchClient) Put(path string, body string) (string, error) {
	request, err := http.NewRequest("PUT", url(es.serverURL, path), strings.NewReader(body))
	if err != nil {
		log.Tracef("Error executing Elasticsearch PUT %v", err)
		return "", err
	}
	request.Header.Set("Content-Type", contentTypeJSON)
	var resp *http.Response
	resp, err = es.client.Do(request)
	if err != nil {
		return "", err
	}
	return readBody(resp)
}

//Post submits a Post request to ES assuming the given body is of type 'application/json'
func (es *DefaultElasticsearchClient) Post(path string, body string) (string, error) {
	resp, err := http.Post(url(es.serverURL, path), contentTypeJSON, strings.NewReader(body))
	if err != nil {
		log.Tracef("Error executing Elasticsearch POST %v", err)
		return "", err
	}
	return readBody(resp)
}

//Delete submits a Delete request to ES assuming the given body is of type 'application/json'
func (es *DefaultElasticsearchClient) Delete(path string) (string, error) {
	request, err := http.NewRequest("DELETE", url(es.serverURL, path), nil)
	if err != nil {
		log.Tracef("Error executing Elasticsearch DELETE %v", err)
		return "", err
	}
	request.Header.Set("Content-Type", contentTypeJSON)
	var resp *http.Response
	resp, err = es.client.Do(request)
	if err != nil {
		return "", err
	}
	return readBody(resp)
}
