package clients

import (
	"encoding/base64"
	"fmt"

	"github.com/bitly/go-simplejson"
	ext "github.com/openshift/elasticsearch-proxy/pkg/handlers"
	"github.com/openshift/elasticsearch-proxy/pkg/handlers/clusterlogging/security"
	log "github.com/sirupsen/logrus"
)

type ESSecurityClient struct {
	esClient *ElasticsearchClient
}

func NewESSecurityClient(opts ext.Options) (*ESSecurityClient, error) {
	if opts.UpstreamURL == nil {
		return nil, fmt.Errorf("The UpstreamURL proxy URL is nil")
	}
	esClient, err := NewElasticsearchClient(opts.SSLInsecureSkipVerify, opts.UpstreamURL.String(), opts.TLSCertFile, opts.TLSKeyFile, opts.OpenshiftCAs)
	if err != nil {
		return nil, err
	}
	return &ESSecurityClient{esClient}, nil
}

func decodeACLDocument(resp, docType string) (string, error) {
	json, err := simplejson.NewJson([]byte(resp))
	if err != nil {
		return "", err
	}
	var encoded string
	encoded, err = json.GetPath("_source", docType).String()
	if err != nil {
		return "", err
	}
	unencoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	return string(unencoded), nil
}

func (sg *ESSecurityClient) FetchRoles() (*security.Roles, error) {
	log.Debug("Fetching Security roles...")
	resp, err := sg.esClient.Get("/.security/security/roles")
	if err != nil {
		return nil, err
	}
	sRoles, err := decodeACLDocument(resp, "roles")
	if err != nil {
		return nil, err
	}
	roles := &security.Roles{}
	err = roles.FromJson(sRoles)
	if err != nil {
		return nil, err
	}
	log.Debugf("Roles: %s", sRoles)
	return roles, nil
}

func (sg *ESSecurityClient) FetchRolesMapping() (*security.RolesMapping, error) {
	log.Debug("Fetching Security rolesmapping...")
	resp, err := sg.esClient.Get("/.security/security/rolesmapping")
	if err != nil {
		return nil, err
	}
	sRolesMapping, err := decodeACLDocument(resp, "rolesmapping")
	if err != nil {
		return nil, err
	}
	rolesmapping := &security.RolesMapping{}
	err = rolesmapping.FromJson(sRolesMapping)
	if err != nil {
		return nil, err
	}
	log.Debugf("Rolesmapping: %s", sRolesMapping)
	return rolesmapping, nil
}

func encodeACLDocument(doc security.Serializable) (string, error) {
	log.Tracef("Encoding %s ACL Document...", doc.Type())
	json, err := doc.ToJson()
	if err != nil {
		return "", err
	}
	log.Tracef("Trying to encode: %s", json)
	updated := map[string]interface{}{doc.Type(): []byte(json)}
	return security.ToJson(updated)
}

func (sg *ESSecurityClient) FlushACL(doc security.Serializable) error {
	log.Tracef("Flushing Security %s: %+v", doc.Type(), doc)
	sDoc, err := encodeACLDocument(doc)
	if err != nil {
		return err
	}
	if _, err = sg.esClient.Put(fmt.Sprintf("/.security/security/%s", doc.Type()), sDoc); err != nil {
		return err
	}
	log.Trace("Calling config reload...")
	var resp string
	if resp, err = sg.esClient.Delete("/_opendistro/_security/api/cache"); err != nil {
		return err
	}
	log.Tracef("Config reload response %v", resp)
	return nil
}
