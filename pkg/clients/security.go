package clients

import (
	"encoding/base64"
	"fmt"

	"github.com/bitly/go-simplejson"
	"github.com/openshift/elasticsearch-proxy/pkg/apis/security"
	ext "github.com/openshift/elasticsearch-proxy/pkg/handlers"
	log "github.com/sirupsen/logrus"
)

const (
	securityIndex = ".security"
	DocType       = "security"
)

//ESSecurityClient for reading and writing security documents
type SecurityClient interface {
	FetchACLs() (*security.ACLDocuments, error)

	//FetchRolesMapping for security
	FetchRolesMapping() (*security.RolesMapping, error)

	//FetchRoles for security
	FetchRoles() (*security.Roles, error)

	//FlushACL documents from the manager to Elasticsearch
	FlushACL(doc security.ACLDocuments) error
}

//DefaultESSecurityClient implementation
type DefaultESSecurityClient struct {
	esClient ElasticsearchClient
}

//NewESSecurityClient initializes the client
func NewESSecurityClient(opts ext.Options) (SecurityClient, error) {
	if opts.UpstreamURL == nil {
		return nil, fmt.Errorf("The UpstreamURL proxy URL is nil")
	}
	esClient, err := NewElasticsearchClient(opts.SSLInsecureSkipVerify, opts.UpstreamURL.String(), opts.TLSCertFile, opts.TLSKeyFile, opts.OpenshiftCAs)
	if err != nil {
		return nil, err
	}
	return &DefaultESSecurityClient{esClient}, nil
}

func decodeACLDocument(resp string, docType security.DocType) (string, error) {
	json, err := simplejson.NewJson([]byte(resp))
	if err != nil {
		return "", err
	}
	var encoded string
	encoded, err = json.GetPath("_source", string(docType)).String()
	if err != nil {
		return "", err
	}
	unencoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	return string(unencoded), nil
}

func decodeACLDocumentFrom(item MGetResponseItem, docType security.DocType) (string, error) {
	log.Tracef("Decoding docType %q from %v", docType, item)
	source := item.Source[string(docType)]
	log.Tracef("ACLDocument _source to decode: %v", source)
	unencoded, err := base64.StdEncoding.DecodeString(source.(string))
	if err != nil {
		return "", err
	}

	return string(unencoded), nil
}

func decodeRolesACLDocumentFrom(item MGetResponseItem) (*security.Roles, error) {
	log.Tracef("Decoding Roles from %v", item)
	sRoles, err := decodeACLDocumentFrom(item, security.DocTypeRoles)
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
func decodeRolesACLDocument(resp string) (*security.Roles, error) {
	sRoles, err := decodeACLDocument(resp, security.DocTypeRoles)
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
func decodeRolesmappingACLDocument(resp string) (*security.RolesMapping, error) {
	sRolesMapping, err := decodeACLDocument(resp, security.DocTypeRoles)
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
func decodeRolesmappingACLDocumentFrom(item MGetResponseItem) (*security.RolesMapping, error) {
	sRolesMapping, err := decodeACLDocumentFrom(item, security.DocTypeRolesmapping)
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

func (sg *DefaultESSecurityClient) FetchACLs() (*security.ACLDocuments, error) {
	log.Debug("FetchACLs ACLs...")
	items := MGetRequest{
		Docs: []MGetItem{
			MGetItem{
				Type: DocType,
				Id:   string(security.DocTypeRoles),
			},
			MGetItem{
				Type: DocType,
				Id:   string(security.DocTypeRolesmapping),
			},
		},
	}
	resp, err := sg.esClient.MGet(securityIndex, items)
	if err != nil {
		return nil, err
	}
	docs := &security.ACLDocuments{}
	for _, item := range resp.Docs {
		switch item.Id {
		case string(security.DocTypeRoles):
			doc, err := decodeRolesACLDocumentFrom(item)
			if err != nil {
				return nil, err
			}
			docs.Set(doc)
		case string(security.DocTypeRolesmapping):
			doc, err := decodeRolesmappingACLDocumentFrom(item)
			if err != nil {
				return nil, err
			}
			docs.Set(doc)
		}
	}
	return docs, nil
}

func (sg *DefaultESSecurityClient) FetchRoles() (*security.Roles, error) {
	log.Debug("Fetching Security roles...")
	resp, err := sg.esClient.Get("/.security/security/roles")
	if err != nil {
		return nil, err
	}
	return decodeRolesACLDocument(resp)
}

func (sg *DefaultESSecurityClient) FetchRolesMapping() (*security.RolesMapping, error) {
	log.Debug("Fetching Security rolesmapping...")
	resp, err := sg.esClient.Get("/.security/security/rolesmapping")
	if err != nil {
		return nil, err
	}
	return decodeRolesmappingACLDocument(resp)
}

func encodeACLDocument(doc security.ACLDocument) (string, error) {
	log.Tracef("Encoding %s ACL Document...", doc.Type())
	json, err := doc.ToJson()
	if err != nil {
		return "", err
	}
	log.Tracef("Trying to encode: %s", json)
	updated := map[security.DocType]interface{}{doc.Type(): []byte(json)}
	return security.ToJson(updated)
}

func (sg *DefaultESSecurityClient) FlushACL(docs security.ACLDocuments) error {
	for _, doc := range docs.Iterate() {
		log.Tracef("Flushing Security %s: %+v", doc.Type(), doc)
		sDoc, err := encodeACLDocument(doc)
		if err != nil {
			return err
		}
		if _, err = sg.esClient.Put(fmt.Sprintf("/.security/security/%s", doc.Type()), sDoc); err != nil {
			return err
		}
	}
	log.Trace("Calling config reload...")
	var resp string
	var err error
	if resp, err = sg.esClient.Delete("/_opendistro/_security/api/cache"); err != nil {
		return err
	}
	log.Tracef("Config reload response %v", resp)
	return nil
}
