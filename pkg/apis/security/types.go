package security

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	cl "github.com/openshift/elasticsearch-proxy/pkg/handlers/clusterlogging/types"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

//DocType is the type of security document
type DocType string

const (
	//DocTypeRoles are the security roles
	DocTypeRoles DocType = "roles"
	//DocTypeRolesmapping are the security mappings of users to roles
	DocTypeRolesmapping DocType = "rolesmapping"
)

//ACLDocuments are the security documents
type ACLDocuments map[DocType]ACLDocument

type ACLDocument interface {
	Iterate() map[string]Expirable
	Remove(name string)
	ToJson() (string, error)
	Type() DocType
}

func (docs *ACLDocuments) Iterate() []ACLDocument {
	entries := []ACLDocument{}
	for _, doc := range *docs {
		entries = append(entries, doc)
	}
	return entries
}

func (docs *ACLDocuments) Set(aclDoc ACLDocument) {
	(*docs)[aclDoc.Type()] = aclDoc
}

func (docs *ACLDocuments) Roles() *Roles {
	return (*docs)[DocTypeRoles].(*Roles)
}

func (docs *ACLDocuments) RolesMapping() *RolesMapping {
	return (*docs)[DocTypeRolesmapping].(*RolesMapping)
}

//AddUser permissions to the ACL documents
func (docs *ACLDocuments) AddUser(user *cl.UserInfo, expires int64) {
	log.Tracef("Adding permissions for %s to expire at %v", user.Username, expires)
	roleName := roleName(user)
	role := Role{
		ClusterPermissions: Permissions{"CLUSTER_MONITOR_KIBANA", "USER_CLUSTER_OPERATIONS"},
		IndicesPermissions: newSecurityDocumentPermissions(user),
	}
	role.ExpiresInMillis = expires
	docs.Roles().Set(roleName, role)
	rolemapping := RoleMapping{
		Users: []string{user.Username},
	}
	rolemapping.ExpiresInMillis = expires
	docs.RolesMapping().Set(roleName, rolemapping)
}

//ExpirePermissions which are older then now
func (docs *ACLDocuments) ExpirePermissions() {
	log.Debug("Expiring permissions...")
	now := time.Now().UnixNano() / int64(time.Millisecond)
	for docType, aclDoc := range *docs {
		for name, entry := range aclDoc.Iterate() {
			expire := entry.GetExpiresInMillis()
			if expire > 0 && expire < now {
				log.Tracef("Expiring %s: %s", docType, name)
				aclDoc.Remove(name)
			}
		}
	}
}

type Expirable interface {
	GetExpiresInMillis() int64
}

//Roles are the roles for the ES Cluster
// root
//   roleName:
//     cluster:
//     expires:
//     indices:
//       indexName:
//         docType: [permissions]
type Roles map[string]Role

func (role *Role) GetExpiresInMillis() int64 {
	return role.ExpiresInMillis
}
func (roles *Roles) Iterate() map[string]Expirable {
	entries := map[string]Expirable{}
	for name, entry := range *roles {
		entries[name] = &entry
	}
	return entries
}

func (roles *Roles) Set(name string, role Role) {
	(*roles)[name] = role
}

func (roles *Roles) Remove(name string) {
	delete(*roles, name)
}

func (roles *Roles) Type() DocType {
	return DocTypeRoles
}
func (roles *Roles) ToYaml() (string, error) {
	return toYaml(roles)
}

func (roles *Roles) ToJson() (string, error) {
	return ToJson(roles)
}

type Role struct {
	ExpiresInMillis    int64            `yaml:"expires,omitempty" json:"expires,omitempty"`
	ClusterPermissions Permissions      `yaml:"cluster,omitempty" json:"cluster,omitempty"`
	IndicesPermissions IndexPermissions `yaml:"indices,omitempty" json:"indices,omitempty"`
}
type Permissions []string

type IndexPermissions map[string]DocumentPermissions

type DocumentPermissions map[string]Permissions

func toYaml(acl interface{}) (string, error) {
	var out []byte
	var err error
	if out, err = yaml.Marshal(acl); err != nil {
		return "", err
	}
	return string(out), nil
}

func ToJson(acl interface{}) (string, error) {
	log.Tracef("Converting acl to json: %+v", acl)
	var out []byte
	var err error
	if out, err = json.Marshal(acl); err != nil {
		return "", err
	}
	resp := string(out)
	log.Tracef("Converted: %s", resp)
	return resp, nil
}

func (roles *Roles) FromJson(acl string) error {
	if err := json.Unmarshal([]byte(acl), roles); err != nil {
		return err
	}
	return nil
}

func (rolesmapping *RolesMapping) FromJson(acl string) error {
	if err := json.Unmarshal([]byte(acl), rolesmapping); err != nil {
		return err
	}
	return nil
}

//Rolesmapping are the mapping of username/groups to roles
// root
//  roleName
//    expires:
//    users:
//    groups:
type RolesMapping map[string]RoleMapping

func (rolesMapping *RolesMapping) Iterate() map[string]Expirable {
	entries := map[string]Expirable{}
	for name, entry := range *rolesMapping {
		entries[name] = &entry
	}
	return entries
}

func (roleMapping *RoleMapping) GetExpiresInMillis() int64 {
	return roleMapping.ExpiresInMillis
}

func (rolesMapping *RolesMapping) Set(name string, rolemapping RoleMapping) {
	(*rolesMapping)[name] = rolemapping
}
func (rolesMapping *RolesMapping) Remove(name string) {
	delete(*rolesMapping, name)
}

type RoleMapping struct {
	ExpiresInMillis int64    `yaml:"expires,omitempty" json:"expires,omitempty"`
	Users           []string `yaml:"users,omitempty" json:"users,omitempty"`
}

func (rolesmapping *RolesMapping) Type() DocType {
	return DocTypeRolesmapping
}

func (rolesmapping *RolesMapping) ToYaml() (string, error) {
	return toYaml(rolesmapping)
}

func (rolesmapping *RolesMapping) ToJson() (string, error) {
	return ToJson(rolesmapping)
}

func newSecurityDocumentPermissions(user *cl.UserInfo) IndexPermissions {
	permissions := IndexPermissions{}
	permissions[fix(kibanaIndexName(user))] = DocumentPermissions{
		"*": Permissions{
			"INDEX_KIBANA",
		},
	}
	for _, project := range user.Projects {
		permissions[fix(projectIndexName(project))] = DocumentPermissions{
			"*": Permissions{
				"INDEX_PROJECT",
			},
		}
	}
	return permissions
}

func fix(indexName string) string {
	return strings.Replace(indexName, ".", "?", -1)
}

func projectIndexName(p cl.Project) string {
	return fmt.Sprintf("project.%s.%s.*", p.Name, p.UUID)
}

func kibanaIndexName(user *cl.UserInfo) string {
	return fmt.Sprintf(".kibana.%s", usernameHash(user))
}

func roleName(user *cl.UserInfo) string {
	return fmt.Sprintf("gen_user_%s", usernameHash(user))
}

func usernameHash(user *cl.UserInfo) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(user.Username)))
}
