package accesscontrol

import (
	"time"

	"github.com/openshift/elasticsearch-proxy/pkg/clients"
	"github.com/openshift/elasticsearch-proxy/pkg/handlers/clusterlogging/security"
	cl "github.com/openshift/elasticsearch-proxy/pkg/handlers/clusterlogging/types"
	log "github.com/sirupsen/logrus"
)

type securityClient interface {
	FetchRolesMapping() (*security.RolesMapping, error)
	FetchRoles() (*security.Roles, error)
	FlushACL(doc security.Serializable) error
}

//DocumentManager understands how to load and sync ACL documents
type DocumentManager struct {
	cl.ExtConfig
	securityClient securityClient
}

//NewDocumentManager creates an instance or returns error
func NewDocumentManager(config cl.ExtConfig) (*DocumentManager, error) {
	log.Tracef("Instantiating a new document manager using: %+v", config)
	sgClient, err := clients.NewESSecurityClient(config.Options)
	if err != nil {
		return nil, err
	}
	return &DocumentManager{
		config,
		sgClient,
	}, nil
}

//SyncACL to include the given UserInfo
func (dm *DocumentManager) SyncACL(userInfo *cl.UserInfo) error {
	log.Debugf("SyncACL for %+v", userInfo)
	if dm.isInfraGroupMember(userInfo) {
		log.Debugf("Skipping sync of ACLs for infragroup member %s. Permissions are assumed to be static", userInfo.Username)
		return nil
	}
	docs, err := dm.loadACL()
	if err != nil {
		return err
	}
	docs.ExpirePermissions()
	docs.AddUser(userInfo, nextExpireTime(dm.ExtConfig.PermissionExpirationMillis))
	if err = dm.writeACL(docs); err != nil {
		return err
	}
	// dm.reloadConfig()
	return nil
}

// func (dm *DocumentManager) reloadConfig() error {
// 	dm.sgclient.
// }

func (dm *DocumentManager) writeACL(docs *security.ACLDocuments) error {
	log.Debug("Writing ACLs...")
	if err := dm.securityClient.FlushACL(&docs.Roles); err != nil {
		return err
	}
	if err := dm.securityClient.FlushACL(&docs.RolesMapping); err != nil {
		return err
	}
	return nil
}

func (dm *DocumentManager) loadACL() (*security.ACLDocuments, error) {
	log.Debug("Loading ACLs...")
	//TODO work on mget of roles/mappings
	roles, err := dm.securityClient.FetchRoles()
	if err != nil {
		return nil, err
	}
	rolesmapping, err := dm.securityClient.FetchRolesMapping()
	if err != nil {
		return nil, err
	}
	docs := &security.ACLDocuments{
		Roles:        *roles,
		RolesMapping: *rolesmapping,
	}
	log.Debugf("Loaded ACLs: %v", docs)
	return docs, nil
}

func (dm *DocumentManager) isInfraGroupMember(user *cl.UserInfo) bool {
	for _, group := range user.Groups {
		if group == dm.ExtConfig.InfraRoleName {
			log.Tracef("%s is a member of the InfraGroup (%s)", user.Username, dm.ExtConfig.InfraRoleName)
			return true
		}
	}
	return false
}

func nextExpireTime(expire int64) int64 {
	return time.Now().UnixNano()/int64(time.Millisecond) + expire
}
