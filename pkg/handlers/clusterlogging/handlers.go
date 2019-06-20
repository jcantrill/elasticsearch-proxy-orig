package clusterlogging

import (
	"net/http"

	"github.com/bitly/go-simplejson"
	"github.com/openshift/elasticsearch-proxy/pkg/clients"
	extensions "github.com/openshift/elasticsearch-proxy/pkg/handlers"
	ac "github.com/openshift/elasticsearch-proxy/pkg/handlers/clusterlogging/accesscontrol"
	config "github.com/openshift/elasticsearch-proxy/pkg/handlers/clusterlogging/types"
	log "github.com/sirupsen/logrus"
)

type setString map[string]interface{}

type extension struct {
	*extensions.Options

	//whitelisted is the list of user and or serviceacccounts for which
	//all proxy logic is skipped (e.g. fluent)
	whitelisted     setString
	documentManager *ac.DocumentManager
	osClient        clients.OpenShiftClient
	config          config.ExtConfig
}

type requestContext struct {
	*config.UserInfo
}

//NewHandlers is the initializer for clusterlogging extensions
func NewHandlers(opts *extensions.Options) []extensions.RequestHandler {
	config := config.ExtConfig{
		KibanaIndexMode:            config.KibanaIndexModeSharedOps,
		InfraRoleName:              "sg_role_admin",
		PermissionExpirationMillis: 1000 * 2 * 60, //2 minutes
		Options:                    *opts,
	}
	dm, err := ac.NewDocumentManager(config)
	if err != nil {
		log.Fatalf("Unable to initialize the cluster logging proxy extension %v", err)
	}
	client, err := clients.NewOpenShiftClient(*opts)
	if err != nil {
		log.Fatalf("Unable to initialize OpenShift Client %v", err)
	}
	return []extensions.RequestHandler{
		&extension{
			opts,
			setString{},
			dm,
			client,
			config,
		},
	}
}

func (ext *extension) Process(req *http.Request, context *extensions.RequestContext) (*http.Request, error) {
	name := context.UserName
	if ext.isWhiteListed(name) || ext.hasInfraRole(context) {
		log.Debugf("Skipping additional processing, %s is whitelisted or has the infra role", name)
		return req, nil
	}
	modRequest := req
	userInfo, err := newUserInfo(ext, context)
	if err != nil {
		return req, err
	}
	// modify kibana request
	// seed kibana dashboards
	ext.documentManager.SyncACL(userInfo)

	return modRequest, nil
}

func (ext *extension) isWhiteListed(name string) bool {
	if _, ok := ext.whitelisted[name]; ok {
		return true
	}
	return false
}

func (ext *extension) hasInfraRole(context *extensions.RequestContext) bool {
	for _, role := range context.Roles {
		if role == ext.config.InfraRoleName {
			log.Tracef("%s has the the Infra Role (%s)", context.UserName, ext.config.InfraRoleName)
			return true
		}
	}
	return false
}

func newUserInfo(ext *extension, context *extensions.RequestContext) (*config.UserInfo, error) {
	projects, err := ext.fetchProjects(context)
	if err != nil {
		return nil, err
	}
	info := &config.UserInfo{
		Username: context.UserName,
		Projects: projects,
		Groups:   context.Groups,
	}
	log.Tracef("Created userInfo: %+v", info)
	return info, nil
}

func (ext *extension) fetchProjects(context *extensions.RequestContext) (projects []config.Project, err error) {
	log.Debugf("Fetching projects for user %q", context.UserName)

	var json *simplejson.Json
	json, err = ext.osClient.Get("apis/project.openshift.io/v1/projects", context.Token)
	if err != nil {
		log.Errorf("There was an error fetching projects: %v", err)
		return nil, err
	}
	projects = []config.Project{}
	if items, ok := json.CheckGet("items"); ok {
		total := len(items.MustArray())
		for i := 0; i < total; i++ {
			//check for missing?
			var name, uid string
			if value := items.GetIndex(i).GetPath("metadata", "name"); value.Interface() != nil {
				name = value.MustString()
			}
			if value := items.GetIndex(i).GetPath("metadata", "uid"); value.Interface() != nil {
				uid = value.MustString()
			}
			projects = append(projects, config.Project{Name: name, UUID: uid})
		}
	}
	return projects, nil
}

func (ext *extension) Name() string {
	return "addUserProjects"
}
