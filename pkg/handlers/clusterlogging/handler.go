package clusterlogging

import (
	"net/http"

	"github.com/bitly/go-simplejson"
	"github.com/openshift/elasticsearch-proxy/pkg/clients"
	"github.com/openshift/elasticsearch-proxy/pkg/config"
	handlers "github.com/openshift/elasticsearch-proxy/pkg/handlers"
	ac "github.com/openshift/elasticsearch-proxy/pkg/handlers/clusterlogging/accesscontrol"
	"github.com/openshift/elasticsearch-proxy/pkg/handlers/clusterlogging/types"
	log "github.com/sirupsen/logrus"
)

type setString map[string]interface{}

type handler struct {
	config *config.Options

	//whitelisted is the list of user and or serviceacccounts for which
	//all proxy logic is skipped (e.g. fluent)
	whitelisted     setString
	documentManager *ac.DocumentManager
	osClient        clients.OpenShiftClient
}

type requestContext struct {
	*types.UserInfo
}

//NewHandlers is the initializer for clusterlogging handlers
func NewHandlers(opts *config.Options) []handlers.RequestHandler {
	dm, err := ac.NewDocumentManager(*opts)
	if err != nil {
		log.Fatalf("Unable to initialize the cluster logging proxy handler %v", err)
	}
	client, err := clients.NewOpenShiftClient(*opts)
	if err != nil {
		log.Fatalf("Unable to initialize OpenShift Client %v", err)
	}
	return []handlers.RequestHandler{
		&handler{
			opts,
			setString{},
			dm,
			client,
		},
	}
}

func (ext *handler) Process(req *http.Request, context *handlers.RequestContext) (*http.Request, error) {
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

func (ext *handler) isWhiteListed(name string) bool {
	if _, ok := ext.whitelisted[name]; ok {
		return true
	}
	return false
}

func (ext *handler) hasInfraRole(context *handlers.RequestContext) bool {
	for _, role := range context.Roles {
		if role == ext.config.InfraRoleName {
			log.Tracef("%s has the the Infra Role (%s)", context.UserName, ext.config.InfraRoleName)
			return true
		}
	}
	return false
}

func newUserInfo(ext *handler, context *handlers.RequestContext) (*types.UserInfo, error) {
	projects, err := ext.fetchProjects(context)
	if err != nil {
		return nil, err
	}
	info := &types.UserInfo{
		Username: context.UserName,
		Projects: projects,
		Groups:   context.Groups,
	}
	log.Tracef("Created userInfo: %+v", info)
	return info, nil
}

func (ext *handler) fetchProjects(context *handlers.RequestContext) (projects []types.Project, err error) {
	log.Debugf("Fetching projects for user %q", context.UserName)

	var json *simplejson.Json
	json, err = ext.osClient.Get("apis/project.openshift.io/v1/projects", context.Token)
	if err != nil {
		log.Errorf("There was an error fetching projects: %v", err)
		return nil, err
	}
	projects = []types.Project{}
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
			projects = append(projects, types.Project{Name: name, UUID: uid})
		}
	}
	return projects, nil
}

func (ext *handler) Name() string {
	return "clusterlogging"
}
