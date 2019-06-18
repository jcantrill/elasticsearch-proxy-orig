package bearertoken

import (
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"

	clients "github.com/openshift/elasticsearch-proxy/pkg/clients"
	extensions "github.com/openshift/elasticsearch-proxy/pkg/handlers"
)

const (
	headerAuthorization     = "Authorization"
	headerForwardedUser     = "X-Forwarded-User"
	headerForwardedRoles    = "X-Forwarded-Roles"
	serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

type backendRoleConfig struct {
	Namespace        string
	Verb             string
	Resource         string
	ResourceAPIGroup string
}

type bearerTokenExtension struct {
	options            *extensions.Options
	osClient           clients.OpenShiftClient
	backendRoleConfigs map[string]backendRoleConfig
}

//NewHandlers is the initializer for this extension
func NewHandlers(opts *extensions.Options) (_ []extensions.RequestHandler) {
	osClient, err := clients.NewOpenShiftClient(*opts)
	if err != nil {
		log.Fatalf("Error constructing OpenShiftClient %v", err)
	}
	return []extensions.RequestHandler{
		&bearerTokenExtension{
			opts,
			osClient,
			map[string]backendRoleConfig{
				"sg_role_admin": backendRoleConfig{Namespace: "default", Verb: "view", Resource: "pods/metrics"},
				"prometheus":    backendRoleConfig{Verb: "get", Resource: "/metrics"},
				"jaeger":        backendRoleConfig{Verb: "get", Resource: "/jaeger", ResourceAPIGroup: "elasticsearch.jaegertracing.io"},
			},
		},
	}
}
func (ext *bearerTokenExtension) Name() string {
	return "Authorization"
}

func (ext *bearerTokenExtension) Process(req *http.Request, context *extensions.RequestContext) (*http.Request, error) {
	log.Tracef("Processing request in handler %q", ext.Name())
	context.Token = getBearerTokenFrom(req)
	if context.Token == "" {
		log.Debugf("Skipping %s as there is no bearer token present", ext.Name())
		return req, nil
	}
	sanitizeHeaders(req)
	json, err := ext.osClient.TokenReview(context.Token)
	if err != nil {
		log.Errorf("Error fetching user info %v", err)
		return req, err
	}
	context.UserName = json.UserName()
	log.Debugf("User is %q", json.UserName())
	if context.UserName != "" {
		req.Header.Set(headerForwardedUser, context.UserName)
	}
	ext.fetchRoles(req, context)
	return req, nil
}

func (ext *bearerTokenExtension) fetchRoles(req *http.Request, context *extensions.RequestContext) {
	log.Debug("Determining roles...")
	for name, sar := range ext.backendRoleConfigs {
		if allowed, err := ext.osClient.SubjectAccessReview(context.UserName, sar.Namespace, sar.Verb, sar.Resource, sar.ResourceAPIGroup); err == nil {
			log.Debugf("%q for %q SAR: %v", context.UserName, name, allowed)
			if allowed {
				context.Roles = append(context.Roles, name)
				req.Header.Add(headerForwardedRoles, name)
			}
		} else {
			log.Warnf("Unable to evaluate %s SAR for user %s", name, context.UserName)
		}
	}
}

func sanitizeHeaders(req *http.Request) {
	req.Header.Del(headerAuthorization)
}

func getBearerTokenFrom(req *http.Request) string {
	parts := strings.SplitN(req.Header.Get(headerAuthorization), " ", 2)
	if len(parts) > 0 && parts[0] == "Bearer" {
		return parts[1]
	}
	log.Trace("No bearer token found on request. Returning ''")
	return ""
}
