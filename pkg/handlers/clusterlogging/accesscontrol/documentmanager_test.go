package accesscontrol

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/openshift/elasticsearch-proxy/pkg/config"
	cl "github.com/openshift/elasticsearch-proxy/pkg/handlers/clusterlogging/types"
)

var _ = Describe("DocumentManager", func() {

	var (
		dm   *DocumentManager
		user *cl.UserInfo
	)
	BeforeEach(func() {
		dm = &DocumentManager{}
		user = &cl.UserInfo{Groups: []string{"foo"}}
	})

	Describe("when the infra group name is ''", func() {
		It("a user should not evaluate as an infra group member", func() {
			Expect(dm.isInfraGroupMember(user)).Should(BeFalse())
		})
	})

	Describe("when the infra group name is a value", func() {
		It("a user should evaluate as an infra group member if they are in the group", func() {
			dm.Options = config.Options{}
			dm.Options.InfraRoleName = "foo"
			Expect(dm.isInfraGroupMember(user)).Should(BeTrue())
		})
	})

})
