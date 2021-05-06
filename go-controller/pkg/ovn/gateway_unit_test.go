package ovn

import (
	"fmt"
	"net"
	"testing"

	goovn "github.com/ebay/go-ovn"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	goovn_mock "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/github.com/ebay/go-ovn"
	"github.com/stretchr/testify/assert"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

const (
	nodeRouteUUID string = "0cac12cf-3e0f-4682-b028-5ea2e0001962"
)

func TestStaticRouteCleanup(t *testing.T) {
	mockGoOvnNBClient := new(goovn_mock.Client)
	gomega.RegisterFailHandler(Fail)
	fexec := ovntest.NewFakeExec()
	err := util.SetExec(fexec)

	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_static_route nexthop=\"100.64.0.1\"",
		Output: nodeRouteUUID,
	})

	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_static_route nexthop=\"100.64.0.1\"",
		Output: nodeRouteUUID,
	})

	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	tests := []struct {
		desc                      string
		errExp                    bool
		errMatch                  error
		onRetArgMockGoOvnNBClient []ovntest.TestifyMockHelper
	}{
		{
			desc:   "test error when ovnNBClient.LRSRDelByUUID() fails",
			errExp: false,
			onRetArgMockGoOvnNBClient: []ovntest.TestifyMockHelper{
				{
					OnCallMethodName: "LRSRDelByUUID", OnCallMethodArgType: []string{"string", "string"}, RetArgList: []interface{}{nil, otherError},
				},
			},
		},
		{
			desc:     "test positive case when ovnNBClient.LRSRDelByUUID() passes",
			errExp:   false,
			errMatch: nil,
			onRetArgMockGoOvnNBClient: []ovntest.TestifyMockHelper{
				{
					OnCallMethodName: "LRSRDelByUUID", OnCallMethodArgType: []string{"string", "string"}, RetArgList: []interface{}{&goovn.OvnCommand{}, nil},
				},
				{
					OnCallMethodName: "Execute", OnCallMethodArgType: []string{"*goovn.OvnCommand"}, RetArgList: []interface{}{nil},
				},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			var err error
			ovntest.ProcessMockFnList(&mockGoOvnNBClient.Mock, tc.onRetArgMockGoOvnNBClient)
			nextHops := []net.IP{ovntest.MustParseIP("100.64.0.1")}
			staticRouteCleanup(mockGoOvnNBClient, nextHops)
			if tc.errExp {
				assert.Error(t, err)
			} else if tc.errMatch != nil {
				assert.Contains(t, err.Error(), tc.errMatch.Error())
			} else {
				assert.Nil(t, err)
			}
			mockGoOvnNBClient.AssertExpectations(t)
		})
	}
}
