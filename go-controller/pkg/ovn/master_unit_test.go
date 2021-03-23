package ovn

import (
	"errors"
	"fmt"
	"testing"

	egressfirewallfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned/fake"
	egressipfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/fake"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	v1 "k8s.io/api/core/v1"
	apiextensionsfake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"

	goovn "github.com/ebay/go-ovn"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	goovn_mock "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/github.com/ebay/go-ovn"
	"github.com/stretchr/testify/assert"
)

var (
	otherError = errors.New("other error")
)

func createNode(name, os, ip string, annotations map[string]string) *v1.Node {
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				v1.LabelOSStable: os,
			},
			Annotations: annotations,
		},
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{
				{Type: v1.NodeInternalIP, Address: ip},
			},
		},
	}
}

func createNodeList() *v1.NodeList {
	return &v1.NodeList{
		Items: []v1.Node{
			*createNode(node1Name, "linux", "10.0.0.1", nil),
		},
	}
}

func createMockOVNController(mockGoOvnNBClient *goovn_mock.Client) *Controller {
	stopChan := make(chan struct{})
	defer close(stopChan)
	kubeFakeClient := fake.NewSimpleClientset()
	egressFirewallFakeClient := &egressfirewallfake.Clientset{}
	crdFakeClient := &apiextensionsfake.Clientset{}
	egressIPFakeClient := &egressipfake.Clientset{}
	fakeClient := &util.OVNClientset{
		KubeClient:           kubeFakeClient,
		EgressIPClient:       egressIPFakeClient,
		EgressFirewallClient: egressFirewallFakeClient,
		APIExtensionsClient:  crdFakeClient,
	}
	f, _ := factory.NewMasterWatchFactory(fakeClient)
	return NewOvnController(fakeClient, f, stopChan,
		addressset.NewFakeAddressSetFactory(), mockGoOvnNBClient,
		ovntest.NewMockOVNClient(goovn.DBSB), record.NewFakeRecorder(0))

}

func TestUpgradeToSingleSwitchOVNTopology(t *testing.T) {
	mockGoOvnNBClient := new(goovn_mock.Client)
	logicalSwitchList := make([]*goovn.LogicalSwitch, 0)

	tests := []struct {
		desc                      string
		errExp                    bool
		errMatch                  error
		onRetArgMockGoOvnNBClient []ovntest.TestifyMockHelper
	}{
		{
			desc:   "test error when ovnNBClient.LSList() fails",
			errExp: true,
			onRetArgMockGoOvnNBClient: []ovntest.TestifyMockHelper{
				{
					OnCallMethodName: "LSList", OnCallMethodArgType: []string{}, RetArgList: []interface{}{nil, goovn.ErrorSchema},
				},
			},
		},
		{
			desc:     "test error when ovnNBClient.LSList() fails",
			errMatch: fmt.Errorf("failed to get all logical switches for upgrade: error: %v", otherError),
			onRetArgMockGoOvnNBClient: []ovntest.TestifyMockHelper{
				{
					OnCallMethodName: "LSList", OnCallMethodArgType: []string{}, RetArgList: []interface{}{nil, otherError},
				},
			},
		},
		{
			desc: "test positive case when ovnNBClient.LSList() passes",
			onRetArgMockGoOvnNBClient: []ovntest.TestifyMockHelper{
				{
					OnCallMethodName: "LSList", OnCallMethodArgType: []string{}, RetArgList: []interface{}{logicalSwitchList, nil},
				},
			},
		},
	}

	nodeList := createNodeList()
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			mockGoOvnNBController := createMockOVNController(mockGoOvnNBClient)

			ovntest.ProcessMockFnList(&mockGoOvnNBClient.Mock, tc.onRetArgMockGoOvnNBClient)

			err := mockGoOvnNBController.upgradeToSingleSwitchOVNTopology(nodeList)
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
