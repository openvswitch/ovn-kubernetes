package ovn

import (
	goovn "github.com/ebay/go-ovn"
	"github.com/onsi/gomega"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"github.com/urfave/cli/v2"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"

	networkattachmentdefinitionfake "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/fake"
	egressfirewall "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	egressfirewallfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned/fake"
	egressip "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	egressipfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/fake"
	apiextensionsfake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
)

const (
	k8sTCPLoadBalancerIP    = "k8s_tcp_load_balancer"
	k8sUDPLoadBalancerIP    = "k8s_udp_load_balancer"
	k8sSCTPLoadBalancerIP   = "k8s_sctp_load_balancer"
	fakeUUID                = "8a86f6d8-7972-4253-b0bd-ddbef66e9303"
	fakeUUIDv6              = "8a86f6d8-7972-4253-b0bd-ddbef66e9304"
	ovnClusterPortGroupUUID = "740515f3-7ece-4cd1-9be5-6fdb9066d198"
)

type FakeOVN struct {
	fakeClient   *util.OVNClientset
	watcher      *factory.WatchFactory
	mhController *OvnMHController
	controller   *Controller
	stopChan     chan struct{}
	fakeExec     *ovntest.FakeExec
	asf          *addressset.FakeAddressSetFactory
	fakeRecorder *record.FakeRecorder
	ovnNBClient  goovn.Client
	ovnSBClient  goovn.Client
}

func NewFakeOVN(fexec *ovntest.FakeExec) *FakeOVN {
	err := util.SetExec(fexec)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return &FakeOVN{
		fakeExec:     fexec,
		asf:          addressset.NewFakeAddressSetFactory(),
		fakeRecorder: record.NewFakeRecorder(10),
	}
}

func (o *FakeOVN) start(ctx *cli.Context, objects ...runtime.Object) {
	egressIPObjects := []runtime.Object{}
	egressFirewallObjects := []runtime.Object{}
	v1Objects := []runtime.Object{}
	for _, object := range objects {
		if _, isEgressIPObject := object.(*egressip.EgressIPList); isEgressIPObject {
			egressIPObjects = append(egressIPObjects, object)
		} else if _, isEgressFirewallObject := object.(*egressfirewall.EgressFirewallList); isEgressFirewallObject {
			egressFirewallObjects = append(egressFirewallObjects, object)
		} else {
			v1Objects = append(v1Objects, object)
		}
	}
	_, err := config.InitConfig(ctx, o.fakeExec, nil)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	o.fakeClient = &util.OVNClientset{
		KubeClient:            fake.NewSimpleClientset(v1Objects...),
		EgressIPClient:        egressipfake.NewSimpleClientset(egressIPObjects...),
		EgressFirewallClient:  egressfirewallfake.NewSimpleClientset(egressFirewallObjects...),
		APIExtensionsClient:   apiextensionsfake.NewSimpleClientset(),
		NetworkAttchDefClient: networkattachmentdefinitionfake.NewSimpleClientset(),
	}
	o.init()
}

func (o *FakeOVN) restart() {
	o.shutdown()
	o.init()
}

func (o *FakeOVN) shutdown() {
	close(o.stopChan)
	o.watcher.ShutdownEgressFirewallWatchFactory()
	o.watcher.Shutdown()
	err := o.mhController.ovnNBClient.Close()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	err = o.mhController.ovnSBClient.Close()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
}

func (o *FakeOVN) init() {
	var err error
	o.stopChan = make(chan struct{})
	o.watcher, err = factory.NewMasterWatchFactory(o.fakeClient)
	o.watcher.InitializeEgressFirewallWatchFactory()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	o.ovnNBClient = ovntest.NewMockOVNClient(goovn.DBNB)
	o.ovnSBClient = ovntest.NewMockOVNClient(goovn.DBSB)
	o.mhController = NewOvnMHController(o.fakeClient, "", o.watcher,
		o.stopChan, o.ovnNBClient,
		o.ovnSBClient, o.fakeRecorder, nil)
	_ = o.mhController.setDefaultOvnController(o.asf)
	o.controller = o.mhController.ovnController
	o.controller.multicastSupport = true
}

func mockAddNBDBError(table, name, field string, err error, ovnNBClient goovn.Client) {
	mockClient, ok := ovnNBClient.(*ovntest.MockOVNClient)
	if !ok {
		panic("type assertion failed for mock NB client")
	}
	mockClient.AddToErrorCache(table, name, field, err)
}

func mockAddSBDBError(table, name, field string, err error, ovnSBClient goovn.Client) {
	mockClient, ok := ovnSBClient.(*ovntest.MockOVNClient)
	if !ok {
		panic("type assertion failed for mock SB client")
	}
	mockClient.AddToErrorCache(table, name, field, err)
}

func mockDelNBDBError(table, name, field string, ovnNBClient goovn.Client) {
	mockClient, ok := ovnNBClient.(*ovntest.MockOVNClient)
	if !ok {
		panic("type assertion failed for mock NB client")
	}
	mockClient.RemoveFromErrorCache(table, name, field)
}

func mockDelSBDBError(table, name, field string, ovnSBClient goovn.Client) {
	mockClient, ok := ovnSBClient.(*ovntest.MockOVNClient)
	if !ok {
		panic("type assertion failed for mock SB client")
	}
	mockClient.RemoveFromErrorCache(table, name, field)
}
