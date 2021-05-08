package ovn

import (
	goovn "github.com/ebay/go-ovn"
	"github.com/onsi/gomega"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"sync"

	"github.com/urfave/cli/v2"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"

	egressfirewall "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	egressfirewallfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned/fake"
	egressip "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	egressipfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/fake"
)

const (
	k8sTCPLoadBalancerIP        = "k8s_tcp_load_balancer"
	k8sUDPLoadBalancerIP        = "k8s_udp_load_balancer"
	k8sSCTPLoadBalancerIP       = "k8s_sctp_load_balancer"
	k8sIdlingTCPLoadBalancerIP  = "k8s_tcp_idling_load_balancer"
	k8sIdlingUDPLoadBalancerIP  = "k8s_udp_idling_load_balancer"
	k8sIdlingSCTPLoadBalancerIP = "k8s_sctp_idling_load_balancer"
	fakeUUID                    = "8a86f6d8-7972-4253-b0bd-ddbef66e9303"
	fakeUUIDv6                  = "8a86f6d8-7972-4253-b0bd-ddbef66e9304"
	fakePgUUID                  = "bf02f460-5058-4689-8fcb-d31a1e484ed2"
	ovnClusterPortGroupUUID     = fakePgUUID
)

type FakeOVN struct {
	fakeClient   *util.OVNClientset
	watcher      *factory.WatchFactory
	controller   *Controller
	stopChan     chan struct{}
	fakeExec     *ovntest.FakeExec
	asf          *addressset.FakeAddressSetFactory
	fakeRecorder *record.FakeRecorder
	ovnNBClient  goovn.Client
	ovnSBClient  goovn.Client
	wg           *sync.WaitGroup
}

func NewFakeOVN(fexec *ovntest.FakeExec) *FakeOVN {
	err := util.SetExec(fexec)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return &FakeOVN{
		fakeExec:     fexec,
		asf:          addressset.NewFakeAddressSetFactory(),
		fakeRecorder: record.NewFakeRecorder(10),
		wg:           &sync.WaitGroup{},
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
		KubeClient:           fake.NewSimpleClientset(v1Objects...),
		EgressIPClient:       egressipfake.NewSimpleClientset(egressIPObjects...),
		EgressFirewallClient: egressfirewallfake.NewSimpleClientset(egressFirewallObjects...),
	}
	o.init()
}

func (o *FakeOVN) restart() {
	o.shutdown()
	o.init()
}

func (o *FakeOVN) shutdown() {
	close(o.stopChan)
	o.watcher.Shutdown()
	err := o.controller.ovnNBClient.Close()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	err = o.controller.ovnSBClient.Close()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	o.wg.Wait()
}

func (o *FakeOVN) init() {
	var err error
	o.stopChan = make(chan struct{})
	o.watcher, err = factory.NewMasterWatchFactory(o.fakeClient)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	o.ovnNBClient = ovntest.NewMockOVNClient(goovn.DBNB)
	o.ovnSBClient = ovntest.NewMockOVNClient(goovn.DBSB)
	o.controller = NewOvnController(o.fakeClient, o.watcher,
		o.stopChan, o.asf, o.ovnNBClient,
		o.ovnSBClient, o.fakeRecorder)
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
