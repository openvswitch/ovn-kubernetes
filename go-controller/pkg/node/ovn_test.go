package node

import (
	"sync"

	. "github.com/onsi/gomega"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/urfave/cli/v2"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"

	egressfirewallfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned/fake"
	egressipfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/fake"
	nodednsinfofake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/nodednsinfo/v1/apis/clientset/versioned/fake"
	apiextensionsfake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"

	egressfirewallapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
)

var fakeNodeName = "node"

type FakeOVNNode struct {
	node       *OvnNode
	watcher    factory.NodeWatchFactory
	stopChan   chan struct{}
	recorder   *record.FakeRecorder
	fakeClient *util.OVNClientset
	fakeExec   *ovntest.FakeExec
	wg         *sync.WaitGroup
}

func NewFakeOVNNode(fexec *ovntest.FakeExec) *FakeOVNNode {
	err := util.SetExec(fexec)
	Expect(err).NotTo(HaveOccurred())

	return &FakeOVNNode{
		fakeExec: fexec,
		recorder: record.NewFakeRecorder(1),
		wg:       &sync.WaitGroup{},
	}
}

func (o *FakeOVNNode) start(ctx *cli.Context, objects ...runtime.Object) {
	v1Objects := []runtime.Object{}
	egressFirewallObjects := []runtime.Object{}
	for _, object := range objects {
		if _, isEgressFirewallObject := object.(*egressfirewallapi.EgressFirewallList); isEgressFirewallObject {
			egressFirewallObjects = append(egressFirewallObjects, object)
		} else {
			v1Objects = append(v1Objects, object)
		}
	}
	_, err := config.InitConfig(ctx, o.fakeExec, nil)
	Expect(err).NotTo(HaveOccurred())

	o.fakeClient = &util.OVNClientset{
		KubeClient:           fake.NewSimpleClientset(v1Objects...),
		EgressIPClient:       egressipfake.NewSimpleClientset(),
		EgressFirewallClient: egressfirewallfake.NewSimpleClientset(egressFirewallObjects...),
		NodeDNSInfoClient:    nodednsinfofake.NewSimpleClientset(),
		APIExtensionsClient:  apiextensionsfake.NewSimpleClientset(),
	}
	o.init()
}

func (o *FakeOVNNode) restart() {
	o.shutdown()
	o.init()
}

func (o *FakeOVNNode) shutdown() {
	close(o.stopChan)
	o.watcher.Shutdown()
	o.wg.Wait()
}

func (o *FakeOVNNode) init() {
	var err error

	o.stopChan = make(chan struct{})

	o.watcher, err = factory.NewNodeWatchFactory(o.fakeClient, fakeNodeName)
	Expect(err).NotTo(HaveOccurred())

	o.node = NewNode(o.fakeClient, o.watcher, fakeNodeName, o.stopChan, o.recorder)
	o.node.Start(o.wg)
}
