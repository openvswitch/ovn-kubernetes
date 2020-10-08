package node

import (
	. "github.com/onsi/gomega"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressipfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/fake"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/urfave/cli/v2"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"

	egressfirewallfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned/fake"
	apiextensionsfake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
)

var fakeNodeName = "node"

type FakeOVNNode struct {
	node               *OvnNode
	watcher            *factory.WatchFactory
	stopChan           chan struct{}
	recorder           *record.FakeRecorder
	fakeClient         *fake.Clientset
	fakeEgressIPClient *egressipfake.Clientset
	fakeEgressClient   *egressfirewallfake.Clientset
	fakeCRDClient      *apiextensionsfake.Clientset
	fakeExec           *ovntest.FakeExec
	exec               util.ExecHelper
}

func NewFakeOVNNode(fexec *ovntest.FakeExec) *FakeOVNNode {
	exec, err := util.NewExecHelper(fexec)
	Expect(err).NotTo(HaveOccurred())

	return &FakeOVNNode{
		fakeExec: fexec,
		exec:     exec,
		recorder: record.NewFakeRecorder(1),
	}
}

func (o *FakeOVNNode) start(ctx *cli.Context, objects ...runtime.Object) {
	v1Objects := []runtime.Object{}
	for _, object := range objects {
		v1Objects = append(v1Objects, object)
	}
	_, err := config.InitConfig(ctx, o.fakeExec, nil)
	Expect(err).NotTo(HaveOccurred())

	o.fakeCRDClient = apiextensionsfake.NewSimpleClientset()
	o.fakeEgressClient = egressfirewallfake.NewSimpleClientset()
	o.fakeEgressIPClient = egressipfake.NewSimpleClientset()
	o.fakeClient = fake.NewSimpleClientset(v1Objects...)
	o.init()
}

func (o *FakeOVNNode) restart() {
	o.shutdown()
	o.init()
}

func (o *FakeOVNNode) shutdown() {
	close(o.stopChan)
}

func (o *FakeOVNNode) init() {
	var err error

	o.stopChan = make(chan struct{})

	o.watcher, err = factory.NewWatchFactory(o.fakeClient, o.fakeEgressIPClient, o.fakeEgressClient, o.fakeCRDClient)
	Expect(err).NotTo(HaveOccurred())

	o.node = NewNode(o.fakeClient, o.exec, o.watcher, fakeNodeName, o.stopChan, o.recorder)
}
