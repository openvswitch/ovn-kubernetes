package node

import (
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube/mocks"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
)

func genListStalePortsCmd() string {
	return fmt.Sprintf("ovs-vsctl --timeout=15 --data=bare --no-headings --columns=name find interface ofport=-1")
}

func genDeleteStalePortCmd(iface string) string {
	return fmt.Sprintf("ovs-vsctl --timeout=15 --if-exists --with-iface del-port %s", iface)
}

func genDeleteStaleRepPortCmd(brName, port string) string {
	return fmt.Sprintf("ovs-vsctl --timeout=15 --if-exists del-port %s %s", brName, port)
}

func genListPortsCmd(brName string) string {
	return fmt.Sprintf("ovs-vsctl --timeout=15 list-ports %s", brName)
}

func genGetPortIfacesCmd(port string) string {
	return fmt.Sprintf("ovs-vsctl --timeout=15 get Port %s Interfaces", port)
}

func genGetInterfaceAttributeCmd(iface, attr string) string {
	return fmt.Sprintf("ovs-vsctl --timeout=15 get Interface %s %s", iface, attr)
}

var _ = Describe("Healthcheck tests", func() {
	var execMock *ovntest.FakeExec
	var kubeMock *mocks.KubeInterface

	BeforeEach(func() {
		execMock = ovntest.NewFakeExec()
		util.SetExec(execMock)
		kubeMock = &mocks.KubeInterface{}
	})

	AfterEach(func() {
		util.ResetRunner()
	})

	Describe("checkForStaleOVSInternalPorts", func() {

		Context("bridge has stale ports", func() {
			It("removes stale ports from bridge", func() {
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    genListStalePortsCmd(),
					Output: "foo\n\nbar\n\n",
					Err:    nil,
				})
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    genDeleteStalePortCmd("foo"),
					Output: "",
					Err:    nil,
				})
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    genDeleteStalePortCmd("bar"),
					Output: "",
					Err:    nil,
				})
				checkForStaleOVSInternalPorts()
				Expect(execMock.CalledMatchesExpected()).To(BeTrue(), execMock.ErrorDesc)
			})
		})

		Context("bridge does not have stale ports", func() {
			It("Does not remove any ports from bridge", func() {
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    genListStalePortsCmd(),
					Output: "",
					Err:    nil,
				})
				checkForStaleOVSInternalPorts()
				Expect(execMock.CalledMatchesExpected()).To(BeTrue(), execMock.ErrorDesc)
			})
		})
	})

	Describe("checkForStaleOVSRepresentorInterfaces", func() {
		nodeName := "localNode"
		podList := &v1.PodList{
			TypeMeta: metav1.TypeMeta{},
			ListMeta: metav1.ListMeta{},
			Items: []v1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "a-pod",
						Namespace:   "a-ns",
						Annotations: map[string]string{},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "b-pod",
						Namespace:   "b-ns",
						Annotations: map[string]string{},
					},
				},
			},
		}
		addCallsForPort := func(portName, interfaceName, sandbox, extIds string) {
			// interface for port
			execMock.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    genGetPortIfacesCmd(portName),
				Output: interfaceName,
				Err:    nil,
			})
			// attributes for interface interface
			execMock.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    genGetInterfaceAttributeCmd(interfaceName, "external_ids:sandbox"),
				Output: sandbox,
				Err:    nil,
			})
			if sandbox != "" {
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    genGetInterfaceAttributeCmd(interfaceName, "external_ids:iface-id"),
					Output: extIds,
					Err:    nil,
				})
			}
		}

		BeforeEach(func() {
			// setup kube output
			kubeMock.On("GetPods", "", metav1.LabelSelector{}, fields.OneTermEqualSelector(
				"spec.nodeName", nodeName).String()).Return(podList, nil)
		})

		Context("bridge has stale representor ports", func() {
			It("removes stale VF rep ports from bridge", func() {
				// ports in br-int
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    genListPortsCmd("br-int"),
					Output: "pod-a-port\npod-b-port\nstale-port\nother-port\n",
					Err:    nil,
				})
				// calls per port
				addCallsForPort("pod-a-port", "123abcfaa", "123abcfaa", "a-ns_a-pod")
				addCallsForPort("pod-b-port", "123abcfaa", "123abcfaa", "b-ns_b-pod")
				addCallsForPort("stale-port", "123abcfaa", "123abcfaa", "stale-ns_stale-pod")
				addCallsForPort("other-port", "other-interface", "", "")

				// mock calls to remove only stale-port
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    genDeleteStaleRepPortCmd("br-int", "stale-port"),
					Output: "",
					Err:    nil,
				})
				checkForStaleOVSRepresentorInterfaces(nodeName, kubeMock)
				Expect(execMock.CalledMatchesExpected()).To(BeTrue(), execMock.ErrorDesc)
			})
		})

		Context("bridge does not have stale representor ports", func() {
			It("does not remove any port from bridge", func() {
				// ports in br-int
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    genListPortsCmd("br-int"),
					Output: "pod-a-port\n",
					Err:    nil,
				})
				addCallsForPort("pod-a-port", "pod-a-port", "123abcfaa", "a-ns_a-pod")
				checkForStaleOVSRepresentorInterfaces(nodeName, kubeMock)
				Expect(execMock.CalledMatchesExpected()).To(BeTrue(), execMock.ErrorDesc)
			})
		})
	})
})
