package node

import (
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube/mocks"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	linkMock "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/github.com/vishvananda/netlink"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	utilMocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/mocks"
)

func genOVSFindCmd(table, column, condition string) string {
	return fmt.Sprintf("ovs-vsctl --timeout=30 --no-heading --format=csv --data=bare --columns=%s find %s %s",
		column, table, condition)
}

func genOVSAddPortCmd(hostIfaceName, ifaceID, mac, ip, sandboxID string) string {
	return fmt.Sprintf("ovs-vsctl --timeout=30 add-port br-int %s -- set interface %s external_ids:attached_mac=%s "+
		"external_ids:iface-id=%s external_ids:ip_addresses=%s external_ids:sandbox=%s",
		hostIfaceName, hostIfaceName, mac, ifaceID, ip, sandboxID)
}

func genOVSDelPortCmd(portName string) string {
	return fmt.Sprintf("ovs-vsctl --timeout=15 --if-exists del-port br-int %s", portName)
}

func genOVSGetCmd(table, record, column, key string) string {
	if key != "" {
		column = column + ":" + key
	}
	return fmt.Sprintf("ovs-vsctl --timeout=30 --if-exists get %s %s %s", table, record, column)
}

func genOfctlDumpFlowsCmd(queryStr string) string {
	return fmt.Sprintf("ovs-ofctl --timeout=10 --no-stats --strict dump-flows br-int %s", queryStr)
}

func genIfaceID(podNamespace, podName string) string {
	return fmt.Sprintf("%s_%s", podNamespace, podName)
}

var _ = Describe("Node Smart NIC tests", func() {
	var sriovnetOpsMock utilMocks.SriovnetOps
	var netlinkOpsMock utilMocks.NetLinkOps
	var execMock *ovntest.FakeExec
	var kubeMock mocks.KubeInterface
	var pod v1.Pod
	var node OvnNode

	origSriovnetOps := util.GetSriovnetOps()
	origNetlinkOps := util.GetNetLinkOps()

	BeforeEach(func() {
		sriovnetOpsMock = utilMocks.SriovnetOps{}
		netlinkOpsMock = utilMocks.NetLinkOps{}
		execMock = ovntest.NewFakeExec()

		util.SetSriovnetOpsInst(&sriovnetOpsMock)
		util.SetNetLinkOpMockInst(&netlinkOpsMock)
		err := util.SetExec(execMock)
		Expect(err).NotTo(HaveOccurred())
		err = cni.SetExec(execMock)
		Expect(err).NotTo(HaveOccurred())

		kubeMock = mocks.KubeInterface{}
		node = OvnNode{Kube: &kubeMock}

		pod = v1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name:        "a-pod",
			Namespace:   "foo-ns",
			Annotations: map[string]string{},
		}}
	})

	AfterEach(func() {
		// Restore mocks so it does not affect other tests in the suite
		util.SetSriovnetOpsInst(origSriovnetOps)
		util.SetNetLinkOpMockInst(origNetlinkOps)
		cni.ResetRunner()
		util.ResetRunner()
	})

	Context("getVfRepName", func() {
		It("gets VF representor based on smartnic.connection-details Pod annotation", func() {
			podAnnot := map[string]string{
				util.SmartNicConnectionDetailsAnnot: `{"pfId":"0","vfId":"9","sandboxId":"a8d09931"}`,
			}
			pod.Annotations = podAnnot
			sriovnetOpsMock.On("GetVfRepresentorSmartNIC", "0", "9").Return("pf0vf9", nil)
			rep, err := node.getVfRepName(&pod)
			Expect(err).ToNot(HaveOccurred())
			Expect(rep).To(Equal("pf0vf9"))
		})
		It("Fails if smartnic.connection-details annotation is missing from Pod", func() {
			_, err := node.getVfRepName(&pod)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("addRepPort", func() {
		var vfRep string
		var vfLink *linkMock.Link
		var ifInfo *cni.PodInterfaceInfo

		BeforeEach(func() {
			vfRep = "pf0vf9"
			vfLink = &linkMock.Link{}
			ifInfo = &cni.PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{},
				MTU:           1500,
				Ingress:       -1,
				Egress:        -1,
				IsSmartNic:    true,
			}

			// set pod annotations
			podAnnot := map[string]string{
				util.SmartNicConnectionDetailsAnnot: `{"pfId":"0","vfId":"9","sandboxId":"a8d09931"}`,
			}
			pod.Annotations = podAnnot
		})

		It("Fails if smartnic.connection-details Pod annotation is not present", func() {
			pod.Annotations = map[string]string{}
			err := node.addRepPort(&pod, vfRep, ifInfo)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to get smart-nic annotation"))
		})

		It("Fails if configure OVS fails", func() {
			// set ovs CMD output
			execMock.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: genOVSFindCmd("Interface", "_uuid",
					"external-ids:iface-id="+genIfaceID(pod.Namespace, pod.Name)),
			})
			execMock.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: genOVSAddPortCmd(vfRep, genIfaceID(pod.Namespace, pod.Name), "", "", "a8d09931"),
				Err: fmt.Errorf("failed to run ovs command"),
			})

			// call addRepPort()
			err := node.addRepPort(&pod, vfRep, ifInfo)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to run ovs command"))
			Expect(execMock.CalledMatchesExpected()).To(BeTrue(), execMock.ErrorDesc())
		})

		Context("After successfully calling ConfigureOVS", func() {
			BeforeEach(func() {
				// set ovs CMD output so cni.ConfigureOVS passes without error
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: genOVSFindCmd("Interface", "_uuid",
						"external-ids:iface-id="+genIfaceID(pod.Namespace, pod.Name)),
				})
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: genOVSAddPortCmd(vfRep, genIfaceID(pod.Namespace, pod.Name), "", "", "a8d09931"),
				})
				// clearPodBandwidth
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: genOVSFindCmd("interface", "name",
						"external-ids:sandbox=a8d09931"),
				})
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: genOVSFindCmd("qos", "_uuid",
						"external-ids:sandbox=a8d09931"),
				})
				// getIfaceOFPort
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    genOVSGetCmd("Interface", "pf0vf9", "ofport", ""),
					Output: "1",
				})
				// waitForPodFlows
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    genOVSGetCmd("Interface", "pf0vf9", "external-ids", "iface-id"),
					Output: genIfaceID(pod.Namespace, pod.Name),
				})
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    genOfctlDumpFlowsCmd("table=9,dl_src="),
					Output: "non-empty-output",
				})
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    genOfctlDumpFlowsCmd("table=0,in_port=1"),
					Output: "non-empty-output",
				})
			})

			Context("Fails if link configuration fails on", func() {
				It("LinkByName()", func() {
					netlinkOpsMock.On("LinkByName", vfRep).Return(nil, fmt.Errorf("failed to get link"))
					// Mock ovs calls for cleanup
					execMock.AddFakeCmd(&ovntest.ExpectedCmd{
						Cmd: genOVSDelPortCmd("pf0vf9"),
					})

					err := node.addRepPort(&pod, vfRep, ifInfo)
					Expect(err).To(HaveOccurred())
					Expect(execMock.CalledMatchesExpected()).To(BeTrue(), execMock.ErrorDesc())
				})

				It("LinkSetMTU()", func() {
					netlinkOpsMock.On("LinkByName", vfRep).Return(vfLink, nil)
					netlinkOpsMock.On("LinkSetMTU", vfLink, ifInfo.MTU).Return(fmt.Errorf("failed to set mtu"))
					// Mock netlink/ovs calls for cleanup
					netlinkOpsMock.On("LinkSetDown", vfLink).Return(nil)
					execMock.AddFakeCmd(&ovntest.ExpectedCmd{
						Cmd: genOVSDelPortCmd("pf0vf9"),
					})

					err := node.addRepPort(&pod, vfRep, ifInfo)
					Expect(err).To(HaveOccurred())
					Expect(execMock.CalledMatchesExpected()).To(BeTrue(), execMock.ErrorDesc())
				})

				It("LinkSetUp()", func() {
					netlinkOpsMock.On("LinkByName", vfRep).Return(vfLink, nil)
					netlinkOpsMock.On("LinkSetMTU", vfLink, ifInfo.MTU).Return(nil)
					netlinkOpsMock.On("LinkSetUp", vfLink).Return(fmt.Errorf("failed to set link up"))
					// Mock netlink/ovs calls for cleanup
					netlinkOpsMock.On("LinkSetDown", vfLink).Return(nil)
					execMock.AddFakeCmd(&ovntest.ExpectedCmd{
						Cmd: genOVSDelPortCmd("pf0vf9"),
					})

					err := node.addRepPort(&pod, vfRep, ifInfo)
					Expect(err).To(HaveOccurred())
					Expect(execMock.CalledMatchesExpected()).To(BeTrue(), execMock.ErrorDesc())
				})
			})

			It("Sets smartnic-connection-status pod annotation on success", func() {
				expectedAnnot := map[string]string{util.SmartNicConnetionStatusAnnot: `{"Status":"Ready"}`}
				netlinkOpsMock.On("LinkByName", vfRep).Return(vfLink, nil)
				netlinkOpsMock.On("LinkSetMTU", vfLink, ifInfo.MTU).Return(nil)
				netlinkOpsMock.On("LinkSetUp", vfLink).Return(nil)
				kubeMock.On("SetAnnotationsOnPod", pod.Namespace, pod.Name, expectedAnnot).Return(nil)

				err := node.addRepPort(&pod, vfRep, ifInfo)
				Expect(err).ToNot(HaveOccurred())
				Expect(execMock.CalledMatchesExpected()).To(BeTrue(), execMock.ErrorDesc())
			})

			It("cleans up representor port if set pod annotation fails", func() {
				netlinkOpsMock.On("LinkByName", vfRep).Return(vfLink, nil)
				netlinkOpsMock.On("LinkSetMTU", vfLink, ifInfo.MTU).Return(nil)
				netlinkOpsMock.On("LinkSetUp", vfLink).Return(nil)
				kubeMock.On("SetAnnotationsOnPod", pod.Namespace, pod.Name, mock.Anything).Return(
					fmt.Errorf("failed to set pod annotations"))
				// Mock netlink/ovs calls for cleanup
				netlinkOpsMock.On("LinkSetDown", vfLink).Return(nil)
				execMock.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: genOVSDelPortCmd("pf0vf9"),
				})

				err := node.addRepPort(&pod, vfRep, ifInfo)
				Expect(err).To(HaveOccurred())
				Expect(execMock.CalledMatchesExpected()).To(BeTrue(), execMock.ErrorDesc())
			})
		})
	})

	Context("delRepPort", func() {
		var vfRep string
		var vfLink *linkMock.Link

		BeforeEach(func() {
			vfRep = "pf0vf9"
			vfLink = &linkMock.Link{}
		})

		It("Sets link down for VF representor and removes VF representor from OVS", func() {
			netlinkOpsMock.On("LinkByName", vfRep).Return(vfLink, nil)
			netlinkOpsMock.On("LinkSetDown", vfLink).Return(nil)
			execMock.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: fmt.Sprintf("ovs-vsctl --timeout=15 --if-exists del-port br-int %s", "pf0vf9"),
			})
			err := node.delRepPort(vfRep)
			Expect(err).ToNot(HaveOccurred())
			Expect(execMock.CalledMatchesExpected()).To(BeTrue(), execMock.ErrorDesc())
		})

		It("Does not fail if LinkByName failed", func() {
			netlinkOpsMock.On("LinkByName", vfRep).Return(nil, fmt.Errorf("failed to get link"))
			execMock.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: genOVSDelPortCmd("pf0vf9"),
			})
			err := node.delRepPort(vfRep)
			Expect(err).ToNot(HaveOccurred())
			Expect(execMock.CalledMatchesExpected()).To(BeTrue(), execMock.ErrorDesc())
		})

		It("Does not fail if removal of VF representor from OVS fails once", func() {
			netlinkOpsMock.On("LinkByName", vfRep).Return(vfLink, nil)
			netlinkOpsMock.On("LinkSetDown", vfLink).Return(nil)
			// fail on first try
			execMock.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: genOVSDelPortCmd("pf0vf9"),
				Err: fmt.Errorf("ovs command failed"),
			})
			// pass on the second
			execMock.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: genOVSDelPortCmd("pf0vf9"),
				Err: nil,
			})
			// pass on the second
			err := node.delRepPort(vfRep)
			Expect(err).ToNot(HaveOccurred())
			Expect(execMock.CalledMatchesExpected()).To(BeTrue(), execMock.ErrorDesc())
		})
	})
})
