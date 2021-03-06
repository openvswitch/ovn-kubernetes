package controller

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/urfave/cli/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	hotypes "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	testOVSMAC     string = "11:22:33:44:55:66"
	testMgmtMAC    string = "06:05:04:03:02:01"
	testDRMAC      string = "00:00:00:7a:af:04"
	testNodeSubnet string = "1.2.3.0/24"
	testNodeIP     string = "1.2.3.3"
)

// returns a fake node IP and DR MAC
func addNodeSetupCmds(fexec *ovntest.FakeExec, nodeName string) (string, string) {
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 get logical_switch mynode other-config:subnet",
		Output: testNodeSubnet,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovs-vsctl --timeout=15 --if-exists get interface ovn-k8s-mp0 mac_in_use",
		Output: testMgmtMAC,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovs-vsctl --timeout=15 --may-exist add-br br-ext -- set Bridge br-ext fail_mode=secure -- set Interface br-ext mtu_request=1400",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovs-vsctl --timeout=15 --if-exists get interface br-ext mac_in_use",
		Output: testOVSMAC,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovs-vsctl --timeout=15 set bridge br-ext other-config:hwaddr=" + testOVSMAC,
		"ovs-vsctl --timeout=15 --may-exist add-port br-int int -- --may-exist add-port br-ext ext -- set Interface int type=patch options:peer=ext external-ids:iface-id=int-" + nodeName + " -- set Interface ext type=patch options:peer=int",
		"ovs-ofctl add-flow br-ext table=0,priority=0,actions=drop",
	})
	testDRMACRaw := strings.Replace(testDRMAC, ":", "", -1)
	testNodeIPRaw := getIPAsHexString(ovntest.MustParseIP(testNodeIP))
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovs-ofctl add-flow br-ext table=0,priority=100,in_port=ext,arp,arp_tpa=" + testNodeIP + ",actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],mod_dl_src:" + testDRMAC + ",load:0x2->NXM_OF_ARP_OP[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],load:0x" + testDRMACRaw + "->NXM_NX_ARP_SHA[],load:0x" + testNodeIPRaw + "->NXM_OF_ARP_SPA[],IN_PORT",
		`ovs-vsctl --timeout=15 --may-exist add-port br-ext ext-vxlan -- set interface ext-vxlan type=vxlan options:remote_ip="flow" options:key="flow" options:dst_port=4789`,
		"ovs-ofctl add-flow br-ext table=0,priority=100,in_port=ext-vxlan,ip,nw_dst=" + testNodeSubnet + ",dl_dst=" + testDRMAC + ",actions=goto_table:10",
		"ovs-ofctl add-flow br-ext table=0,priority=100,arp,in_port=ext-vxlan,arp_tpa=" + testNodeSubnet + ",actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],mod_dl_src:" + testDRMAC + ",load:0x2->NXM_OF_ARP_OP[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],load:0x" + testDRMACRaw + "->NXM_NX_ARP_SHA[],move:NXM_OF_ARP_TPA[]->NXM_NX_REG0[],move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],move:NXM_NX_REG0[]->NXM_OF_ARP_SPA[],IN_PORT",
		"ovs-ofctl add-flow br-ext table=10,priority=0,actions=drop",
	})
	return testNodeIP, testDRMAC
}

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

func createPod(namespace, name, node, podIP, podMAC string) *v1.Pod {
	annotations := map[string]string{}
	if podIP != "" || podMAC != "" {
		ipn := ovntest.MustParseIPNet(podIP)
		gatewayIP := util.NextIP(ipn.IP)
		annotations[util.OvnPodAnnotationName] = fmt.Sprintf(`{"default": {"ip_address":"` + podIP + `", "mac_address":"` + podMAC + `", "gateway_ip": "` + gatewayIP.String() + `"}}`)
	}

	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   namespace,
			Name:        name,
			Annotations: annotations,
		},
		Spec: v1.PodSpec{
			NodeName: node,
		},
		Status: v1.PodStatus{
			Phase: v1.PodRunning,
		},
	}
}

func expectRouteForSubnet(routes []netlink.Route, subnet *net.IPNet, hoIfAddr net.IP) {
	found := false
	for _, route := range routes {
		if route.Dst.String() == subnet.String() && route.Gw.String() == hoIfAddr.String() {
			found = true
			break
		}
	}
	Expect(found).To(BeTrue(), fmt.Sprintf("failed to find hybrid overlay host route %s via %s", subnet, hoIfAddr))
}

func validateNetlinkState(nodeSubnet string) {
	link, err := netlink.LinkByName(extBridgeName)
	Expect(err).NotTo(HaveOccurred())
	Expect(link.Attrs().Flags & net.FlagUp).To(Equal(net.FlagUp))

	link, err = netlink.LinkByName(types.K8sMgmtIntfName)
	Expect(err).NotTo(HaveOccurred())
	Expect(link.Attrs().Flags & net.FlagUp).To(Equal(net.FlagUp))

	routes, err := netlink.RouteList(link, netlink.FAMILY_ALL)
	Expect(err).NotTo(HaveOccurred())

	// Expect a route to the hybrid overlay CIDR via the .3 address
	// through the management port
	_, ipnet, err := net.ParseCIDR(nodeSubnet)
	Expect(err).NotTo(HaveOccurred())
	hybridOverlayIfAddr := util.GetNodeHybridOverlayIfAddr(ipnet)
	Expect(len(config.HybridOverlay.ClusterSubnets)).ToNot(BeZero())
	for _, hoSubnet := range config.HybridOverlay.ClusterSubnets {
		expectRouteForSubnet(routes, hoSubnet.CIDR, hybridOverlayIfAddr.IP)
	}
}

func appRun(app *cli.App, netns ns.NetNS) {
	_ = netns.Do(func(ns.NetNS) error {
		defer GinkgoRecover()
		err := app.Run([]string{
			app.Name,
			"-enable-hybrid-overlay",
			"-no-hostsubnet-nodes=" + v1.LabelOSStable + "=windows",
			"-cluster-subnets=10.130.0.0/15/24",
		})
		Expect(err).NotTo(HaveOccurred())
		return nil
	})
}

func createNodeAnnotationsForSubnet(subnet string) map[string]string {
	subnetAnnotations := map[string]string{}
	err := util.UpdateNodeHostSubnetAnnotation(subnetAnnotations, ovntest.MustParseIPNets(subnet), types.DefaultNetworkName)
	Expect(err).NotTo(HaveOccurred())
	annotations := make(map[string]string)
	for k, v := range subnetAnnotations {
		annotations[k] = fmt.Sprintf("%s", v)
	}
	return annotations
}

var _ = Describe("Hybrid Overlay Node Linux Operations", func() {
	var (
		app      *cli.App
		fexec    *ovntest.FakeExec
		netns    ns.NetNS
		stopChan chan struct{}
		wg       *sync.WaitGroup
	)
	const (
		thisNode   string = "mynode"
		thisSubnet string = "1.2.3.0/24"
	)

	BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		stopChan = make(chan struct{})
		wg = &sync.WaitGroup{}

		fexec = ovntest.NewLooseCompareFakeExec()
		err := util.SetExec(fexec)
		Expect(err).NotTo(HaveOccurred())

		netns, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		// prepare br-ext and ovn-k8s-mp0 in original namespace
		_ = netns.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			ovntest.AddLink(extBridgeName)

			// Set up management interface with its address
			link := ovntest.AddLink(types.K8sMgmtIntfName)
			_, thisNet, err := net.ParseCIDR(thisSubnet)
			Expect(err).NotTo(HaveOccurred())
			mgmtIfAddr := util.GetNodeManagementIfAddr(thisNet)
			err = netlink.AddrAdd(link, &netlink.Addr{IPNet: mgmtIfAddr})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
	})

	AfterEach(func() {
		close(stopChan)
		wg.Wait()
		Expect(netns.Close()).To(Succeed())
		Expect(testutils.UnmountNS(netns)).To(Succeed())
	})

	It("does not set up tunnels for non-hybrid-overlay nodes without annotations", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				node1Name string = "node1"
			)

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{
					*createNode(node1Name, "linux", "10.0.0.1", nil),
				},
			})

			addNodeSetupCmds(fexec, thisNode)
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: "ovs-ofctl dump-flows br-ext table=0",
				// Assume fresh OVS bridge
				Output: "",
			})

			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)

			n, err := NewNode(
				&kube.Kube{KClient: fakeClient},
				thisNode,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Pods().Informer(),
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			f.Start(stopChan)
			wg.Add(1)
			go func() {
				defer wg.Done()
				n.nodeEventHandler.Run(1, stopChan)
			}()

			// FIXME
			// Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			return nil
		}
		appRun(app, netns)
	})

	It("does not set up tunnels for non-hybrid-overlay nodes with subnet annotations", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				node1Name   string = "node1"
				node1Subnet string = "1.2.4.0/24"
				node1IP     string = "10.0.0.2"
			)

			annotations := createNodeAnnotationsForSubnet(node1Subnet)
			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{
					*createNode(node1Name, "linux", node1IP, annotations),
				},
			})

			addNodeSetupCmds(fexec, thisNode)
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: "ovs-ofctl dump-flows br-ext table=0",
				// Assume fresh OVS bridge
				Output: "",
			})

			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())
			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)

			n, err := NewNode(
				&kube.Kube{KClient: fakeClient},
				thisNode,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Pods().Informer(),
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			f.Start(stopChan)
			wg.Add(1)
			go func() {
				defer wg.Done()
				n.nodeEventHandler.Run(1, stopChan)
			}()

			// FIXME
			// Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			return nil
		}
		appRun(app, netns)
	})

	It("sets up local node hybrid overlay bridge", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				thisDrMAC string = "22:33:44:55:66:77"
			)

			annotations := createNodeAnnotationsForSubnet(thisSubnet)
			annotations[hotypes.HybridOverlayDRMAC] = thisDrMAC
			node := createNode(thisNode, "linux", "10.0.0.1", annotations)
			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{*node},
			})

			// Node setup from initial node sync
			addNodeSetupCmds(fexec, thisNode)
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: "ovs-ofctl dump-flows br-ext table=0",
				// Assume fresh OVS bridge
				Output: "",
			})
			config.HybridOverlay.RawClusterSubnets = "10.0.0.1/16/23"
			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())
			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)

			n, err := NewNode(
				&kube.Kube{KClient: fakeClient},
				thisNode,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Pods().Informer(),
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			err = n.controller.EnsureHybridOverlayBridge(node)
			Expect(err).NotTo(HaveOccurred())

			// FIXME
			// Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			validateNetlinkState(thisSubnet)
			return nil
		}
		appRun(app, netns)
	})
	It("sets up local linux pod", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				thisDrMAC string = "22:33:44:55:66:77"
				pod1IP    string = "1.2.3.5"
				pod1CIDR  string = pod1IP + "/24"
				pod1MAC   string = "aa:bb:cc:dd:ee:ff"
			)

			annotations := createNodeAnnotationsForSubnet(thisSubnet)
			annotations[hotypes.HybridOverlayDRMAC] = thisDrMAC
			node := createNode(thisNode, "linux", "10.0.0.1", annotations)
			testPod := createPod("test", "pod1", thisNode, pod1CIDR, pod1MAC)
			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{*node},
			})

			// Node setup from initial node sync
			addNodeSetupCmds(fexec, thisNode)
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: "ovs-ofctl dump-flows br-ext table=0",
				// Assume fresh OVS bridge
				Output: "",
			})
			config.HybridOverlay.RawClusterSubnets = "10.0.0.1/16/23"
			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)

			n, err := NewNode(
				&kube.Kube{KClient: fakeClient},
				thisNode,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Pods().Informer(),
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			err = n.controller.EnsureHybridOverlayBridge(node)
			Expect(err).NotTo(HaveOccurred())

			// FIXME
			// Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			validateNetlinkState(thisSubnet)
			err = n.controller.AddPod(testPod)
			Expect(err).NotTo(HaveOccurred())
			return nil
		}
		appRun(app, netns)
	})

	It("sets up tunnels for Windows nodes", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				node1Name   string = "node1"
				node1IP     string = "10.0.0.2"
				node1DrMAC  string = "22:33:44:55:66:77"
				node1Subnet string = "5.6.7.0/24"
			)

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{
					*createNode(node1Name, "windows", node1IP, map[string]string{
						hotypes.HybridOverlayNodeSubnet: node1Subnet,
						hotypes.HybridOverlayDRMAC:      node1DrMAC,
					}),
				},
			})

			node1DrMACRaw := strings.Replace(node1DrMAC, ":", "", -1)

			addNodeSetupCmds(fexec, thisNode)
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovs-ofctl dump-flows br-ext table=0",
				// Adds flows for existing node1
				"ovs-ofctl add-flow br-ext cookie=0xca12f31b,table=0,priority=100,arp,in_port=ext,arp_tpa=" + node1Subnet + ",actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],mod_dl_src:" + node1DrMAC + ",load:0x2->NXM_OF_ARP_OP[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],load:0x" + node1DrMACRaw + "->NXM_NX_ARP_SHA[],move:NXM_OF_ARP_TPA[]->NXM_NX_REG0[],move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],move:NXM_NX_REG0[]->NXM_OF_ARP_SPA[],IN_PORT",
				"ovs-ofctl add-flow br-ext cookie=0xca12f31b,table=0,priority=100,ip,nw_dst=5.6.7.0/24,actions=load:4097->NXM_NX_TUN_ID[0..31],set_field:10.0.0.2->tun_dst,set_field:22:33:44:55:66:77->eth_dst,output:ext-vxlan",
			})

			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)

			n, err := NewNode(
				&kube.Kube{KClient: fakeClient},
				thisNode,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Pods().Informer(),
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			f.Start(stopChan)
			wg.Add(1)
			go func() {
				defer wg.Done()
				n.nodeEventHandler.Run(1, stopChan)
			}()

			// FIXME
			// Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			return nil
		}
		appRun(app, netns)
	})

	It("removes stale node flows on initial sync", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				node1Name string = "node1"
				node1IP   string = "10.0.0.2"
			)

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{*createNode(node1Name, "linux", node1IP, nil)},
			})

			addNodeSetupCmds(fexec, thisNode)
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: "ovs-ofctl dump-flows br-ext table=0",
				// Return output for a stale node
				Output: ` cookie=0x0, duration=137014.498s, table=0, n_packets=20, n_bytes=2605, priority=100,ip,in_port="ext-vxlan",dl_dst=00:00:00:4d:d9:c1,nw_dst=10.128.1.0/24 actions=resubmit(,10)
 cookie=0x1f40e27c, duration=61107.432s, table=0, n_packets=0, n_bytes=0, priority=100,arp,in_port=ext,arp_tpa=10.132.0.0/24 actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],mod_dl_src:00:00:00:33:65:d0,load:0x2->NXM_OF_ARP_OP[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],load:0x3365d0->NXM_NX_ARP_SHA[],move:NXM_OF_ARP_TPA[]->NXM_NX_REG0[],move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],move:NXM_NX_REG0[]->NXM_OF_ARP_SPA[],IN_PORT
 cookie=0x1f40e27c, duration=61107.417s, table=0, n_packets=0, n_bytes=0, priority=100,ip,nw_dst=10.132.0.0/24 actions=load:0x1001->NXM_NX_TUN_ID[0..31],load:0xac110003->NXM_NX_TUN_IPV4_DST[],mod_dl_dst:00:00:00:33:65:d0,output:"ext-vxlan"
 cookie=0x0, duration=61107.658s, table=0, n_packets=50, n_bytes=3576, priority=0 actions=drop`,
			})
			fexec.AddFakeCmdsNoOutputNoError([]string{
				// Deletes flows for stale node in OVS
				"ovs-ofctl del-flows br-ext cookie=0x1f40e27c/0xffffffff",
			})

			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())
			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)

			n, err := NewNode(
				&kube.Kube{KClient: fakeClient},
				thisNode,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Pods().Informer(),
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			f.Start(stopChan)
			wg.Add(1)
			go func() {
				defer wg.Done()
				n.nodeEventHandler.Run(1, stopChan)
			}()

			//FIXME
			// Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			return nil
		}
		appRun(app, netns)
	})

	It("removes stale pod flows on initial sync", func() {
		app.Action = func(ctx *cli.Context) error {
			fakeClient := fake.NewSimpleClientset()

			addNodeSetupCmds(fexec, thisNode)

			// Put one live pod and one stale pod into the OVS bridge flows
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: "ovs-ofctl dump-flows br-ext table=10",
				Output: ` cookie=0xaabbccdd, duration=29398.539s, table=10, n_packets=0, n_bytes=0, priority=100,ip,nw_dst=1.2.3.4 actions=mod_dl_src:ab:cd:ef:ab:cd:ef,mod_dl_dst:ef:cd:ab:ef:cd:ab,output:ext
 cookie=0x0, duration=29398.687s, table=10, n_packets=0, n_bytes=0, priority=0 actions=drop`,
			})
			fexec.AddFakeCmdsNoOutputNoError([]string{
				// Deletes flows for pod in OVS that is not in Kube
				"ovs-ofctl del-flows br-ext cookie=0xaabbccdd/0xffffffff",
				// provide cover for up to 3 runs of flows thread
				"ovs-ofctl dump-flows --no-stats br-ext table=20",
				"ovs-ofctl -O OpenFlow13 --bundle replace-flows br-ext -",
				"ovs-ofctl dump-flows --no-stats br-ext table=20",
				"ovs-ofctl -O OpenFlow13 --bundle replace-flows br-ext -",
				"ovs-ofctl dump-flows --no-stats br-ext table=20",
				"ovs-ofctl -O OpenFlow13 --bundle replace-flows br-ext -",
			})

			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())
			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)

			n, err := NewNode(
				&kube.Kube{KClient: fakeClient},
				thisNode,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Pods().Informer(),
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			f.Start(stopChan)
			wg.Add(1)
			go func() {
				defer wg.Done()
				n.Run(stopChan)
			}()

			// Wait for the controller to start
			err = wait.PollImmediate(500*time.Millisecond, 5*time.Second, func() (bool, error) { return n.ready == true, nil })
			Expect(err).NotTo(HaveOccurred())

			// FIXME
			// Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			return nil
		}
		appRun(app, netns)
	})

	It("sets up local pod flows", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				pod1IP   string = "1.2.3.5"
				pod1CIDR string = pod1IP + "/24"
				pod1MAC  string = "aa:bb:cc:dd:ee:ff"
			)

			ns := &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					UID:  k8stypes.UID("test"),
					Name: "test",
					Annotations: map[string]string{
						hotypes.HybridOverlayDRMAC: "00:11:22:33:44:55:66",
					},
				},
				Spec:   v1.NamespaceSpec{},
				Status: v1.NamespaceStatus{},
			}
			fakeClient := fake.NewSimpleClientset([]runtime.Object{
				ns,
				createPod("test", "pod1", thisNode, pod1CIDR, pod1MAC),
			}...)

			_, hybMAC := addNodeSetupCmds(fexec, thisNode)

			// Put one live pod and one stale pod into the OVS bridge flows
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: "ovs-ofctl dump-flows br-ext table=10",
				Output: ` cookie=0x7fdcde17, duration=29398.539s, table=10, n_packets=0, n_bytes=0, priority=100,ip,nw_dst=` + pod1CIDR + ` actions=mod_dl_src:` + hybMAC + `,mod_dl_dst:` + pod1MAC + `,output:ext
 cookie=0x0, duration=29398.687s, table=10, n_packets=0, n_bytes=0, priority=0 actions=drop`,
			})
			fexec.AddFakeCmdsNoOutputNoError([]string{
				// provide cover for up to 3 runs of flows thread
				"ovs-ofctl dump-flows --no-stats br-ext table=20",
				"ovs-ofctl -O OpenFlow13 --bundle replace-flows br-ext -",
				"ovs-ofctl dump-flows --no-stats br-ext table=20",
				"ovs-ofctl -O OpenFlow13 --bundle replace-flows br-ext -",
				"ovs-ofctl dump-flows --no-stats br-ext table=20",
				"ovs-ofctl -O OpenFlow13 --bundle replace-flows br-ext -",
			})

			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())
			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)

			n, err := NewNode(
				&kube.Kube{KClient: fakeClient},
				thisNode,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Pods().Informer(),
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())
			// FIXME: DT Why are these needed?
			// n.drIP = net.ParseIP(hybIP)
			// n.drMAC, err = net.ParseMAC(hybMAC)
			// Expect(err).NotTo(HaveOccurred())

			f.Start(stopChan)
			wg.Add(1)
			go func() {
				defer wg.Done()
				n.Run(stopChan)
			}()

			// Wait for the controller to start
			err = wait.PollImmediate(500*time.Millisecond, 5*time.Second, func() (bool, error) { return n.ready == true, nil })
			Expect(err).NotTo(HaveOccurred())

			// FIXME
			// Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			return nil
		}
		appRun(app, netns)
	})
})
