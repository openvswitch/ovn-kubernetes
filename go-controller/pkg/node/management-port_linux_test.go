// +build linux

package node

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/coreos/go-iptables/iptables"
	"github.com/urfave/cli/v2"
	"github.com/vishvananda/netlink"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressipv1fake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/fake"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	egressfirewallfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned/fake"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var tmpDir string

var _ = AfterSuite(func() {
	err := os.RemoveAll(tmpDir)
	Expect(err).NotTo(HaveOccurred())
})

func createTempFile(name string) (string, error) {
	fname := filepath.Join(tmpDir, name)
	if err := ioutil.WriteFile(fname, []byte{0x20}, 0644); err != nil {
		return "", err
	}
	return fname, nil
}

type managementPortTestConfig struct {
	family   int
	protocol iptables.Protocol

	clusterCIDR string
	serviceCIDR string
	nodeSubnet  string

	expectedManagementPortIP string
	expectedGatewayIP        string
}

func testManagementPort(ctx *cli.Context, fexec *ovntest.FakeExec, testNS ns.NetNS,
	configs []managementPortTestConfig, expectedLRPMAC string) {
	const (
		nodeName      string = "node1"
		mgtPortMAC    string = "00:00:00:55:66:77"
		mgtPort       string = types.K8sMgmtIntfName
		legacyMgtPort string = types.K8sPrefix + nodeName
		mtu           string = "1400"
	)

	// generic setup
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovs-vsctl --timeout=15 -- --if-exists del-port br-int " + legacyMgtPort + " -- --may-exist add-port br-int " + mgtPort + " -- set interface " + mgtPort + " type=internal mtu_request=" + mtu + " external-ids:iface-id=" + legacyMgtPort,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovs-vsctl --timeout=15 --if-exists get interface " + mgtPort + " mac_in_use",
		Output: mgtPortMAC,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovs-vsctl --timeout=15 set interface " + mgtPort + " " + fmt.Sprintf("mac=%s", strings.ReplaceAll(mgtPortMAC, ":", "\\:")),
	})

	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovs-vsctl --timeout=15 --if-exists get interface " + mgtPort + " ofport",
		Output: "1",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovs-ofctl --no-stats --no-names dump-flows br-int table=65,out_port=1",
		Output: " table=65, priority=100,reg15=0x2,metadata=0x2 actions=output:1",
	})

	err := util.SetExec(fexec)
	Expect(err).NotTo(HaveOccurred())

	nodeSubnetCIDRs := make([]*net.IPNet, len(configs))
	mgtPortAddrs := make([]*netlink.Addr, len(configs))

	iptV4, iptV6 := util.SetFakeIPTablesHelpers()
	for i, cfg := range configs {
		nodeSubnetCIDRs[i] = ovntest.MustParseIPNet(cfg.nodeSubnet)
		mpCIDR := &net.IPNet{
			IP:   ovntest.MustParseIP(cfg.expectedManagementPortIP),
			Mask: nodeSubnetCIDRs[i].Mask,
		}
		mgtPortAddrs[i], err = netlink.ParseAddr(mpCIDR.String())
		Expect(err).NotTo(HaveOccurred())

		if cfg.protocol == iptables.ProtocolIPv4 {
			err = iptV4.NewChain("nat", "POSTROUTING")
			Expect(err).NotTo(HaveOccurred())
			err = iptV4.NewChain("nat", "OVN-KUBE-SNAT-MGMTPORT")
			Expect(err).NotTo(HaveOccurred())
		} else {
			err = iptV6.NewChain("nat", "POSTROUTING")
			Expect(err).NotTo(HaveOccurred())
			err = iptV6.NewChain("nat", "OVN-KUBE-SNAT-MGMTPORT")
			Expect(err).NotTo(HaveOccurred())
		}
	}

	existingNode := v1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: nodeName,
	}}

	fakeClient := fake.NewSimpleClientset(&v1.NodeList{
		Items: []v1.Node{existingNode},
	})

	_, err = config.InitConfig(ctx, fexec, nil)
	Expect(err).NotTo(HaveOccurred())

	nodeAnnotator := kube.NewNodeAnnotator(&kube.Kube{fakeClient, egressipv1fake.NewSimpleClientset(), &egressfirewallfake.Clientset{}}, &existingNode)
	waiter := newStartupWaiter()

	err = testNS.Do(func(ns.NetNS) error {
		defer GinkgoRecover()

		mgmtPort := NewManagementPort(nodeName, nodeSubnetCIDRs)
		_, err = mgmtPort.Create(nodeAnnotator, waiter)
		Expect(err).NotTo(HaveOccurred())
		l, err := netlink.LinkByName(mgtPort)
		Expect(err).NotTo(HaveOccurred())

		for i, cfg := range configs {
			// Check whether IP has been added
			addrs, err := netlink.AddrList(l, cfg.family)
			Expect(err).NotTo(HaveOccurred())
			var foundAddr bool
			for _, a := range addrs {
				if a.IP.Equal(mgtPortAddrs[i].IP) && bytes.Equal(a.Mask, mgtPortAddrs[i].Mask) {
					foundAddr = true
					break
				}
			}
			Expect(foundAddr).To(BeTrue(), "did not find expected management port IP %s", mgtPortAddrs[i].String())

			// Check whether the routes have been added
			j := 0
			gatewayIP := ovntest.MustParseIP(cfg.expectedGatewayIP)
			subnets := []string{cfg.clusterCIDR, cfg.serviceCIDR}
			for _, subnet := range subnets {
				foundRoute := false
				dstIPnet := ovntest.MustParseIPNet(subnet)
				route := &netlink.Route{Dst: dstIPnet}
				filterMask := netlink.RT_FILTER_DST
				routes, err := netlink.RouteListFiltered(cfg.family, route, filterMask)
				Expect(err).NotTo(HaveOccurred())
				for _, r := range routes {
					if r.Gw.Equal(gatewayIP) && r.LinkIndex == l.Attrs().Index {
						foundRoute = true
						break
					}
				}
				Expect(foundRoute).To(BeTrue(), "did not find expected route to %s", subnet)
				foundRoute = false
				j++
			}
			Expect(j).To(Equal(2))

			// Check whether router IP has been added in the arp entry for mgmt port
			neighbours, err := netlink.NeighList(l.Attrs().Index, cfg.family)
			Expect(err).NotTo(HaveOccurred())
			var foundNeighbour bool
			for _, neighbour := range neighbours {
				if neighbour.IP.Equal(gatewayIP) && (neighbour.HardwareAddr.String() == expectedLRPMAC) {
					foundNeighbour = true
					break
				}
			}
			Expect(foundNeighbour).To(BeTrue())
		}

		return nil
	})
	Expect(err).NotTo(HaveOccurred())

	err = nodeAnnotator.Run()
	Expect(err).NotTo(HaveOccurred())
	err = waiter.Wait()
	Expect(err).NotTo(HaveOccurred())

	for _, cfg := range configs {
		expectedTables := map[string]util.FakeTable{
			"nat": {
				"POSTROUTING": []string{
					"-o " + mgtPort + " -j OVN-KUBE-SNAT-MGMTPORT",
				},
				"OVN-KUBE-SNAT-MGMTPORT": []string{
					"-o " + mgtPort + " -j SNAT --to-source " + cfg.expectedManagementPortIP + " -m comment --comment OVN SNAT to Management Port",
				},
			},
		}
		if cfg.protocol == iptables.ProtocolIPv4 {
			f := iptV4.(*util.FakeIPTables)
			err = f.MatchState(expectedTables)
			Expect(err).NotTo(HaveOccurred())
		} else {
			f := iptV6.(*util.FakeIPTables)
			err = f.MatchState(expectedTables)
			Expect(err).NotTo(HaveOccurred())
		}
	}

	updatedNode, err := fakeClient.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())

	macFromAnnotation, err := util.ParseNodeManagementPortMACAddress(updatedNode)
	Expect(err).NotTo(HaveOccurred())
	Expect(macFromAnnotation.String()).To(Equal(mgtPortMAC))

	Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
}

var _ = Describe("Management Port Operations", func() {
	var tmpErr error
	var app *cli.App
	var testNS ns.NetNS
	var fexec *ovntest.FakeExec

	tmpDir, tmpErr = ioutil.TempDir("", "clusternodetest_certdir")
	if tmpErr != nil {
		GinkgoT().Errorf("failed to create tempdir: %v", tmpErr)
	}

	BeforeEach(func() {
		var err error
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		// Set up a fake k8sMgmt interface
		testNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		err = testNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			ovntest.AddLink(types.K8sMgmtIntfName)
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		fexec = ovntest.NewFakeExec()
	})

	AfterEach(func() {
		Expect(testNS.Close()).To(Succeed())
	})

	const (
		v4clusterCIDR string = "10.1.0.0/16"
		v4nodeSubnet  string = "10.1.1.0/24"
		v4gwIP        string = "10.1.1.1"
		v4mgtPortIP   string = "10.1.1.2"
		v4serviceCIDR string = "172.16.1.0/24"
		v4lrpMAC      string = "0a:58:0a:01:01:01"

		v6clusterCIDR string = "fda6::/48"
		v6nodeSubnet  string = "fda6:0:0:1::/64"
		v6gwIP        string = "fda6:0:0:1::1"
		v6mgtPortIP   string = "fda6:0:0:1::2"
		v6serviceCIDR string = "fc95::/64"
		// generated from util.IPAddrToHWAddr(net.ParseIP("fda6:0:0:1::1")).String()
		v6lrpMAC string = "0a:58:23:5a:40:f1"
	)

	It("sets up the management port for IPv4 clusters", func() {
		app.Action = func(ctx *cli.Context) error {
			testManagementPort(ctx, fexec, testNS,
				[]managementPortTestConfig{
					{
						family:   netlink.FAMILY_V4,
						protocol: iptables.ProtocolIPv4,

						clusterCIDR: v4clusterCIDR,
						serviceCIDR: v4serviceCIDR,
						nodeSubnet:  v4nodeSubnet,

						expectedManagementPortIP: v4mgtPortIP,
						expectedGatewayIP:        v4gwIP,
					},
				}, v4lrpMAC)
			return nil
		}
		err := app.Run([]string{
			app.Name,
			"--cluster-subnets=" + v4clusterCIDR,
			"--k8s-service-cidr=" + v4serviceCIDR,
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("sets up the management port for IPv6 clusters", func() {
		app.Action = func(ctx *cli.Context) error {
			testManagementPort(ctx, fexec, testNS,
				[]managementPortTestConfig{
					{
						family:   netlink.FAMILY_V6,
						protocol: iptables.ProtocolIPv6,

						clusterCIDR: v6clusterCIDR,
						serviceCIDR: v6serviceCIDR,
						nodeSubnet:  v6nodeSubnet,

						expectedManagementPortIP: v6mgtPortIP,
						expectedGatewayIP:        v6gwIP,
					},
				}, v6lrpMAC)
			return nil
		}
		err := app.Run([]string{
			app.Name,
			"--cluster-subnets=" + v6clusterCIDR,
			"--k8s-service-cidr=" + v6serviceCIDR,
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("sets up the management port for dual-stack clusters", func() {
		app.Action = func(ctx *cli.Context) error {
			testManagementPort(ctx, fexec, testNS,
				[]managementPortTestConfig{
					{
						family:   netlink.FAMILY_V4,
						protocol: iptables.ProtocolIPv4,

						clusterCIDR: v4clusterCIDR,
						serviceCIDR: v4serviceCIDR,
						nodeSubnet:  v4nodeSubnet,

						expectedManagementPortIP: v4mgtPortIP,
						expectedGatewayIP:        v4gwIP,
					},
					{
						family:   netlink.FAMILY_V6,
						protocol: iptables.ProtocolIPv6,

						clusterCIDR: v6clusterCIDR,
						serviceCIDR: v6serviceCIDR,
						nodeSubnet:  v6nodeSubnet,

						expectedManagementPortIP: v6mgtPortIP,
						expectedGatewayIP:        v6gwIP,
					},
				}, v4lrpMAC)
			return nil
		}
		err := app.Run([]string{
			app.Name,
			"--cluster-subnets=" + v4clusterCIDR + "," + v6clusterCIDR,
			"--k8s-service-cidr=" + v4serviceCIDR + "," + v6serviceCIDR,
		})
		Expect(err).NotTo(HaveOccurred())
	})
})
