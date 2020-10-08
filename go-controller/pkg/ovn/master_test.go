package ovn

import (
	"context"
	"fmt"
	goovn "github.com/ebay/go-ovn"
	"github.com/urfave/cli/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
	"net"
	"strings"

	egressfirewallfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned/fake"
	egressipfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/fake"
	apiextensionsfake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/ipallocator"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// Please use following subnets for various networks that we have
// 172.16.1.0/24 -- physical network that k8s nodes connect to
// 100.64.0.0/16 -- the join subnet that connects all the L3 gateways with the distributed router
// 169.254.33.0/24 -- the subnet that connects OVN logical network to physical network
// 10.1.0.0/16 -- the overlay subnet that Pods connect to.

func cleanupPBRandNATRules(fexec *ovntest.FakeExec, nodeName string, nodeSubnet []*net.IPNet) {
	mgmtPortIP := util.GetNodeManagementIfAddr(nodeSubnet[0]).IP.String()
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=external_ip find nat logical_port=" + util.K8sPrefix + nodeName,
		Output: "External_IP",
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists lr-nat-del " + ovnClusterRouter + " dnat_and_snat External_IP",
	})
	matchstr1 := fmt.Sprintf("ip4.src == %s && ip4.dst == nodePhysicalIP /* %s */", mgmtPortIP, nodeName)
	matchstr2 := fmt.Sprintf(`inport == "rtos-%s" && ip4.dst == nodePhysicalIP /* %s */`, nodeName, nodeName)
	matchstr3 := fmt.Sprintf("ip4.src == source && ip4.dst == nodePhysicalIP")
	matchstr4 := fmt.Sprintf(`ip4.src == NO DELETE  && ip4.dst != 10.244.0.0/16 /* inter-%s-no */`, nodeName)
	matchstr5 := fmt.Sprintf(`ip4.src == 10.244.0.2  && ip4.dst != 10.244.0.0/16 /* inter-%s */`, nodeName)
	matchstr6 := fmt.Sprintf("ip4.src == NO DELETE && ip4.dst == nodePhysicalIP /* %s-no */", nodeName)

	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd: "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=match find logical_router_policy",
		Output: fmt.Sprintf(`%s

%s

%s

%s

%s

%s
`, matchstr1, matchstr2, matchstr3, matchstr4, matchstr5, matchstr6),
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 lr-policy-del " + ovnClusterRouter + " " + mgmtPortPolicyPriority + " " + matchstr1,
		"ovn-nbctl --timeout=15 lr-policy-del " + ovnClusterRouter + " " + nodeSubnetPolicyPriority + " " + matchstr2,
		"ovn-nbctl --timeout=15 lr-policy-del " + ovnClusterRouter + " " + interNodePolicyPriority + " " + matchstr5,
	})
}

func cleanupGateway(fexec *ovntest.FakeExec, nodeName string, nodeSubnet string, clusterCIDR string, nextHop string) {
	const (
		node1RouteUUID    string = "0cac12cf-3e0f-4682-b028-5ea2e0001962"
		node1mgtRouteUUID string = "0cac12cf-3e0f-4682-b028-5ea2e0001963"
	)

	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --if-exist get logical_router_port " + gwRouterToJoinSwitchPrefix + gwRouterPrefix + nodeName + " networks",
		Output: "[\"100.64.0.1/29\"]",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_static_route nexthop=\"100.64.0.1\"",
		Output: node1RouteUUID,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists remove logical_router " + ovnClusterRouter + " static_routes " + node1RouteUUID,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exist ls-del " + joinSwitchPrefix + nodeName,
		"ovn-nbctl --timeout=15 --if-exist lr-del " + gwRouterPrefix + nodeName,
		"ovn-nbctl --timeout=15 --if-exist ls-del " + externalSwitchPrefix + nodeName,
		"ovn-nbctl --timeout=15 --if-exist lrp-del " + distRouterToJoinSwitchPrefix + nodeName,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=" + gwRouterPrefix + nodeName,
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:UDP_lb_gateway_router=" + gwRouterPrefix + nodeName,
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:SCTP_lb_gateway_router=" + gwRouterPrefix + nodeName,
		Output: "",
	})

	cleanupPBRandNATRules(fexec, nodeName, []*net.IPNet{ovntest.MustParseIPNet(nodeSubnet)})
}

func defaultFakeExec(nodeSubnet, nodeName string, sctpSupport bool) (*ovntest.FakeExec, string, string, string) {
	const (
		tcpLBUUID  string = "1a3dfc82-2749-4931-9190-c30e7c0ecea3"
		udpLBUUID  string = "6d3142fc-53e8-4ac1-88e6-46094a5a9957"
		sctpLBUUID string = "0514c521-a120-4756-aec6-883fe5db7139"
		mgmtMAC    string = "01:02:03:04:05:06"
	)

	fexec := ovntest.NewLooseCompareFakeExec()
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --columns=_uuid list port_group",
		"ovn-sbctl --timeout=15 --columns=_uuid list IGMP_Group",
		"ovn-nbctl --timeout=15 -- --may-exist lr-add ovn_cluster_router -- set logical_router ovn_cluster_router external_ids:k8s-cluster-router=yes",
	})
	if sctpSupport {
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovsdb-client list-columns  --data=bare --no-heading --format=json OVN_Northbound Load_Balancer",
			Output: `{"data":[["_version","uuid"],["health_check",{"key":{"refTable":"Load_Balancer_Health_Check","type":"uuid"},"max":"unlimited","min":0}],["name","string"],["protocol",{"key":{"enum":["set",["sctp","tcp","udp"]],"type":"string"},"min":0}]],"headings":["Column","Type"]}`,
		})
	} else {
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovsdb-client list-columns  --data=bare --no-heading --format=json OVN_Northbound Load_Balancer",
			Output: `{"data":[["_version","uuid"],["health_check",{"key":{"refTable":"Load_Balancer_Health_Check","type":"uuid"},"max":"unlimited","min":0}],["name","string"],["protocol",{"key":{"enum":["set",["tcp","udp"]],"type":"string"},"min":0}]],"headings":["Column","Type"]}`,
		})
	}
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 -- set logical_router ovn_cluster_router options:mcast_relay=\"true\"",
		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=mcastPortGroupDeny",
		"ovn-nbctl --timeout=15 create port_group name=mcastPortGroupDeny external-ids:name=mcastPortGroupDeny",
		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"inport == @mcastPortGroupDeny && ip4.mcast\" action=drop external-ids:default-deny-policy-type=Egress",
		"ovn-nbctl --timeout=15 --id=@acl create acl priority=1011 direction=from-lport match=\"inport == @mcastPortGroupDeny && ip4.mcast\" action=drop external-ids:default-deny-policy-type=Egress -- add port_group  acls @acl",
		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"outport == @mcastPortGroupDeny && ip4.mcast\" action=drop external-ids:default-deny-policy-type=Ingress",
		"ovn-nbctl --timeout=15 --id=@acl create acl priority=1011 direction=to-lport match=\"outport == @mcastPortGroupDeny && ip4.mcast\" action=drop external-ids:default-deny-policy-type=Ingress -- add port_group  acls @acl",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 -- create load_balancer external_ids:k8s-cluster-lb-tcp=yes protocol=tcp",
		Output: tcpLBUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-udp=yes",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 -- create load_balancer external_ids:k8s-cluster-lb-udp=yes protocol=udp",
		Output: udpLBUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-sctp=yes",
		Output: "",
	})
	if sctpSupport {
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 -- create load_balancer external_ids:k8s-cluster-lb-sctp=yes protocol=sctp",
			Output: sctpLBUUID,
		})
	}
	// Node-related logical network stuff
	cidr := ovntest.MustParseIPNet(nodeSubnet)
	cidr.IP = util.NextIP(cidr.IP)
	lrpMAC := util.IPAddrToHWAddr(cidr.IP).String()
	gwCIDR := cidr.String()
	gwIP := cidr.IP.String()
	nodeMgmtPortIP := util.NextIP(cidr.IP)
	hybridOverlayIP := util.NextIP(nodeMgmtPortIP)

	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name,other-config find logical_switch",
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists lrp-del " + routerToSwitchPrefix + nodeName + " -- lrp-add ovn_cluster_router " + routerToSwitchPrefix + nodeName + " " + lrpMAC + " " + gwCIDR,
		"ovn-nbctl --timeout=15 --may-exist ls-add " + nodeName + " -- set logical_switch " + nodeName + " other-config:subnet=" + nodeSubnet + " other-config:exclude_ips=" + nodeMgmtPortIP.String() + ".." + hybridOverlayIP.String(),
		"ovn-nbctl --timeout=15 set logical_switch " + nodeName + " other-config:mcast_snoop=\"true\"",
		"ovn-nbctl --timeout=15 set logical_switch " + nodeName + " other-config:mcast_querier=\"true\" other-config:mcast_eth_src=\"" + lrpMAC + "\" other-config:mcast_ip4_src=\"" + gwIP + "\"",
		"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + nodeName + " " + switchToRouterPrefix + nodeName + " -- set logical_switch_port " + switchToRouterPrefix + nodeName + " type=router options:router-port=" + routerToSwitchPrefix + nodeName + " addresses=\"" + lrpMAC + "\"",
		"ovn-nbctl --timeout=15 set logical_switch " + nodeName + " load_balancer=" + tcpLBUUID,
		"ovn-nbctl --timeout=15 add logical_switch " + nodeName + " load_balancer " + udpLBUUID,
	})
	if sctpSupport {
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 add logical_switch " + nodeName + " load_balancer " + sctpLBUUID,
		})
	}
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --may-exist acl-add " + nodeName + " to-lport 1001 ip4.src==" + nodeMgmtPortIP.String() + " allow-related",
		"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + nodeName + " " + util.K8sPrefix + nodeName + " -- lsp-set-addresses " + util.K8sPrefix + nodeName + " " + mgmtMAC + " " + nodeMgmtPortIP.String(),
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 lsp-list " + nodeName,
		Output: "29df5ce5-2802-4ee5-891f-4fb27ca776e9 (" + util.K8sPrefix + nodeName + ")",
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 -- --if-exists set logical_switch " + nodeName + " other-config:exclude_ips=" + hybridOverlayIP.String(),
	})

	return fexec, tcpLBUUID, udpLBUUID, sctpLBUUID
}

func addNodeportLBs(fexec *ovntest.FakeExec, nodeName, tcpLBUUID, udpLBUUID, sctpLBUUID string) {
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=" + gwRouterPrefix + nodeName,
		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:UDP_lb_gateway_router=" + gwRouterPrefix + nodeName,
		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:SCTP_lb_gateway_router=" + gwRouterPrefix + nodeName,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 -- create load_balancer external_ids:TCP_lb_gateway_router=" + gwRouterPrefix + nodeName + " protocol=tcp",
		Output: tcpLBUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 -- create load_balancer external_ids:UDP_lb_gateway_router=" + gwRouterPrefix + nodeName + " protocol=udp",
		Output: udpLBUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 -- create load_balancer external_ids:SCTP_lb_gateway_router=" + gwRouterPrefix + nodeName + " protocol=sctp",
		Output: sctpLBUUID,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 set logical_router " + gwRouterPrefix + nodeName + " load_balancer=" + tcpLBUUID +
			"," + udpLBUUID + "," + sctpLBUUID,
		"ovn-nbctl --timeout=15 get logical_switch " + nodeName + " load_balancer",
		"ovn-nbctl --timeout=15 ls-lb-add " + nodeName + " " + tcpLBUUID,
		"ovn-nbctl --timeout=15 ls-lb-add " + nodeName + " " + udpLBUUID,
		"ovn-nbctl --timeout=15 ls-lb-add " + nodeName + " " + sctpLBUUID,
	})
}

func populatePortAddresses(nodeName, lsp, mac, ips string, ovnClient goovn.Client) {
	cmd, err := ovnClient.LSPAdd(nodeName, lsp)
	Expect(err).NotTo(HaveOccurred())
	err = cmd.Execute()
	Expect(err).NotTo(HaveOccurred())
	addresses := mac + " " + ips
	addresses = strings.TrimSpace(addresses)
	cmd, err = ovnClient.LSPSetDynamicAddresses(lsp, addresses)
	Expect(err).NotTo(HaveOccurred())
	err = cmd.Execute()
	Expect(err).NotTo(HaveOccurred())
}

/* FIXME for updated local gw
var _ = Describe("Master Operations", func() {
	var (
		app      *cli.App
		f        *factory.WatchFactory
		stopChan chan struct{}
		wg       *sync.WaitGroup
	)

	BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags
		stopChan = make(chan struct{})
		wg = &sync.WaitGroup{}
	})

	AfterEach(func() {
		close(stopChan)
		f.Shutdown()
		wg.Wait()
	})

	It("creates logical network elements for a 2-node cluster", func() {
		const (
			clusterIPNet string = "10.1.0.0"
			clusterCIDR  string = clusterIPNet + "/16"
		)

		app.Action = func(ctx *cli.Context) error {
			const (
				nodeName    string = "node1"
				nodeSubnet  string = "10.1.0.0/24"
				clusterCIDR string = "10.1.0.0/16"
				nextHop     string = "10.1.0.2"
				mgmtMAC     string = "01:02:03:04:05:06"
				hybMAC      string = "02:03:04:05:06:07"
				hybIP       string = "10.1.0.3"
			)

			fexec, tcpLBUUID, udpLBUUID, sctpLBUUID := defaultFakeExec(nodeSubnet, nodeName, true)
			cleanupGateway(fexec, nodeName, nodeSubnet, clusterCIDR, nextHop)

			testNode := v1.Node{ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
			}}

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{testNode},
			})
			egressFirewallFakeClient := &egressfirewallfake.Clientset{}
			crdFakeClient := &apiextensionsfake.Clientset{}
			egressIPFakeClient := &egressipfake.Clientset{}

			err := util.SetExec(fexec)
			Expect(err).NotTo(HaveOccurred())

			_, err = config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			mockOVNNBClient := ovntest.NewMockOVNClient(goovn.DBNB)
			mockOVNSBClient := ovntest.NewMockOVNClient(goovn.DBSB)
			lsp := "int-" + nodeName
			populatePortAddresses(nodeName, lsp, hybMAC, hybIP, mockOVNNBClient)
			nodeAnnotator := kube.NewNodeAnnotator(&kube.Kube{fakeClient, egressIPFakeClient, egressFirewallFakeClient}, &testNode)
			err = util.SetL3GatewayConfig(nodeAnnotator, &util.L3GatewayConfig{Mode: config.GatewayModeDisabled})
			Expect(err).NotTo(HaveOccurred())
			err = util.SetNodeManagementPortMACAddress(nodeAnnotator, ovntest.MustParseMAC(mgmtMAC))
			Expect(err).NotTo(HaveOccurred())
			err = nodeAnnotator.Run()
			Expect(err).NotTo(HaveOccurred())

			f, err = factory.NewWatchFactory(fakeClient, egressIPFakeClient, egressFirewallFakeClient, crdFakeClient)
			Expect(err).NotTo(HaveOccurred())

			clusterController := NewOvnController(fakeClient, egressIPFakeClient, egressFirewallFakeClient, f, stopChan,
				newFakeAddressSetFactory(),
				mockOVNNBClient,
				mockOVNSBClient, record.NewFakeRecorder(0))

			Expect(clusterController).NotTo(BeNil())
			clusterController.TCPLoadBalancerUUID = tcpLBUUID
			clusterController.UDPLoadBalancerUUID = udpLBUUID
			clusterController.SCTPLoadBalancerUUID = sctpLBUUID

			err = clusterController.StartClusterMaster("master")
			Expect(err).NotTo(HaveOccurred())

			clusterController.WatchNodes()

			wg.Add(1)
			go func() {
				defer wg.Done()
				clusterController.hoMaster.Run(stopChan)
			}()

			Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			updatedNode, err := fakeClient.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())

			subnetsFromAnnotation, err := util.ParseNodeHostSubnetAnnotation(updatedNode)
			Expect(err).NotTo(HaveOccurred())
			Expect(subnetsFromAnnotation[0].String()).To(Equal(nodeSubnet))

			macFromAnnotation, err := util.ParseNodeManagementPortMACAddress(updatedNode)
			Expect(err).NotTo(HaveOccurred())
			Expect(macFromAnnotation.String()).To(Equal(mgmtMAC))

			Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			return nil
		}

		err := app.Run([]string{
			app.Name,
			"-cluster-subnets=" + clusterCIDR,
			"-enable-multicast",
			"-enable-hybrid-overlay",
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("works without SCTP support", func() {
		const (
			clusterIPNet string = "10.1.0.0"
			clusterCIDR  string = clusterIPNet + "/16"
		)

		app.Action = func(ctx *cli.Context) error {
			const (
				nodeName    string = "sctp-test-node"
				nodeSubnet  string = "10.1.0.0/24"
				clusterCIDR string = "10.1.0.0/16"
				nextHop     string = "10.1.0.2"
				mgmtMAC     string = "01:02:03:04:05:06"
				hybMAC      string = "02:03:04:05:06:07"
				hybIP       string = "10.1.0.3"
			)

			fexec, tcpLBUUID, udpLBUUID, _ := defaultFakeExec(nodeSubnet, nodeName, false)
			cleanupGateway(fexec, nodeName, nodeSubnet, clusterCIDR, nextHop)

			testNode := v1.Node{ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
			}}

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{testNode},
			})
			egressFirewallFakeClient := &egressfirewallfake.Clientset{}
			crdFakeClient := &apiextensionsfake.Clientset{}
			egressIPFakeClient := &egressipfake.Clientset{}

			err := util.SetExec(fexec)
			Expect(err).NotTo(HaveOccurred())

			_, err = config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			mockOVNNBClient := ovntest.NewMockOVNClient(goovn.DBNB)
			mockOVNSBClient := ovntest.NewMockOVNClient(goovn.DBSB)
			lsp := "int-" + nodeName
			populatePortAddresses(nodeName, lsp, hybMAC, hybIP, mockOVNNBClient)
			nodeAnnotator := kube.NewNodeAnnotator(&kube.Kube{fakeClient, egressIPFakeClient, egressFirewallFakeClient}, &testNode)
			err = util.SetL3GatewayConfig(nodeAnnotator, &util.L3GatewayConfig{Mode: config.GatewayModeDisabled})
			Expect(err).NotTo(HaveOccurred())
			err = util.SetNodeManagementPortMACAddress(nodeAnnotator, ovntest.MustParseMAC(mgmtMAC))
			Expect(err).NotTo(HaveOccurred())
			err = nodeAnnotator.Run()
			Expect(err).NotTo(HaveOccurred())

			f, err = factory.NewWatchFactory(fakeClient, egressIPFakeClient, egressFirewallFakeClient, crdFakeClient)
			Expect(err).NotTo(HaveOccurred())

			clusterController := NewOvnController(fakeClient, egressIPFakeClient, egressFirewallFakeClient, f, stopChan,
				newFakeAddressSetFactory(), mockOVNNBClient,
				mockOVNSBClient, record.NewFakeRecorder(0))

			Expect(clusterController).NotTo(BeNil())
			clusterController.TCPLoadBalancerUUID = tcpLBUUID
			clusterController.UDPLoadBalancerUUID = udpLBUUID
			clusterController.SCTPLoadBalancerUUID = ""

			err = clusterController.StartClusterMaster("master")
			Expect(err).NotTo(HaveOccurred())

			clusterController.WatchNodes()

			wg.Add(1)
			go func() {
				defer wg.Done()
				clusterController.hoMaster.Run(stopChan)
			}()

			Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			updatedNode, err := fakeClient.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())

			subnetsFromAnnotation, err := util.ParseNodeHostSubnetAnnotation(updatedNode)
			Expect(err).NotTo(HaveOccurred())
			Expect(subnetsFromAnnotation[0].String()).To(Equal(nodeSubnet))

			macFromAnnotation, err := util.ParseNodeManagementPortMACAddress(updatedNode)
			Expect(err).NotTo(HaveOccurred())
			Expect(macFromAnnotation.String()).To(Equal(mgmtMAC))

			Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			return nil
		}

		err := app.Run([]string{
			app.Name,
			"-cluster-subnets=" + clusterCIDR,
			"-enable-multicast",
			"-enable-hybrid-overlay",
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("does not allocate a hostsubnet for a node that already has one", func() {
		const (
			clusterIPNet string = "10.1.0.0"
			clusterCIDR  string = clusterIPNet + "/16"
		)

		app.Action = func(ctx *cli.Context) error {
			const (
				nodeName    string = "node1"
				nodeSubnet  string = "10.1.3.0/24"
				clusterCIDR string = "10.1.0.0/16"
				nextHop     string = "10.1.3.2"
				mgmtMAC     string = "01:02:03:04:05:06"
				hybMAC      string = "02:03:04:05:06:07"
				hybIP       string = "10.1.0.3"
			)

			testNode := v1.Node{ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
			}}

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{testNode},
			})
			egressFirewallFakeClient := &egressfirewallfake.Clientset{}
			crdFakeClient := &apiextensionsfake.Clientset{}
			egressIPFakeClient := &egressipfake.Clientset{}

			fexec, tcpLBUUID, udpLBUUID, sctpLBUUID := defaultFakeExec(nodeSubnet, nodeName, true)
			err := util.SetExec(fexec)
			Expect(err).NotTo(HaveOccurred())
			cleanupGateway(fexec, nodeName, nodeSubnet, clusterCIDR, nextHop)

			_, err = config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())
			mockOVNNBClient := ovntest.NewMockOVNClient(goovn.DBNB)
			mockOVNSBClient := ovntest.NewMockOVNClient(goovn.DBSB)
			lsp := "int-" + nodeName
			populatePortAddresses(nodeName, lsp, hybMAC, hybIP, mockOVNNBClient)
			nodeAnnotator := kube.NewNodeAnnotator(&kube.Kube{fakeClient, egressIPFakeClient, egressFirewallFakeClient}, &testNode)
			err = util.SetL3GatewayConfig(nodeAnnotator, &util.L3GatewayConfig{Mode: config.GatewayModeDisabled})
			Expect(err).NotTo(HaveOccurred())
			err = util.SetNodeManagementPortMACAddress(nodeAnnotator, ovntest.MustParseMAC(mgmtMAC))
			Expect(err).NotTo(HaveOccurred())
			err = util.SetNodeHostSubnetAnnotation(nodeAnnotator, ovntest.MustParseIPNets(nodeSubnet))
			Expect(err).NotTo(HaveOccurred())
			err = nodeAnnotator.Run()
			Expect(err).NotTo(HaveOccurred())

			f, err = factory.NewWatchFactory(fakeClient, egressIPFakeClient, egressFirewallFakeClient, crdFakeClient)
			Expect(err).NotTo(HaveOccurred())

			clusterController := NewOvnController(fakeClient, egressIPFakeClient, egressFirewallFakeClient, f, stopChan,
				newFakeAddressSetFactory(), mockOVNNBClient, mockOVNSBClient, record.NewFakeRecorder(0))
			Expect(clusterController).NotTo(BeNil())
			clusterController.TCPLoadBalancerUUID = tcpLBUUID
			clusterController.UDPLoadBalancerUUID = udpLBUUID
			clusterController.SCTPLoadBalancerUUID = sctpLBUUID

			err = clusterController.StartClusterMaster("master")
			Expect(err).NotTo(HaveOccurred())

			clusterController.WatchNodes()

			wg.Add(1)
			go func() {
				defer wg.Done()
				clusterController.hoMaster.Run(stopChan)
			}()

			Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			updatedNode, err := fakeClient.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())

			subnetsFromAnnotation, err := util.ParseNodeHostSubnetAnnotation(updatedNode)
			Expect(err).NotTo(HaveOccurred())
			Expect(subnetsFromAnnotation[0].String()).To(Equal(nodeSubnet))

			macFromAnnotation, err := util.ParseNodeManagementPortMACAddress(updatedNode)
			Expect(err).NotTo(HaveOccurred())
			Expect(macFromAnnotation.String()).To(Equal(mgmtMAC))

			Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			return nil
		}

		err := app.Run([]string{
			app.Name,
			"-cluster-subnets=" + clusterCIDR,
			"-enable-multicast",
			"-enable-hybrid-overlay",
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("removes deleted nodes from the OVN database", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				tcpLBUUID         string = "1a3dfc82-2749-4931-9190-c30e7c0ecea3"
				udpLBUUID         string = "6d3142fc-53e8-4ac1-88e6-46094a5a9957"
				sctpLBUUID        string = "0514c521-a120-4756-aec6-883fe5db7139"
				node1Name         string = "openshift-node-1"
				node1Subnet       string = "10.128.0.0/24"
				node1MgmtPortIP   string = "10.128.0.2"
				masterName        string = "openshift-master-node"
				masterSubnet      string = "10.128.2.0/24"
				masterGWCIDR      string = "10.128.2.1/24"
				masterMgmtPortIP  string = "10.128.2.2"
				lrpMAC            string = "0a:58:0a:80:02:01"
				masterMgmtPortMAC string = "00:00:00:55:66:77"
			)

			fexec := ovntest.NewFakeExec()
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name,other-config find logical_switch",
				// Return two nodes
				Output: fmt.Sprintf(`%s
subnet=%s

%s
subnet=%s
`, node1Name, node1Subnet, masterName, masterSubnet),
			})

			// Expect the code to delete node1 which no longer exists in Kubernetes API
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 --if-exist ls-del " + node1Name,
				"ovn-nbctl --timeout=15 --if-exist lrp-del " + routerToSwitchPrefix + node1Name,
			})
			cleanupGateway(fexec, node1Name, node1Subnet, ovnClusterRouter, node1MgmtPortIP)

			// Expect the code to re-add the master (which still exists)
			// when the factory watch begins and enumerates all existing
			// Kubernetes API nodes
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 --if-exists lrp-del " + routerToSwitchPrefix + masterName + " -- lrp-add ovn_cluster_router " + routerToSwitchPrefix + masterName + " " + lrpMAC + " " + masterGWCIDR,
				"ovn-nbctl --timeout=15 --may-exist ls-add " + masterName + " -- set logical_switch " + masterName + " other-config:subnet=" + masterSubnet + " other-config:exclude_ips=" + masterMgmtPortIP,
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + masterName + " " + switchToRouterPrefix + masterName + " -- set logical_switch_port " + switchToRouterPrefix + masterName + " type=router options:router-port=" + routerToSwitchPrefix + masterName + " addresses=\"" + lrpMAC + "\"",
				"ovn-nbctl --timeout=15 set logical_switch " + masterName + " load_balancer=" + tcpLBUUID,
				"ovn-nbctl --timeout=15 add logical_switch " + masterName + " load_balancer " + udpLBUUID,
				"ovn-nbctl --timeout=15 add logical_switch " + masterName + " load_balancer " + sctpLBUUID,
				"ovn-nbctl --timeout=15 --may-exist acl-add " + masterName + " to-lport 1001 ip4.src==" + masterMgmtPortIP + " allow-related",
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + masterName + " " + util.K8sPrefix + masterName + " -- lsp-set-addresses " + util.K8sPrefix + masterName + " " + masterMgmtPortMAC + " " + masterMgmtPortIP,
			})
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovn-nbctl --timeout=15 lsp-list " + masterName,
				Output: "29df5ce5-2802-4ee5-891f-4fb27ca776e9 (" + util.K8sPrefix + masterName + ")",
			})
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 -- --if-exists remove logical_switch " + masterName + " other-config exclude_ips",
			})

			cleanupGateway(fexec, masterName, masterSubnet, masterGWCIDR, masterMgmtPortIP)

			masterNode := v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: masterName,
				},
				Spec: v1.NodeSpec{
					ProviderID: "gce://openshift-gce-devel-ci/us-east1-b/ci-op-tbtpp-m-0",
				},
				Status: v1.NodeStatus{
					Conditions: []v1.NodeCondition{
						{
							Type:               v1.NodeNetworkUnavailable,
							Status:             v1.ConditionTrue,
							Reason:             "NoRouteCreated",
							Message:            "Node created without a route",
							LastTransitionTime: metav1.Now(),
						},
					},
				},
			}
			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{masterNode},
			})
			egressFirewallFakeClient := &egressfirewallfake.Clientset{}
			crdFakeClient := &apiextensionsfake.Clientset{}
			egressIPFakeClient := &egressipfake.Clientset{}

			err := util.SetExec(fexec)
			Expect(err).NotTo(HaveOccurred())

			_, err = config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			nodeAnnotator := kube.NewNodeAnnotator(&kube.Kube{fakeClient, egressIPFakeClient, egressFirewallFakeClient}, &masterNode)
			err = util.SetL3GatewayConfig(nodeAnnotator, &util.L3GatewayConfig{Mode: config.GatewayModeDisabled})
			Expect(err).NotTo(HaveOccurred())
			err = util.SetNodeManagementPortMACAddress(nodeAnnotator, ovntest.MustParseMAC(masterMgmtPortMAC))
			Expect(err).NotTo(HaveOccurred())
			err = util.SetNodeHostSubnetAnnotation(nodeAnnotator, ovntest.MustParseIPNets(masterSubnet))
			Expect(err).NotTo(HaveOccurred())
			err = nodeAnnotator.Run()
			Expect(err).NotTo(HaveOccurred())

			f, err = factory.NewWatchFactory(fakeClient, egressIPFakeClient, egressFirewallFakeClient, crdFakeClient)
			Expect(err).NotTo(HaveOccurred())

			clusterController := NewOvnController(fakeClient, egressIPFakeClient, egressFirewallFakeClient, f, stopChan,
				newFakeAddressSetFactory(), ovntest.NewMockOVNClient(goovn.DBNB),
				ovntest.NewMockOVNClient(goovn.DBSB), record.NewFakeRecorder(0))
			Expect(clusterController).NotTo(BeNil())
			clusterController.TCPLoadBalancerUUID = tcpLBUUID
			clusterController.UDPLoadBalancerUUID = udpLBUUID
			clusterController.SCTPLoadBalancerUUID = sctpLBUUID
			clusterController.SCTPSupport = true

			_ = clusterController.joinSubnetAllocator.AddNetworkRange(ovntest.MustParseIPNet("100.64.0.0/16"), 29)

			// Let the real code run and ensure OVN database sync
			clusterController.WatchNodes()

			Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)

			node, err := fakeClient.CoreV1().Nodes().Get(context.TODO(), masterNode.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(len(node.Status.Conditions)).To(BeIdenticalTo(1))
			Expect(node.Status.Conditions[0].Message).To(BeIdenticalTo("ovn-kube cleared kubelet-set NoRouteCreated"))

			return nil
		}

		err := app.Run([]string{app.Name})
		Expect(err).NotTo(HaveOccurred())
	})
})
*/

func addPBRandNATRules(fexec *ovntest.FakeExec, nodeName, nodeSubnet, nodeIP, mgmtPortIP, mgmtPortMAC string) {
	externalIP := "169.254.0.1"
	matchStr1 := fmt.Sprintf(`inport == "rtos-%s" && ip4.dst == %s /* %s */`, nodeName, nodeIP, nodeName)
	matchStr2 := fmt.Sprintf("ip4.src == %s && ip4.dst == %s /* %s */", mgmtPortIP, nodeIP, nodeName)

	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 lr-policy-add " + ovnClusterRouter + " " + nodeSubnetPolicyPriority + " " + matchStr1 + " reroute " + mgmtPortIP,
		"ovn-nbctl --timeout=15 lr-policy-add " + ovnClusterRouter + " " + mgmtPortPolicyPriority + " " + matchStr2 + " reroute " + util.V4NodeLocalNatSubnetNextHop,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists lr-nat-del " + ovnClusterRouter + " dnat_and_snat " +
			externalIP + " -- lr-nat-add " + ovnClusterRouter + " dnat_and_snat " +
			externalIP + " " + mgmtPortIP + " " + util.K8sPrefix + nodeName + " " + mgmtPortMAC,
	})
}

var _ = Describe("Gateway Init Operations", func() {
	var (
		app      *cli.App
		f        *factory.WatchFactory
		stopChan chan struct{}
	)

	const (
		clusterIPNet string = "10.1.0.0"
		clusterCIDR  string = clusterIPNet + "/16"
	)

	BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags
		stopChan = make(chan struct{})
	})

	AfterEach(func() {
		close(stopChan)
		f.Shutdown()
	})

	/* FIXME with update to local gw
	It("sets up a localnet gateway", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				nodeName               string = "node1"
				nodeLRPMAC             string = "0a:58:0a:01:01:01"
				joinSubnet             string = "100.64.0.0/29"
				lrpMAC                 string = "0a:58:64:40:00:01"
				lrpIP                  string = "100.64.0.1"
				drLrpMAC               string = "0a:58:64:40:00:02"
				drLrpIP                string = "100.64.0.2"
				brLocalnetMAC          string = "11:22:33:44:55:66"
				systemID               string = "cb9ec8fa-b409-4ef3-9f42-d9283c47aac6"
				tcpLBUUID              string = "d2e858b2-cb5a-441b-a670-ed450f79a91f"
				udpLBUUID              string = "12832f14-eb0f-44d4-b8db-4cccbc73c792"
				sctpLBUUID             string = "0514c521-a120-4756-aec6-883fe5db7139"
				nodeSubnet             string = "10.1.1.0/24"
				nextHop                string = "10.1.1.2"
				gwRouter               string = gwRouterPrefix + nodeName
				clusterIPNet           string = "10.1.0.0"
				clusterCIDR            string = clusterIPNet + "/16"
				localnetGatewayIP      string = "169.254.33.2/24"
				localnetGatewayNextHop string = "169.254.33.1"
				localnetBridgeName     string = "br-local"
				masterGWCIDR           string = "10.1.1.1/24"
				masterMgmtPortIP       string = "10.1.1.2"
				node1RouteUUID         string = "0cac12cf-3e0f-4682-b028-5ea2e0001962"
				node1mgtRouteUUID      string = "0cac12cf-3e0f-4682-b028-5ea2e0001963"
			)

			testNode := v1.Node{ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
			}}

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{testNode},
			})
			egressFirewallFakeClient := &egressfirewallfake.Clientset{}
			crdFakeClient := &apiextensionsfake.Clientset{}
			egressIPFakeClient := &egressipfake.Clientset{}

			fexec := ovntest.NewFakeExec()
			err := util.SetExec(fexec)
			Expect(err).NotTo(HaveOccurred())

			_, err = config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			nodeAnnotator := kube.NewNodeAnnotator(&kube.Kube{fakeClient, egressIPFakeClient, egressFirewallFakeClient}, &testNode)
			ifaceID := localnetBridgeName + "_" + nodeName
			err = util.SetL3GatewayConfig(nodeAnnotator, &util.L3GatewayConfig{
				Mode:           config.GatewayModeLocal,
				ChassisID:      systemID,
				InterfaceID:    ifaceID,
				MACAddress:     ovntest.MustParseMAC(brLocalnetMAC),
				IPAddresses:    ovntest.MustParseIPNets(localnetGatewayIP),
				NextHops:       ovntest.MustParseIPs(localnetGatewayNextHop),
				NodePortEnable: true,
			})
			Expect(err).NotTo(HaveOccurred())
			err = util.SetNodeManagementPortMACAddress(nodeAnnotator, ovntest.MustParseMAC(brLocalnetMAC))
			Expect(err).NotTo(HaveOccurred())
			err = util.SetNodeHostSubnetAnnotation(nodeAnnotator, ovntest.MustParseIPNets(nodeSubnet))
			Expect(err).NotTo(HaveOccurred())
			err = util.SetNodeJoinSubnetAnnotation(nodeAnnotator, ovntest.MustParseIPNets(joinSubnet))
			Expect(err).NotTo(HaveOccurred())
			err = nodeAnnotator.Run()
			Expect(err).NotTo(HaveOccurred())

			updatedNode, err := fakeClient.CoreV1().Nodes().Get(context.TODO(), testNode.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			l3GatewayConfig, err := util.ParseNodeL3GatewayAnnotation(updatedNode)
			Expect(err).NotTo(HaveOccurred())

			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name,other-config find logical_switch",
			})

			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 --if-exists lrp-del " + routerToSwitchPrefix + nodeName + " -- lrp-add ovn_cluster_router " + routerToSwitchPrefix + nodeName + " " + nodeLRPMAC + " " + masterGWCIDR,
				"ovn-nbctl --timeout=15 --may-exist ls-add " + nodeName + " -- set logical_switch " + nodeName + " other-config:subnet=" + nodeSubnet + " other-config:exclude_ips=" + masterMgmtPortIP,
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + nodeName + " " + switchToRouterPrefix + nodeName + " -- set logical_switch_port " + switchToRouterPrefix + nodeName + " type=router options:router-port=" + routerToSwitchPrefix + nodeName + " addresses=\"" + nodeLRPMAC + "\"",
				"ovn-nbctl --timeout=15 set logical_switch " + nodeName + " load_balancer=" + tcpLBUUID,
				"ovn-nbctl --timeout=15 add logical_switch " + nodeName + " load_balancer " + udpLBUUID,
				"ovn-nbctl --timeout=15 add logical_switch " + nodeName + " load_balancer " + sctpLBUUID,
				"ovn-nbctl --timeout=15 --may-exist acl-add " + nodeName + " to-lport 1001 ip4.src==" + masterMgmtPortIP + " allow-related",
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + nodeName + " " + util.K8sPrefix + nodeName + " -- lsp-set-addresses " + util.K8sPrefix + nodeName + " " + brLocalnetMAC + " " + masterMgmtPortIP,
			})
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovn-nbctl --timeout=15 lsp-list " + nodeName,
				Output: "29df5ce5-2802-4ee5-891f-4fb27ca776e9 (" + util.K8sPrefix + nodeName + ")",
			})
			joinSwitch := joinSwitchPrefix + nodeName
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 -- --if-exists remove logical_switch " + nodeName + " other-config exclude_ips",
				"ovn-nbctl --timeout=15 -- --may-exist lr-add " + gwRouter + " -- set logical_router " + gwRouter + " options:chassis=" + systemID + " external_ids:physical_ip=169.254.33.2 external_ids:physical_ips=169.254.33.2",
				"ovn-nbctl --timeout=15 -- --may-exist ls-add " + joinSwitch,
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + joinSwitch + " " + joinSwitchToGwRouterPrefix + gwRouter + " -- set logical_switch_port " + joinSwitchToGwRouterPrefix + gwRouter + " type=router options:router-port=" + gwRouterToJoinSwitchPrefix + gwRouter + " addresses=router",
				"ovn-nbctl --timeout=15 -- --if-exists lrp-del " + gwRouterToJoinSwitchPrefix + gwRouter + " -- lrp-add " + gwRouter + " " + gwRouterToJoinSwitchPrefix + gwRouter + " " + lrpMAC + " " + lrpIP + "/29",
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + joinSwitch + " " + joinSwitchToDistRouterPrefix + nodeName + " -- set logical_switch_port " + joinSwitchToDistRouterPrefix + nodeName + " type=router options:router-port=" + distRouterToJoinSwitchPrefix + nodeName + " addresses=router",
				"ovn-nbctl --timeout=15 -- --if-exists lrp-del " + distRouterToJoinSwitchPrefix + nodeName + " -- lrp-add " + ovnClusterRouter + " " + distRouterToJoinSwitchPrefix + nodeName + " " + drLrpMAC + " " + drLrpIP + "/29",
			})
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 set logical_router " + gwRouter + " options:lb_force_snat_ip=" + lrpIP,
				"ovn-nbctl --timeout=15 --may-exist lr-route-add " + gwRouter + " " + clusterCIDR + " " + drLrpIP,
			})
			addNodeportLBs(fexec, nodeName, tcpLBUUID, udpLBUUID, sctpLBUUID)
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 --may-exist ls-add " + externalSwitchPrefix + nodeName,
			})
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + externalSwitchPrefix + nodeName + " br-local_" + nodeName + " -- lsp-set-addresses br-local_" + nodeName + " unknown -- lsp-set-type br-local_" + nodeName + " localnet -- lsp-set-options br-local_" + nodeName + " network_name=" + util.PhysicalNetworkName,
				"ovn-nbctl --timeout=15 -- --if-exists lrp-del " + gwRouterToExtSwitchPrefix + gwRouter + " -- lrp-add " + gwRouter + " " + gwRouterToExtSwitchPrefix + gwRouter + " " + brLocalnetMAC + " 169.254.33.2/24 -- set logical_router_port " + gwRouterToExtSwitchPrefix + gwRouter + " external-ids:gateway-physical-ip=yes",
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + externalSwitchPrefix + nodeName + " " + extSwitchToGwRouterPrefix + gwRouter + " -- set logical_switch_port " + extSwitchToGwRouterPrefix + gwRouter + " type=router options:router-port=" + gwRouterToExtSwitchPrefix + gwRouter + " addresses=\"" + brLocalnetMAC + "\"",
				"ovn-nbctl --timeout=15 --may-exist lr-route-add " + gwRouter + " 0.0.0.0/0 169.254.33.1 " + gwRouterToExtSwitchPrefix + gwRouter,
				"ovn-nbctl --timeout=15 --may-exist --policy=src-ip lr-route-add " + ovnClusterRouter + " " + nodeSubnet + " " + lrpIP,
				"ovn-nbctl --timeout=15 --if-exists lr-nat-del " + gwRouter + " snat " + clusterCIDR + " -- lr-nat-add " +
					gwRouter + " snat 169.254.33.2 " + clusterCIDR,
			})
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovn-nbctl --timeout=15 get logical_router " + gwRouterPrefix + nodeName + " external_ids:physical_ips",
				Output: "169.254.33.2",
			})
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 -- --may-exist lr-add " + gwRouter + " -- set logical_router " + gwRouter + " options:chassis=" + systemID + " external_ids:physical_ip=169.254.33.2 external_ids:physical_ips=169.254.33.2",
				"ovn-nbctl --timeout=15 -- --may-exist ls-add " + joinSwitch,
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + joinSwitch + " " + joinSwitchToGwRouterPrefix + gwRouter + " -- set logical_switch_port " + joinSwitchToGwRouterPrefix + gwRouter + " type=router options:router-port=" + gwRouterToJoinSwitchPrefix + gwRouter + " addresses=router",
				"ovn-nbctl --timeout=15 -- --if-exists lrp-del " + gwRouterToJoinSwitchPrefix + gwRouter + " -- lrp-add " + gwRouter + " " + gwRouterToJoinSwitchPrefix + gwRouter + " " + lrpMAC + " " + lrpIP + "/29",
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + joinSwitch + " " + joinSwitchToDistRouterPrefix + nodeName + " -- set logical_switch_port " + joinSwitchToDistRouterPrefix + nodeName + " type=router options:router-port=" + distRouterToJoinSwitchPrefix + nodeName + " addresses=router",
				"ovn-nbctl --timeout=15 -- --if-exists lrp-del " + distRouterToJoinSwitchPrefix + nodeName + " -- lrp-add " + ovnClusterRouter + " " + distRouterToJoinSwitchPrefix + nodeName + " " + drLrpMAC + " " + drLrpIP + "/29",
			})
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 set logical_router " + gwRouter + " options:lb_force_snat_ip=" + lrpIP,
				"ovn-nbctl --timeout=15 --may-exist lr-route-add " + gwRouter + " " + clusterCIDR + " " + drLrpIP,
			})
			addNodeportLBs(fexec, nodeName, tcpLBUUID, udpLBUUID, sctpLBUUID)
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 --may-exist ls-add " + externalSwitchPrefix + nodeName,
			})
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + externalSwitchPrefix + nodeName + " br-local_" + nodeName + " -- lsp-set-addresses br-local_" + nodeName + " unknown -- lsp-set-type br-local_" + nodeName + " localnet -- lsp-set-options br-local_" + nodeName + " network_name=" + util.PhysicalNetworkName,
				"ovn-nbctl --timeout=15 -- --if-exists lrp-del " + gwRouterToExtSwitchPrefix + gwRouter + " -- lrp-add " + gwRouter + " " + gwRouterToExtSwitchPrefix + gwRouter + " " + brLocalnetMAC + " 169.254.33.2/24 -- set logical_router_port " + gwRouterToExtSwitchPrefix + gwRouter + " external-ids:gateway-physical-ip=yes",
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + externalSwitchPrefix + nodeName + " " + extSwitchToGwRouterPrefix + gwRouter + " -- set logical_switch_port " + extSwitchToGwRouterPrefix + gwRouter + " type=router options:router-port=" + gwRouterToExtSwitchPrefix + gwRouter + " addresses=\"" + brLocalnetMAC + "\"",
				"ovn-nbctl --timeout=15 --may-exist lr-route-add " + gwRouter + " 0.0.0.0/0 169.254.33.1 " + gwRouterToExtSwitchPrefix + gwRouter,
				"ovn-nbctl --timeout=15 --may-exist --policy=src-ip lr-route-add " + ovnClusterRouter + " " + nodeSubnet + " " + lrpIP,
				"ovn-nbctl --timeout=15 --if-exists lr-nat-del " + gwRouter + " snat " + clusterCIDR +
					" -- lr-nat-add " + gwRouter + " snat 169.254.33.2 " + clusterCIDR,
			})
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovn-nbctl --timeout=15 get logical_router " + gwRouterPrefix + nodeName + " external_ids:physical_ips",
				Output: "169.254.33.2",
			})

			f, err = factory.NewWatchFactory(fakeClient, egressIPFakeClient, egressFirewallFakeClient, crdFakeClient)
			Expect(err).NotTo(HaveOccurred())

			clusterController := NewOvnController(fakeClient, egressIPFakeClient, egressFirewallFakeClient, f, stopChan, newFakeAddressSetFactory(),
				ovntest.NewMockOVNClient(goovn.DBNB),
				ovntest.NewMockOVNClient(goovn.DBSB), record.NewFakeRecorder(0))
			Expect(clusterController).NotTo(BeNil())
			clusterController.TCPLoadBalancerUUID = tcpLBUUID
			clusterController.UDPLoadBalancerUUID = udpLBUUID
			clusterController.SCTPLoadBalancerUUID = sctpLBUUID
			clusterController.SCTPSupport = true

			_ = clusterController.joinSubnetAllocator.AddNetworkRange(ovntest.MustParseIPNet("100.64.0.0/16"), 29)

			// Let the real code run and ensure OVN database sync
			clusterController.WatchNodes()

			subnet := ovntest.MustParseIPNet(nodeSubnet)
			err = clusterController.syncGatewayLogicalNetwork(updatedNode, l3GatewayConfig, []*net.IPNet{subnet})
			Expect(err).NotTo(HaveOccurred())

			Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
			return nil
		}

		err := app.Run([]string{
			app.Name,
			"-cluster-subnets=" + clusterCIDR,
			"--init-gateways",
			"--gateway-local",
			"--nodeport",
		})
		Expect(err).NotTo(HaveOccurred())
	})
	*/

	It("sets up a shared gateway", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				nodeName             string = "node1"
				nodeLRPMAC           string = "0a:58:0a:01:01:01"
				joinSubnet           string = "100.64.0.0/29"
				lrpMAC               string = "0a:58:64:40:00:01"
				lrpIP                string = "100.64.0.1"
				drLrpMAC             string = "0a:58:64:40:00:02"
				drLrpIP              string = "100.64.0.2"
				physicalBridgeMAC    string = "11:22:33:44:55:66"
				systemID             string = "cb9ec8fa-b409-4ef3-9f42-d9283c47aac6"
				tcpLBUUID            string = "d2e858b2-cb5a-441b-a670-ed450f79a91f"
				udpLBUUID            string = "12832f14-eb0f-44d4-b8db-4cccbc73c792"
				sctpLBUUID           string = "0514c521-a120-4756-aec6-883fe5db7139"
				nodeSubnet           string = "10.1.1.0/24"
				gwRouter             string = gwRouterPrefix + nodeName
				clusterIPNet         string = "10.1.0.0"
				clusterCIDR          string = clusterIPNet + "/16"
				gatewayRouterIPMask  string = "172.16.16.2/24"
				gatewayRouterIP      string = "172.16.16.2"
				gatewayRouterNextHop string = "172.16.16.1"
				physicalBridgeName   string = "br-eth0"
				nodeGWIP             string = "10.1.1.1/24"
				nodeMgmtPortIP       string = "10.1.1.2"
				nodeMgmtPortMAC      string = "0a:58:0a:01:01:02"
				dnatSnatIP           string = "169.254.0.1"
			)

			testNode := v1.Node{ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
			}}

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{testNode},
			})
			egressFirewallFakeClient := &egressfirewallfake.Clientset{}
			crdFakeClient := &apiextensionsfake.Clientset{}
			egressIPFakeClient := &egressipfake.Clientset{}

			fexec := ovntest.NewFakeExec()
			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())
			exec, err := util.NewExecHelper(fexec)
			Expect(err).NotTo(HaveOccurred())

			nodeAnnotator := kube.NewNodeAnnotator(&kube.Kube{fakeClient, egressIPFakeClient, egressFirewallFakeClient}, &testNode)
			ifaceID := physicalBridgeName + "_" + nodeName
			vlanID := uint(1024)
			err = util.SetL3GatewayConfig(nodeAnnotator, &util.L3GatewayConfig{
				Mode:           config.GatewayModeShared,
				ChassisID:      systemID,
				InterfaceID:    ifaceID,
				MACAddress:     ovntest.MustParseMAC(physicalBridgeMAC),
				IPAddresses:    ovntest.MustParseIPNets(gatewayRouterIPMask),
				NextHops:       ovntest.MustParseIPs(gatewayRouterNextHop),
				NodePortEnable: true,
				VLANID:         &vlanID,
			})
			err = util.SetNodeManagementPortMACAddress(nodeAnnotator, ovntest.MustParseMAC(nodeMgmtPortMAC))
			Expect(err).NotTo(HaveOccurred())
			err = util.SetNodeHostSubnetAnnotation(nodeAnnotator, ovntest.MustParseIPNets(nodeSubnet))
			Expect(err).NotTo(HaveOccurred())
			err = util.SetNodeJoinSubnetAnnotation(nodeAnnotator, ovntest.MustParseIPNets(joinSubnet))
			Expect(err).NotTo(HaveOccurred())
			err = util.SetNodeLocalNatAnnotation(nodeAnnotator, []net.IP{ovntest.MustParseIP(dnatSnatIP)})
			Expect(err).NotTo(HaveOccurred())
			err = nodeAnnotator.Run()
			Expect(err).NotTo(HaveOccurred())

			updatedNode, err := fakeClient.CoreV1().Nodes().Get(context.TODO(), testNode.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			l3GatewayConfig, err := util.ParseNodeL3GatewayAnnotation(updatedNode)
			Expect(err).NotTo(HaveOccurred())

			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name,other-config find logical_switch",
			})

			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 --if-exists lrp-del " + routerToSwitchPrefix + nodeName + " -- lrp-add ovn_cluster_router " + routerToSwitchPrefix + nodeName + " " + nodeLRPMAC + " " + nodeGWIP,
				"ovn-nbctl --timeout=15 --may-exist ls-add " + nodeName + " -- set logical_switch " + nodeName + " other-config:subnet=" + nodeSubnet + " other-config:exclude_ips=" + nodeMgmtPortIP,
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + nodeName + " " + switchToRouterPrefix + nodeName + " -- set logical_switch_port " + switchToRouterPrefix + nodeName + " type=router options:router-port=" + routerToSwitchPrefix + nodeName + " addresses=\"" + nodeLRPMAC + "\"",
				"ovn-nbctl --timeout=15 set logical_switch " + nodeName + " load_balancer=" + tcpLBUUID,
				"ovn-nbctl --timeout=15 add logical_switch " + nodeName + " load_balancer " + udpLBUUID,
				"ovn-nbctl --timeout=15 add logical_switch " + nodeName + " load_balancer " + sctpLBUUID,
				"ovn-nbctl --timeout=15 --may-exist acl-add " + nodeName + " to-lport 1001 ip4.src==" + nodeMgmtPortIP + " allow-related",
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + nodeName + " " + util.K8sPrefix + nodeName + " -- lsp-set-addresses " + util.K8sPrefix + nodeName + " " + nodeMgmtPortMAC + " " + nodeMgmtPortIP,
			})
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovn-nbctl --timeout=15 lsp-list " + nodeName,
				Output: "29df5ce5-2802-4ee5-891f-4fb27ca776e9 (" + util.K8sPrefix + nodeName + ")",
			})
			joinSwitch := joinSwitchPrefix + nodeName
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 -- --if-exists remove logical_switch " + nodeName + " other-config exclude_ips",
				"ovn-nbctl --timeout=15 -- --may-exist lr-add " + gwRouter + " -- set logical_router " + gwRouter + " options:chassis=" + systemID + " external_ids:physical_ip=" + gatewayRouterIP + " external_ids:physical_ips=" + gatewayRouterIP,
				"ovn-nbctl --timeout=15 -- --may-exist ls-add " + joinSwitch,
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + joinSwitch + " " + joinSwitchToGwRouterPrefix + gwRouter + " -- set logical_switch_port " + joinSwitchToGwRouterPrefix + gwRouter + " type=router options:router-port=" + gwRouterToJoinSwitchPrefix + gwRouter + " addresses=router",
				"ovn-nbctl --timeout=15 -- --if-exists lrp-del " + gwRouterToJoinSwitchPrefix + gwRouter + " -- lrp-add " + gwRouter + " " + gwRouterToJoinSwitchPrefix + gwRouter + " " + lrpMAC + " " + lrpIP + "/29",
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + joinSwitch + " " + joinSwitchToDistRouterPrefix + nodeName + " -- set logical_switch_port " + joinSwitchToDistRouterPrefix + nodeName + " type=router options:router-port=" + distRouterToJoinSwitchPrefix + nodeName + " addresses=router",
				"ovn-nbctl --timeout=15 -- --if-exists lrp-del " + distRouterToJoinSwitchPrefix + nodeName + " -- lrp-add " + ovnClusterRouter + " " + distRouterToJoinSwitchPrefix + nodeName + " " + drLrpMAC + " " + drLrpIP + "/29",
			})
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 set logical_router " + gwRouter + " options:lb_force_snat_ip=" + lrpIP,
				"ovn-nbctl --timeout=15 --may-exist lr-route-add " + gwRouter + " " + clusterCIDR + " " + drLrpIP,
			})
			addNodeportLBs(fexec, nodeName, tcpLBUUID, udpLBUUID, sctpLBUUID)
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 --may-exist ls-add " + externalSwitchPrefix + nodeName,
			})
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + externalSwitchPrefix + nodeName + " br-eth0_" + nodeName + " -- lsp-set-addresses br-eth0_" + nodeName + " unknown -- lsp-set-type br-eth0_" + nodeName + " localnet -- lsp-set-options br-eth0_" + nodeName + " network_name=" + util.PhysicalNetworkName + " -- set logical_switch_port br-eth0_" + nodeName + " tag_request=" + "1024",
				"ovn-nbctl --timeout=15 -- --if-exists lrp-del " + gwRouterToExtSwitchPrefix + gwRouter + " -- lrp-add " + gwRouter + " " + gwRouterToExtSwitchPrefix + gwRouter + " " + physicalBridgeMAC + " " + gatewayRouterIPMask + " -- set logical_router_port " + gwRouterToExtSwitchPrefix + gwRouter + " external-ids:gateway-physical-ip=yes",
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + externalSwitchPrefix + nodeName + " " + extSwitchToGwRouterPrefix + gwRouter + " -- set logical_switch_port " + extSwitchToGwRouterPrefix + gwRouter + " type=router options:router-port=" + gwRouterToExtSwitchPrefix + gwRouter + " addresses=\"" + physicalBridgeMAC + "\"",
				"ovn-nbctl --timeout=15 --may-exist lr-route-add " + gwRouter + " 0.0.0.0/0 " + gatewayRouterNextHop + " " + gwRouterToExtSwitchPrefix + gwRouter,
				"ovn-nbctl --timeout=15 --may-exist --policy=src-ip lr-route-add " + ovnClusterRouter + " " + nodeSubnet + " " + lrpIP,
				"ovn-nbctl --timeout=15 --if-exists lr-nat-del " + gwRouter + " snat " + clusterCIDR +
					" -- lr-nat-add " + gwRouter + " snat " + gatewayRouterIP + " " + clusterCIDR,
			})

			addPBRandNATRules(fexec, nodeName, nodeSubnet, gatewayRouterIP, nodeMgmtPortIP, nodeMgmtPortMAC)

			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovn-nbctl --timeout=15 get logical_router " + gwRouterPrefix + nodeName + " external_ids:physical_ips",
				Output: "169.254.33.2",
			})
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 -- --may-exist lr-add " + gwRouter + " -- set logical_router " + gwRouter + " options:chassis=" + systemID + " external_ids:physical_ip=" + gatewayRouterIP + " external_ids:physical_ips=" + gatewayRouterIP,
				"ovn-nbctl --timeout=15 -- --may-exist ls-add " + joinSwitch,
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + joinSwitch + " " + joinSwitchToGwRouterPrefix + gwRouter + " -- set logical_switch_port " + joinSwitchToGwRouterPrefix + gwRouter + " type=router options:router-port=" + gwRouterToJoinSwitchPrefix + gwRouter + " addresses=router",
				"ovn-nbctl --timeout=15 -- --if-exists lrp-del " + gwRouterToJoinSwitchPrefix + gwRouter + " -- lrp-add " + gwRouter + " " + gwRouterToJoinSwitchPrefix + gwRouter + " " + lrpMAC + " " + lrpIP + "/29",
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + joinSwitch + " " + joinSwitchToDistRouterPrefix + nodeName + " -- set logical_switch_port " + joinSwitchToDistRouterPrefix + nodeName + " type=router options:router-port=" + distRouterToJoinSwitchPrefix + nodeName + " addresses=router",
				"ovn-nbctl --timeout=15 -- --if-exists lrp-del " + distRouterToJoinSwitchPrefix + nodeName + " -- lrp-add " + ovnClusterRouter + " " + distRouterToJoinSwitchPrefix + nodeName + " " + drLrpMAC + " " + drLrpIP + "/29",
			})

			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 set logical_router " + gwRouter + " options:lb_force_snat_ip=" + lrpIP,
				"ovn-nbctl --timeout=15 --may-exist lr-route-add " + gwRouter + " " + clusterCIDR + " " + drLrpIP,
			})
			addNodeportLBs(fexec, nodeName, tcpLBUUID, udpLBUUID, sctpLBUUID)
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 --may-exist ls-add " + externalSwitchPrefix + nodeName,
			})
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + externalSwitchPrefix + nodeName + " br-eth0_" + nodeName + " -- lsp-set-addresses br-eth0_" + nodeName + " unknown -- lsp-set-type br-eth0_" + nodeName + " localnet -- lsp-set-options br-eth0_" + nodeName + " network_name=" + util.PhysicalNetworkName + " -- set logical_switch_port br-eth0_" + nodeName + " tag_request=" + "1024",
				"ovn-nbctl --timeout=15 -- --if-exists lrp-del " + gwRouterToExtSwitchPrefix + gwRouter + " -- lrp-add " + gwRouter + " " + gwRouterToExtSwitchPrefix + gwRouter + " " + physicalBridgeMAC + " " + gatewayRouterIPMask + " -- set logical_router_port " + gwRouterToExtSwitchPrefix + gwRouter + " external-ids:gateway-physical-ip=yes",
				"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + externalSwitchPrefix + nodeName + " " + extSwitchToGwRouterPrefix + gwRouter + " -- set logical_switch_port " + extSwitchToGwRouterPrefix + gwRouter + " type=router options:router-port=" + gwRouterToExtSwitchPrefix + gwRouter + " addresses=\"" + physicalBridgeMAC + "\"",
				"ovn-nbctl --timeout=15 --may-exist lr-route-add " + gwRouter + " 0.0.0.0/0 " + gatewayRouterNextHop + " " + gwRouterToExtSwitchPrefix + gwRouter,
				"ovn-nbctl --timeout=15 --may-exist --policy=src-ip lr-route-add " + ovnClusterRouter + " " + nodeSubnet + " " + lrpIP,
				"ovn-nbctl --timeout=15 --if-exists lr-nat-del " + gwRouter + " snat " + clusterCIDR +
					" -- lr-nat-add " + gwRouter + " snat " + gatewayRouterIP + " " + clusterCIDR,
			})

			addPBRandNATRules(fexec, nodeName, nodeSubnet, gatewayRouterIP, nodeMgmtPortIP, nodeMgmtPortMAC)

			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovn-nbctl --timeout=15 get logical_router " + gwRouterPrefix + nodeName + " external_ids:physical_ips",
				Output: "169.254.33.2",
			})

			f, err = factory.NewWatchFactory(fakeClient, egressIPFakeClient, egressFirewallFakeClient, crdFakeClient)
			Expect(err).NotTo(HaveOccurred())

			clusterController := NewOvnController(fakeClient, exec, egressIPFakeClient, egressFirewallFakeClient, f, stopChan,
				newFakeAddressSetFactory(), ovntest.NewMockOVNClient(goovn.DBNB),
				ovntest.NewMockOVNClient(goovn.DBSB), record.NewFakeRecorder(0))
			Expect(clusterController).NotTo(BeNil())
			clusterController.TCPLoadBalancerUUID = tcpLBUUID
			clusterController.UDPLoadBalancerUUID = udpLBUUID
			clusterController.SCTPLoadBalancerUUID = sctpLBUUID
			clusterController.SCTPSupport = true

			_ = clusterController.joinSubnetAllocator.AddNetworkRange(ovntest.MustParseIPNet("100.64.0.0/16"), 29)
			clusterController.nodeLocalNatIPv4Allocator, _ = ipallocator.NewCIDRRange(ovntest.MustParseIPNet(util.V4NodeLocalNatSubnet))

			// Let the real code run and ensure OVN database sync
			clusterController.WatchNodes()

			subnet := ovntest.MustParseIPNet(nodeSubnet)
			err = clusterController.syncGatewayLogicalNetwork(updatedNode, l3GatewayConfig, []*net.IPNet{subnet})
			Expect(err).NotTo(HaveOccurred())

			Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
			return nil
		}

		err := app.Run([]string{
			app.Name,
			"-cluster-subnets=" + clusterCIDR,
			"--init-gateways",
			"--nodeport",
		})
		Expect(err).NotTo(HaveOccurred())
	})
})
