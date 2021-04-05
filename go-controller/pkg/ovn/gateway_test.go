package ovn

import (
	"net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("Gateway Init Operations", func() {
	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()
		// TODO make contexts here for shared gw mode and local gw mode, right now this only tests shared gw
		config.Gateway.Mode = config.GatewayModeShared
	})

	ginkgo.It("correctly sorts gateway routers", func() {
		fexec := ovntest.NewFakeExec()

		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd: "ovn-nbctl --timeout=15 --data=bare --format=table --no-heading --columns=name,options find logical_router options:lb_force_snat_ip!=-",
			Output: `node5      chassis=842fdade-747a-43b8-b40a-d8e8e26379fa lb_force_snat_ip=100.64.0.5
node2 chassis=6a47b33b-89d3-4d65-ac31-b19b549326c7 lb_force_snat_ip=100.64.0.2
node1 chassis=d17ddb5a-050d-42ab-ab50-7c6ce79a8f2e lb_force_snat_ip=100.64.0.1
node4 chassis=912d592c-904c-40cd-9ef1-c2e5b49a33dd lb_force_snat_ip=100.64.0.4`,
		})

		err := util.SetExec(fexec)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("ignores malformatted gateway router entires", func() {
		fexec := ovntest.NewFakeExec()
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd: "ovn-nbctl --timeout=15 --data=bare --format=table --no-heading --columns=name,options find logical_router options:lb_force_snat_ip!=-",
			Output: `node5      chassis=842fdade-747a-43b8-b40a-d8e8e26379fa lb_force_snat_ip=100.64.0.5
node2 chassis=6a47b33b-89d3-4d65-ac31-b19b549326c7 lb_force_snat_ip=asdfsadf
node1 chassis=d17ddb5a-050d-42ab-ab50-7c6ce79a8f2e lb_force_xxxxxxx=100.64.0.1
node4 chassis=912d592c-904c-40cd-9ef1-c2e5b49a33dd lb_force_snat_ip=100.64.0.4`,
		})

		err := util.SetExec(fexec)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("creates an IPv4 gateway in OVN", func() {
		clusterIPSubnets := ovntest.MustParseIPNets("10.128.0.0/14")
		hostSubnets := ovntest.MustParseIPNets("10.130.0.0/23")
		joinLRPIPs := ovntest.MustParseIPNets("100.64.0.3/16")
		defLRPIPs := ovntest.MustParseIPNets("100.64.0.1/16")
		nodeName := "test-node"
		l3GatewayConfig := &util.L3GatewayConfig{
			Mode:           config.GatewayModeLocal,
			ChassisID:      "SYSTEM-ID",
			InterfaceID:    "INTERFACE-ID",
			MACAddress:     ovntest.MustParseMAC("11:22:33:44:55:66"),
			IPAddresses:    ovntest.MustParseIPNets("169.254.33.2/24"),
			NextHops:       ovntest.MustParseIPs("169.254.33.1"),
			NodePortEnable: true,
		}
		sctpSupport := false

		fexec := ovntest.NewFakeExec()
		err := util.SetExec(fexec)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 -- --may-exist lr-add GR_test-node -- set logical_router GR_test-node options:chassis=SYSTEM-ID external_ids:physical_ip=169.254.33.2 external_ids:physical_ips=169.254.33.2",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + types.OVNJoinSwitch + " jtor-GR_test-node -- set logical_switch_port jtor-GR_test-node type=router options:router-port=rtoj-GR_test-node addresses=router",
			"ovn-nbctl --timeout=15 -- --if-exists lrp-del rtoj-GR_test-node -- lrp-add GR_test-node rtoj-GR_test-node 0a:58:64:40:00:03 100.64.0.3/16",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:lb_force_snat_ip=router_ip",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:snat-ct-zone=0",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:always_learn_from_arp_request=false",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:dynamic_neigh_routers=true",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add GR_test-node 10.128.0.0/14 100.64.0.1",
		})

		const (
			// TODO: Add new UUID's for local lbs
			tcpLBUUID string = "1a3dfc82-2749-4931-9190-c30e7c0ecea3"
			udpLBUUID string = "6d3142fc-53e8-4ac1-88e6-46094a5a9957"
		)
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBTCP + "=GR_test-node",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBUDP + "=GR_test-node",
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBSCTP + "=GR_test-node",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBTCP + "=GR_test-node_local",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBUDP + "=GR_test-node_local",
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBSCTP + "=GR_test-node_local",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.WorkerLBTCP + "=test-node",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.WorkerLBUDP + "=test-node",
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.WorkerLBSCTP + "=test-node",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 create load_balancer external_ids:" + types.GatewayLBUDP + "=GR_test-node protocol=udp",
			Output: udpLBUUID,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 create load_balancer external_ids:" + types.GatewayLBUDP + "=GR_test-node_local protocol=udp options:skip_snat=true",
			Output: udpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 set logical_router GR_test-node load_balancer=" + tcpLBUUID + "," + udpLBUUID + "," + tcpLBUUID + "," + udpLBUUID,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 create load_balancer external_ids:" + types.WorkerLBUDP + "=test-node protocol=udp",
			Output: udpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 get logical_switch test-node load_balancer",
			"ovn-nbctl --timeout=15 ls-lb-add test-node " + tcpLBUUID,
			"ovn-nbctl --timeout=15 ls-lb-add test-node " + udpLBUUID,
		})

		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --may-exist ls-add ext_test-node",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add ext_test-node INTERFACE-ID -- lsp-set-addresses INTERFACE-ID unknown -- lsp-set-type INTERFACE-ID localnet -- lsp-set-options INTERFACE-ID network_name=physnet",
			"ovn-nbctl --timeout=15 -- --if-exists lrp-del rtoe-GR_test-node -- lrp-add GR_test-node rtoe-GR_test-node 11:22:33:44:55:66 169.254.33.2/24 -- set logical_router_port rtoe-GR_test-node external-ids:gateway-physical-ip=yes",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add ext_test-node etor-GR_test-node -- set logical_switch_port etor-GR_test-node type=router options:router-port=rtoe-GR_test-node addresses=\"11:22:33:44:55:66\"",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add GR_test-node 0.0.0.0/0 169.254.33.1 rtoe-GR_test-node",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add ovn_cluster_router 100.64.0.3 100.64.0.3",
			"ovn-nbctl --timeout=15 --may-exist --policy=src-ip lr-route-add ovn_cluster_router 10.130.0.0/23 100.64.0.3",
			"ovn-nbctl --timeout=15 --columns _uuid --format=csv --no-headings find nat external_ip=\"169.254.33.2\" type=snat logical_ip=\"10.128.0.0/14\"",
			"ovn-nbctl --timeout=15 --if-exists lr-nat-del GR_test-node snat 10.128.0.0/14",
			"ovn-nbctl --timeout=15 lr-nat-add GR_test-node snat 169.254.33.2 10.128.0.0/14",
		})

		err = gatewayInit(nodeName, clusterIPSubnets, hostSubnets, l3GatewayConfig, sctpSupport, joinLRPIPs, defLRPIPs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue())
	})

	ginkgo.It("creates an IPv6 gateway in OVN", func() {
		clusterIPSubnets := ovntest.MustParseIPNets("fd01::/48")
		hostSubnets := ovntest.MustParseIPNets("fd01:0:0:2::/64")
		joinLRPIPs := ovntest.MustParseIPNets("fd98::3/64")
		defLRPIPs := ovntest.MustParseIPNets("fd98::1/64")
		nodeName := "test-node"
		l3GatewayConfig := &util.L3GatewayConfig{
			Mode:           config.GatewayModeLocal,
			ChassisID:      "SYSTEM-ID",
			InterfaceID:    "INTERFACE-ID",
			MACAddress:     ovntest.MustParseMAC("11:22:33:44:55:66"),
			IPAddresses:    ovntest.MustParseIPNets("fd99::2/64"),
			NextHops:       ovntest.MustParseIPs("fd99::1"),
			NodePortEnable: true,
		}
		sctpSupport := false

		fexec := ovntest.NewFakeExec()
		err := util.SetExec(fexec)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		// 0a:58:ee:33:fc:1a generated from util.IPAddrToHWAddr(net.ParseIP("fd98::1")).String()
		// 0a:58:5f:8a:48:8c generated from util.IPAddrToHWAddr(net.ParseIP("fd98::2")).String()
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 -- --may-exist lr-add GR_test-node -- set logical_router GR_test-node options:chassis=SYSTEM-ID external_ids:physical_ip=fd99::2 external_ids:physical_ips=fd99::2",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + types.OVNJoinSwitch + " jtor-GR_test-node -- set logical_switch_port jtor-GR_test-node type=router options:router-port=rtoj-GR_test-node addresses=router",
			"ovn-nbctl --timeout=15 -- --if-exists lrp-del rtoj-GR_test-node -- lrp-add GR_test-node rtoj-GR_test-node 0a:58:87:f0:33:ca fd98::3/64",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:lb_force_snat_ip=router_ip",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:snat-ct-zone=0",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:always_learn_from_arp_request=false",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:dynamic_neigh_routers=true",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add GR_test-node fd01::/48 fd98::1",
		})

		const (
			tcpLBUUID string = "1a3dfc82-2749-4931-9190-c30e7c0ecea3"
			udpLBUUID string = "6d3142fc-53e8-4ac1-88e6-46094a5a9957"
		)
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBTCP + "=GR_test-node",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBUDP + "=GR_test-node",
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBSCTP + "=GR_test-node",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBTCP + "=GR_test-node_local",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBUDP + "=GR_test-node_local",
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBSCTP + "=GR_test-node_local",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.WorkerLBTCP + "=test-node",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.WorkerLBUDP + "=test-node",
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.WorkerLBSCTP + "=test-node",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 create load_balancer external_ids:" + types.GatewayLBUDP + "=GR_test-node protocol=udp",
			Output: udpLBUUID,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 create load_balancer external_ids:" + types.GatewayLBUDP + "=GR_test-node_local protocol=udp options:skip_snat=true",
			Output: udpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 set logical_router GR_test-node load_balancer=" + tcpLBUUID + "," + udpLBUUID + "," + tcpLBUUID + "," + udpLBUUID,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 create load_balancer external_ids:" + types.WorkerLBUDP + "=test-node protocol=udp",
			Output: udpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 get logical_switch test-node load_balancer",
			"ovn-nbctl --timeout=15 ls-lb-add test-node " + tcpLBUUID,
			"ovn-nbctl --timeout=15 ls-lb-add test-node " + udpLBUUID,
		})

		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --may-exist ls-add ext_test-node",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add ext_test-node INTERFACE-ID -- lsp-set-addresses INTERFACE-ID unknown -- lsp-set-type INTERFACE-ID localnet -- lsp-set-options INTERFACE-ID network_name=physnet",
			"ovn-nbctl --timeout=15 -- --if-exists lrp-del rtoe-GR_test-node -- lrp-add GR_test-node rtoe-GR_test-node 11:22:33:44:55:66 fd99::2/64 -- set logical_router_port rtoe-GR_test-node external-ids:gateway-physical-ip=yes",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add ext_test-node etor-GR_test-node -- set logical_switch_port etor-GR_test-node type=router options:router-port=rtoe-GR_test-node addresses=\"11:22:33:44:55:66\"",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add GR_test-node ::/0 fd99::1 rtoe-GR_test-node",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add ovn_cluster_router fd98::3 fd98::3",
			"ovn-nbctl --timeout=15 --may-exist --policy=src-ip lr-route-add ovn_cluster_router fd01:0:0:2::/64 fd98::3",
			"ovn-nbctl --timeout=15 --columns _uuid --format=csv --no-headings find nat external_ip=\"fd99::2\" type=snat logical_ip=\"fd01::/48\"",
			"ovn-nbctl --timeout=15 --if-exists lr-nat-del GR_test-node snat fd01::/48",
			"ovn-nbctl --timeout=15 lr-nat-add GR_test-node snat fd99::2 fd01::/48",
		})

		err = gatewayInit(nodeName, clusterIPSubnets, hostSubnets, l3GatewayConfig, sctpSupport, joinLRPIPs, defLRPIPs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue())
	})

	ginkgo.It("creates a dual-stack gateway in OVN", func() {
		clusterIPSubnets := ovntest.MustParseIPNets("10.128.0.0/14", "fd01::/48")
		hostSubnets := ovntest.MustParseIPNets("10.130.0.0/23", "fd01:0:0:2::/64")
		joinLRPIPs := ovntest.MustParseIPNets("100.64.0.3/16", "fd98::3/64")
		defLRPIPs := ovntest.MustParseIPNets("100.64.0.1/16", "fd98::1/64")
		nodeName := "test-node"
		l3GatewayConfig := &util.L3GatewayConfig{
			Mode:           config.GatewayModeLocal,
			ChassisID:      "SYSTEM-ID",
			InterfaceID:    "INTERFACE-ID",
			MACAddress:     ovntest.MustParseMAC("11:22:33:44:55:66"),
			IPAddresses:    ovntest.MustParseIPNets("169.254.33.2/24", "fd99::2/64"),
			NextHops:       ovntest.MustParseIPs("169.254.33.1", "fd99::1"),
			NodePortEnable: true,
		}
		sctpSupport := false

		fexec := ovntest.NewFakeExec()
		err := util.SetExec(fexec)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 -- --may-exist lr-add GR_test-node -- set logical_router GR_test-node options:chassis=SYSTEM-ID external_ids:physical_ip=169.254.33.2 external_ids:physical_ips=169.254.33.2,fd99::2",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + types.OVNJoinSwitch + " jtor-GR_test-node -- set logical_switch_port jtor-GR_test-node type=router options:router-port=rtoj-GR_test-node addresses=router",
			"ovn-nbctl --timeout=15 -- --if-exists lrp-del rtoj-GR_test-node -- lrp-add GR_test-node rtoj-GR_test-node 0a:58:64:40:00:03 100.64.0.3/16 fd98::3/64",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:lb_force_snat_ip=router_ip",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:snat-ct-zone=0",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:always_learn_from_arp_request=false",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:dynamic_neigh_routers=true",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add GR_test-node 10.128.0.0/14 100.64.0.1",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add GR_test-node fd01::/48 fd98::1",
		})

		const (
			tcpLBUUID string = "1a3dfc82-2749-4931-9190-c30e7c0ecea3"
			udpLBUUID string = "6d3142fc-53e8-4ac1-88e6-46094a5a9957"
		)
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBTCP + "=GR_test-node",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBUDP + "=GR_test-node",
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBSCTP + "=GR_test-node",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBTCP + "=GR_test-node_local",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBUDP + "=GR_test-node_local",
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBSCTP + "=GR_test-node_local",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.WorkerLBTCP + "=test-node",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.WorkerLBUDP + "=test-node",
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.WorkerLBSCTP + "=test-node",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 create load_balancer external_ids:" + types.GatewayLBUDP + "=GR_test-node protocol=udp",
			Output: udpLBUUID,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 create load_balancer external_ids:" + types.GatewayLBUDP + "=GR_test-node_local protocol=udp options:skip_snat=true",
			Output: udpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 set logical_router GR_test-node load_balancer=" + tcpLBUUID + "," + udpLBUUID + "," + tcpLBUUID + "," + udpLBUUID,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 create load_balancer external_ids:" + types.WorkerLBUDP + "=test-node protocol=udp",
			Output: udpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 get logical_switch test-node load_balancer",
			"ovn-nbctl --timeout=15 ls-lb-add test-node " + tcpLBUUID,
			"ovn-nbctl --timeout=15 ls-lb-add test-node " + udpLBUUID,
		})

		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --may-exist ls-add ext_test-node",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add ext_test-node INTERFACE-ID -- lsp-set-addresses INTERFACE-ID unknown -- lsp-set-type INTERFACE-ID localnet -- lsp-set-options INTERFACE-ID network_name=physnet",
			"ovn-nbctl --timeout=15 -- --if-exists lrp-del rtoe-GR_test-node -- lrp-add GR_test-node rtoe-GR_test-node 11:22:33:44:55:66 169.254.33.2/24 fd99::2/64 -- set logical_router_port rtoe-GR_test-node external-ids:gateway-physical-ip=yes",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add ext_test-node etor-GR_test-node -- set logical_switch_port etor-GR_test-node type=router options:router-port=rtoe-GR_test-node addresses=\"11:22:33:44:55:66\"",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add GR_test-node 0.0.0.0/0 169.254.33.1 rtoe-GR_test-node",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add GR_test-node ::/0 fd99::1 rtoe-GR_test-node",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add ovn_cluster_router 100.64.0.3 100.64.0.3",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add ovn_cluster_router fd98::3 fd98::3",
			"ovn-nbctl --timeout=15 --may-exist --policy=src-ip lr-route-add ovn_cluster_router 10.130.0.0/23 100.64.0.3",
			"ovn-nbctl --timeout=15 --may-exist --policy=src-ip lr-route-add ovn_cluster_router fd01:0:0:2::/64 fd98::3",
			"ovn-nbctl --timeout=15 --columns _uuid --format=csv --no-headings find nat external_ip=\"169.254.33.2\" type=snat logical_ip=\"10.128.0.0/14\"",
			"ovn-nbctl --timeout=15 --if-exists lr-nat-del GR_test-node snat 10.128.0.0/14",
			"ovn-nbctl --timeout=15 lr-nat-add GR_test-node snat 169.254.33.2 10.128.0.0/14",
			"ovn-nbctl --timeout=15 --columns _uuid --format=csv --no-headings find nat external_ip=\"fd99::2\" type=snat logical_ip=\"fd01::/48\"",
			"ovn-nbctl --timeout=15 --if-exists lr-nat-del GR_test-node snat fd01::/48",
			"ovn-nbctl --timeout=15 lr-nat-add GR_test-node snat fd99::2 fd01::/48",
		})

		err = gatewayInit(nodeName, clusterIPSubnets, hostSubnets, l3GatewayConfig, sctpSupport, joinLRPIPs, defLRPIPs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue())
	})

	ginkgo.It("cleans up a single-stack gateway in OVN", func() {
		nodeName := "test-node"
		hostSubnet := ovntest.MustParseIPNet("10.130.0.0/23")
		const (
			nodeRouteUUID string = "0cac12cf-3e0f-4682-b028-5ea2e0001962"
			tcpLBUUID     string = "1a3dfc82-2749-4931-9190-c30e7c0ecea3"
		)

		fexec := ovntest.NewFakeExec()
		err := util.SetExec(fexec)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --if-exist get logical_router_port rtoj-GR_test-node networks",
			Output: "[\"100.64.0.1/16\"]",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_static_route nexthop=\"100.64.0.1\"",
			Output: nodeRouteUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove logical_router ovn_cluster_router static_routes " + nodeRouteUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exist lsp-del jtor-GR_test-node",
			"ovn-nbctl --timeout=15 --if-exist lr-del GR_test-node",
			"ovn-nbctl --timeout=15 --if-exist ls-del ext_test-node",
		})

		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_test-node",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:UDP_lb_gateway_router=GR_test-node",
			Output: "",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:SCTP_lb_gateway_router=GR_test-node",
			Output: "",
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 lb-del " + tcpLBUUID,
		})
		cleanupPBRandNATRules(fexec, nodeName, []*net.IPNet{hostSubnet})

		err = gatewayCleanup(nodeName)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue())
	})

	ginkgo.It("cleans up a dual-stack gateway in OVN", func() {
		nodeName := "test-node"
		hostSubnets := ovntest.MustParseIPNets("10.130.0.0/23", "fd01:0:0:2::/64")
		const (
			v4RouteUUID    string = "0cac12cf-3e0f-4682-b028-5ea2e0001962"
			v6RouteUUID    string = "0cac12cf-4682-3e0f-b028-5ea2e0001962"
			v4mgtRouteUUID string = "0cac12cf-3e0f-4682-b028-5ea2e0001963"
			v6mgtRouteUUID string = "0cac12cf-4682-3e0f-b028-5ea2e0001963"
			tcpLBUUID      string = "1a3dfc82-2749-4931-9190-c30e7c0ecea3"
		)

		fexec := ovntest.NewFakeExec()
		err := util.SetExec(fexec)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --if-exist get logical_router_port rtoj-GR_test-node networks",
			Output: "[\"100.64.0.1/16\", \"fd98::1/64\"]",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_static_route nexthop=\"100.64.0.1\"",
			Output: v4RouteUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove logical_router ovn_cluster_router static_routes " + v4RouteUUID,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find logical_router_static_route nexthop=\"fd98::1\"",
			Output: v6RouteUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove logical_router ovn_cluster_router static_routes " + v6RouteUUID,
		})

		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exist lsp-del jtor-GR_test-node",
			"ovn-nbctl --timeout=15 --if-exist lr-del GR_test-node",
			"ovn-nbctl --timeout=15 --if-exist ls-del ext_test-node",
		})

		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=GR_test-node",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:UDP_lb_gateway_router=GR_test-node",
			Output: "",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:SCTP_lb_gateway_router=GR_test-node",
			Output: "",
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 lb-del " + tcpLBUUID,
		})
		cleanupPBRandNATRules(fexec, nodeName, hostSubnets)

		err = gatewayCleanup(nodeName)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue())
	})

	ginkgo.It("removes leftover SNAT entries during init", func() {
		clusterIPSubnets := ovntest.MustParseIPNets("10.128.0.0/14")
		hostSubnets := ovntest.MustParseIPNets("10.130.0.0/23")
		joinLRPIPs := ovntest.MustParseIPNets("100.64.0.3/16")
		defLRPIPs := ovntest.MustParseIPNets("100.64.0.1/16")
		nodeName := "test-node"
		l3GatewayConfig := &util.L3GatewayConfig{
			Mode:           config.GatewayModeLocal,
			ChassisID:      "SYSTEM-ID",
			InterfaceID:    "INTERFACE-ID",
			MACAddress:     ovntest.MustParseMAC("11:22:33:44:55:66"),
			IPAddresses:    ovntest.MustParseIPNets("169.254.33.2/24"),
			NextHops:       ovntest.MustParseIPs("169.254.33.1"),
			NodePortEnable: true,
		}
		sctpSupport := false
		config.Gateway.DisableSNATMultipleGWs = true

		fexec := ovntest.NewFakeExec()
		err := util.SetExec(fexec)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 -- --may-exist lr-add GR_test-node -- set logical_router GR_test-node options:chassis=SYSTEM-ID external_ids:physical_ip=169.254.33.2 external_ids:physical_ips=169.254.33.2",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add " + types.OVNJoinSwitch + " jtor-GR_test-node -- set logical_switch_port jtor-GR_test-node type=router options:router-port=rtoj-GR_test-node addresses=router",
			"ovn-nbctl --timeout=15 -- --if-exists lrp-del rtoj-GR_test-node -- lrp-add GR_test-node rtoj-GR_test-node 0a:58:64:40:00:03 100.64.0.3/16",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:lb_force_snat_ip=router_ip",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:snat-ct-zone=0",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:always_learn_from_arp_request=false",
			"ovn-nbctl --timeout=15 set logical_router GR_test-node options:dynamic_neigh_routers=true",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add GR_test-node 10.128.0.0/14 100.64.0.1",
		})

		const (
			tcpLBUUID string = "1a3dfc82-2749-4931-9190-c30e7c0ecea3"
			udpLBUUID string = "6d3142fc-53e8-4ac1-88e6-46094a5a9957"
		)
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBTCP + "=GR_test-node",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBUDP + "=GR_test-node",
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBSCTP + "=GR_test-node",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBTCP + "=GR_test-node_local",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBUDP + "=GR_test-node_local",
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.GatewayLBSCTP + "=GR_test-node_local",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.WorkerLBTCP + "=test-node",
			Output: tcpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.WorkerLBUDP + "=test-node",
			"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:" + types.WorkerLBSCTP + "=test-node",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 create load_balancer external_ids:" + types.GatewayLBUDP + "=GR_test-node protocol=udp",
			Output: udpLBUUID,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 create load_balancer external_ids:" + types.GatewayLBUDP + "=GR_test-node_local protocol=udp options:skip_snat=true",
			Output: udpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 set logical_router GR_test-node load_balancer=" + tcpLBUUID + "," + udpLBUUID + "," + tcpLBUUID + "," + udpLBUUID,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 create load_balancer external_ids:" + types.WorkerLBUDP + "=test-node protocol=udp",
			Output: udpLBUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 get logical_switch test-node load_balancer",
			"ovn-nbctl --timeout=15 ls-lb-add test-node " + tcpLBUUID,
			"ovn-nbctl --timeout=15 ls-lb-add test-node " + udpLBUUID,
		})

		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --may-exist ls-add ext_test-node",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add ext_test-node INTERFACE-ID -- lsp-set-addresses INTERFACE-ID unknown -- lsp-set-type INTERFACE-ID localnet -- lsp-set-options INTERFACE-ID network_name=physnet",
			"ovn-nbctl --timeout=15 -- --if-exists lrp-del rtoe-GR_test-node -- lrp-add GR_test-node rtoe-GR_test-node 11:22:33:44:55:66 169.254.33.2/24 -- set logical_router_port rtoe-GR_test-node external-ids:gateway-physical-ip=yes",
			"ovn-nbctl --timeout=15 -- --may-exist lsp-add ext_test-node etor-GR_test-node -- set logical_switch_port etor-GR_test-node type=router options:router-port=rtoe-GR_test-node addresses=\"11:22:33:44:55:66\"",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add GR_test-node 0.0.0.0/0 169.254.33.1 rtoe-GR_test-node",
			"ovn-nbctl --timeout=15 --may-exist lr-route-add ovn_cluster_router 100.64.0.3 100.64.0.3",
			"ovn-nbctl --timeout=15 --may-exist --policy=src-ip lr-route-add ovn_cluster_router 10.130.0.0/23 100.64.0.3",
			"ovn-nbctl --timeout=15 --if-exists lr-nat-del GR_test-node snat 10.128.0.0/14",
		})

		err = gatewayInit(nodeName, clusterIPSubnets, hostSubnets, l3GatewayConfig, sctpSupport, joinLRPIPs, defLRPIPs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue())
	})
})
