package ovn

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

// gatewayInit creates a gateway router for the local chassis.
func gatewayInit(nodeName string, clusterIPSubnet []*net.IPNet, hostSubnets []*net.IPNet,
	l3GatewayConfig *util.L3GatewayConfig, sctpSupport bool, gwLRPIfAddrs, drLRPIfAddrs []*net.IPNet) error {

	gwLRPIPs := make([]net.IP, 0)
	for _, gwLRPIfAddr := range gwLRPIfAddrs {
		gwLRPIPs = append(gwLRPIPs, gwLRPIfAddr.IP)
	}

	// Create a gateway router.
	gatewayRouter := types.GWRouterPrefix + nodeName
	physicalIPs := make([]string, len(l3GatewayConfig.IPAddresses))
	for i, ip := range l3GatewayConfig.IPAddresses {
		physicalIPs[i] = ip.IP.String()
	}
	stdout, stderr, err := util.RunOVNNbctl("--", "--may-exist", "lr-add",
		gatewayRouter, "--", "set", "logical_router", gatewayRouter,
		"options:chassis="+l3GatewayConfig.ChassisID,
		"external_ids:physical_ip="+physicalIPs[0],
		"external_ids:physical_ips="+strings.Join(physicalIPs, ","))
	if err != nil {
		return fmt.Errorf("failed to create logical router %v, stdout: %q, "+
			"stderr: %q, error: %v", gatewayRouter, stdout, stderr, err)
	}

	gwSwitchPort := types.JoinSwitchToGWRouterPrefix + gatewayRouter
	gwRouterPort := types.GWRouterToJoinSwitchPrefix + gatewayRouter

	stdout, stderr, err = util.RunOVNNbctl(
		"--", "--may-exist", "lsp-add", types.OVNJoinSwitch, gwSwitchPort,
		"--", "set", "logical_switch_port", gwSwitchPort, "type=router", "options:router-port="+gwRouterPort,
		"addresses=router")
	if err != nil {
		return fmt.Errorf("failed to add port %q to logical switch %q, "+
			"stdout: %q, stderr: %q, error: %v", gwSwitchPort, types.OVNJoinSwitch, stdout, stderr, err)
	}

	gwLRPMAC := util.IPAddrToHWAddr(gwLRPIPs[0])
	args := []string{
		"--", "--if-exists", "lrp-del", gwRouterPort,
		"--", "lrp-add", gatewayRouter, gwRouterPort, gwLRPMAC.String(),
	}
	for _, gwLRPIfAddr := range gwLRPIfAddrs {
		args = append(args, gwLRPIfAddr.String())
	}
	_, stderr, err = util.RunOVNNbctl(args...)
	if err != nil {
		return fmt.Errorf("failed to add logical router port %q for gateway router %s, "+
			"stderr: %q, error: %v", gwRouterPort, gatewayRouter, stderr, err)
	}

	// Local gateway mode does not need SNAT or routes on GR because GR is only used for multiple external gws
	// without SNAT. For normal N/S traffic, ingress/egress is mp0 on node switches
	if config.Gateway.Mode != config.GatewayModeLocal {
		// When there are multiple gateway routers (which would be the likely
		// default for any sane deployment), we need to SNAT traffic
		// heading to the logical space with the Gateway router's IP so that
		// return traffic comes back to the same gateway router.
		stdout, stderr, err = util.RunOVNNbctl("set", "logical_router",
			gatewayRouter, "options:lb_force_snat_ip="+util.JoinIPs(gwLRPIPs, " "))
		if err != nil {
			return fmt.Errorf("failed to set logical router %s's lb_force_snat_ip option, "+
				"stdout: %q, stderr: %q, error: %v", gatewayRouter, stdout, stderr, err)
		}

		// Set shared gw SNAT to use host CT Zone. This will avoid potential SNAT collisions between
		// host networked pods and OVN networked pods northbound traffic
		stdout, stderr, err = util.RunOVNNbctl("set", "logical_router", gatewayRouter, "options:snat-ct-zone=0")
		if err != nil {
			return fmt.Errorf("failed to set logical router %s's SNAT CT Zone to 0, "+
				"stdout: %q, stderr: %q, error: %v", gatewayRouter, stdout, stderr, err)
		}
	}

	// To decrease the numbers of MAC_Binding entries in a large scale cluster, change the default behavior of always
	// learning the MAC/IP binding and adding a new MAC_Binding entry. Only do it when necessary.
	// See details in ovn-northd(8).
	stdout, stderr, err = util.RunOVNNbctl("set", "logical_router", gatewayRouter,
		"options:always_learn_from_arp_request=false")
	if err != nil {
		klog.Warningf("Failed to set logical router %s's always_learn_from_arp_request "+
			"stdout: %q, stderr: %q, error: %v", gatewayRouter, stdout, stderr, err)
	}

	// To avoid flow exploding problem in large scale ovn-kubernetes cluster, not to prepopulate static mappings
	// for all neighbor routers in the ARP/ND Resolution stage. See details in ovn-northd(8).
	stdout, stderr, err = util.RunOVNNbctl("set", "logical_router",
		gatewayRouter, "options:dynamic_neigh_routers=true")
	if err != nil {
		klog.Warningf("Failed to set logical router %s's dynamic_neigh_routers "+
			"stdout: %q, stderr: %q, error: %v", gatewayRouter, stdout, stderr, err)
	}

	for _, entry := range clusterIPSubnet {
		drLRPIfAddr, err := util.MatchIPNetFamily(utilnet.IsIPv6CIDR(entry), drLRPIfAddrs)
		if err != nil {
			return fmt.Errorf("failed to add a static route in GR %s with distributed "+
				"router as the nexthop: %v",
				gatewayRouter, err)
		}

		// Add a static route in GR with distributed router as the nexthop.
		stdout, stderr, err = util.RunOVNNbctl("--may-exist", "lr-route-add",
			gatewayRouter, entry.String(), drLRPIfAddr.IP.String())
		if err != nil {
			return fmt.Errorf("failed to add a static route in GR %s with distributed "+
				"router as the nexthop, stdout: %q, stderr: %q, error: %v",
				gatewayRouter, stdout, stderr, err)
		}
	}

	if l3GatewayConfig.NodePortEnable {
		// Create 3 load-balancers for north-south traffic for each gateway
		// router: UDP, TCP, SCTP
		var k8sNSLbTCP, k8sNSLbUDP, k8sNSLbSCTP string
		k8sNSLbTCP, k8sNSLbUDP, k8sNSLbSCTP, err = getGatewayLoadBalancers(gatewayRouter)
		if err != nil {
			return err
		}
		protoLBMap := map[kapi.Protocol]string{
			kapi.ProtocolTCP:  k8sNSLbTCP,
			kapi.ProtocolUDP:  k8sNSLbUDP,
			kapi.ProtocolSCTP: k8sNSLbSCTP,
		}
		enabledProtos := []kapi.Protocol{kapi.ProtocolTCP, kapi.ProtocolUDP}
		if sctpSupport {
			enabledProtos = append(enabledProtos, kapi.ProtocolSCTP)
		}
		for _, proto := range enabledProtos {
			if protoLBMap[proto] == "" {
				protoLBMap[proto], stderr, err = util.RunOVNNbctl("--", "create",
					"load_balancer",
					fmt.Sprintf("external_ids:%s_lb_gateway_router=%s", proto, gatewayRouter),
					fmt.Sprintf("protocol=%s", strings.ToLower(string(proto))))
				if err != nil {
					return fmt.Errorf("failed to create load balancer for gateway router %s for protocol %s: "+
						"stderr: %q, error: %v", gatewayRouter, proto, stderr, err)
				}
			}
		}

		// Local gateway mode does not use GR for ingress node port traffic, it uses mp0 instead
		if config.Gateway.Mode != config.GatewayModeLocal {
			// Add north-south load-balancers to the gateway router.
			lbString := fmt.Sprintf("%s,%s", protoLBMap[kapi.ProtocolTCP], protoLBMap[kapi.ProtocolUDP])
			if sctpSupport {
				lbString = lbString + "," + protoLBMap[kapi.ProtocolSCTP]
			}
			stdout, stderr, err = util.RunOVNNbctl("set", "logical_router", gatewayRouter, "load_balancer="+lbString)
			if err != nil {
				return fmt.Errorf("failed to set north-south load-balancers to the "+
					"gateway router %s, stdout: %q, stderr: %q, error: %v",
					gatewayRouter, stdout, stderr, err)
			}
		}
		// Also add north-south load-balancers to local switches for pod -> nodePort traffic
		stdout, stderr, err = util.RunOVNNbctl("get", "logical_switch", nodeName, "load_balancer")
		if err != nil {
			return fmt.Errorf("failed to get load-balancers on the node switch %s, stdout: %q, "+
				"stderr: %q, error: %v", nodeName, stdout, stderr, err)
		}
		for _, proto := range enabledProtos {
			if !strings.Contains(stdout, protoLBMap[proto]) {
				stdout, stderr, err = util.RunOVNNbctl("ls-lb-add", nodeName, protoLBMap[proto])
				if err != nil {
					return fmt.Errorf("failed to add north-south load-balancer %s to the "+
						"node switch %s, stdout: %q, stderr: %q, error: %v",
						protoLBMap[proto], nodeName, stdout, stderr, err)
				}
			}
		}
	}

	// Create the external switch for the physical interface to connect to.
	externalSwitch := types.ExternalSwitchPrefix + nodeName
	stdout, stderr, err = util.RunOVNNbctl("--may-exist", "ls-add",
		externalSwitch)
	if err != nil {
		return fmt.Errorf("failed to create logical switch %s, stdout: %q, "+
			"stderr: %q, error: %v", externalSwitch, stdout, stderr, err)
	}

	// Add external interface as a logical port to external_switch.
	// This is a learning switch port with "unknown" address. The external
	// world is accessed via this port.
	cmdArgs := []string{
		"--", "--may-exist", "lsp-add", externalSwitch, l3GatewayConfig.InterfaceID,
		"--", "lsp-set-addresses", l3GatewayConfig.InterfaceID, "unknown",
		"--", "lsp-set-type", l3GatewayConfig.InterfaceID, "localnet",
		"--", "lsp-set-options", l3GatewayConfig.InterfaceID, "network_name=" + types.PhysicalNetworkName}

	if l3GatewayConfig.VLANID != nil {
		lspArgs := []string{
			"--", "set", "logical_switch_port", l3GatewayConfig.InterfaceID,
			fmt.Sprintf("tag_request=%d", *l3GatewayConfig.VLANID),
		}
		cmdArgs = append(cmdArgs, lspArgs...)
	}

	stdout, stderr, err = util.RunOVNNbctl(cmdArgs...)
	if err != nil {
		return fmt.Errorf("failed to add logical port to switch %s, stdout: %q, "+
			"stderr: %q, error: %v", externalSwitch, stdout, stderr, err)
	}

	// Connect GR to external_switch with mac address of external interface
	// and that IP address. In the case of `local` gateway mode, whenever ovnkube-node container
	// restarts a new br-local bridge will be created with a new `nicMacAddress`. As a result,
	// direct addition of logical_router_port with --may-exists will not work since the MAC
	// has changed. So, we need to delete that port, if it exists, and it back.
	cmdArgs = []string{
		"--", "--if-exists", "lrp-del", types.GWRouterToExtSwitchPrefix + gatewayRouter,
		"--", "lrp-add", gatewayRouter, types.GWRouterToExtSwitchPrefix + gatewayRouter,
		l3GatewayConfig.MACAddress.String(),
	}
	for _, ip := range l3GatewayConfig.IPAddresses {
		cmdArgs = append(cmdArgs, ip.String())
	}
	cmdArgs = append(cmdArgs,
		"--", "set", "logical_router_port", types.GWRouterToExtSwitchPrefix+gatewayRouter,
		"external-ids:gateway-physical-ip=yes")

	stdout, stderr, err = util.RunOVNNbctl(cmdArgs...)
	if err != nil {
		return fmt.Errorf("failed to add logical port to router %s, stdout: %q, "+
			"stderr: %q, error: %v", gatewayRouter, stdout, stderr, err)
	}

	// Connect the external_switch to the router.
	stdout, stderr, err = util.RunOVNNbctl("--", "--may-exist", "lsp-add",
		externalSwitch, types.EXTSwitchToGWRouterPrefix+gatewayRouter, "--", "set",
		"logical_switch_port", types.EXTSwitchToGWRouterPrefix+gatewayRouter, "type=router",
		"options:router-port="+types.GWRouterToExtSwitchPrefix+gatewayRouter,
		"addresses="+"\""+l3GatewayConfig.MACAddress.String()+"\"")
	if err != nil {
		return fmt.Errorf("failed to add logical port to router %s, stdout: %q, "+
			"stderr: %q, error: %v", gatewayRouter, stdout, stderr, err)
	}

	// Add static routes in GR with gateway router as the default next hop.
	for _, nextHop := range l3GatewayConfig.NextHops {
		var allIPs string
		if utilnet.IsIPv6(nextHop) {
			allIPs = "::/0"
		} else {
			allIPs = "0.0.0.0/0"
		}
		stdout, stderr, err = util.RunOVNNbctl("--may-exist", "lr-route-add",
			gatewayRouter, allIPs, nextHop.String(),
			fmt.Sprintf("%s%s", types.GWRouterToExtSwitchPrefix, gatewayRouter))
		if err != nil {
			return fmt.Errorf("failed to add a static route in GR %s with physical "+
				"gateway as the default next hop, stdout: %q, "+
				"stderr: %q, error: %v", gatewayRouter, stdout, stderr, err)
		}
	}

	// We need to add a route to the Gateway router's IP, on the
	// cluster router, to ensure that the return traffic goes back
	// to the same gateway router
	//
	// This can be removed once https://bugzilla.redhat.com/show_bug.cgi?id=1891516 is fixed.
	for _, gwLRPIP := range gwLRPIPs {
		stdout, stderr, err = util.RunOVNNbctl("--may-exist", "lr-route-add",
			types.OVNClusterRouter, gwLRPIP.String(), gwLRPIP.String())
		if err != nil {
			return fmt.Errorf("failed to add the route to Gateway router's IP of %q "+
				"on the distributed router, stdout: %q, stderr: %q, error: %v",
				gwLRPIP.String(), stdout, stderr, err)
		}
	}

	// Add source IP address based routes in distributed router
	// for this gateway router.
	for _, hostSubnet := range hostSubnets {
		gwLRPIP, err := util.MatchIPFamily(utilnet.IsIPv6CIDR(hostSubnet), gwLRPIPs)
		if err != nil {
			return fmt.Errorf("failed to add source IP address based "+
				"routes in distributed router %s: %v",
				types.OVNClusterRouter, err)
		}

		if config.Gateway.Mode != config.GatewayModeLocal {
			stdout, stderr, err = util.RunOVNNbctl("--may-exist",
				"--policy=src-ip", "lr-route-add", types.OVNClusterRouter,
				hostSubnet.String(), gwLRPIP[0].String())
			if err != nil {
				return fmt.Errorf("failed to add source IP address based "+
					"routes in distributed router %s, stdout: %q, "+
					"stderr: %q, error: %v", types.OVNClusterRouter, stdout, stderr, err)
			}
		}
	}

	// if config.Gateway.DisabledSNATMultipleGWs is not set (by default it is not),
	// the NAT rules for pods not having annotations to route through either external
	// gws or pod CNFs will be added within pods.go addLogicalPort
	if !config.Gateway.DisableSNATMultipleGWs && config.Gateway.Mode != config.GatewayModeLocal {
		// Default SNAT rules.
		externalIPs := make([]net.IP, len(l3GatewayConfig.IPAddresses))
		for i, ip := range l3GatewayConfig.IPAddresses {
			externalIPs[i] = ip.IP
		}
		for _, entry := range clusterIPSubnet {
			externalIP, err := util.MatchIPFamily(utilnet.IsIPv6CIDR(entry), externalIPs)
			if err != nil {
				return fmt.Errorf("failed to create default SNAT rules for gateway router %s: %v",
					gatewayRouter, err)
			}
			// delete the existing lr-nat rule first otherwise gateway init fails
			// if the external ip has changed, but the logical ip has stayed the same
			stdout, stderr, err := util.RunOVNNbctl("--if-exists", "lr-nat-del",
				gatewayRouter, "snat", entry.String(), "--", "lr-nat-add",
				gatewayRouter, "snat", externalIP[0].String(), entry.String())
			if err != nil {
				return fmt.Errorf("failed to create default SNAT rules for gateway router %s, "+
					"stdout: %q, stderr: %q, error: %v", gatewayRouter, stdout, stderr, err)
			}
		}
	}
	return nil
}

// This DistributedGWPort guarantees to always have both IPv4 and IPv6 regardless of dual-stack
func addDistributedGWPort() error {
	masterChassisID, err := util.GetNodeChassisID()
	if err != nil {
		return fmt.Errorf("failed to get master's chassis ID error: %v", err)
	}

	// the distributed gateway port is always dual-stack and uses the IPv4 address to generate its mac
	dgpName := types.RouterToSwitchPrefix + types.NodeLocalSwitch
	dgpMac := util.IPAddrToHWAddr(net.ParseIP(types.V4NodeLocalDistributedGWPortIP)).String()
	dgpNetworkV4 := fmt.Sprintf("%s/%d", types.V4NodeLocalDistributedGWPortIP, types.V4NodeLocalNATSubnetPrefix)
	dgpNetworkV6 := fmt.Sprintf("%s/%d", types.V6NodeLocalDistributedGWPortIP, types.V6NodeLocalNATSubnetPrefix)

	// check if there is already a distributed gateway port
	dgpUUID, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "logical_router_port", "name="+dgpName)
	if err != nil {
		return fmt.Errorf("error executing find logical_router_port for distributed GW port, stderr: %q, %+v", stderr, err)
	}

	// if the port exists convert it to dual-stack if needed
	// otherwise create a new dual-stack port
	var nbctlArgs []string
	if len(dgpUUID) > 0 {
		klog.V(5).Infof("Distributed GW port already exists with uuid %s", dgpUUID)
		// update the mac address if necessary
		currentMac, _, err := util.RunOVNNbctl("--data=bare", "--no-heading",
			"get", "logical_router_port", dgpUUID, "mac")
		if err != nil {
			return err
		}
		if currentMac != dgpMac {
			_, _, err := util.RunOVNNbctl("--data=bare", "--no-heading",
				"set", "logical_router_port", dgpUUID, "mac=\""+dgpMac+"\"")
			if err != nil {
				return err
			}
			klog.V(5).Infof("Updated mac address of distributed GW port from %s to %s", currentMac, dgpMac)
		}
		// update the port networks if necessary
		currentNetworks, _, err := util.RunOVNNbctl("--data=bare", "--no-heading",
			"get", "logical_router_port", dgpUUID, "networks")
		if err != nil {
			return err
		}
		// only consider converting from single to dual-stack
		if len(strings.Split(currentNetworks, ",")) != 2 {
			_, _, err := util.RunOVNNbctl("--data=bare", "--no-heading",
				"set", "logical_router_port", dgpUUID, "networks=\""+dgpNetworkV4+"\",\""+dgpNetworkV6+"\"")
			if err != nil {
				return err
			}
			klog.V(5).Infof("Updated network addresses of distributed GW port from %s to %s,%s",
				currentNetworks, dgpNetworkV4, dgpNetworkV6)
		}
	} else {
		nbctlArgs = append(nbctlArgs, "lrp-add",
			types.OVNClusterRouter, dgpName, dgpMac, dgpNetworkV4, dgpNetworkV6,
		)
	}
	// set gateway chassis (the current master node) for distributed gateway port)
	nbctlArgs = append(nbctlArgs,
		"--", "--id=@gw", "create", "gateway_chassis", "chassis_name="+masterChassisID, "external_ids:dgp_name="+dgpName,
		fmt.Sprintf("name=%s_%s", dgpName, masterChassisID), "priority=100",
		"--", "set", "logical_router_port", dgpName, "gateway_chassis=@gw")
	stdout, stderr, err := util.RunOVNNbctl(nbctlArgs...)
	if err != nil {
		return fmt.Errorf("failed to set gateway chassis %s for distributed gateway port %s: "+
			"stdout: %q, stderr: %q, error: %v", masterChassisID, dgpName, stdout, stderr, err)
	}

	// connect the distributed gateway port to logical switch configured with localnet port
	nbctlArgs = []string{
		"--may-exist", "ls-add", types.NodeLocalSwitch,
	}
	// add localnet port to the logical switch
	lclNetPortname := "lnet-" + types.NodeLocalSwitch
	nbctlArgs = append(nbctlArgs,
		"--", "--may-exist", "lsp-add", types.NodeLocalSwitch, lclNetPortname,
		"--", "set", "logical_switch_port", lclNetPortname, "addresses=unknown", "type=localnet",
		"options:network_name="+types.LocalNetworkName)
	// connect the switch to the distributed router
	lspName := types.SwitchToRouterPrefix + types.NodeLocalSwitch
	nbctlArgs = append(nbctlArgs,
		"--", "--may-exist", "lsp-add", types.NodeLocalSwitch, lspName,
		"--", "set", "logical_switch_port", lspName, "type=router", "addresses=router",
		"options:nat-addresses=router", "options:router-port="+dgpName)
	stdout, stderr, err = util.RunOVNNbctl(nbctlArgs...)
	if err != nil {
		return fmt.Errorf("failed creating logical switch %s and its ports (%s, %s) "+
			"stdout: %q, stderr: %q, error: %v", types.NodeLocalSwitch, lclNetPortname, lspName, stdout, stderr, err)
	}
	// finally add an entry to the OVN SB MAC_Binding table, if not present, to capture the
	// MAC-IP binding of types.V4NodeLocalNATSubnetNextHop address or
	// types.V6NodeLocalNATSubnetNextHop address to its MAC. Normally, this will
	// be learnt and added by the chassis to which the distributed gateway port (DGP) is
	// bound. However, in our case we don't send any traffic out with the DGP port's IP
	// as source IP, so that binding will never be learnt and we need to seed it.
	var dnatSnatNextHopMac string
	// Only used for Error Strings
	var nodeLocalNatSubnetNextHop string
	dnatSnatNextHopMac = util.IPAddrToHWAddr(net.ParseIP(types.V4NodeLocalNATSubnetNextHop)).String()
	nodeLocalNatSubnetNextHop = types.V4NodeLocalNATSubnetNextHop + " " + types.V6NodeLocalNATSubnetNextHop
	stdout, stderr, err = util.RunOVNSbctl("--data=bare", "--no-heading", "--columns=_uuid", "find", "MAC_Binding",
		"logical_port="+dgpName, fmt.Sprintf(`mac="%s"`, dnatSnatNextHopMac))
	if err != nil {
		return fmt.Errorf("failed to check existence of MAC_Binding entry of (%s, %s) for distributed router port %s "+
			"stderr: %q, error: %v", nodeLocalNatSubnetNextHop, dnatSnatNextHopMac, dgpName, stderr, err)
	}
	if stdout != "" {
		klog.Infof("The MAC_Binding entry of (%s, %s) exists on distributed router port %s with uuid %s",
			nodeLocalNatSubnetNextHop, dnatSnatNextHopMac, dgpName, stdout)
		return nil
	}

	// Wait a bit for northd to create the cluster router's datapath in southbound
	var datapath string
	err = wait.PollImmediate(time.Second, 30*time.Second, func() (bool, error) {
		datapath, stderr, err = util.RunOVNSbctl("--data=bare", "--no-heading", "--columns=_uuid", "find", "datapath",
			"external_ids:name="+types.OVNClusterRouter)
		// Ignore errors; can't easily detect which are transient or fatal
		return datapath != "", nil
	})
	if err != nil {
		return fmt.Errorf("failed to get the datapatah UUID of %s from OVN SB "+
			"stdout: %q, stderr: %q, error: %v", types.OVNClusterRouter, datapath, stderr, err)
	}

	_, stderr, err = util.RunOVNSbctl("create", "mac_binding", "datapath="+datapath, "ip="+types.V4NodeLocalNATSubnetNextHop,
		"logical_port="+dgpName, fmt.Sprintf(`mac="%s"`, dnatSnatNextHopMac))
	if err != nil {
		return fmt.Errorf("failed to create a MAC_Binding entry of (%s, %s) for distributed router port %s "+
			"stderr: %q, error: %v", types.V4NodeLocalNATSubnetNextHop, dnatSnatNextHopMac, dgpName, stderr, err)
	}
	_, stderr, err = util.RunOVNSbctl("create", "mac_binding", "datapath="+datapath, fmt.Sprintf(`ip="%s"`, types.V6NodeLocalNATSubnetNextHop),
		"logical_port="+dgpName, fmt.Sprintf(`mac="%s"`, dnatSnatNextHopMac))
	if err != nil {
		return fmt.Errorf("failed to create a MAC_Binding entry of (%s, %s) for distributed router port %s "+
			"stderr: %q, error: %v", types.V6NodeLocalNATSubnetNextHop, dnatSnatNextHopMac, dgpName, stderr, err)
	}
	return nil
}

func addPolicyBasedRoutes(nodeName, mgmtPortIP string, hostIfAddr *net.IPNet) error {
	var l3Prefix string
	var natSubnetNextHop string
	if utilnet.IsIPv6(hostIfAddr.IP) {
		l3Prefix = "ip6"
		natSubnetNextHop = types.V6NodeLocalNATSubnetNextHop
	} else {
		l3Prefix = "ip4"
		natSubnetNextHop = types.V4NodeLocalNATSubnetNextHop
	}
	// embed nodeName as comment so that it is easier to delete these rules later on.
	// logical router policy doesn't support external_ids to stash metadata
	matchStr := fmt.Sprintf(`inport == "%s%s" && %s.dst == %s /* %s */`,
		types.RouterToSwitchPrefix, nodeName, l3Prefix, hostIfAddr.IP.String(), nodeName)
	_, stderr, err := util.RunOVNNbctl("lr-policy-add", types.OVNClusterRouter, types.NodeSubnetPolicyPriority, matchStr, "reroute",
		mgmtPortIP)
	if err != nil {
		// TODO: lr-policy-add doesn't support --may-exist, resort to this workaround for now.
		// Have raised an issue against ovn repository (https://github.com/ovn-org/ovn/issues/49)
		if !strings.Contains(stderr, "already existed") {
			return fmt.Errorf("failed to add policy route '%s' for host %q on %s "+
				"stderr: %s, error: %v", matchStr, nodeName, types.OVNClusterRouter, stderr, err)
		}
	}

	// policy to allow host -> service -> hairpin back to host
	matchStr = fmt.Sprintf("%s.src == %s && %s.dst == %s /* %s */",
		l3Prefix, mgmtPortIP, l3Prefix, hostIfAddr.IP.String(), nodeName)
	_, stderr, err = util.RunOVNNbctl("lr-policy-add", types.OVNClusterRouter, types.MGMTPortPolicyPriority, matchStr,
		"reroute", natSubnetNextHop)
	if err != nil {
		if !strings.Contains(stderr, "already existed") {
			return fmt.Errorf("failed to add policy route '%s' for host %q on %s "+
				"stderr: %s, error: %v", matchStr, nodeName, types.OVNClusterRouter, stderr, err)
		}
	}

	if config.Gateway.Mode == config.GatewayModeLocal {
		var matchDst string
		// Local gw mode needs to use DGP to do hostA -> service -> hostB
		var clusterL3Prefix string
		for _, clusterSubnet := range config.Default.ClusterSubnets {
			if utilnet.IsIPv6CIDR(clusterSubnet.CIDR) {
				clusterL3Prefix = "ip6"
			} else {
				clusterL3Prefix = "ip4"
			}
			if l3Prefix != clusterL3Prefix {
				continue
			}
			matchDst += fmt.Sprintf(" && %s.dst != %s", clusterL3Prefix, clusterSubnet.CIDR)
		}
		matchStr = fmt.Sprintf("%s.src == %s %s /* inter-%s */",
			l3Prefix, mgmtPortIP, matchDst, nodeName)
		_, stderr, err = util.RunOVNNbctl("lr-policy-add", types.OVNClusterRouter, types.InterNodePolicyPriority, matchStr,
			"reroute", natSubnetNextHop)
		if err != nil {
			if !strings.Contains(stderr, "already existed") {
				return fmt.Errorf("failed to add policy route '%s' for host %q on %s "+
					"stderr: %s, error: %v", matchStr, nodeName, types.OVNClusterRouter, stderr, err)
			}
		}
	}

	return nil
}

func (oc *Controller) addNodeLocalNatEntries(node *kapi.Node, mgmtPortMAC string, mgmtPortIfAddr *net.IPNet) error {
	var externalIP net.IP

	isIPv6 := utilnet.IsIPv6CIDR(mgmtPortIfAddr)
	annotationPresent := false
	externalIPs, err := util.ParseNodeLocalNatIPAnnotation(node)
	if err == nil {
		for _, ip := range externalIPs {
			if isIPv6 == utilnet.IsIPv6(ip) {
				klog.V(5).Infof("Found node local NAT IP %s in %v for the node %s, so reusing it", ip, externalIPs, node.Name)
				externalIP = ip
				annotationPresent = true
				break
			}
		}
	}
	if !annotationPresent {
		if isIPv6 {
			externalIP, err = oc.nodeLocalNatIPv6Allocator.AllocateNext()
		} else {
			externalIP, err = oc.nodeLocalNatIPv4Allocator.AllocateNext()
		}
		if err != nil {
			return fmt.Errorf("error allocating node local NAT IP for node %s: %v", node.Name, err)
		}
		externalIPs = append(externalIPs, externalIP)
		defer func() {
			// Release the allocation on error
			if err != nil {
				if isIPv6 {
					_ = oc.nodeLocalNatIPv6Allocator.Release(externalIP)
				} else {
					_ = oc.nodeLocalNatIPv4Allocator.Release(externalIP)
				}
			}
		}()
	}

	mgmtPortName := types.K8sPrefix + node.Name
	stdout, stderr, err := util.RunOVNNbctl("--if-exists", "lr-nat-del", types.OVNClusterRouter,
		"dnat_and_snat", externalIP.String())
	if err != nil {
		return fmt.Errorf("failed to delete dnat_and_snat entry for the management port on node %s, "+
			"stdout: %s, stderr: %q, error: %v", node.Name, stdout, stderr, err)
	}
	stdout, stderr, err = util.RunOVNNbctl("lr-nat-add", types.OVNClusterRouter, "dnat_and_snat",
		externalIP.String(), mgmtPortIfAddr.IP.String(), mgmtPortName, mgmtPortMAC)
	if err != nil {
		return fmt.Errorf("failed to add dnat_and_snat entry for the management port on node %s, "+
			"stdout: %s, stderr: %q, error: %v", node.Name, stdout, stderr, err)
	}

	if annotationPresent {
		return nil
	}
	// capture the node local NAT IP as a node annotation so that we can re-create it on onvkube-restart
	nodeAnnotations, err := util.CreateNodeLocalNatAnnotation(externalIPs)
	if err != nil {
		return fmt.Errorf("failed to marshal node %q annotation for node local NAT IP %s",
			node.Name, externalIP.String())
	}
	err = oc.mc.kube.SetAnnotationsOnNode(node, nodeAnnotations)
	if err != nil {
		return fmt.Errorf("failed to set node local NAT IP annotation on node %s: %v",
			node.Name, err)
	}
	return nil
}
