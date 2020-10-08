package ovn

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog"
	utilnet "k8s.io/utils/net"
)

// gatewayInit creates a gateway router for the local chassis.
func gatewayInit(exec util.ExecHelper, nodeName string, clusterIPSubnet []*net.IPNet,
	hostSubnets []*net.IPNet, joinSubnets []*net.IPNet,
	l3GatewayConfig *util.L3GatewayConfig, sctpSupport bool) error {
	// Create a gateway router.
	gatewayRouter := gwRouterPrefix + nodeName
	physicalIPs := make([]string, len(l3GatewayConfig.IPAddresses))
	for i, ip := range l3GatewayConfig.IPAddresses {
		physicalIPs[i] = ip.IP.String()
	}
	stdout, stderr, err := exec.RunOVNNbctl("--", "--may-exist", "lr-add",
		gatewayRouter, "--", "set", "logical_router", gatewayRouter,
		"options:chassis="+l3GatewayConfig.ChassisID,
		"external_ids:physical_ip="+physicalIPs[0],
		"external_ids:physical_ips="+strings.Join(physicalIPs, ","))
	if err != nil {
		return fmt.Errorf("failed to create logical router %v, stdout: %q, "+
			"stderr: %q, error: %v", gatewayRouter, stdout, stderr, err)
	}

	var gwLRPMAC, drLRPMAC net.HardwareAddr
	var gwLRPIPs, drLRPIPs []net.IP
	var gwLRPAddrs, drLRPAddrs []string

	for _, joinSubnet := range joinSubnets {
		prefixLen, _ := joinSubnet.Mask.Size()
		gwLRPIP := util.NextIP(joinSubnet.IP)
		gwLRPIPs = append(gwLRPIPs, gwLRPIP)
		gwLRPAddrs = append(gwLRPAddrs, fmt.Sprintf("%s/%d", gwLRPIP.String(), prefixLen))
		drLRPIP := util.NextIP(gwLRPIP)
		drLRPIPs = append(drLRPIPs, drLRPIP)
		drLRPAddrs = append(drLRPAddrs, fmt.Sprintf("%s/%d", drLRPIP.String(), prefixLen))

		if gwLRPMAC == nil || !utilnet.IsIPv6(gwLRPIP) {
			gwLRPMAC = util.IPAddrToHWAddr(gwLRPIP)
			drLRPMAC = util.IPAddrToHWAddr(drLRPIP)
		}
	}

	joinSwitch := joinSwitchPrefix + nodeName
	// create the per-node join switch
	stdout, stderr, err = exec.RunOVNNbctl("--", "--may-exist", "ls-add", joinSwitch)
	if err != nil {
		return fmt.Errorf("failed to create logical switch %q, stdout: %q, stderr: %q, error: %v",
			joinSwitch, stdout, stderr, err)
	}

	gwSwitchPort := joinSwitchToGwRouterPrefix + gatewayRouter
	gwRouterPort := gwRouterToJoinSwitchPrefix + gatewayRouter
	stdout, stderr, err = exec.RunOVNNbctl(
		"--", "--may-exist", "lsp-add", joinSwitch, gwSwitchPort,
		"--", "set", "logical_switch_port", gwSwitchPort, "type=router", "options:router-port="+gwRouterPort,
		"addresses=router")
	if err != nil {
		return fmt.Errorf("failed to add port %q to logical switch %q, "+
			"stdout: %q, stderr: %q, error: %v", gwSwitchPort, joinSwitch, stdout, stderr, err)
	}

	args := []string{
		"--", "--if-exists", "lrp-del", gwRouterPort,
		"--", "lrp-add", gatewayRouter, gwRouterPort, gwLRPMAC.String(),
	}
	args = append(args, gwLRPAddrs...)
	_, stderr, err = exec.RunOVNNbctl(args...)
	if err != nil {
		return fmt.Errorf("failed to add logical router port %q for gateway router %s, "+
			"stderr: %q, error: %v", gwRouterPort, gatewayRouter, stderr, err)
	}

	// jtod/dtoj - patch ports that connect the per-node join switch to distributed router
	drSwitchPort := joinSwitchToDistRouterPrefix + nodeName
	drRouterPort := distRouterToJoinSwitchPrefix + nodeName

	// Connect the per-node join switch to the distributed router.
	stdout, stderr, err = exec.RunOVNNbctl(
		"--", "--may-exist", "lsp-add", joinSwitch, drSwitchPort,
		"--", "set", "logical_switch_port", drSwitchPort, "type=router", "options:router-port="+drRouterPort,
		"addresses=router")
	if err != nil {
		return fmt.Errorf("failed to add port %q to logical switch %q, "+
			"stdout: %q, stderr: %q, error: %v", drSwitchPort, joinSwitch, stdout, stderr, err)
	}

	args = []string{
		"--", "--if-exists", "lrp-del", drRouterPort,
		"--", "lrp-add", ovnClusterRouter, drRouterPort, drLRPMAC.String(),
	}
	args = append(args, drLRPAddrs...)
	_, stderr, err = exec.RunOVNNbctl(args...)
	if err != nil {
		return fmt.Errorf("failed to add logical router port %q to %s, "+
			"stderr: %q, error: %v", drRouterPort, ovnClusterRouter, stderr, err)
	}

	// Local gateway mode does not need SNAT or routes on GR because GR is only used for multiple external gws
	// without SNAT. For normal N/S traffic, ingress/egress is mp0 on node switches
	if config.Gateway.Mode != config.GatewayModeLocal {
		// When there are multiple gateway routers (which would be the likely
		// default for any sane deployment), we need to SNAT traffic
		// heading to the logical space with the Gateway router's IP so that
		// return traffic comes back to the same gateway router.
		stdout, stderr, err = exec.RunOVNNbctl("set", "logical_router",
			gatewayRouter, "options:lb_force_snat_ip="+util.JoinIPs(gwLRPIPs, " "))
		if err != nil {
			return fmt.Errorf("failed to set logical router %s's lb_force_snat_ip option, "+
				"stdout: %q, stderr: %q, error: %v", gatewayRouter, stdout, stderr, err)
		}
	}

	for _, entry := range clusterIPSubnet {
		drLRPIP, err := util.MatchIPFamily(utilnet.IsIPv6CIDR(entry), drLRPIPs)
		if err != nil {
			return fmt.Errorf("failed to add a static route in GR %s with distributed "+
				"router as the nexthop: %v",
				gatewayRouter, err)
		}

		// Add a static route in GR with distributed router as the nexthop.
		stdout, stderr, err = exec.RunOVNNbctl("--may-exist", "lr-route-add",
			gatewayRouter, entry.String(), drLRPIP.String())
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
		k8sNSLbTCP, k8sNSLbUDP, k8sNSLbSCTP, err = getGatewayLoadBalancers(exec, gatewayRouter)
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
				protoLBMap[proto], stderr, err = exec.RunOVNNbctl("--", "create",
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
			stdout, stderr, err = exec.RunOVNNbctl("set", "logical_router", gatewayRouter, "load_balancer="+lbString)
			if err != nil {
				return fmt.Errorf("failed to set north-south load-balancers to the "+
					"gateway router %s, stdout: %q, stderr: %q, error: %v",
					gatewayRouter, stdout, stderr, err)
			}
		}
		// Also add north-south load-balancers to local switches for pod -> nodePort traffic
		stdout, stderr, err = exec.RunOVNNbctl("get", "logical_switch", nodeName, "load_balancer")
		if err != nil {
			return fmt.Errorf("failed to get load-balancers on the node switch %s, stdout: %q, "+
				"stderr: %q, error: %v", nodeName, stdout, stderr, err)
		}
		for _, proto := range enabledProtos {
			if !strings.Contains(stdout, protoLBMap[proto]) {
				stdout, stderr, err = exec.RunOVNNbctl("ls-lb-add", nodeName, protoLBMap[proto])
				if err != nil {
					return fmt.Errorf("failed to add north-south load-balancer %s to the "+
						"node switch %s, stdout: %q, stderr: %q, error: %v",
						protoLBMap[proto], nodeName, stdout, stderr, err)
				}
			}
		}
	}

	// Create the external switch for the physical interface to connect to.
	externalSwitch := externalSwitchPrefix + nodeName
	stdout, stderr, err = exec.RunOVNNbctl("--may-exist", "ls-add",
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
		"--", "lsp-set-options", l3GatewayConfig.InterfaceID, "network_name=" + util.PhysicalNetworkName}

	if l3GatewayConfig.VLANID != nil {
		lspArgs := []string{
			"--", "set", "logical_switch_port", l3GatewayConfig.InterfaceID,
			fmt.Sprintf("tag_request=%d", *l3GatewayConfig.VLANID),
		}
		cmdArgs = append(cmdArgs, lspArgs...)
	}

	stdout, stderr, err = exec.RunOVNNbctl(cmdArgs...)
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
		"--", "--if-exists", "lrp-del", gwRouterToExtSwitchPrefix + gatewayRouter,
		"--", "lrp-add", gatewayRouter, gwRouterToExtSwitchPrefix + gatewayRouter,
		l3GatewayConfig.MACAddress.String(),
	}
	for _, ip := range l3GatewayConfig.IPAddresses {
		cmdArgs = append(cmdArgs, ip.String())
	}
	cmdArgs = append(cmdArgs,
		"--", "set", "logical_router_port", gwRouterToExtSwitchPrefix+gatewayRouter,
		"external-ids:gateway-physical-ip=yes")

	stdout, stderr, err = exec.RunOVNNbctl(cmdArgs...)
	if err != nil {
		return fmt.Errorf("failed to add logical port to router %s, stdout: %q, "+
			"stderr: %q, error: %v", gatewayRouter, stdout, stderr, err)
	}

	// Connect the external_switch to the router.
	stdout, stderr, err = exec.RunOVNNbctl("--", "--may-exist", "lsp-add",
		externalSwitch, extSwitchToGwRouterPrefix+gatewayRouter, "--", "set",
		"logical_switch_port", extSwitchToGwRouterPrefix+gatewayRouter, "type=router",
		"options:router-port="+gwRouterToExtSwitchPrefix+gatewayRouter,
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
		stdout, stderr, err = exec.RunOVNNbctl("--may-exist", "lr-route-add",
			gatewayRouter, allIPs, nextHop.String(),
			fmt.Sprintf("rtoe-%s", gatewayRouter))
		if err != nil {
			return fmt.Errorf("failed to add a static route in GR %s with physical "+
				"gateway as the default next hop, stdout: %q, "+
				"stderr: %q, error: %v", gatewayRouter, stdout, stderr, err)
		}
	}

	// Add source IP address based routes in distributed router
	// for this gateway router.
	for _, hostSubnet := range hostSubnets {
		gwLRPIP, err := util.MatchIPFamily(utilnet.IsIPv6CIDR(hostSubnet), gwLRPIPs)
		if err != nil {
			return fmt.Errorf("failed to add source IP address based "+
				"routes in distributed router %s: %v",
				ovnClusterRouter, err)
		}

		if config.Gateway.Mode != config.GatewayModeLocal {
			stdout, stderr, err = exec.RunOVNNbctl("--may-exist",
				"--policy=src-ip", "lr-route-add", ovnClusterRouter,
				hostSubnet.String(), gwLRPIP.String())
			if err != nil {
				return fmt.Errorf("failed to add source IP address based "+
					"routes in distributed router %s, stdout: %q, "+
					"stderr: %q, error: %v", ovnClusterRouter, stdout, stderr, err)
			}
		}
	}

	// if config.Gateway.DisabledSNATMultipleGWs is not set (by default is not),
	// the NAT rules for pods not having annotations to route thru either external
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
			stdout, stderr, err := exec.RunOVNNbctl("--if-exists", "lr-nat-del",
				gatewayRouter, "snat", entry.String(), "--", "lr-nat-add",
				gatewayRouter, "snat", externalIP.String(), entry.String())
			if err != nil {
				return fmt.Errorf("failed to create default SNAT rules for gateway router %s, "+
					"stdout: %q, stderr: %q, error: %v", gatewayRouter, stdout, stderr, err)
			}
		}
	}
	return nil
}

func addDistributedGWPort(exec util.ExecHelper) error {
	masterChassisID, err := util.GetNodeChassisID(exec)
	if err != nil {
		return fmt.Errorf("failed to get master's chassis ID error: %v", err)
	}

	var dgpMac string
	var nbctlArgs []string
	// add a distributed gateway port to the distributed router
	dgpName := routerToSwitchPrefix + nodeLocalSwitch
	if config.IPv4Mode {
		dgpMac = util.IPAddrToHWAddr(net.ParseIP(util.V4NodeLocalDistributedGwPortIP)).String()
	} else {
		dgpMac = util.IPAddrToHWAddr(net.ParseIP(util.V6NodeLocalDistributedGwPortIP)).String()
	}
	nbctlArgs = append(nbctlArgs,
		"--may-exist", "lrp-add", ovnClusterRouter, dgpName, dgpMac,
	)
	if config.IPv4Mode && config.IPv6Mode {
		nbctlArgs = append(nbctlArgs,
			fmt.Sprintf("%s/%d", util.V4NodeLocalDistributedGwPortIP, util.V4NodeLocalNatSubnetPrefix),
			fmt.Sprintf("%s/%d", util.V6NodeLocalDistributedGwPortIP, util.V6NodeLocalNatSubnetPrefix),
		)
	} else if config.IPv4Mode {
		nbctlArgs = append(nbctlArgs,
			fmt.Sprintf("%s/%d", util.V4NodeLocalDistributedGwPortIP, util.V4NodeLocalNatSubnetPrefix),
		)
	} else if config.IPv6Mode {
		nbctlArgs = append(nbctlArgs,
			fmt.Sprintf("%s/%d", util.V6NodeLocalDistributedGwPortIP, util.V6NodeLocalNatSubnetPrefix),
		)
	}
	// set gateway chassis (the current master node) for distributed gateway port)
	nbctlArgs = append(nbctlArgs,
		"--", "--id=@gw", "create", "gateway_chassis", "chassis_name="+masterChassisID, "external_ids:dgp_name="+dgpName,
		fmt.Sprintf("name=%s_%s", dgpName, masterChassisID), "priority=100",
		"--", "set", "logical_router_port", dgpName, "gateway_chassis=@gw")
	stdout, stderr, err := exec.RunOVNNbctl(nbctlArgs...)
	if err != nil {
		return fmt.Errorf("failed to set gateway chassis %s for distributed gateway port %s: "+
			"stdout: %q, stderr: %q, error: %v", masterChassisID, dgpName, stdout, stderr, err)
	}

	// connect the distributed gateway port to logical switch configured with localnet port
	nbctlArgs = []string{
		"--may-exist", "ls-add", nodeLocalSwitch,
	}
	// add localnet port to the logical switch
	lclNetPortname := "lnet-" + nodeLocalSwitch
	nbctlArgs = append(nbctlArgs,
		"--", "--may-exist", "lsp-add", nodeLocalSwitch, lclNetPortname,
		"--", "set", "logical_switch_port", lclNetPortname, "addresses=unknown", "type=localnet",
		"options:network_name="+util.LocalNetworkName)
	// connect the switch to the distributed router
	lspName := switchToRouterPrefix + nodeLocalSwitch
	nbctlArgs = append(nbctlArgs,
		"--", "--may-exist", "lsp-add", nodeLocalSwitch, lspName,
		"--", "set", "logical_switch_port", lspName, "type=router", "addresses=router",
		"options:nat-addresses=router", "options:router-port="+dgpName)
	stdout, stderr, err = exec.RunOVNNbctl(nbctlArgs...)
	if err != nil {
		return fmt.Errorf("failed creating logical switch %s and its ports (%s, %s) "+
			"stdout: %q, stderr: %q, error: %v", nodeLocalSwitch, lclNetPortname, lspName, stdout, stderr, err)
	}
	// finally add an entry to the OVN SB MAC_Binding table, if not present, to capture the
	// MAC-IP binding of util.V4NodeLocalNatSubnetNextHop address or
	// util.V6NodeLocalNatSubnetNextHop address to its MAC. Normally, this will
	// be learnt and added by the chassis to which the distributed gateway port (DGP) is
	// bound. However, in our case we don't send any traffic out with the DGP port's IP
	// as source IP, so that binding will never be learnt and we need to seed it.
	var dnatSnatNextHopMac string
	// Only used for Error Strings
	var nodeLocalNatSubnetNextHop string
	if config.IPv4Mode && config.IPv6Mode {
		dnatSnatNextHopMac = util.IPAddrToHWAddr(net.ParseIP(util.V4NodeLocalNatSubnetNextHop)).String()
		nodeLocalNatSubnetNextHop = util.V4NodeLocalNatSubnetNextHop + " " + util.V6NodeLocalNatSubnetNextHop
	} else if config.IPv4Mode {
		dnatSnatNextHopMac = util.IPAddrToHWAddr(net.ParseIP(util.V4NodeLocalNatSubnetNextHop)).String()
		nodeLocalNatSubnetNextHop = util.V4NodeLocalNatSubnetNextHop
	} else if config.IPv6Mode {
		dnatSnatNextHopMac = util.IPAddrToHWAddr(net.ParseIP(util.V6NodeLocalNatSubnetNextHop)).String()
		nodeLocalNatSubnetNextHop = util.V6NodeLocalNatSubnetNextHop
	}
	stdout, stderr, err = exec.RunOVNSbctl("--data=bare", "--no-heading", "--columns=_uuid", "find", "MAC_Binding",
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
		datapath, stderr, err = exec.RunOVNSbctl("--data=bare", "--no-heading", "--columns=_uuid", "find", "datapath",
			"external_ids:name="+ovnClusterRouter)
		// Ignore errors; can't easily detect which are transient or fatal
		return datapath != "", nil
	})
	if err != nil {
		return fmt.Errorf("failed to get the datapatah UUID of %s from OVN SB "+
			"stdout: %q, stderr: %q, error: %v", ovnClusterRouter, datapath, stderr, err)
	}

	if config.IPv4Mode {
		_, stderr, err = exec.RunOVNSbctl("create", "mac_binding", "datapath="+datapath, "ip="+util.V4NodeLocalNatSubnetNextHop,
			"logical_port="+dgpName, fmt.Sprintf(`mac="%s"`, dnatSnatNextHopMac))
		if err != nil {
			return fmt.Errorf("failed to create a MAC_Binding entry of (%s, %s) for distributed router port %s "+
				"stderr: %q, error: %v", util.V4NodeLocalNatSubnetNextHop, dnatSnatNextHopMac, dgpName, stderr, err)
		}
	}
	if config.IPv6Mode {
		_, stderr, err = exec.RunOVNSbctl("create", "mac_binding", "datapath="+datapath, fmt.Sprintf(`ip="%s"`, util.V6NodeLocalNatSubnetNextHop),
			"logical_port="+dgpName, fmt.Sprintf(`mac="%s"`, dnatSnatNextHopMac))
		if err != nil {
			return fmt.Errorf("failed to create a MAC_Binding entry of (%s, %s) for distributed router port %s "+
				"stderr: %q, error: %v", util.V6NodeLocalNatSubnetNextHop, dnatSnatNextHopMac, dgpName, stderr, err)
		}
	}
	return nil
}

func addPolicyBasedRoutes(exec util.ExecHelper, nodeName, mgmtPortIP string, hostIfAddr *net.IPNet) error {
	var l3Prefix string
	var natSubnetNextHop string
	if utilnet.IsIPv6(hostIfAddr.IP) {
		l3Prefix = "ip6"
		natSubnetNextHop = util.V6NodeLocalNatSubnetNextHop
	} else {
		l3Prefix = "ip4"
		natSubnetNextHop = util.V4NodeLocalNatSubnetNextHop
	}
	// embed nodeName as comment so that it is easier to delete these rules later on.
	// logical router policy doesn't support external_ids to stash metadata
	matchStr := fmt.Sprintf(`inport == "rtos-%s" && %s.dst == %s /* %s */`,
		nodeName, l3Prefix, hostIfAddr.IP.String(), nodeName)
	_, stderr, err := exec.RunOVNNbctl("lr-policy-add", ovnClusterRouter, nodeSubnetPolicyPriority, matchStr, "reroute",
		mgmtPortIP)
	if err != nil {
		// TODO: lr-policy-add doesn't support --may-exist, resort to this workaround for now.
		// Have raised an issue against ovn repository (https://github.com/ovn-org/ovn/issues/49)
		if !strings.Contains(stderr, "already existed") {
			return fmt.Errorf("failed to add policy route '%s' for host %q on %s "+
				"stderr: %s, error: %v", matchStr, nodeName, ovnClusterRouter, stderr, err)
		}
	}

	// policy to allow host -> service -> hairpin back to host
	matchStr = fmt.Sprintf("%s.src == %s && %s.dst == %s /* %s */",
		l3Prefix, mgmtPortIP, l3Prefix, hostIfAddr.IP.String(), nodeName)
	_, stderr, err = exec.RunOVNNbctl("lr-policy-add", ovnClusterRouter, mgmtPortPolicyPriority, matchStr,
		"reroute", natSubnetNextHop)
	if err != nil {
		if !strings.Contains(stderr, "already existed") {
			return fmt.Errorf("failed to add policy route '%s' for host %q on %s "+
				"stderr: %s, error: %v", matchStr, nodeName, ovnClusterRouter, stderr, err)
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
		_, stderr, err = exec.RunOVNNbctl("lr-policy-add", ovnClusterRouter, interNodePolicyPriority, matchStr,
			"reroute", natSubnetNextHop)
		if err != nil {
			if !strings.Contains(stderr, "already existed") {
				return fmt.Errorf("failed to add policy route '%s' for host %q on %s "+
					"stderr: %s, error: %v", matchStr, nodeName, ovnClusterRouter, stderr, err)
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

	mgmtPortName := util.K8sPrefix + node.Name
	stdout, stderr, err := oc.exec.RunOVNNbctl("--if-exists", "lr-nat-del", ovnClusterRouter,
		"dnat_and_snat", externalIP.String(), "--",
		"lr-nat-add", ovnClusterRouter, "dnat_and_snat",
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
	err = oc.kube.SetAnnotationsOnNode(node, nodeAnnotations)
	if err != nil {
		return fmt.Errorf("failed to set node local NAT IP annotation on node %s: %v",
			node.Name, err)
	}
	return nil
}
