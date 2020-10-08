package node

import (
	"fmt"
	"net"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"k8s.io/klog"
	utilnet "k8s.io/utils/net"
)

// bridgedGatewayNodeSetup makes the bridge's MAC address permanent (if needed), sets up
// the physical network name mappings for the bridge, and returns an ifaceID
// created from the bridge name and the node name
func bridgedGatewayNodeSetup(exec util.ExecHelper, nodeName, bridgeName, bridgeInterface, physicalNetworkName string,
	syncBridgeMAC bool) (string, net.HardwareAddr, error) {
	// A OVS bridge's mac address can change when ports are added to it.
	// We cannot let that happen, so make the bridge mac address permanent.
	macAddress, err := util.GetOVSPortMACAddress(exec, bridgeInterface)
	if err != nil {
		return "", nil, err
	}
	if syncBridgeMAC {
		var err error

		stdout, stderr, err := exec.RunOVSVsctl("set", "bridge",
			bridgeName, "other-config:hwaddr="+macAddress.String())
		if err != nil {
			return "", nil, fmt.Errorf("failed to set bridge, stdout: %q, stderr: %q, "+
				"error: %v", stdout, stderr, err)
		}
	}

	// ovn-bridge-mappings maps a physical network name to a local ovs bridge
	// that provides connectivity to that network. It is in the form of physnet1:br1,physnet2:br2.
	// Note that there may be multiple ovs bridge mappings, be sure not to override
	// the mappings for the other physical network
	stdout, stderr, err := exec.RunOVSVsctl("--if-exists", "get", "Open_vSwitch", ".",
		"external_ids:ovn-bridge-mappings")
	if err != nil {
		return "", nil, fmt.Errorf("failed to get ovn-bridge-mappings stderr:%s (%v)", stderr, err)
	}
	// skip the existing mapping setting for the specified physicalNetworkName
	mapString := ""
	bridgeMappings := strings.Split(stdout, ",")
	for _, bridgeMapping := range bridgeMappings {
		m := strings.Split(bridgeMapping, ":")
		if network := m[0]; network != physicalNetworkName {
			if len(mapString) != 0 {
				mapString += ","
			}
			mapString += bridgeMapping
		}
	}
	if len(mapString) != 0 {
		mapString += ","
	}
	mapString += physicalNetworkName + ":" + bridgeName

	_, stderr, err = exec.RunOVSVsctl("set", "Open_vSwitch", ".",
		fmt.Sprintf("external_ids:ovn-bridge-mappings=%s", mapString))
	if err != nil {
		return "", nil, fmt.Errorf("failed to set ovn-bridge-mappings for ovs bridge %s"+
			", stderr:%s (%v)", bridgeName, stderr, err)
	}

	ifaceID := bridgeName + "_" + nodeName
	return ifaceID, macAddress, nil
}

// getNetworkInterfaceIPAddresses returns the IP addresses for the network interface 'iface'.
func getNetworkInterfaceIPAddresses(iface string) ([]*net.IPNet, error) {
	allIPs, err := util.GetNetworkInterfaceIPs(iface)
	if err != nil {
		return nil, fmt.Errorf("could not find IP addresses: %v", err)
	}

	var ips []*net.IPNet
	var foundIPv4 bool
	var foundIPv6 bool
	for _, ip := range allIPs {
		if utilnet.IsIPv6CIDR(ip) {
			if config.IPv6Mode && !foundIPv6 {
				ips = append(ips, ip)
				foundIPv6 = true
			}
		} else if config.IPv4Mode && !foundIPv4 {
			ips = append(ips, ip)
			foundIPv4 = true
		}
	}
	if config.IPv4Mode && !foundIPv4 {
		return nil, fmt.Errorf("failed to find IPv4 address on interface %s", iface)
	} else if config.IPv6Mode && !foundIPv6 {
		return nil, fmt.Errorf("failed to find IPv6 address on interface %s", iface)
	}
	return ips, nil
}

func getGatewayNextHops() ([]net.IP, string, error) {
	var gatewayNextHops []net.IP
	var needIPv4NextHop bool
	var needIPv6NextHop bool

	if config.IPv4Mode {
		needIPv4NextHop = true
	}
	if config.IPv6Mode {
		needIPv6NextHop = true
	}

	// FIXME DUAL-STACK: config.Gateway.NextHop should be a slice of nexthops
	if config.Gateway.NextHop != "" {
		// Parse NextHop to make sure it is valid before using. Return error if not valid.
		nextHop := net.ParseIP(config.Gateway.NextHop)
		if nextHop == nil {
			return nil, "", fmt.Errorf("failed to parse configured next-hop: %s", config.Gateway.NextHop)
		}
		if config.IPv4Mode && !utilnet.IsIPv6(nextHop) {
			gatewayNextHops = append(gatewayNextHops, nextHop)
			needIPv4NextHop = false
		}
		if config.IPv6Mode && utilnet.IsIPv6(nextHop) {
			gatewayNextHops = append(gatewayNextHops, nextHop)
			needIPv6NextHop = false
		}
	}
	gatewayIntf := config.Gateway.Interface
	if needIPv4NextHop || needIPv6NextHop || gatewayIntf == "" {
		defaultGatewayIntf, defaultGatewayNextHops, err := getDefaultGatewayInterfaceDetails()
		if err != nil {
			return nil, "", err
		}
		if needIPv4NextHop || needIPv6NextHop {
			for _, defaultGatewayNextHop := range defaultGatewayNextHops {
				if needIPv4NextHop && !utilnet.IsIPv6(defaultGatewayNextHop) {
					gatewayNextHops = append(gatewayNextHops, defaultGatewayNextHop)
					needIPv4NextHop = false
				} else if needIPv6NextHop && utilnet.IsIPv6(defaultGatewayNextHop) {
					gatewayNextHops = append(gatewayNextHops, defaultGatewayNextHop)
					needIPv6NextHop = false
				}
			}
			if needIPv4NextHop || needIPv6NextHop {
				return nil, "", fmt.Errorf("failed to get next-hop: IPv4=%v IPv6=%v", needIPv4NextHop, needIPv6NextHop)
			}
		}
		if gatewayIntf == "" {
			gatewayIntf = defaultGatewayIntf
		}
	}
	return gatewayNextHops, gatewayIntf, nil
}

func (n *OvnNode) initGateway(subnets []*net.IPNet, nodeAnnotator kube.Annotator,
	waiter *startupWaiter) error {

	if config.Gateway.NodeportEnable {
		initLoadBalancerHealthChecker(n.name, n.watchFactory)
		initPortClaimWatcher(n.recorder, n.watchFactory)
	}

	gatewayNextHops, gatewayIntf, err := getGatewayNextHops()
	if err != nil {
		return err
	}

	v4IfAddr, v6IfAddr, err := getDefaultIfAddr(gatewayIntf)
	if err == nil {
		if err := util.SetNodePrimaryIfAddr(nodeAnnotator, v4IfAddr, v6IfAddr); err != nil {
			klog.Errorf("Unable to set primary IP net label on node, err: %v", err)
		}
	}

	var prFn postWaitFunc
	switch config.Gateway.Mode {
	case config.GatewayModeLocal:
		prFn, err = n.initSharedGateway(subnets, gatewayNextHops, gatewayIntf, nodeAnnotator)
	case config.GatewayModeShared:
		prFn, err = n.initSharedGateway(subnets, gatewayNextHops, gatewayIntf, nodeAnnotator)
	case config.GatewayModeDisabled:
		err = util.SetL3GatewayConfig(nodeAnnotator, &util.L3GatewayConfig{
			Mode: config.GatewayModeDisabled,
		})
	}
	if err != nil {
		return err
	}

	// Wait for gateway resources to be created by the master if DisableSNATMultipleGWs is not set,
	// as that option does not add default SNAT rules on the GR and the gatewayReady function checks
	// those default NAT rules are present
	if !config.Gateway.DisableSNATMultipleGWs && config.Gateway.Mode != config.GatewayModeLocal {
		waiter.AddWait(n.gatewayReady, prFn)
	} else {
		waiter.AddWait(func() (bool, error) { return true, nil }, prFn)
	}
	return nil
}

// CleanupClusterNode cleans up OVS resources on the k8s node on ovnkube-node daemonset deletion.
// This is going to be a best effort cleanup.
func CleanupClusterNode(exec util.ExecHelper, name string) error {
	var err error

	klog.V(5).Infof("Cleaning up gateway resources on node: %q", name)
	if config.Gateway.Mode == config.GatewayModeLocal || config.Gateway.Mode == config.GatewayModeShared {
		err = cleanupLocalnetGateway(exec, util.LocalNetworkName)
		if err != nil {
			klog.Errorf("Failed to cleanup Localnet Gateway, error: %v", err)
		}
		err = cleanupSharedGateway(exec)
	}
	if err != nil {
		klog.Errorf("Failed to cleanup Gateway, error: %v", err)
	}

	stdout, stderr, err := exec.RunOVSVsctl("--", "--if-exists", "remove", "Open_vSwitch", ".", "external_ids",
		"ovn-bridge-mappings")
	if err != nil {
		klog.Errorf("Failed to delete ovn-bridge-mappings, stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
	}

	// Delete iptable rules for management port
	DelMgtPortIptRules()

	return nil
}

// gatewayReady will check to see if we have successfully added SNAT OpenFlow rules in the L3Gateway Routers
func (n *OvnNode) gatewayReady() (bool, error) {
	// OpenFlow table 41 performs SNATing of packets that are heading to physical network from
	// logical network.
	for _, clusterSubnet := range config.Default.ClusterSubnets {
		var cidr, match string
		cidr = clusterSubnet.CIDR.String()
		if strings.Contains(cidr, ":") {
			match = "ipv6,ipv6_src=" + cidr
		} else {
			match = "ip,nw_src=" + cidr
		}
		stdout, _, err := n.exec.RunOVSOfctl("--no-stats", "--no-names", "dump-flows", "br-int",
			"table=41,"+match)
		if err != nil {
			return false, nil
		}
		if !strings.Contains(stdout, cidr) {
			return false, nil
		}
	}
	return true, nil
}
