package node

import (
	"fmt"
	"net"
	"os"
	"strings"

	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// bridgedGatewayNodeSetup makes the bridge's MAC address permanent (if needed), sets up
// the physical network name mappings for the bridge, and returns an ifaceID
// created from the bridge name and the node name
func bridgedGatewayNodeSetup(nodeName, bridgeName, bridgeInterface, physicalNetworkName string,
	syncBridgeMAC bool) (string, net.HardwareAddr, error) {
	// A OVS bridge's mac address can change when ports are added to it.
	// We cannot let that happen, so make the bridge mac address permanent.
	macAddress, err := util.GetOVSPortMACAddress(bridgeInterface)
	if err != nil {
		return "", nil, err
	}
	if syncBridgeMAC {
		var err error

		stdout, stderr, err := util.RunOVSVsctl("set", "bridge",
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
	stdout, stderr, err := util.RunOVSVsctl("--if-exists", "get", "Open_vSwitch", ".",
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

	_, stderr, err = util.RunOVSVsctl("set", "Open_vSwitch", ".",
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

// getSmartNICHostPrimaryIPAdresses returns the smart-nic host IP/Network based on K8s Node IP
// and Smart-NIC IP subnet overriden by config config.Gateway.RouterSubnet
func getSmartNICHostPrimaryIPAdresses(k8sNodeIP net.IP, ifAddrs []*net.IPNet) ([]*net.IPNet, error) {
	// Note(adrianc): No Dual-Stack support at this point as we rely on k8s node IP to derrive gateway information
	// for each node.
	var gwIps []*net.IPNet
	isIPv4 := utilnet.IsIPv4(k8sNodeIP)

	// override subnet mask via config
	if config.Gateway.RouterSubnet != "" {
		_, addr, err := net.ParseCIDR(config.Gateway.RouterSubnet)
		if err != nil {
			return nil, err
		}
		if utilnet.IsIPv4CIDR(addr) != isIPv4 {
			return nil, fmt.Errorf("unexpected gateway router subnet provided (%s). "+
				"does not match Node IP address format", config.Gateway.RouterSubnet)
		}
		if !addr.Contains(k8sNodeIP) {
			return nil, fmt.Errorf("unexpected gateway router subnet provided (%s). "+
				"subnet does not contain Node IP address (%s)", config.Gateway.RouterSubnet, k8sNodeIP)
		}
		addr.IP = k8sNodeIP
		gwIps = append(gwIps, addr)
	} else {
		// Assume Host and Smart-NIC share the same subnet
		// in this case just update the matching IPNet with the Host's IP address
		for _, addr := range ifAddrs {
			if utilnet.IsIPv4CIDR(addr) != isIPv4 {
				continue
			}
			// expect k8s Node IP to be contained in the given subnet
			if !addr.Contains(k8sNodeIP) {
				continue
			}
			newAddr := *addr
			newAddr.IP = k8sNodeIP
			gwIps = append(gwIps, &newAddr)
		}
		if len(gwIps) == 0 {
			return nil, fmt.Errorf("could not find subnet on Smart-NIC matching node IP %s", k8sNodeIP)
		}
	}
	return gwIps, nil
}

// getInterfaceByIP retrieves Interface that has `ip` assigned to it
func getInterfaceByIP(ip net.IP) (string, error) {
	links, err := util.GetNetLinkOps().LinkList()
	if err != nil {
		return "", fmt.Errorf("failed to list network devices in the system. %v", err)
	}

	for _, link := range links {
		ips, err := util.GetNetworkInterfaceIPs(link.Attrs().Name)
		if err != nil {
			return "", err
		}
		for _, netdevIp := range ips {
			if netdevIp.Contains(ip) {
				return link.Attrs().Name, nil
			}
		}
	}
	return "", fmt.Errorf("failed to find network interface with IP: %s", ip)
}

// configureSvcRouteViaInterface routes svc traffic through the provided interface
func configureSvcRouteViaInterface(iface string, gwIPs []net.IP) error {
	link, err := util.LinkSetUp(iface)
	if err != nil {
		return fmt.Errorf("unable to get link for %s, error: %v", iface, err)
	}

	for _, subnet := range config.Kubernetes.ServiceCIDRs {
		gwIP, err := util.MatchIPFamily(utilnet.IsIPv6CIDR(subnet), gwIPs)
		if err != nil {
			return fmt.Errorf("unable to find gateway IP for subnet: %v, found IPs: %v", subnet, gwIPs)
		}
		err = util.LinkRoutesAdd(link, gwIP[0], []*net.IPNet{subnet})
		if err != nil && !os.IsExist(err) {
			return fmt.Errorf("unable to add route for service via %s, error: %v", iface, err)
		}
	}
	return nil
}

func (n *OvnNode) initGateway(subnets []*net.IPNet, nodeAnnotator kube.Annotator,
	waiter *startupWaiter, managementPortConfig *managementPortConfig, nodeIP net.IP) error {
	klog.Info("Initializing Gateway Functionality")
	var err error
	var ifAddrs []*net.IPNet

	var loadBalancerHealthChecker *loadBalancerHealthChecker
	var portClaimWatcher *portClaimWatcher

	if config.Gateway.NodeportEnable && config.OvnKubeNode.Mode == types.NodeModeFull {
		loadBalancerHealthChecker = newLoadBalancerHealthChecker(n.name)
		portClaimWatcher, err = newPortClaimWatcher(n.recorder)
		if err != nil {
			return err
		}
	}

	gatewayNextHops, gatewayIntf, err := getGatewayNextHops()
	if err != nil {
		return err
	}

	ifAddrs, err = getNetworkInterfaceIPAddresses(gatewayIntf)
	if err != nil {
		return err
	}

	// For smart-NIC need to use the host IP addr which currently is assumed to be K8s Node cluster
	// internal IP address.
	if config.OvnKubeNode.Mode == types.NodeModeSmartNIC {
		ifAddrs, err = getSmartNICHostPrimaryIPAdresses(nodeIP, ifAddrs)
		if err != nil {
			return err
		}
	}

	v4IfAddr, _ := util.MatchIPNetFamily(false, ifAddrs)
	v6IfAddr, _ := util.MatchIPNetFamily(true, ifAddrs)

	if err := util.SetNodePrimaryIfAddr(nodeAnnotator, v4IfAddr, v6IfAddr); err != nil {
		klog.Errorf("Unable to set primary IP net label on node, err: %v", err)
	}

	var gw *gateway
	switch config.Gateway.Mode {
	case config.GatewayModeLocal:
		klog.Info("Preparing Local Gateway")
		gw, err = newLocalGateway(n.name, subnets, gatewayNextHops, gatewayIntf, nodeAnnotator, n.recorder, managementPortConfig)
	case config.GatewayModeShared:
		klog.Info("Preparing Shared Gateway")
		gw, err = newSharedGateway(n.name, subnets, gatewayNextHops, gatewayIntf, ifAddrs, nodeAnnotator)
	case config.GatewayModeDisabled:
		var chassisID string
		klog.Info("Gateway Mode is disabled")
		gw = &gateway{
			initFunc:  func() error { return nil },
			readyFunc: func() (bool, error) { return true, nil },
		}
		chassisID, err = util.GetNodeChassisID()
		if err != nil {
			return err
		}
		err = util.SetL3GatewayConfig(nodeAnnotator, &util.L3GatewayConfig{
			Mode:      config.GatewayModeDisabled,
			ChassisID: chassisID,
		})
	}
	if err != nil {
		return err
	}
	// a golang interface has two values <type, value>. an interface is nil if both type and
	// value is nil. so, you cannot directly set the value to an interface and later check if
	// value was nil by comparing the interface to nil. this is because if the value is `nil`,
	// then the interface will still hold the type of the value being set.

	if config.Gateway.Mode == config.GatewayModeShared && config.OvnKubeNode.Mode == types.NodeModeFull {
		gw.nodeIPManager = newAddressManager(nodeAnnotator, managementPortConfig)
	}

	if loadBalancerHealthChecker != nil {
		gw.loadBalancerHealthChecker = loadBalancerHealthChecker
	}
	if portClaimWatcher != nil {
		gw.portClaimWatcher = portClaimWatcher
	}
	initGw := func() error {
		return gw.Init(n.watchFactory)
	}

	waiter.AddWait(gw.readyFunc, initGw)
	n.gateway = gw
	return err
}

func (n *OvnNode) initGatewaySmartNicHost(nodeIP net.IP) error {
	// A smart NIC host gateway is complementary to the shared gateway running
	// on the Smart-NIC embedded CPU. it performs some initializations and
	// watch on services for iptable rule updates and run a loadBalancerHealth checker
	// Note: all K8s Node related annotations are handled from Smart-NIC.
	klog.Info("Initializing Shared Gateway Functionality on Smart-NIC host")
	var err error

	if config.OvnKubeNode.Mode != types.NodeModeSmartNICHost || config.Gateway.Mode != config.GatewayModeShared {
		return fmt.Errorf("smart-nic gateway is only supported for shared gateway mode running on the" +
			"smart-nic host")
	}

	// Force gateway interface to be the interface associated with nodeIP
	gwIntf, err := getInterfaceByIP(nodeIP)
	if err != nil {
		return err
	}
	config.Gateway.Interface = gwIntf

	gatewayNextHops, gatewayIntf, err := getGatewayNextHops()
	if err != nil {
		return err
	}

	err = addMasqueradeRoutes(gatewayIntf, gatewayNextHops)
	if err != nil {
		return err
	}

	err = configureSvcRouteViaInterface(gatewayIntf, gatewayNextHops)
	if err != nil {
		return err
	}

	gw := &gateway{
		initFunc:  func() error { return nil },
		readyFunc: func() (bool, error) { return true, nil },
	}

	// TODO(adrianc): revisite if support for nodeIPManager is needed.

	if config.Gateway.NodeportEnable {
		if err := initSharedGatewayIPTables(); err != nil {
			return err
		}
		gw.nodePortWatcher = newNodePortWatcherIptables()
		gw.loadBalancerHealthChecker = newLoadBalancerHealthChecker(n.name)
		portClaimWatcher, err := newPortClaimWatcher(n.recorder)
		if err != nil {
			return err
		}
		gw.portClaimWatcher = portClaimWatcher
	}

	err = gw.Init(n.watchFactory)
	n.gateway = gw
	return err
}

// CleanupClusterNode cleans up OVS resources on the k8s node on ovnkube-node daemonset deletion.
// This is going to be a best effort cleanup.
func CleanupClusterNode(name string) error {
	var err error

	klog.V(5).Infof("Cleaning up gateway resources on node: %q", name)
	if config.Gateway.Mode == config.GatewayModeLocal || config.Gateway.Mode == config.GatewayModeShared {
		err = cleanupLocalnetGateway(types.LocalNetworkName)
		if err != nil {
			klog.Errorf("Failed to cleanup Localnet Gateway, error: %v", err)
		}
		err = cleanupSharedGateway()
	}
	if err != nil {
		klog.Errorf("Failed to cleanup Gateway, error: %v", err)
	}

	stdout, stderr, err := util.RunOVSVsctl("--", "--if-exists", "remove", "Open_vSwitch", ".", "external_ids",
		"ovn-bridge-mappings")
	if err != nil {
		klog.Errorf("Failed to delete ovn-bridge-mappings, stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
	}

	// Delete iptable rules for management port
	DelMgtPortIptRules()

	return nil
}
