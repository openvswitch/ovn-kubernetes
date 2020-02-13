package util

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
)

const (
	// PhysicalNetworkName is the name that maps to an OVS bridge that provides
	// access to physical/external network
	PhysicalNetworkName = "physnet"
	// OvnClusterRouter is the name of the distributed router
	OvnClusterRouter = "ovn_cluster_router"
)

// GetK8sClusterRouter returns back the OVN distributed router. This is meant to be used on the
// master alone. If the worker nodes need to know about distributed cluster router (which they
// don't need to), then they need to use ovn-nbctl call and shouldn't make any assumption on
// how the distributed router is named.
func GetK8sClusterRouter() string {
	return OvnClusterRouter
}

// GetDefaultGatewayRouterIP returns the first gateway logical router name
// and IP address as listed in the OVN database
func GetDefaultGatewayRouterIP() (string, net.IP, error) {
	stdout, stderr, err := RunOVNNbctl("--data=bare", "--format=table",
		"--no-heading", "--columns=name,options", "find", "logical_router",
		"options:lb_force_snat_ip!=-")
	if err != nil {
		return "", nil, fmt.Errorf("failed to get logical routers, stdout: %q, "+
			"stderr: %q, err: %v", stdout, stderr, err)
	}
	// Convert \r\n to \n to support Windows line endings
	stdout = strings.Replace(strings.TrimSpace(stdout), "\r\n", "\n", -1)
	gatewayRouters := strings.Split(stdout, "\n")
	if len(gatewayRouters) == 0 {
		return "", nil, fmt.Errorf("failed to get default gateway router (no routers found)")
	}

	type gwRouter struct {
		name string
		ip   net.IP
	}

	// Get the list of all gateway router names and IPs
	routers := make([]gwRouter, 0, len(gatewayRouters))
	for _, gwRouterLine := range gatewayRouters {
		parts := strings.Fields(gwRouterLine)
		for _, p := range parts {
			const forceTag string = "lb_force_snat_ip="
			if strings.HasPrefix(p, forceTag) {
				ipStr := p[len(forceTag):]
				if ip := net.ParseIP(ipStr); ip != nil {
					routers = append(routers, gwRouter{parts[0], ip})
				} else {
					logrus.Warnf("failed to parse gateway router %q IP %q", parts[0], ipStr)
				}
			}
		}
	}
	if len(routers) == 0 {
		return "", nil, fmt.Errorf("failed to parse gateway routers")
	}

	// Stably sort the list
	sort.Slice(routers, func(i, j int) bool {
		return bytes.Compare(routers[i].ip, routers[j].ip) < 0
	})
	return routers[0].name, routers[0].ip, nil
}

func ensureGatewayPortAddress(portName string) (net.HardwareAddr, *net.IPNet, error) {
	mac, ip, _ := GetPortAddresses(portName)
	if mac == nil || ip == nil {
		// Create the gateway switch port in 'join' if it doesn't exist yet
		stdout, stderr, err := RunOVNNbctl("--wait=sb",
			"--may-exist", "lsp-add", "join", portName,
			"--", "--if-exists", "clear", "logical_switch_port", portName, "dynamic_addresses",
			"--", "lsp-set-addresses", portName, "dynamic")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to add logical switch "+
				"port %s, stdout: %q, stderr: %q, error: %v",
				portName, stdout, stderr, err)
		}
		// Should have an address already since we waited for the SB above
		mac, ip, err = GetPortAddresses(portName)
		if err != nil {
			return nil, nil, fmt.Errorf("error while waiting for addresses "+
				"for gateway switch port %q: %v", portName, err)
		}
		if mac == nil || ip == nil {
			return nil, nil, fmt.Errorf("empty addresses for gateway "+
				"switch port %q", portName)
		}
	}

	// Grab the 'join' switch prefix length to add to our gateway router's IP
	cidrStr, stderr, err := RunOVNNbctl("--if-exists", "get",
		"logical_switch", "join", config.OtherConfigSubnet())
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get 'join' switch external-ids: "+
			"stderr: %q, %v", stderr, err)
	}
	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse 'join' switch subnet %q: %v",
			cidrStr, err)
	}
	if !cidr.Contains(ip) {
		return nil, nil, fmt.Errorf("gateway router port %q IP %q not "+
			"contained in 'join' switch subnet %q", portName, ip, cidrStr)
	}
	cidr.IP = ip

	return mac, cidr, nil
}

// getGatewayLoadBalancers find TCP UDP load-balancers from gateway router.
func getGatewayLoadBalancers(gatewayRouter string) (string, string, error) {
	lbTCP, stderr, err := RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "load_balancer",
		"external_ids:TCP_lb_gateway_router="+gatewayRouter)
	if err != nil {
		return "", "", fmt.Errorf("Failed to get gateway router %q TCP "+
			"loadbalancer, stderr: %q, error: %v", gatewayRouter, stderr, err)
	}

	lbUDP, stderr, err := RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "load_balancer",
		"external_ids:UDP_lb_gateway_router="+gatewayRouter)
	if err != nil {
		return "", "", fmt.Errorf("Failed to get gateway router %q UDP "+
			"loadbalancer, stderr: %q, error: %v", gatewayRouter, stderr, err)
	}

	return lbTCP, lbUDP, nil
}

// GatewayInit creates a gateway router for the local chassis.
func GatewayInit(clusterIPSubnet []string, systemID, nodeName, ifaceID, nicIP, nicMacAddress,
	defaultGW string, rampoutIPSubnet string, nodePortEnable bool, lspArgs []string) error {

	ip, physicalIPNet, err := net.ParseCIDR(nicIP)
	if err != nil {
		return fmt.Errorf("error parsing %s (%v)", nicIP, err)
	}
	n, _ := physicalIPNet.Mask.Size()
	physicalIPMask := fmt.Sprintf("%s/%d", ip.String(), n)
	physicalIP := ip.String()

	if defaultGW != "" {
		defaultgwByte := net.ParseIP(defaultGW)
		defaultGW = defaultgwByte.String()
	}

	k8sClusterRouter := GetK8sClusterRouter()
	// Create a gateway router.
	gatewayRouter := "GR_" + nodeName
	stdout, stderr, err := RunOVNNbctl("--", "--may-exist", "lr-add",
		gatewayRouter, "--", "set", "logical_router", gatewayRouter,
		"options:chassis="+systemID, "external_ids:physical_ip="+physicalIP)
	if err != nil {
		return fmt.Errorf("Failed to create logical router %v, stdout: %q, "+
			"stderr: %q, error: %v", gatewayRouter, stdout, stderr, err)
	}

	gwSwitchPort := "jtor-" + gatewayRouter
	gwRouterPort := "rtoj-" + gatewayRouter
	routerMac, routerCIDR, err := ensureGatewayPortAddress(gwSwitchPort)
	if err != nil {
		return err
	}

	// Must move the IP from the LSP to the LRP and set the LSP addresses
	// to 'router' in one transaction, because IPAM doesn't consider LSPs that
	// are attached to routers when checking reserved addresses.
	stdout, stderr, err = RunOVNNbctl(
		"--", "--may-exist", "lrp-add", gatewayRouter, gwRouterPort, routerMac.String(), routerCIDR.String(),
		"--", "set", "logical_switch_port", gwSwitchPort, "type=router",
		"options:router-port="+gwRouterPort, "addresses=router")
	if err != nil {
		return fmt.Errorf("failed to add logical port to router, stdout: %q, "+
			"stderr: %q, error: %v", stdout, stderr, err)
	}

	// When there are multiple gateway routers (which would be the likely
	// default for any sane deployment), we need to SNAT traffic
	// heading to the logical space with the Gateway router's IP so that
	// return traffic comes back to the same gateway router.
	stdout, stderr, err = RunOVNNbctl("set", "logical_router",
		gatewayRouter, "options:lb_force_snat_ip="+routerCIDR.IP.String())
	if err != nil {
		return fmt.Errorf("Failed to set logical router, stdout: %q, "+
			"stderr: %q, error: %v", stdout, stderr, err)
	}

	for _, entry := range clusterIPSubnet {
		// Add a static route in GR with distributed router as the nexthop.
		var joinAddr string
		if config.IPv6Mode {
			joinAddr = "fd98::1"
		} else {
			joinAddr = "100.64.0.1"
		}
		stdout, stderr, err = RunOVNNbctl("--may-exist", "lr-route-add",
			gatewayRouter, entry, joinAddr)
		if err != nil {
			return fmt.Errorf("Failed to add a static route in GR with distributed "+
				"router as the nexthop, stdout: %q, stderr: %q, error: %v",
				stdout, stderr, err)
		}
	}

	if nodePortEnable {
		// Create 2 load-balancers for north-south traffic for each gateway
		// router.  One handles UDP and another handles TCP.
		var k8sNSLbTCP, k8sNSLbUDP string
		k8sNSLbTCP, k8sNSLbUDP, err = getGatewayLoadBalancers(gatewayRouter)
		if err != nil {
			return err
		}
		if k8sNSLbTCP == "" {
			k8sNSLbTCP, stderr, err = RunOVNNbctl("--", "create",
				"load_balancer",
				"external_ids:TCP_lb_gateway_router="+gatewayRouter,
				"protocol=tcp")
			if err != nil {
				return fmt.Errorf("Failed to create load balancer: "+
					"stderr: %q, error: %v", stderr, err)
			}
		}
		if k8sNSLbUDP == "" {
			k8sNSLbUDP, stderr, err = RunOVNNbctl("--", "create",
				"load_balancer",
				"external_ids:UDP_lb_gateway_router="+gatewayRouter,
				"protocol=udp")
			if err != nil {
				return fmt.Errorf("Failed to create load balancer: "+
					"stderr: %q, error: %v", stderr, err)
			}
		}

		// Add north-south load-balancers to the gateway router.
		stdout, stderr, err = RunOVNNbctl("set", "logical_router",
			gatewayRouter, "load_balancer="+k8sNSLbTCP)
		if err != nil {
			return fmt.Errorf("Failed to set north-south load-balancers to the "+
				"gateway router, stdout: %q, stderr: %q, error: %v",
				stdout, stderr, err)
		}
		stdout, stderr, err = RunOVNNbctl("add", "logical_router",
			gatewayRouter, "load_balancer", k8sNSLbUDP)
		if err != nil {
			return fmt.Errorf("Failed to add north-south load-balancers to the "+
				"gateway router, stdout: %q, stderr: %q, error: %v",
				stdout, stderr, err)
		}
	}

	// Create the external switch for the physical interface to connect to.
	externalSwitch := "ext_" + nodeName
	stdout, stderr, err = RunOVNNbctl("--may-exist", "ls-add",
		externalSwitch)
	if err != nil {
		return fmt.Errorf("Failed to create logical switch, stdout: %q, "+
			"stderr: %q, error: %v", stdout, stderr, err)
	}

	// Add external interface as a logical port to external_switch.
	// This is a learning switch port with "unknown" address. The external
	// world is accessed via this port.
	cmdArgs := []string{
		"--", "--may-exist", "lsp-add", externalSwitch, ifaceID,
		"--", "lsp-set-addresses", ifaceID, "unknown",
		"--", "lsp-set-type", ifaceID, "localnet",
		"--", "lsp-set-options", ifaceID, "network_name=" + PhysicalNetworkName}
	cmdArgs = append(cmdArgs, lspArgs...)
	stdout, stderr, err = RunOVNNbctl(cmdArgs...)
	if err != nil {
		return fmt.Errorf("Failed to add logical port to switch, stdout: %q, "+
			"stderr: %q, error: %v", stdout, stderr, err)
	}

	// Connect GR to external_switch with mac address of external interface
	// and that IP address. In the case of `local` gateway mode, whenever ovnkube-node container
	// restarts a new br-local bridge will be created with a new `nicMacAddress`. As a result,
	// direct addition of logical_router_port with --may-exists will not work since the MAC
	// has changed. So, we need to delete that port, if it exists, and it back.
	stdout, stderr, err = RunOVNNbctl(
		"--", "--if-exists", "lrp-del", "rtoe-"+gatewayRouter,
		"--", "lrp-add", gatewayRouter, "rtoe-"+gatewayRouter, nicMacAddress, physicalIPMask,
		"--", "set", "logical_router_port", "rtoe-"+gatewayRouter,
		"external-ids:gateway-physical-ip=yes")
	if err != nil {
		return fmt.Errorf("Failed to add logical port to router, stdout: %q, "+
			"stderr: %q, error: %v", stdout, stderr, err)
	}

	// Connect the external_switch to the router.
	stdout, stderr, err = RunOVNNbctl("--", "--may-exist", "lsp-add",
		externalSwitch, "etor-"+gatewayRouter, "--", "set",
		"logical_switch_port", "etor-"+gatewayRouter, "type=router",
		"options:router-port=rtoe-"+gatewayRouter,
		"addresses="+"\""+nicMacAddress+"\"")
	if err != nil {
		return fmt.Errorf("Failed to add logical port to router, stdout: %q, "+
			"stderr: %q, error: %v", stdout, stderr, err)
	}

	// Add a static route in GR with physical gateway as the default next hop.
	if defaultGW != "" {
		var allIPs string
		if config.IPv6Mode {
			allIPs = "::/0"
		} else {
			allIPs = "0.0.0.0/0"
		}
		stdout, stderr, err = RunOVNNbctl("--may-exist", "lr-route-add",
			gatewayRouter, allIPs, defaultGW,
			fmt.Sprintf("rtoe-%s", gatewayRouter))
		if err != nil {
			return fmt.Errorf("Failed to add a static route in GR with physical "+
				"gateway as the default next hop, stdout: %q, "+
				"stderr: %q, error: %v", stdout, stderr, err)
		}
	}

	// We need to add a /32 route to the Gateway router's IP, on the
	// cluster router, to ensure that the return traffic goes back
	// to the same gateway router
	stdout, stderr, err = RunOVNNbctl("--may-exist", "lr-route-add",
		k8sClusterRouter, routerCIDR.IP.String(), routerCIDR.IP.String())
	if err != nil {
		return fmt.Errorf("Failed to add /32 route to Gateway router's IP of %q "+
			"on the distributed router, stdout: %q, stderr: %q, error: %v",
			routerCIDR.IP.String(), stdout, stderr, err)
	}

	if rampoutIPSubnet != "" {
		rampoutIPSubnets := strings.Split(rampoutIPSubnet, ",")
		for _, rampoutIPSubnet = range rampoutIPSubnets {
			_, _, err = net.ParseCIDR(rampoutIPSubnet)
			if err != nil {
				continue
			}

			// Add source IP address based routes in distributed router
			// for this gateway router.
			stdout, stderr, err = RunOVNNbctl("--may-exist",
				"--policy=src-ip", "lr-route-add", k8sClusterRouter,
				rampoutIPSubnet, routerCIDR.IP.String())
			if err != nil {
				return fmt.Errorf("Failed to add source IP address based "+
					"routes in distributed router, stdout: %q, "+
					"stderr: %q, error: %v", stdout, stderr, err)
			}
		}
	}

	// Default SNAT rules.
	for _, entry := range clusterIPSubnet {
		stdout, stderr, err = RunOVNNbctl("--may-exist", "lr-nat-add",
			gatewayRouter, "snat", physicalIP, entry)
		if err != nil {
			return fmt.Errorf("Failed to create default SNAT rules, stdout: %q, "+
				"stderr: %q, error: %v", stdout, stderr, err)
		}
	}

	return nil
}
