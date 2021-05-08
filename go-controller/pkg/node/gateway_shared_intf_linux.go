// +build linux

package node

import (
	"fmt"
	"net"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

// Creates br-local OVS bridge on the node and adds ovn-k8s-gw0 port to it with the
// appropriate IP and MAC address on it. All the traffic from this node's hostNetwork
// Pod towards cluster service ip whose backend is the node itself is forwarded to the
// ovn-k8s-gw0 port after SNATing by the OVN's distributed gateway port.
func setupLocalNodeAccessBridge(nodeName string, subnets []*net.IPNet) error {
	localBridgeName := types.LocalBridgeName
	_, stderr, err := util.RunOVSVsctl("--may-exist", "add-br", localBridgeName)
	if err != nil {
		return fmt.Errorf("failed to create bridge %s, stderr:%s (%v)",
			localBridgeName, stderr, err)
	}

	_, _, err = bridgedGatewayNodeSetup(nodeName, localBridgeName, localBridgeName,
		types.LocalNetworkName, true)
	if err != nil {
		return fmt.Errorf("failed while setting up local node access bridge : %v", err)
	}

	_, err = util.LinkSetUp(localBridgeName)
	if err != nil {
		return err
	}

	macAddress := util.IPAddrToHWAddr(net.ParseIP(types.V4NodeLocalNATSubnetNextHop)).String()

	_, stderr, err = util.RunOVSVsctl(
		"--may-exist", "add-port", localBridgeName, localnetGatewayNextHopPort,
		"--", "set", "interface", localnetGatewayNextHopPort, "type=internal",
		"mtu_request="+fmt.Sprintf("%d", config.Default.MTU),
		fmt.Sprintf("mac=%s", strings.ReplaceAll(macAddress, ":", "\\:")))
	if err != nil {
		return fmt.Errorf("failed to add the port %s to bridge %s, stderr:%s (%v)",
			localnetGatewayNextHopPort, localBridgeName, stderr, err)
	}

	link, err := util.LinkSetUp(localnetGatewayNextHopPort)
	if err != nil {
		return err
	}

	// Flush all (non-LL) IP addresses on the nexthop port and add the new IP address(es)
	if err = util.LinkAddrFlush(link); err != nil {
		return err
	}

	var gatewayIfAddrs []*net.IPNet
	for _, subnet := range subnets {
		var gatewayNextHop net.IP
		var gatewaySubnetMask net.IPMask
		isSubnetIPv6 := utilnet.IsIPv6CIDR(subnet)
		if isSubnetIPv6 {
			gatewayNextHop = net.ParseIP(types.V6NodeLocalNATSubnetNextHop)
			gatewaySubnetMask = net.CIDRMask(types.V6NodeLocalNATSubnetPrefix, 128)
		} else {
			gatewayNextHop = net.ParseIP(types.V4NodeLocalNATSubnetNextHop)
			gatewaySubnetMask = net.CIDRMask(types.V4NodeLocalNATSubnetPrefix, 32)
		}
		gatewayNextHopCIDR := &net.IPNet{IP: gatewayNextHop, Mask: gatewaySubnetMask}
		if err = util.LinkAddrAdd(link, gatewayNextHopCIDR); err != nil {
			return err
		}
		gatewayIfAddrs = append(gatewayIfAddrs, gatewayNextHopCIDR)
	}

	if config.Gateway.Mode == config.GatewayModeLocal {
		// need to add masquerading for ovn-k8s-gw0 port for hostA -> service -> hostB via DGP
		for _, ifaddr := range gatewayIfAddrs {
			err = initLocalGatewayNATRules(localnetGatewayNextHopPort, ifaddr)
			if err != nil {
				return fmt.Errorf("failed to add NAT rules for localnet gateway (%v)", err)
			}
		}
	}

	return nil
}

// deletes the local bridge used for DGP and removes the corresponding iface, as well as OVS bridge mappings
func deleteLocalNodeAccessBridge() error {
	// remove br-local bridge
	_, stderr, err := util.RunOVSVsctl("--if-exists", "del-br", types.LocalBridgeName)
	if err != nil {
		return fmt.Errorf("failed to delete bridge %s, stderr:%s (%v)",
			types.LocalBridgeName, stderr, err)
	}
	// ovn-bridge-mappings maps a physical network name to a local ovs bridge
	// that provides connectivity to that network. It is in the form of physnet1:br1,physnet2:br2.
	stdout, stderr, err := util.RunOVSVsctl("--if-exists", "get", "Open_vSwitch", ".",
		"external_ids:ovn-bridge-mappings")
	if err != nil {
		return fmt.Errorf("failed to get ovn-bridge-mappings stderr:%s (%v)", stderr, err)
	}
	if len(stdout) > 0 {
		locnetMapping := fmt.Sprintf("%s:%s", types.LocalNetworkName, types.LocalBridgeName)
		if strings.Contains(stdout, locnetMapping) {
			var newMappings string
			bridgeMappings := strings.Split(stdout, ",")
			for _, bridgeMapping := range bridgeMappings {
				if bridgeMapping != locnetMapping {
					if len(newMappings) != 0 {
						newMappings += ","
					}
					newMappings += bridgeMapping
				}
			}
			_, stderr, err = util.RunOVSVsctl("set", "Open_vSwitch", ".",
				fmt.Sprintf("external_ids:ovn-bridge-mappings=%s", newMappings))
			if err != nil {
				return fmt.Errorf("failed to set ovn-bridge-mappings, stderr:%s, error: (%v)", stderr, err)
			}
		}
	}

	klog.Info("Local Node Access bridge removed")
	return nil
}

// If A Service External Traffic Policy==Local and backend is a host-networked pod
// we must steer traffic from host -> svc straight to the host instead of into OVN
// via the cluster IP of the service
func addSharedGatewayIptRules(service *kapi.Service, nodeLocalHostEndpoint bool, nodeIPs []string) {
	var rules []iptRule
	if nodeLocalHostEndpoint {
		// First try to delete existing rule that was added
		rules = getGatewayIPTRules(service, nodeIPs)
	} else {
		rules = getGatewayIPTRules(service, nil)
	}
	if err := addIptRules(rules); err != nil {
		klog.Errorf("Failed to add iptables rules for service %s/%s: %v", service.Namespace, service.Name, err)
	}
}

func delSharedGatewayIptRules(service *kapi.Service, nodeLocalHostEndpoint bool, nodeIPs []string) {
	var rules []iptRule
	if nodeLocalHostEndpoint {
		rules = getGatewayIPTRules(service, nodeIPs)
	} else {
		rules = getGatewayIPTRules(service, nil)
	}
	if err := delIptRules(rules); err != nil {
		klog.Errorf("Failed to delete iptables rules for service %s/%s: %v", service.Namespace, service.Name, err)
	}
}

func syncSharedGatewayIptRules(services []interface{}, nodeLocalHostEndpoint bool, nodeIPs []string) {
	keepIPTRules := []iptRule{}
	for _, service := range services {
		svc, ok := service.(*kapi.Service)
		if !ok {
			klog.Errorf("Spurious object in syncSharedGatewayIptRules: %v", service)
			continue
		}
		if nodeLocalHostEndpoint {
			keepIPTRules = append(keepIPTRules, getGatewayIPTRules(svc, nodeIPs)...)
		} else {
			keepIPTRules = append(keepIPTRules, getGatewayIPTRules(svc, nil)...)
		}
	}
	for _, chain := range []string{iptableNodePortChain, iptableExternalIPChain} {
		recreateIPTRules("nat", chain, keepIPTRules)
	}
}
