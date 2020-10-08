// +build linux

package node

import (
	"fmt"
	"net"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/klog"
	utilnet "k8s.io/utils/net"
)

// Creates br-local OVS bridge on the node and adds ovn-k8s-gw0 port to it with the
// appropriate IP and MAC address on it. All the traffic from this node's hostNetwork
// Pod towards cluster service ip whose backend is the node itself is forwarded to the
// ovn-k8s-gw0 port after SNATing by the OVN's distributed gateway port.
func setupLocalNodeAccessBridge(exec util.ExecHelper, nodeName string, subnets []*net.IPNet) error {
	localBridgeName := "br-local"
	_, stderr, err := exec.RunOVSVsctl("--may-exist", "add-br", localBridgeName)
	if err != nil {
		return fmt.Errorf("failed to create bridge %s, stderr:%s (%v)",
			localBridgeName, stderr, err)
	}

	_, _, err = bridgedGatewayNodeSetup(exec, nodeName, localBridgeName, localBridgeName,
		util.LocalNetworkName, true)
	if err != nil {
		return fmt.Errorf("failed while setting up local node access bridge : %v", err)
	}

	_, err = util.LinkSetUp(localBridgeName)
	if err != nil {
		return err
	}

	var macAddress string
	if config.IPv4Mode {
		macAddress = util.IPAddrToHWAddr(net.ParseIP(util.V4NodeLocalNatSubnetNextHop)).String()
	} else {
		macAddress = util.IPAddrToHWAddr(net.ParseIP(util.V6NodeLocalNatSubnetNextHop)).String()
	}

	_, stderr, err = exec.RunOVSVsctl(
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
			gatewayNextHop = net.ParseIP(util.V6NodeLocalNatSubnetNextHop)
			gatewaySubnetMask = net.CIDRMask(util.V6NodeLocalNatSubnetPrefix, 128)
		} else {
			gatewayNextHop = net.ParseIP(util.V4NodeLocalNatSubnetNextHop)
			gatewaySubnetMask = net.CIDRMask(util.V4NodeLocalNatSubnetPrefix, 32)
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

func addSharedGatewayIptRules(service *kapi.Service, nodeIP *net.IPNet) {
	rules := getGatewayIPTRules(service, "", nodeIP)
	if err := addIptRules(rules); err != nil {
		klog.Errorf("Failed to add iptables rules for service %s/%s: %v", service.Namespace, service.Name, err)
	}
}

func delSharedGatewayIptRules(service *kapi.Service, nodeIP *net.IPNet) {
	rules := getGatewayIPTRules(service, "", nodeIP)
	if err := delIptRules(rules); err != nil {
		klog.Errorf("Failed to delete iptables rules for service %s/%s: %v", service.Namespace, service.Name, err)
	}
}

func syncSharedGatewayIptRules(services []interface{}, nodeIP *net.IPNet) {
	keepIPTRules := []iptRule{}
	for _, service := range services {
		svc, ok := service.(*kapi.Service)
		if !ok {
			klog.Errorf("Spurious object in syncSharedGatewayIptRules: %v", service)
			continue
		}
		keepIPTRules = append(keepIPTRules, getGatewayIPTRules(svc, "", nodeIP)...)
	}
	for _, chain := range []string{iptableNodePortChain, iptableExternalIPChain} {
		recreateIPTRules("nat", chain, keepIPTRules)
		recreateIPTRules("filter", chain, keepIPTRules)
	}
}
