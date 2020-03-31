// +build linux

package node

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"k8s.io/klog"
	utilnet "k8s.io/utils/net"
)

const (
	iptableMgmPortChain = "OVN-KUBE-SNAT-MGMTPORT"
)

// createPlatformManagementPort creates a management port attached to the node switch
// that lets the node access its pods via their private IP address. This is used
// for health checking and other management tasks.
func createPlatformManagementPort(interfaceName, interfaceIP, routerIP, routerMAC string) error {
	link, err := util.LinkSetUp(interfaceName)
	if err != nil {
		return err
	}
	// Flush any existing IP addresses and assign the new IP
	if err = util.LinkAddrFlush(link); err == nil {
		err = util.LinkAddrAdd(link, interfaceIP)
	}
	if err != nil {
		return err
	}

	var allSubnets []string
	for _, subnet := range config.Default.ClusterSubnets {
		allSubnets = append(allSubnets, subnet.CIDR.String())
	}
	allSubnets = append(allSubnets, config.Kubernetes.ServiceCIDR)

	// delete any existing routes and add new routes
	if err = util.LinkRoutesDel(link, allSubnets); err == nil {
		err = util.LinkRoutesAdd(link, routerIP, allSubnets)
	}
	if err != nil {
		if os.IsExist(err) {
			klog.V(5).Infof("Ignoring error %s from 'route add %s via %s' - already added via IPv6 RA?",
				err.Error(), config.Kubernetes.ServiceCIDR, routerIP)
		} else {
			return err
		}
	}

	// Add a neighbour entry on the K8s node to map routerIP with routerMAC. This is
	// required because in certain cases ARP requests from the K8s Node to the routerIP
	// arrives on OVN Logical Router pipeline with ARP source protocol address set to
	// K8s Node IP. OVN Logical Router pipeline drops such packets since it expects
	// source protocol address to be in the Logical Switch's subnet.
	err = util.LinkNeighAdd(link, routerIP, routerMAC)
	if err != nil {
		return err
	}

	// Set up necessary iptables rules
	err = addMgtPortIptRules(interfaceName, interfaceIP)
	if err != nil {
		return err
	}

	return nil
}

func addMgtPortIptRules(ifname, interfaceIP string) error {
	interfaceAddr := strings.Split(interfaceIP, "/")
	ip := net.ParseIP(interfaceAddr[0])
	if ip == nil {
		return fmt.Errorf("Failed to parse IP '%s'", interfaceAddr[0])
	}
	var ipt util.IPTablesHelper
	var err error
	if utilnet.IsIPv6(ip) {
		ipt, err = util.GetIPTablesHelper(iptables.ProtocolIPv6)
	} else {
		ipt, err = util.GetIPTablesHelper(iptables.ProtocolIPv4)
	}
	if err != nil {
		return err
	}
	err = ipt.ClearChain("nat", iptableMgmPortChain)
	if err != nil {
		return fmt.Errorf("could not set up iptables chain for management port: %v", err)
	}
	rule := []string{"-o", ifname, "-j", iptableMgmPortChain}
	exists, err := ipt.Exists("nat", "POSTROUTING", rule...)
	if err == nil && !exists {
		err = ipt.Insert("nat", "POSTROUTING", 1, rule...)
	}
	if err != nil {
		return fmt.Errorf("could not set up iptables chain rules for management port: %v", err)
	}
	rule = []string{"-o", ifname, "-j", "SNAT", "--to-source", interfaceAddr[0], "-m", "comment", "--comment", "OVN SNAT to Management Port"}
	err = ipt.Insert("nat", iptableMgmPortChain, 1, rule...)
	if err != nil {
		return fmt.Errorf("could not set up iptables rules for management port: %v", err)
	}

	return nil
}

//DelMgtPortIptRules delete all the iptable rules for the management port.
func DelMgtPortIptRules() {
	// Clean up all iptables and ip6tables remnants that may be left around
	ipt, err := util.GetIPTablesHelper(iptables.ProtocolIPv4)
	if err != nil {
		return
	}
	ipt6, err := util.GetIPTablesHelper(iptables.ProtocolIPv6)
	if err != nil {
		return
	}
	rule := []string{"-o", util.K8sMgmtIntfName, "-j", iptableMgmPortChain}
	_ = ipt.Delete("nat", "POSTROUTING", rule...)
	_ = ipt6.Delete("nat", "POSTROUTING", rule...)
	_ = ipt.ClearChain("nat", iptableMgmPortChain)
	_ = ipt6.ClearChain("nat", iptableMgmPortChain)
	_ = ipt.DeleteChain("nat", iptableMgmPortChain)
	_ = ipt6.DeleteChain("nat", iptableMgmPortChain)
}
