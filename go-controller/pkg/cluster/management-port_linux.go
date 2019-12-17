// +build linux

package cluster

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/coreos/go-iptables/iptables"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/sirupsen/logrus"
)

const (
	iptableMgmPortChain = "OVN-KUBE-SNAT-MGMTPORT"
)

// CreateManagementPort creates a management port attached to the node switch
// that lets the node access its pods via their private IP address. This is used
// for health checking and other management tasks.
func CreateManagementPort(nodeName string, localSubnet *net.IPNet, clusterSubnet []string) (map[string]string, error) {
	interfaceName, interfaceIP, macAddress, routerIP, routerMAC, err :=
		createManagementPortGeneric(nodeName, localSubnet)
	if err != nil {
		return nil, err
	}

	// TODO - Migrate to using netlink.

	// Up the interface.
	_, _, err = util.RunIP("link", "set", interfaceName, "up")
	if err != nil {
		return nil, err
	}

	// The interface may already exist, in which case delete the routes and IP.
	_, _, err = util.RunIP("addr", "flush", "dev", interfaceName)
	if err != nil {
		return nil, err
	}

	// Assign IP address to the internal interface.
	_, _, err = util.RunIP("addr", "add", interfaceIP, "dev", interfaceName)
	if err != nil {
		return nil, err
	}

	for _, subnet := range clusterSubnet {
		// Flush the route for the entire subnet (in case it was added before).
		_, _, err = util.RunIP("route", "flush", subnet)
		if err != nil {
			return nil, err
		}

		// Create a route for the entire subnet.
		_, stderr, err := util.RunIP("route", "add", subnet, "via", routerIP)
		if err != nil {
			if strings.HasPrefix(stderr, "RTNETLINK answers: File exists") {
				logrus.Debugf("Ignoring error %s from 'route add %s via %s' - already added via IPv6 RA?",
					strings.TrimSpace(stderr), subnet, routerIP)
			} else {
				return nil, fmt.Errorf("Failed to add route for %s via %s: %s", subnet, routerIP, err)
			}
		}
	}

	// Flush the route for the services subnet (in case it was added before).
	_, _, err = util.RunIP("route", "flush", config.Kubernetes.ServiceCIDR)
	if err != nil {
		return nil, err
	}

	// Create a route for the services subnet.
	_, stderr, err := util.RunIP("route", "add", config.Kubernetes.ServiceCIDR, "via", routerIP)
	if err != nil {
		if strings.HasPrefix(stderr, "RTNETLINK answers: File exists") {
			logrus.Debugf("Ignoring error %s from 'route add %s via %s' - already added via IPv6 RA?",
				strings.TrimSpace(stderr), config.Kubernetes.ServiceCIDR, routerIP)
		} else {
			return nil, fmt.Errorf("Failed to add route for %s via %s: %s", config.Kubernetes.ServiceCIDR, routerIP, err)
		}
	}

	// Add a neighbour entry on the K8s node to map routerIP with routerMAC. This is
	// required because in certain cases ARP requests from the K8s Node to the routerIP
	// arrives on OVN Logical Router pipeline with ARP source protocol address set to
	// K8s Node IP. OVN Logical Router pipeline drops such packets since it expects
	// source protocol address to be in the Logical Switch's subnet.
	_, _, err = util.RunIP("neigh", "add", routerIP, "dev", interfaceName, "lladdr", routerMAC)
	if err != nil && os.IsNotExist(err) {
		return nil, err
	}

	// Set up necessary iptables rules
	err = addMgtPortIptRules(interfaceName, interfaceIP)
	if err != nil {
		return nil, err
	}

	return map[string]string{ovn.OvnNodeManagementPortMacAddress: macAddress}, nil
}

func addMgtPortIptRules(ifname, interfaceIP string) error {
	ipt, err := util.GetIPTablesHelper(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}
	interfaceAddr := strings.Split(interfaceIP, "/")
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
func DelMgtPortIptRules(nodeName string) {
	ipt, err := util.GetIPTablesHelper(iptables.ProtocolIPv4)
	if err != nil {
		return
	}
	ifname := util.GetK8sMgmtIntfName(nodeName)
	rule := []string{"-o", ifname, "-j", iptableMgmPortChain}
	_ = ipt.Delete("nat", "POSTROUTING", rule...)
	_ = ipt.ClearChain("nat", iptableMgmPortChain)
	_ = ipt.DeleteChain("nat", iptableMgmPortChain)
}
