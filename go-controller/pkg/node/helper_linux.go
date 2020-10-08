// +build linux

package node

import (
	"fmt"
	"net"
	"syscall"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/vishvananda/netlink"
	kapi "k8s.io/api/core/v1"
	utilnet "k8s.io/utils/net"
)

// getDefaultGatewayInterfaceDetails returns the interface name on
// which the default gateway (for route to 0.0.0.0) is configured.
// It also returns the default gateways themselves.
func getDefaultGatewayInterfaceDetails() (string, []net.IP, error) {
	var intfName string
	var gatewayIPs []net.IP

	needIPv4 := config.IPv4Mode
	needIPv6 := config.IPv6Mode
	routes, err := netlink.RouteList(nil, syscall.AF_UNSPEC)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get routing table in node")
	}

	for _, route := range routes {
		if route.Dst == nil && route.Gw != nil && route.LinkIndex > 0 {
			intfLink, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				continue
			}
			if utilnet.IsIPv6(route.Gw) {
				if !needIPv6 {
					continue
				}
				needIPv6 = false
			} else {
				if !needIPv4 {
					continue
				}
				needIPv4 = false
			}

			if intfName == "" {
				intfName = intfLink.Attrs().Name
			} else if intfName != intfLink.Attrs().Name {
				return "", nil, fmt.Errorf("multiple gateway interfaces detected: %s %s", intfName, intfLink.Attrs().Name)
			}
			gatewayIPs = append(gatewayIPs, route.Gw)
		}
	}

	if len(gatewayIPs) == 0 {
		return "", nil, fmt.Errorf("failed to get default gateway interface")
	}
	return intfName, gatewayIPs, nil
}

func getDefaultIfAddr(defaultGatewayIntf string) (*net.IPNet, *net.IPNet, error) {
	var v4IfAddr, v6IfAddr *net.IPNet
	primaryLink, err := netlink.LinkByName(defaultGatewayIntf)
	if err != nil {
		return nil, nil, fmt.Errorf("error: unable to get link for default interface: %s, err: %v", defaultGatewayIntf, err)
	}
	addrs, err := netlink.AddrList(primaryLink, netlink.FAMILY_ALL)
	if err != nil {
		return nil, nil, fmt.Errorf("error: unable to list addresses for default interface, err: %v", err)
	}
	for _, addr := range addrs {
		if addr.IP.IsGlobalUnicast() {
			if utilnet.IsIPv6(addr.IP) {
				v6IfAddr = addr.IPNet
			} else {
				v4IfAddr = addr.IPNet
			}
		}
	}
	return v4IfAddr, v6IfAddr, nil
}

func getIntfName(exec util.ExecHelper, gatewayIntf string) (string, error) {
	// The given (or autodetected) interface is an OVS bridge and this could be
	// created by us using util.NicToBridge() or it was pre-created by the user.

	// Is intfName a port of gatewayIntf?
	intfName, err := util.GetNicName(exec, gatewayIntf)
	if err != nil {
		return "", err
	}
	_, stderr, err := exec.RunOVSVsctl("get", "interface", intfName, "ofport")
	if err != nil {
		return "", fmt.Errorf("failed to get ofport of %s, stderr: %q, error: %v",
			intfName, stderr, err)
	}
	return intfName, nil
}

func deleteConntrack(ip string, port int32, protocol kapi.Protocol) error {
	return util.DeleteConntrack(ip, port, protocol)
}
