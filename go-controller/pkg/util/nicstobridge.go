// +build linux

package util

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
	utilsysctl "k8s.io/kubernetes/pkg/util/sysctl"
	utilnet "k8s.io/utils/net"
)

const (
	ubuntuDefaultFile = "/etc/default/openvswitch-switch"
	rhelDefaultFile   = "/etc/default/openvswitch"
)

func getBridgeName(iface string) string {
	return fmt.Sprintf("br%s", iface)
}

// GetNicName returns the physical NIC name, given an OVS bridge name
// configured by NicToBridge()
func GetNicName(brName string) (string, error) {
	// Check for system type port (required to be set if using NetworkManager)
	stdout, stderr, err := RunOVSVsctl("list-ports", brName)
	if err != nil {
		return "", fmt.Errorf("failed to get list of ports on bridge %q:, stderr: %q, error: %v",
			brName, stderr, err)
	}

	for _, port := range strings.Split(stdout, "\n") {
		stdout, stderr, err = RunOVSVsctl("get", "Port", port, "Interfaces")
		if err != nil {
			return "", fmt.Errorf("failed to get port %q on bridge %q:, stderr: %q, error: %v",
				port, brName, stderr, err)

		}
		// remove brackets on list of interfaces
		ifaces := strings.TrimPrefix(strings.TrimSuffix(stdout, "]"), "[")
		for _, iface := range strings.Split(ifaces, ",") {
			stdout, stderr, err = RunOVSVsctl("get", "Interface", strings.TrimSpace(iface), "Type")
			if err != nil {
				return "", fmt.Errorf("failed to get Interface %q Type on bridge %q:, stderr: %q, error: %v",
					iface, brName, stderr, err)

			}
			// If system Type we know this is the OVS port is the NIC
			if stdout == "system" {
				return port, nil
			}
		}
	}

	// Check for bridge-uplink to indicate the NIC
	stdout, stderr, err = RunOVSVsctl(
		"br-get-external-id", brName, "bridge-uplink")
	if err != nil {
		return "", fmt.Errorf("failed to get the bridge-uplink for the bridge %q:, stderr: %q, error: %v",
			brName, stderr, err)
	}
	if stdout == "" && strings.HasPrefix(brName, "br") {
		// This would happen if the bridge was created before the bridge-uplink
		// changes got integrated. Assuming naming format of "br<nic name>".
		return brName[len("br"):], nil
	}
	return stdout, nil
}

func saveIPAddress(oldLink, newLink netlink.Link, addrs []netlink.Addr) error {
	sysctl := utilsysctl.New()
	ipv6Disable, err := sysctl.GetSysctl(fmt.Sprintf("net/ipv6/conf/%s/disable_ipv6", newLink.Attrs().Name))
	if err != nil {
		klog.Errorf("Error obtaining IPv6 status of interface %s : %v", newLink.Attrs().Name, err)
		// be conservative, assume IPv6 is disabled if we can't read it.
		ipv6Disable = 1
	}

	for _, addr := range addrs {
		if addr.IP.IsGlobalUnicast() {
			// Remove from oldLink
			if err := netLinkOps.AddrDel(oldLink, &addr); err != nil {
				klog.Errorf("Remove addr %v from %q failed: %v", addr, oldLink.Attrs().Name, err)
				return err
			}

			// The interface must have IPv6 enable in order to configure an IPv6 address or it will fail.
			if ipv6Disable != 0 && utilnet.IsIPv6(addr.IP) {
				err := sysctl.SetSysctl(fmt.Sprintf("net/ipv6/conf/%s/disable_ipv6", newLink.Attrs().Name), 0)
				if err != nil {
					klog.Errorf("Errors setting IPv6 status of interface %s : %v", newLink.Attrs().Name, err)
					return err
				}
				ipv6Disable = 0
			}

			// Add to newLink
			addr.Label = newLink.Attrs().Name
			if err := netLinkOps.AddrAdd(newLink, &addr); err != nil {
				klog.Errorf("Add addr to newLink %v failed: %v", addr, err)
				return err
			}
			klog.Infof("Successfully saved addr %q to newLink %q", addr.String(), addr.Label)
		}
	}

	return netLinkOps.LinkSetUp(newLink)
}

// delAddRoute removes 'route' from 'oldLink' and moves to 'newLink'
func delAddRoute(oldLink, newLink netlink.Link, route netlink.Route) error {
	// Remove route from old interface
	if err := netLinkOps.RouteDel(&route); err != nil && !strings.Contains(err.Error(), "no such process") {
		klog.Errorf("Remove route from %q failed: %v", oldLink.Attrs().Name, err)
		return err
	}

	// Add route to newLink
	route.LinkIndex = newLink.Attrs().Index
	if err := netLinkOps.RouteAdd(&route); err != nil && !os.IsExist(err) {
		klog.Errorf("Add route %v to newLink %q failed: %v", route, newLink.Attrs().Name, err)
		return err
	}

	klog.Infof("Successfully saved route %q", route.String())
	return nil
}

func saveRoute(oldLink, newLink netlink.Link, routes []netlink.Route) error {
	// Handle routes for default gateway later.  This is a special case for
	// GCE where we have /32 IP addresses and we can't add the default
	// gateway before the route to the gateway.
	for _, route := range routes {
		if route.Dst == nil {
			continue
		}
		// only consider routes for /32 or /128 IP addresses
		ones, len := route.Dst.Mask.Size()
		if (ones == 32 && len == 32) ||
			(ones == 128 && len == 128) {
			// if this is needed for the gateway we fail later
			// otherwise just log the error
			err := delAddRoute(oldLink, newLink, route)
			if err != nil {
				klog.Errorf("Skipping route %v: %v", route, err)
			}
		}
	}

	for _, route := range routes {
		// Get the default gateways or multipath routes
		if (route.Dst == nil && route.Gw != nil && route.LinkIndex > 0) ||
			(route.Dst == nil && len(route.MultiPath) > 0) {
			// Remove route from 'oldLink' and move it to 'newLink'
			err := delAddRoute(oldLink, newLink, route)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func setupDefaultFile() {
	platform, err := runningPlatform()
	if err != nil {
		klog.Errorf("Failed to set OVS package default file (%v)", err)
		return
	}

	var defaultFile, text string
	if platform == ubuntu {
		defaultFile = ubuntuDefaultFile
		text = "OVS_CTL_OPTS=\"$OVS_CTL_OPTS --delete-transient-ports\""
	} else if platform == rhel {
		defaultFile = rhelDefaultFile
		text = "OPTIONS=--delete-transient-ports"
	} else {
		return
	}

	fileContents, err := ioutil.ReadFile(defaultFile)
	if err != nil {
		klog.Warningf("Failed to parse file %s (%v)",
			defaultFile, err)
		return
	}

	ss := strings.Split(string(fileContents), "\n")
	for _, line := range ss {
		if strings.Contains(line, "--delete-transient-ports") {
			// Nothing to do
			return
		}
	}

	// The defaultFile does not contain '--delete-transient-ports' set.
	// We should set it.
	f, err := os.OpenFile(defaultFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		klog.Errorf("Failed to open %s to write (%v)", defaultFile, err)
		return
	}
	defer f.Close()

	if _, err = f.WriteString(text); err != nil {
		klog.Errorf("Failed to write to %s (%v)",
			defaultFile, err)
		return
	}
}

// NicToBridge creates a OVS bridge for the 'iface' and also moves the IP
// address and routes of 'iface' to OVS bridge.
func NicToBridge(iface string) (string, error) {
	ifaceLink, err := netLinkOps.LinkByName(iface)
	if err != nil {
		return "", err
	}

	bridge := getBridgeName(iface)
	stdout, stderr, err := RunOVSVsctl(
		"--", "--may-exist", "add-br", bridge,
		"--", "br-set-external-id", bridge, "bridge-id", bridge,
		"--", "br-set-external-id", bridge, "bridge-uplink", iface,
		"--", "set", "bridge", bridge, "fail-mode=standalone",
		fmt.Sprintf("other_config:hwaddr=%s", ifaceLink.Attrs().HardwareAddr),
		"--", "--may-exist", "add-port", bridge, iface,
		"--", "set", "port", iface, "other-config:transient=true")
	if err != nil {
		klog.Errorf("Failed to create OVS bridge, stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
		return "", err
	}
	klog.Infof("Successfully created OVS bridge %q", bridge)

	setupDefaultFile()

	// Get ip addresses and routes before any real operations.
	family := syscall.AF_UNSPEC
	addrs, err := netLinkOps.AddrList(ifaceLink, family)
	if err != nil {
		return "", err
	}
	routes, err := netLinkOps.RouteList(ifaceLink, family)
	if err != nil {
		return "", err
	}

	bridgeLink, err := netLinkOps.LinkByName(bridge)
	if err != nil {
		return "", err
	}

	// save ip addresses to bridge.
	if err = saveIPAddress(ifaceLink, bridgeLink, addrs); err != nil {
		return "", err
	}

	// save routes to bridge.
	if err = saveRoute(ifaceLink, bridgeLink, routes); err != nil {
		return "", err
	}

	return bridge, nil
}

// BridgeToNic moves the IP address and routes of internal port of the bridge to
// underlying NIC interface and deletes the OVS bridge.
func BridgeToNic(bridge string) error {
	// Internal port is named same as the bridge
	bridgeLink, err := netLinkOps.LinkByName(bridge)
	if err != nil {
		return err
	}

	// Get ip addresses and routes before any real operations.
	family := syscall.AF_UNSPEC
	addrs, err := netLinkOps.AddrList(bridgeLink, family)
	if err != nil {
		return err
	}
	routes, err := netLinkOps.RouteList(bridgeLink, family)
	if err != nil {
		return err
	}

	nicName, err := GetNicName(bridge)
	if err != nil {
		return err
	}
	ifaceLink, err := netLinkOps.LinkByName(nicName)
	if err != nil {
		return err
	}

	// save ip addresses to iface.
	if err = saveIPAddress(bridgeLink, ifaceLink, addrs); err != nil {
		return err
	}

	// save routes to iface.
	if err = saveRoute(bridgeLink, ifaceLink, routes); err != nil {
		return err
	}

	// for every bridge interface that is of type "patch", find the peer
	// interface and delete that interface from the integration bridge
	stdout, stderr, err := RunOVSVsctl("list-ifaces", bridge)
	if err != nil {
		klog.Errorf("Failed to get interfaces for OVS bridge: %q, "+
			"stderr: %q, error: %v", bridge, stderr, err)
		return err
	}
	ifacesList := strings.Split(strings.TrimSpace(stdout), "\n")
	for _, iface := range ifacesList {
		stdout, stderr, err = RunOVSVsctl("get", "interface", iface, "type")
		if err != nil {
			klog.Warningf("Failed to determine the type of interface: %q, "+
				"stderr: %q, error: %v", iface, stderr, err)
			continue
		} else if stdout != "patch" {
			continue
		}
		stdout, stderr, err = RunOVSVsctl("get", "interface", iface, "options:peer")
		if err != nil {
			klog.Warningf("Failed to get the peer port for patch interface: %q, "+
				"stderr: %q, error: %v", iface, stderr, err)
			continue
		}
		// stdout has the peer interface, just delete it
		peer := strings.TrimSpace(stdout)
		_, stderr, err = RunOVSVsctl("--if-exists", "del-port", "br-int", peer)
		if err != nil {
			klog.Warningf("Failed to delete patch port %q on br-int, "+
				"stderr: %q, error: %v", peer, stderr, err)
		}
	}

	// Now delete the bridge
	stdout, stderr, err = RunOVSVsctl("--", "--if-exists", "del-br", bridge)
	if err != nil {
		klog.Errorf("Failed to delete OVS bridge, stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
		return err
	}
	klog.Infof("Successfully deleted OVS bridge %q", bridge)
	return nil
}
