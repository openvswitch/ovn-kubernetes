package node

import (
	"fmt"
	"net"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"k8s.io/klog"
	utilnet "k8s.io/utils/net"
)

func (n *OvnNode) createManagementPort(hostSubnets []*net.IPNet, nodeAnnotator kube.Annotator,
	waiter *startupWaiter) error {
	// Kubernetes emits events when pods are created. The event will contain
	// only lowercase letters of the hostname even though the kubelet is
	// started with a hostname that contains lowercase and uppercase letters.
	// When the kubelet is started with a hostname containing lowercase and
	// uppercase letters, this causes a mismatch between what the watcher
	// will try to fetch and what kubernetes provides, thus failing to
	// create the port on the logical switch.
	// Until the above is changed, switch to a lowercase hostname
	nodeName := strings.ToLower(n.name)

	// Create a OVS internal interface.
	legacyMgmtIntfName := util.GetLegacyK8sMgmtIntfName(nodeName)
	stdout, stderr, err := n.exec.RunOVSVsctl(
		"--", "--if-exists", "del-port", "br-int", legacyMgmtIntfName,
		"--", "--may-exist", "add-port", "br-int", util.K8sMgmtIntfName,
		"--", "set", "interface", util.K8sMgmtIntfName,
		"type=internal", "mtu_request="+fmt.Sprintf("%d", config.Default.MTU),
		"external-ids:iface-id="+util.K8sPrefix+nodeName)
	if err != nil {
		klog.Errorf("Failed to add port to br-int, stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
		return err
	}
	macAddress, err := util.GetOVSPortMACAddress(n.exec, util.K8sMgmtIntfName)
	if err != nil {
		klog.Errorf("Failed to get management port MAC address: %v", err)
		return err
	}
	// persist the MAC address so that upon node reboot we get back the same mac address.
	_, stderr, err = n.exec.RunOVSVsctl("set", "interface", util.K8sMgmtIntfName,
		fmt.Sprintf("mac=%s", strings.ReplaceAll(macAddress.String(), ":", "\\:")))
	if err != nil {
		klog.Errorf("Failed to persist MAC address %q for %q: stderr:%s (%v)", macAddress.String(),
			util.K8sMgmtIntfName, stderr, err)
		return err
	}

	cfg, err := createPlatformManagementPort(util.K8sMgmtIntfName, hostSubnets, n.stopChan)
	if err != nil {
		return err
	}

	if err := util.SetNodeManagementPortMACAddress(nodeAnnotator, macAddress); err != nil {
		return err
	}

	if config.Gateway.Mode == config.GatewayModeLocal {
		var gatewayIfAddrs []*net.IPNet
		for _, hostSubnet := range hostSubnets {
			// local gateway mode uses mp0 as default path for all ingress traffic into OVN
			var nextHop *net.IPNet
			if utilnet.IsIPv6CIDR(hostSubnet) {
				nextHop = cfg.ipv6.ifAddr
			} else {
				nextHop = cfg.ipv4.ifAddr
			}
			gatewayIfAddrs = append(gatewayIfAddrs, nextHop)

			// add iptables masquerading for mp0 to exit the host for egress
			cidr := nextHop.IP.Mask(nextHop.Mask)
			cidrNet := &net.IPNet{IP: cidr, Mask: nextHop.Mask}
			err = initLocalGatewayNATRules(util.K8sMgmtIntfName, cidrNet)
			if err != nil {
				return fmt.Errorf("failed to add local NAT rules for: %s, err: %v", util.K8sMgmtIntfName, err)
			}
		}

		if config.Gateway.NodeportEnable {
			localAddrSet, err := getLocalAddrs()
			if err != nil {
				return err
			}
			err = n.watchLocalPorts(
				newLocalPortWatcherData(n.exec, gatewayIfAddrs, n.recorder, localAddrSet),
			)
			if err != nil {
				return err
			}
		}
	}

	waiter.AddWait(n.managementPortReady, nil)
	return nil
}

// managementPortReady will check to see if OpenFlow rules for management port has been created
func (n *OvnNode) managementPortReady() (bool, error) {
	// Get the OVS interface name for the Management Port
	ofport, _, err := n.exec.RunOVSVsctl("--if-exists", "get", "interface", util.K8sMgmtIntfName, "ofport")
	if err != nil {
		return false, nil
	}

	// OpenFlow table 65 performs logical-to-physical translation. It matches the packet’s logical
	// egress  port. Its actions output the packet to the port attached to the OVN integration bridge
	// that represents that logical  port.
	stdout, _, err := n.exec.RunOVSOfctl("--no-stats", "--no-names", "dump-flows", "br-int",
		"table=65,out_port="+ofport)
	if err != nil {
		return false, nil
	}
	if !strings.Contains(stdout, "actions=output:"+ofport) {
		return false, nil
	}
	return true, nil
}
