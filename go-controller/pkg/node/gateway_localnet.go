// +build linux

package node

import (
	"fmt"
	"net"
	"reflect"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"
	utilnet "k8s.io/utils/net"
)

const (
	v4localnetGatewayIP = "169.254.33.2"

	// localnetGatewayNextHopPort is the name of the gateway port on the host to which all
	// the packets leaving the OVN logical topology will be forwarded
	localnetGatewayNextHopPort = "ovn-k8s-gw0"

	// Routing table for ExternalIP communication
	localnetGatewayExternalIDTable = "6"
)

func getGatewayFamilyAddrs(gatewayIfAddrs []*net.IPNet) (string, string) {
	var gatewayIPv4, gatewayIPv6 string
	for _, gatewayIfAddr := range gatewayIfAddrs {
		if utilnet.IsIPv6(gatewayIfAddr.IP) {
			gatewayIPv6 = gatewayIfAddr.IP.String()
		} else {
			gatewayIPv4 = gatewayIfAddr.IP.String()
		}
	}
	return gatewayIPv4, gatewayIPv6
}

type localPortWatcherData struct {
	exec         util.ExecHelper
	recorder     record.EventRecorder
	gatewayIPv4  string
	gatewayIPv6  string
	localAddrSet map[string]net.IPNet
}

func newLocalPortWatcherData(exec util.ExecHelper, gatewayIfAddrs []*net.IPNet, recorder record.EventRecorder, localAddrSet map[string]net.IPNet) *localPortWatcherData {
	gatewayIPv4, gatewayIPv6 := getGatewayFamilyAddrs(gatewayIfAddrs)
	return &localPortWatcherData{
		exec:         exec,
		gatewayIPv4:  gatewayIPv4,
		gatewayIPv6:  gatewayIPv6,
		recorder:     recorder,
		localAddrSet: localAddrSet,
	}
}

func getLocalAddrs() (map[string]net.IPNet, error) {
	localAddrSet := make(map[string]net.IPNet)
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		ip, ipNet, err := net.ParseCIDR(addr.String())
		if err != nil {
			return nil, err
		}
		localAddrSet[ip.String()] = *ipNet
	}
	klog.V(5).Infof("Node local addresses initialized to: %v", localAddrSet)
	return localAddrSet, nil
}

func (npw *localPortWatcherData) networkHasAddress(ip net.IP) bool {
	for _, net := range npw.localAddrSet {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

func (npw *localPortWatcherData) addService(svc *kapi.Service) error {
	iptRules := []iptRule{}
	isIPv6Service := utilnet.IsIPv6String(svc.Spec.ClusterIP)
	gatewayIP := npw.gatewayIPv4
	if isIPv6Service {
		gatewayIP = npw.gatewayIPv6
	}
	for _, port := range svc.Spec.Ports {
		if util.ServiceTypeHasNodePort(svc) {
			if err := util.ValidatePort(port.Protocol, port.NodePort); err != nil {
				klog.Warningf("Invalid service node port %s, err: %v", port.Name, err)
				continue
			}

			if gatewayIP != "" {
				// Fix Azure/GCP LoadBalancers. They will forward traffic directly to the node with the
				// dest address as the load-balancer ingress IP and port
				iptRules = append(iptRules, getLoadBalancerIPTRules(svc, port, svc.Spec.ClusterIP, port.Port)...)
				iptRules = append(iptRules, getNodePortIPTRules(port, nil, svc.Spec.ClusterIP, port.Port)...)
				klog.V(5).Infof("Will add iptables rule for NodePort and Cloud load balancers: %v and "+
					"protocol: %v", port.NodePort, port.Protocol)
			} else {
				klog.Warningf("No gateway of appropriate IP family for NodePort Service %s/%s %s",
					svc.Namespace, svc.Name, svc.Spec.ClusterIP)
			}
		}
		for _, externalIP := range svc.Spec.ExternalIPs {
			if err := util.ValidatePort(port.Protocol, port.Port); err != nil {
				klog.Warningf("Invalid service port %s, err: %v", port.Name, err)
				break
			}
			if utilnet.IsIPv6String(externalIP) != isIPv6Service {
				klog.Warningf("Invalid ExternalIP %s for Service %s/%s with ClusterIP %s",
					externalIP, svc.Namespace, svc.Name, svc.Spec.ClusterIP)
				continue
			}
			if _, exists := npw.localAddrSet[externalIP]; exists {
				if !util.IsClusterIPSet(svc) {
					serviceRef := kapi.ObjectReference{
						Kind:      "Service",
						Namespace: svc.Namespace,
						Name:      svc.Name,
					}
					npw.recorder.Eventf(&serviceRef, kapi.EventTypeWarning, "UnsupportedServiceDefinition", "Unsupported service definition, headless service: %s with a local ExternalIP is not supported by ovn-kubernetes in local gateway mode", svc.Name)
					klog.Warningf("UnsupportedServiceDefinition event for service %s in namespace %s", svc.Name, svc.Namespace)
					continue
				}
				iptRules = append(iptRules, getExternalIPTRules(port, externalIP, svc.Spec.ClusterIP)...)
				klog.V(5).Infof("Will add iptables rule for ExternalIP: %s", externalIP)
			} else if npw.networkHasAddress(net.ParseIP(externalIP)) {
				klog.V(5).Infof("ExternalIP: %s is reachable through one of the interfaces on this node, will skip setup", externalIP)
			} else {
				if gatewayIP != "" {
					if stdout, stderr, err := npw.exec.RunIP("route", "replace", externalIP, "via", gatewayIP, "dev", localnetGatewayNextHopPort, "table", localnetGatewayExternalIDTable); err != nil {
						klog.Errorf("Error adding routing table entry for ExternalIP %s: stdout: %s, stderr: %s, err: %v", externalIP, stdout, stderr, err)
					} else {
						klog.V(5).Infof("Successfully added route for ExternalIP: %s", externalIP)
					}
				} else {
					klog.Warningf("No gateway of appropriate IP family for ExternalIP %s for Service %s/%s",
						externalIP, svc.Namespace, svc.Name)
				}
			}
		}
	}
	klog.V(5).Infof("Adding iptables rules: %v for service: %v", iptRules, svc.Name)
	return addIptRules(iptRules)
}

func (npw *localPortWatcherData) deleteService(svc *kapi.Service) error {
	iptRules := []iptRule{}
	isIPv6Service := utilnet.IsIPv6String(svc.Spec.ClusterIP)
	gatewayIP := npw.gatewayIPv4
	if isIPv6Service {
		gatewayIP = npw.gatewayIPv6
	}
	// Note that unlike with addService we just silently ignore IPv4/IPv6 mismatches here
	for _, port := range svc.Spec.Ports {
		if util.ServiceTypeHasNodePort(svc) {
			if gatewayIP != "" {
				// Fix Azure/GCP LoadBalancers. They will forward traffic directly to the node with the
				// dest address as the load-balancer ingress IP and port
				iptRules = append(iptRules, getLoadBalancerIPTRules(svc, port, svc.Spec.ClusterIP, port.Port)...)
				iptRules = append(iptRules, getNodePortIPTRules(port, nil, svc.Spec.ClusterIP, port.Port)...)
				klog.V(5).Infof("Will delete iptables rule for NodePort and cloud load balancers: %v and "+
					"protocol: %v", port.NodePort, port.Protocol)
			}
		}
		for _, externalIP := range svc.Spec.ExternalIPs {
			if utilnet.IsIPv6String(externalIP) != isIPv6Service {
				continue
			}
			if _, exists := npw.localAddrSet[externalIP]; exists {
				iptRules = append(iptRules, getExternalIPTRules(port, externalIP, svc.Spec.ClusterIP)...)
				klog.V(5).Infof("Will delete iptables rule for ExternalIP: %s", externalIP)
			} else if npw.networkHasAddress(net.ParseIP(externalIP)) {
				klog.V(5).Infof("ExternalIP: %s is reachable through one of the interfaces on this node, will skip cleanup", externalIP)
			} else {
				if gatewayIP != "" {
					if stdout, stderr, err := npw.exec.RunIP("route", "del", externalIP, "via", gatewayIP, "dev", localnetGatewayNextHopPort, "table", localnetGatewayExternalIDTable); err != nil {
						klog.Errorf("Error delete routing table entry for ExternalIP %s: stdout: %s, stderr: %s, err: %v", externalIP, stdout, stderr, err)
					} else {
						klog.V(5).Infof("Successfully deleted route for ExternalIP: %s", externalIP)
					}
				}
			}
		}
	}
	klog.V(5).Infof("Deleting iptables rules: %v for service: %v", iptRules, svc.Name)
	return delIptRules(iptRules)
}

func (npw *localPortWatcherData) syncServices(serviceInterface []interface{}) {
	removeStaleRoutes := func(keepRoutes []string) {
		stdout, stderr, err := npw.exec.RunIP("route", "list", "table", localnetGatewayExternalIDTable)
		if err != nil || stdout == "" {
			klog.Infof("No routing table entries for ExternalIP table %s: stdout: %s, stderr: %s, err: %v", localnetGatewayExternalIDTable, stdout, stderr, err)
			return
		}
		for _, existingRoute := range strings.Split(stdout, "\n") {
			isFound := false
			for _, keepRoute := range keepRoutes {
				if strings.Contains(existingRoute, keepRoute) {
					isFound = true
					break
				}
			}
			if !isFound {
				klog.V(5).Infof("Deleting stale routing rule: %s", existingRoute)
				if _, stderr, err := npw.exec.RunIP("route", "del", existingRoute, "table", localnetGatewayExternalIDTable); err != nil {
					klog.Errorf("Error deleting stale routing rule: stderr: %s, err: %v", stderr, err)
				}
			}
		}
	}
	keepIPTRules := []iptRule{}
	keepRoutes := []string{}
	for _, service := range serviceInterface {
		svc, ok := service.(*kapi.Service)
		if !ok {
			klog.Errorf("Spurious object in syncServices: %v", serviceInterface)
			continue
		}
		gatewayIP := npw.gatewayIPv4
		if utilnet.IsIPv6String(svc.Spec.ClusterIP) {
			gatewayIP = npw.gatewayIPv6
		}
		if gatewayIP != "" {
			keepIPTRules = append(keepIPTRules, getGatewayIPTRules(svc, gatewayIP, nil)...)
		}
		keepRoutes = append(keepRoutes, svc.Spec.ExternalIPs...)
	}
	for _, chain := range []string{iptableNodePortChain, iptableExternalIPChain} {
		recreateIPTRules("nat", chain, keepIPTRules)
		recreateIPTRules("filter", chain, keepIPTRules)
	}
	removeStaleRoutes(keepRoutes)
}

func initRoutingRules(exec util.ExecHelper) error {
	stdout, stderr, err := exec.RunIP("rule")
	if err != nil {
		return fmt.Errorf("error listing routing rules, stdout: %s, stderr: %s, err: %v", stdout, stderr, err)
	}
	if !strings.Contains(stdout, fmt.Sprintf("from all lookup %s", localnetGatewayExternalIDTable)) {
		if stdout, stderr, err := exec.RunIP("rule", "add", "from", "all", "table", localnetGatewayExternalIDTable); err != nil {
			return fmt.Errorf("error adding routing rule for ExternalIP table (%s): stdout: %s, stderr: %s, err: %v", localnetGatewayExternalIDTable, stdout, stderr, err)
		}
	}
	return nil
}

func (n *OvnNode) watchLocalPorts(npw *localPortWatcherData) error {
	if err := initLocalGatewayIPTables(); err != nil {
		return err
	}
	if err := initRoutingRules(n.exec); err != nil {
		return err
	}
	n.watchFactory.AddServiceHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			svc := obj.(*kapi.Service)
			err := npw.addService(svc)
			if err != nil {
				klog.Errorf("Error in adding service: %v", err)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			svcNew := new.(*kapi.Service)
			svcOld := old.(*kapi.Service)
			if reflect.DeepEqual(svcNew.Spec, svcOld.Spec) &&
				reflect.DeepEqual(svcNew.Status, svcOld.Status) {
				return
			}
			err := npw.deleteService(svcOld)
			if err != nil {
				klog.Errorf("Error in deleting service - %v", err)
			}
			err = npw.addService(svcNew)
			if err != nil {
				klog.Errorf("Error in modifying service: %v", err)
			}
		},
		DeleteFunc: func(obj interface{}) {
			svc := obj.(*kapi.Service)
			err := npw.deleteService(svc)
			if err != nil {
				klog.Errorf("Error in deleting service - %v", err)
			}
		},
	}, npw.syncServices)
	return nil
}

func cleanupLocalnetGateway(exec util.ExecHelper, physnet string) error {
	stdout, stderr, err := exec.RunOVSVsctl("--if-exists", "get", "Open_vSwitch", ".",
		"external_ids:ovn-bridge-mappings")
	if err != nil {
		return fmt.Errorf("failed to get ovn-bridge-mappings stderr:%s (%v)", stderr, err)
	}
	bridgeMappings := strings.Split(stdout, ",")
	for _, bridgeMapping := range bridgeMappings {
		m := strings.Split(bridgeMapping, ":")
		if physnet == m[0] {
			bridgeName := m[1]
			_, stderr, err = exec.RunOVSVsctl("--", "--if-exists", "del-br", bridgeName)
			if err != nil {
				return fmt.Errorf("failed to ovs-vsctl del-br %s stderr:%s (%v)", bridgeName, stderr, err)
			}
			break
		}
	}
	return err
}

func getLoadBalancerIPTRules(svc *kapi.Service, svcPort kapi.ServicePort, gatewayIP string, targetPort int32) []iptRule {
	var rules []iptRule
	ingPort := fmt.Sprintf("%d", svcPort.Port)
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		if ing.IP == "" {
			continue
		}
		rules = append(rules, iptRule{
			table: "nat",
			chain: iptableNodePortChain,
			args: []string{
				"-d", ing.IP,
				"-p", string(svcPort.Protocol), "--dport", ingPort,
				"-j", "DNAT", "--to-destination", util.JoinHostPortInt32(gatewayIP, targetPort),
			},
		})
		rules = append(rules, iptRule{
			table: "filter",
			chain: iptableNodePortChain,
			args: []string{
				"-d", ing.IP,
				"-p", string(svcPort.Protocol), "--dport", ingPort,
				"-j", "ACCEPT",
			},
		})
	}
	return rules
}

// since we share the host's k8s node IP, add OpenFlow flows
// -- to steer the NodePort traffic arriving on the host to the OVN logical topology and
// -- to also connection track the outbound north-south traffic through l3 gateway so that
//    the return traffic can be steered back to OVN logical topology
// -- to also handle unDNAT return traffic back out of the host
func addDefaultConntrackRulesLocal(exec util.ExecHelper, nodeName, gwBridge, gwIntf string, stopChan chan struct{}) error {
	// the name of the patch port created by ovn-controller is of the form
	// patch-<logical_port_name_of_localnet_port>-to-br-int
	localnetLpName := gwBridge + "_" + nodeName
	patchPort := "patch-" + localnetLpName + "-to-br-int"
	// Get ofport of patchPort, but before that make sure ovn-controller created
	// one for us (waits for about ovsCommandTimeout seconds)
	ofportPatch, stderr, err := exec.RunOVSVsctl("wait-until", "Interface", patchPort, "ofport>0",
		"--", "get", "Interface", patchPort, "ofport")
	if err != nil {
		return fmt.Errorf("failed while waiting on patch port %q to be created by ovn-controller and "+
			"while getting ofport. stderr: %q, error: %v", patchPort, stderr, err)
	}

	// Get ofport of physical interface
	ofportPhys, stderr, err := exec.RunOVSVsctl("get", "interface", gwIntf, "ofport")
	if err != nil {
		return fmt.Errorf("failed to get ofport of %s, stderr: %q, error: %v",
			gwIntf, stderr, err)
	}

	// replace the left over OpenFlow flows with the FLOOD action flow
	_, stderr, err = util.AddFloodActionOFFlow(exec, gwBridge)
	if err != nil {
		return fmt.Errorf("failed to replace-flows on bridge %q stderr:%s (%v)", gwBridge, stderr, err)
	}

	nFlows := 0
	if config.IPv4Mode {
		// table 0, packets coming from pods headed externally. Commit connections
		// so that reverse direction goes back to the pods.
		_, stderr, err = exec.RunOVSOfctl("add-flow", gwBridge,
			fmt.Sprintf("cookie=%s, priority=100, table=0, in_port=%s, ip, "+
				"actions=ct(commit, exec(load:0x1->NXM_NX_CT_LABEL), zone=%d), output:%s",
				defaultOpenFlowCookie, ofportPatch, config.Default.ConntrackZone, ofportPhys))
		if err != nil {
			return fmt.Errorf("failed to add openflow flow to %s, stderr: %q, "+
				"error: %v", gwBridge, stderr, err)
		}
		nFlows++

		// table 0, packets coming from external. Send it through conntrack and
		// resubmit to table 1 to know the state of the connection.
		_, stderr, err = exec.RunOVSOfctl("add-flow", gwBridge,
			fmt.Sprintf("cookie=%s, priority=50, table=0, in_port=%s, ip, "+
				"actions=ct(zone=%d, table=1)", defaultOpenFlowCookie, ofportPhys, config.Default.ConntrackZone))
		if err != nil {
			return fmt.Errorf("failed to add openflow flow to %s, stderr: %q, "+
				"error: %v", gwBridge, stderr, err)
		}
		nFlows++
	}
	if config.IPv6Mode {
		// table 0, packets coming from pods headed externally. Commit connections
		// so that reverse direction goes back to the pods.
		_, stderr, err = exec.RunOVSOfctl("add-flow", gwBridge,
			fmt.Sprintf("cookie=%s, priority=100, table=0, in_port=%s, ipv6, "+
				"actions=ct(commit, exec(load:0x1->NXM_NX_CT_LABEL), zone=%d), output:%s",
				defaultOpenFlowCookie, ofportPatch, config.Default.ConntrackZone, ofportPhys))
		if err != nil {
			return fmt.Errorf("failed to add openflow flow to %s, stderr: %q, "+
				"error: %v", gwBridge, stderr, err)
		}
		nFlows++

		// table 0, packets coming from external. Send it through conntrack and
		// resubmit to table 1 to know the state of the connection.
		_, stderr, err = exec.RunOVSOfctl("add-flow", gwBridge,
			fmt.Sprintf("cookie=%s, priority=50, table=0, in_port=%s, ipv6, "+
				"actions=ct(zone=%d, table=1)", defaultOpenFlowCookie, ofportPhys, config.Default.ConntrackZone))
		if err != nil {
			return fmt.Errorf("failed to add openflow flow to %s, stderr: %q, "+
				"error: %v", gwBridge, stderr, err)
		}
		nFlows++
	}

	// table 0, packets coming from host should go out physical port
	_, stderr, err = exec.RunOVSOfctl("add-flow", gwBridge,
		fmt.Sprintf("cookie=%s, priority=100, table=0, in_port=LOCAL, actions=output:%s",
			defaultOpenFlowCookie, ofportPhys))
	if err != nil {
		return fmt.Errorf("failed to add openflow flow to %s, stderr: %q, error: %v", gwBridge, stderr, err)
	}
	nFlows++

	// table 0, packets coming from OVN that are not IP should go out of the host
	_, stderr, err = exec.RunOVSOfctl("add-flow", gwBridge,
		fmt.Sprintf("cookie=%s, priority=99, table=0, in_port=%s, actions=output:%s",
			defaultOpenFlowCookie, ofportPatch, ofportPhys))
	if err != nil {
		return fmt.Errorf("failed to add openflow flow to %s, stderr: %q, error: %v", gwBridge, stderr, err)
	}

	nFlows++

	// table 1, known connections with ct_label 1 go to pod
	_, stderr, err = exec.RunOVSOfctl("add-flow", gwBridge,
		fmt.Sprintf("cookie=%s, priority=100, table=1, ct_label=0x1, "+
			"actions=output:%s", defaultOpenFlowCookie, ofportPatch))
	if err != nil {
		return fmt.Errorf("failed to add openflow flow to %s, stderr: %q, "+
			"error: %v", gwBridge, stderr, err)
	}
	nFlows++

	// table 1, traffic to pod subnet go directly to OVN
	for _, clusterEntry := range config.Default.ClusterSubnets {
		cidr := clusterEntry.CIDR
		var ipPrefix string
		if cidr.IP.To4() != nil {
			ipPrefix = "ip"
		} else {
			ipPrefix = "ipv6"
		}
		mask, _ := cidr.Mask.Size()
		_, stderr, err = exec.RunOVSOfctl("add-flow", gwBridge,
			fmt.Sprintf("cookie=%s, priority=3, table=1, %s, %s_dst=%s/%d, actions=output:%s",
				defaultOpenFlowCookie, ipPrefix, ipPrefix, cidr.IP, mask, ofportPatch))
		if err != nil {
			return fmt.Errorf("failed to add openflow flow to %s, stderr: %q, "+
				"error: %v", gwBridge, stderr, err)
		}
		nFlows++

	}

	if config.IPv6Mode {
		// REMOVEME(trozet) when https://bugzilla.kernel.org/show_bug.cgi?id=11797 is resolved
		// must flood icmpv6 traffic as it fails to create a CT entry
		_, stderr, err = exec.RunOVSOfctl("add-flow", gwBridge,
			fmt.Sprintf("cookie=%s, priority=1, table=1,icmp6 actions=FLOOD", defaultOpenFlowCookie))
		if err != nil {
			return fmt.Errorf("failed to add openflow flow to %s, stderr: %q, "+
				"error: %v", gwBridge, stderr, err)
		}
		nFlows++
	}

	// table 1, all other connections go to host
	_, stderr, err = exec.RunOVSOfctl("add-flow", gwBridge,
		fmt.Sprintf("cookie=%s, priority=0, table=1, actions=LOCAL", defaultOpenFlowCookie))
	if err != nil {
		return fmt.Errorf("failed to add openflow flow to %s, stderr: %q, "+
			"error: %v", gwBridge, stderr, err)
	}
	nFlows++

	// add health check function to check default OpenFlow flows are on the shared gateway bridge
	go checkDefaultConntrackRules(exec, gwBridge, gwIntf, patchPort, ofportPhys, ofportPatch, nFlows, stopChan)
	return nil
}
