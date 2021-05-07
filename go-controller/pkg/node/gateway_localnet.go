// +build linux

package node

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

const (
	// localnetGatewayNextHopPort is the name of the gateway port on the host to which all
	// the packets leaving/entering the OVN logical topology to the host will egress for shared gw mode
	localnetGatewayNextHopPort = "ovn-k8s-gw0"

	// Routing table for ExternalIP communication
	localnetGatewayExternalIDTable = "6"
)

func newLocalGateway(nodeName string, hostSubnets []*net.IPNet, gwNextHops []net.IP, gwIntf string, nodeAnnotator kube.Annotator, recorder record.EventRecorder, cfg *managementPortConfig) (*gateway, error) {
	gw := &gateway{}
	var gatewayIfAddrs []*net.IPNet
	for _, hostSubnet := range hostSubnets {
		// local gateway mode uses mp0 as default path for all ingress traffic into OVN
		var nextHop *net.IPNet
		if utilnet.IsIPv6CIDR(hostSubnet) {
			nextHop = cfg.ipv6.ifAddr
		} else {
			nextHop = cfg.ipv4.ifAddr
		}
		// gatewayIfAddrs are the OVN next hops via mp0
		gatewayIfAddrs = append(gatewayIfAddrs, util.GetNodeGatewayIfAddr(hostSubnet))

		// add iptables masquerading for mp0 to exit the host for egress
		cidr := nextHop.IP.Mask(nextHop.Mask)
		cidrNet := &net.IPNet{IP: cidr, Mask: nextHop.Mask}
		err := initLocalGatewayNATRules(types.K8sMgmtIntfName, cidrNet)
		if err != nil {
			return nil, fmt.Errorf("failed to add local NAT rules for: %s, err: %v", types.K8sMgmtIntfName, err)
		}
	}

	bridgeName, uplinkName, macAddress, _, err := gatewayInitInternal(
		nodeName, gwIntf, hostSubnets, gwNextHops, nil, nodeAnnotator)
	if err != nil {
		return nil, err
	}

	// the name of the patch port created by ovn-controller is of the form
	// patch-<logical_port_name_of_localnet_port>-to-br-int
	patchPort := "patch-" + bridgeName + "_" + nodeName + "-to-br-int"

	if config.Gateway.NodeportEnable {
		localAddrSet, err := getLocalAddrs()
		if err != nil {
			return nil, err
		}

		if err := initLocalGatewayIPTables(); err != nil {
			return nil, err
		}
		if err := initRoutingRules(); err != nil {
			return nil, err
		}
		gw.localPortWatcher = newLocalPortWatcher(gatewayIfAddrs, recorder, localAddrSet)
	}

	gw.readyFunc = func() (bool, error) {
		return gatewayReady(patchPort)
	}

	gw.initFunc = func() error {
		klog.Info("Creating Local Gateway Openflow Manager")
		var err error
		gw.openflowManager, err = newLocalGatewayOpenflowManager(patchPort, macAddress.String(), bridgeName, uplinkName)
		return err
	}

	return gw, nil
}

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

type localPortWatcher struct {
	recorder     record.EventRecorder
	gatewayIPv4  string
	gatewayIPv6  string
	localAddrSet map[string]net.IPNet
}

func newLocalPortWatcher(gatewayIfAddrs []*net.IPNet, recorder record.EventRecorder, localAddrSet map[string]net.IPNet) *localPortWatcher {
	gatewayIPv4, gatewayIPv6 := getGatewayFamilyAddrs(gatewayIfAddrs)
	return &localPortWatcher{
		recorder:     recorder,
		gatewayIPv4:  gatewayIPv4,
		gatewayIPv6:  gatewayIPv6,
		localAddrSet: localAddrSet,
	}
}

func (l *localPortWatcher) AddService(svc *kapi.Service) {
	err := l.addService(svc)
	if err != nil {
		klog.Errorf("Error in adding service: %v", err)
	}
}

func (l *localPortWatcher) UpdateService(old, new *kapi.Service) {
	if reflect.DeepEqual(new.Spec.Ports, old.Spec.Ports) &&
		reflect.DeepEqual(new.Spec.ExternalIPs, old.Spec.ExternalIPs) &&
		reflect.DeepEqual(new.Spec.ClusterIP, old.Spec.ClusterIP) &&
		reflect.DeepEqual(new.Spec.ClusterIPs, old.Spec.ClusterIPs) &&
		reflect.DeepEqual(new.Spec.Type, old.Spec.Type) &&
		reflect.DeepEqual(new.Status.LoadBalancer.Ingress, old.Status.LoadBalancer.Ingress) {
		klog.V(5).Infof("Skipping service update for: %s as change does not apply to any of .Spec.Ports, "+
			".Spec.ExternalIP, .Spec.ClusterIP, .Spec.Type, .Status.LoadBalancer.Ingress", new.Name)
		return
	}
	err := l.deleteService(old)
	if err != nil {
		klog.Errorf("Error in deleting service - %v", err)
	}
	err = l.addService(new)
	if err != nil {
		klog.Errorf("Error in modifying service: %v", err)
	}
}

func (l *localPortWatcher) DeleteService(svc *kapi.Service) {
	err := l.deleteService(svc)
	if err != nil {
		klog.Errorf("Error in deleting service - %v", err)
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

func (l *localPortWatcher) networkHasAddress(ip net.IP) bool {
	for _, net := range l.localAddrSet {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

func (l *localPortWatcher) addService(svc *kapi.Service) error {
	// don't process headless service or services that doesn't have NodePorts or ExternalIPs
	if !util.ServiceTypeHasClusterIP(svc) || !util.IsClusterIPSet(svc) {
		return nil
	}

	for _, ip := range util.GetClusterIPs(svc) {
		iptRules := []iptRule{}
		isIPv6Service := utilnet.IsIPv6String(ip)
		gatewayIP := l.gatewayIPv4
		if isIPv6Service {
			gatewayIP = l.gatewayIPv6
		}
		// holds map of external ips and if they are currently using routes
		routeUsage := make(map[string]bool)
		for _, port := range svc.Spec.Ports {
			// Fix Azure/GCP LoadBalancers. They will forward traffic directly to the node with the
			// dest address as the load-balancer ingress IP and port
			iptRules = append(iptRules, getLoadBalancerIPTRules(svc, port, ip, port.Port)...)

			if port.NodePort > 0 {
				if gatewayIP != "" {
					iptRules = append(iptRules, getNodePortIPTRules(port, ip, port.Port)...)
					klog.V(5).Infof("Will add iptables rule for NodePort: %v and "+
						"protocol: %v", port.NodePort, port.Protocol)
				} else {
					klog.Warningf("No gateway of appropriate IP family for NodePort Service %s/%s %s",
						svc.Namespace, svc.Name, ip)
				}
			}
			for _, externalIP := range svc.Spec.ExternalIPs {
				if utilnet.IsIPv6String(externalIP) != isIPv6Service {
					continue
				}
				if _, exists := l.localAddrSet[externalIP]; exists {
					iptRules = append(iptRules, getExternalIPTRules(port, externalIP, ip)...)
					klog.V(5).Infof("Will add iptables rule for ExternalIP: %s", externalIP)
				} else if l.networkHasAddress(net.ParseIP(externalIP)) {
					klog.V(5).Infof("ExternalIP: %s is reachable through one of the interfaces on this node, will skip setup", externalIP)
				} else {
					if gatewayIP != "" {
						routeUsage[externalIP] = true
					} else {
						klog.Warningf("No gateway of appropriate IP family for ExternalIP %s for Service %s/%s",
							externalIP, svc.Namespace, svc.Name)
					}
				}
			}
		}
		for externalIP := range routeUsage {
			if stdout, stderr, err := util.RunIP("route", "replace", externalIP, "via", gatewayIP, "dev", types.K8sMgmtIntfName, "table", localnetGatewayExternalIDTable); err != nil {
				klog.Errorf("Error adding routing table entry for ExternalIP %s, via gw: %s: stdout: %s, stderr: %s, err: %v", externalIP, gatewayIP, stdout, stderr, err)
			} else {
				klog.Infof("Successfully added route for ExternalIP: %s", externalIP)
			}
		}
		klog.Infof("Adding iptables rules: %v for service: %v", iptRules, svc.Name)
		if err := addIptRules(iptRules); err != nil {
			klog.Errorf("Error adding iptables rules: %v for service: %v err: %v", iptRules, svc.Name, err)
		}
	}
	return nil
}

func (l *localPortWatcher) deleteService(svc *kapi.Service) error {
	// don't process headless service or services that doesn't have NodePorts or ExternalIPs
	if !util.ServiceTypeHasClusterIP(svc) || !util.IsClusterIPSet(svc) {
		return nil
	}

	for _, ip := range util.GetClusterIPs(svc) {
		iptRules := []iptRule{}
		isIPv6Service := utilnet.IsIPv6String(ip)
		gatewayIP := l.gatewayIPv4
		if isIPv6Service {
			gatewayIP = l.gatewayIPv6
		}
		// holds map of external ips and if they are currently using routes
		routeUsage := make(map[string]bool)
		// Note that unlike with addService we just silently ignore IPv4/IPv6 mismatches here
		for _, port := range svc.Spec.Ports {
			// Fix Azure/GCP LoadBalancers. They will forward traffic directly to the node with the
			// dest address as the load-balancer ingress IP and port
			iptRules = append(iptRules, getLoadBalancerIPTRules(svc, port, ip, port.Port)...)
			if port.NodePort > 0 {
				if gatewayIP != "" {
					iptRules = append(iptRules, getNodePortIPTRules(port, ip, port.Port)...)
					klog.V(5).Infof("Will delete iptables rule for NodePort: %v and "+
						"protocol: %v", port.NodePort, port.Protocol)
				}
			}
			for _, externalIP := range svc.Spec.ExternalIPs {
				if utilnet.IsIPv6String(externalIP) != isIPv6Service {
					continue
				}
				if _, exists := l.localAddrSet[externalIP]; exists {
					iptRules = append(iptRules, getExternalIPTRules(port, externalIP, ip)...)
					klog.V(5).Infof("Will delete iptables rule for ExternalIP: %s", externalIP)
				} else if l.networkHasAddress(net.ParseIP(externalIP)) {
					klog.V(5).Infof("ExternalIP: %s is reachable through one of the interfaces on this node, will skip cleanup", externalIP)
				} else {
					if gatewayIP != "" {
						routeUsage[externalIP] = true
					}
				}
			}
		}

		for externalIP := range routeUsage {
			if stdout, stderr, err := util.RunIP("route", "del", externalIP, "via", gatewayIP, "dev", types.K8sMgmtIntfName, "table", localnetGatewayExternalIDTable); err != nil {
				klog.Errorf("Error delete routing table entry for ExternalIP %s: stdout: %s, stderr: %s, err: %v", externalIP, stdout, stderr, err)
			} else {
				klog.Infof("Successfully deleted route for ExternalIP: %s", externalIP)
			}
		}

		klog.Infof("Deleting iptables rules: %v for service: %v", iptRules, svc.Name)
		if err := delIptRules(iptRules); err != nil {
			klog.Errorf("Error deleting iptables rules: %v for service: %v err: %v", iptRules, svc.Name, err)
		}
	}
	return nil
}

func (l *localPortWatcher) SyncServices(serviceInterface []interface{}) {
	removeStaleRoutes := func(keepRoutes []string) {
		stdout, stderr, err := util.RunIP("route", "list", "table", localnetGatewayExternalIDTable)
		if err != nil || stdout == "" {
			klog.Infof("No routing table entries for ExternalIP table %s: stdout: %s, stderr: %s, err: %v",
				localnetGatewayExternalIDTable, stdout, strings.Replace(stderr, "\n", "", -1), err)
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
				klog.Infof("Deleting stale routing rule: %s", existingRoute)
				if _, stderr, err := util.RunIP("route", "del", existingRoute, "table", localnetGatewayExternalIDTable); err != nil {
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
		keepIPTRules = append(keepIPTRules, getGatewayIPTRules(svc, []string{l.gatewayIPv4, l.gatewayIPv6})...)
		keepRoutes = append(keepRoutes, svc.Spec.ExternalIPs...)
	}
	for _, chain := range []string{iptableNodePortChain, iptableExternalIPChain} {
		recreateIPTRules("nat", chain, keepIPTRules)
	}
	removeStaleRoutes(keepRoutes)
}

func initRoutingRules() error {
	stdout, stderr, err := util.RunIP("rule")
	if err != nil {
		return fmt.Errorf("error listing routing rules, stdout: %s, stderr: %s, err: %v", stdout, stderr, err)
	}
	if !strings.Contains(stdout, fmt.Sprintf("from all lookup %s", localnetGatewayExternalIDTable)) {
		if stdout, stderr, err := util.RunIP("rule", "add", "from", "all", "table", localnetGatewayExternalIDTable); err != nil {
			return fmt.Errorf("error adding routing rule for ExternalIP table (%s): stdout: %s, stderr: %s, err: %v", localnetGatewayExternalIDTable, stdout, stderr, err)
		}
	}
	return nil
}

func cleanupLocalnetGateway(physnet string) error {
	stdout, stderr, err := util.RunOVSVsctl("--if-exists", "get", "Open_vSwitch", ".",
		"external_ids:ovn-bridge-mappings")
	if err != nil {
		return fmt.Errorf("failed to get ovn-bridge-mappings stderr:%s (%v)", stderr, err)
	}
	bridgeMappings := strings.Split(stdout, ",")
	for _, bridgeMapping := range bridgeMappings {
		m := strings.Split(bridgeMapping, ":")
		if physnet == m[0] {
			bridgeName := m[1]
			_, stderr, err = util.RunOVSVsctl("--", "--if-exists", "del-br", bridgeName)
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
	}
	return rules
}

// since we share the host's k8s node IP, add OpenFlow flows
// -- to steer the NodePort traffic arriving on the host to the OVN logical topology and
// -- to also connection track the outbound north-south traffic through l3 gateway so that
//    the return traffic can be steered back to OVN logical topology
// -- to also handle unDNAT return traffic back out of the host
func newLocalGatewayOpenflowManager(patchPort, macAddress, gwBridge, gwIntf string) (*openflowManager, error) {
	// Get ofport of patchPort, but before that make sure ovn-controller created
	// one for us (waits for about ovsCommandTimeout seconds)
	ofportPatch, stderr, err := util.RunOVSVsctl("get", "Interface", patchPort, "ofport")
	if err != nil {
		return nil, fmt.Errorf("failed while waiting on patch port %q to be created by ovn-controller and "+
			"while getting ofport. stderr: %q, error: %v", patchPort, stderr, err)
	}

	// Get ofport of physical interface
	ofportPhys, stderr, err := util.RunOVSVsctl("get", "interface", gwIntf, "ofport")
	if err != nil {
		return nil, fmt.Errorf("failed to get ofport of %s, stderr: %q, error: %v",
			gwIntf, stderr, err)
	}

	var dftFlows []string

	// table 0, we check to see if this dest mac is the shared mac, if so flood to both ports (non-IP traffic)
	dftFlows = append(dftFlows,
		fmt.Sprintf("cookie=%s, priority=10, table=0, in_port=%s, dl_dst=%s, actions=output:%s,output:LOCAL",
			defaultOpenFlowCookie, ofportPhys, macAddress, ofportPatch))

	if config.IPv4Mode {
		// table 0, packets coming from pods headed externally. Commit connections
		// so that reverse direction goes back to the pods.
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=100, table=0, in_port=%s, ip, "+
				"actions=ct(commit, exec(load:0x1->NXM_NX_CT_LABEL), zone=%d), output:%s",
				defaultOpenFlowCookie, ofportPatch, config.Default.ConntrackZone, ofportPhys))

		// table 0, packets coming from external. Send it through conntrack and
		// resubmit to table 1 to know the state of the connection.
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=50, table=0, in_port=%s, ip, "+
				"actions=ct(zone=%d, table=1)", defaultOpenFlowCookie, ofportPhys, config.Default.ConntrackZone))
	}
	if config.IPv6Mode {
		// table 0, packets coming from pods headed externally. Commit connections
		// so that reverse direction goes back to the pods.
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=100, table=0, in_port=%s, ipv6, "+
				"actions=ct(commit, exec(load:0x1->NXM_NX_CT_LABEL), zone=%d), output:%s",
				defaultOpenFlowCookie, ofportPatch, config.Default.ConntrackZone, ofportPhys))

		// table 0, packets coming from external. Send it through conntrack and
		// resubmit to table 1 to know the state of the connection.
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=50, table=0, in_port=%s, ipv6, "+
				"actions=ct(zone=%d, table=1)", defaultOpenFlowCookie, ofportPhys, config.Default.ConntrackZone))
	}

	// table 0, packets coming from host should go out physical port
	dftFlows = append(dftFlows,
		fmt.Sprintf("cookie=%s, priority=100, table=0, in_port=LOCAL, actions=output:%s",
			defaultOpenFlowCookie, ofportPhys))

	// table 0, packets coming from OVN that are not IP should go out of the host
	dftFlows = append(dftFlows,
		fmt.Sprintf("cookie=%s, priority=99, table=0, in_port=%s, actions=output:%s",
			defaultOpenFlowCookie, ofportPatch, ofportPhys))

	// table 1, known connections with ct_label 1 go to pod
	dftFlows = append(dftFlows,
		fmt.Sprintf("cookie=%s, priority=100, table=1, ct_label=0x1, "+
			"actions=output:%s", defaultOpenFlowCookie, ofportPatch))

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
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=15, table=1, %s, %s_dst=%s/%d, actions=output:%s",
				defaultOpenFlowCookie, ipPrefix, ipPrefix, cidr.IP, mask, ofportPatch))
	}

	if config.IPv6Mode {
		// REMOVEME(trozet) when https://bugzilla.kernel.org/show_bug.cgi?id=11797 is resolved
		// must flood icmpv6 Route Advertisement and Neighbor Advertisement traffic as it fails to create a CT entry
		for _, icmpType := range []int{types.RouteAdvertisementICMPType, types.NeighborAdvertisementICMPType} {
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=14, table=1,icmp6,icmpv6_type=%d actions=FLOOD",
					defaultOpenFlowCookie, icmpType))
		}

		// We send BFD traffic both on the host and in ovn
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=13, table=1, in_port=%s, udp6, tp_dst=3784, actions=output:%s,output:LOCAL",
				defaultOpenFlowCookie, ofportPhys, ofportPatch))
	}

	if config.IPv4Mode {
		// We send BFD traffic both on the host and in ovn
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=13, table=1, in_port=%s, udp, tp_dst=3784, actions=output:%s,output:LOCAL",
				defaultOpenFlowCookie, ofportPhys, ofportPatch))
	}

	// table 1, we check to see if this dest mac is the shared mac, if so send to host
	dftFlows = append(dftFlows,
		fmt.Sprintf("cookie=%s, priority=10, table=1, dl_dst=%s, actions=output:LOCAL",
			defaultOpenFlowCookie, macAddress))

	// table 1, all other connections do normal processing
	dftFlows = append(dftFlows,
		fmt.Sprintf("cookie=%s, priority=0, table=1, actions=NORMAL", defaultOpenFlowCookie))

	// add health check function to check default OpenFlow flows are on the shared gateway bridge
	ofm := &openflowManager{
		gwBridge:    gwBridge,
		physIntf:    gwIntf,
		patchIntf:   patchPort,
		ofportPhys:  ofportPhys,
		ofportPatch: ofportPatch,
		flowCache:   make(map[string][]string),
		flowMutex:   sync.Mutex{},
		flowChan:    make(chan struct{}, 1),
	}
	ofm.updateFlowCacheEntry("NORMAL", []string{fmt.Sprintf("table=0,priority=0,actions=%s\n", util.NormalAction)})
	ofm.updateFlowCacheEntry("DEFAULT", dftFlows)
	ofm.requestFlowSync()
	return ofm, nil
}
