package node

import (
	"fmt"
	"hash/fnv"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

const (
	// defaultOpenFlowCookie identifies default open flow rules added to the host OVS bridge.
	// The hex number 0xdeff105, aka defflos, is meant to sound like default flows.
	defaultOpenFlowCookie = "0xdeff105"
)

// nodePortWatcher manages OpenfLow and iptables rules
// to ensure that services using NodePorts are accessible
type nodePortWatcher struct {
	ofportPhys  string
	ofportPatch string
	gwBridge    string
	ofm         *openflowManager
}

func (npw *nodePortWatcher) updateServiceFlowCache(service *kapi.Service, add bool) {
	var cookie, key string
	var err error

	// cookie is only used for debugging purpose. so it is not fatal error if cookie is failed to be generated.
	for _, svcPort := range service.Spec.Ports {
		protocol := strings.ToLower(string(svcPort.Protocol))
		if svcPort.NodePort > 0 {
			flowProtocols := []string{}
			if config.IPv4Mode {
				flowProtocols = append(flowProtocols, protocol)
			}
			if config.IPv6Mode {
				flowProtocols = append(flowProtocols, protocol+"6")
			}
			for _, flowProtocol := range flowProtocols {
				cookie, err = svcToCookie(service.Namespace, service.Name, flowProtocol, svcPort.NodePort)
				if err != nil {
					klog.Warningf("Unable to generate cookie for nodePort svc: %s, %s, %s, %d, error: %v",
						service.Namespace, service.Name, flowProtocol, svcPort.Port, err)
					cookie = "0"
				}
				key = strings.Join([]string{"NodePort", service.Namespace, service.Name, flowProtocol, fmt.Sprintf("%d", svcPort.NodePort)}, "_")
				if !add {
					npw.ofm.deleteFlowsByKey(key)
				} else {
					npw.ofm.updateFlowCacheEntry(key, []string{
						fmt.Sprintf("cookie=%s, priority=100, in_port=%s, %s, tp_dst=%d, actions=%s",
							cookie, npw.ofportPhys, flowProtocol, svcPort.NodePort, npw.ofportPatch)})
				}
			}
		}

		// Flows for cloud load balancers on Azure/GCP
		// Established traffic is handled by default conntrack rules
		// NodePort/Ingress access in the OVS bridge will only ever come from outside of the host
		for _, ing := range service.Status.LoadBalancer.Ingress {
			if ing.IP == "" {
				continue
			}
			ingIP := net.ParseIP(ing.IP)
			if ingIP == nil {
				klog.Errorf("Failed to parse ingress IP: %s", ing.IP)
				continue
			}
			cookie, err = svcToCookie(service.Namespace, service.Name, ingIP.String(), svcPort.Port)
			if err != nil {
				klog.Warningf("Unable to generate cookie for ingress svc: %s, %s, %s, %d, error: %v",
					service.Namespace, service.Name, ingIP.String(), svcPort.Port, err)
				cookie = "0"
			}
			flowProtocol := protocol
			nwDst := "nw_dst"
			if utilnet.IsIPv6String(ing.IP) {
				flowProtocol = protocol + "6"
				nwDst = "ipv6_dst"
			}
			key = strings.Join([]string{"Ingress", service.Namespace, service.Name, ingIP.String(), fmt.Sprintf("%d", svcPort.Port)}, "_")
			if !add {
				npw.ofm.deleteFlowsByKey(key)
			} else {
				npw.ofm.updateFlowCacheEntry(key, []string{
					fmt.Sprintf("cookie=%s, priority=100, in_port=%s, %s, %s=%s, tp_dst=%d, actions=%s",
						cookie, npw.ofportPhys, flowProtocol, nwDst, ing.IP, svcPort.Port, npw.ofportPatch)})
			}
		}

		for _, externalIP := range service.Spec.ExternalIPs {
			flowProtocol := protocol
			nwDst := "nw_dst"
			if utilnet.IsIPv6String(externalIP) {
				flowProtocol = protocol + "6"
				nwDst = "ipv6_dst"
			}
			cookie, err = svcToCookie(service.Namespace, service.Name, externalIP, svcPort.Port)
			if err != nil {
				klog.Warningf("Unable to generate cookie for external svc: %s, %s, %s, %d, error: %v",
					service.Namespace, service.Name, externalIP, svcPort.Port, err)
				cookie = "0"
			}
			key := strings.Join([]string{"External", service.Namespace, service.Name, externalIP, fmt.Sprintf("%d", svcPort.Port)}, "_")
			if !add {
				npw.ofm.deleteFlowsByKey(key)
			} else {
				npw.ofm.updateFlowCacheEntry(key, []string{
					fmt.Sprintf("cookie=%s, priority=100, in_port=%s, %s, %s=%s, tp_dst=%d, actions=%s",
						cookie, npw.ofportPhys, flowProtocol, nwDst, externalIP, svcPort.Port, npw.ofportPatch)})
			}
		}
	}
}

// AddService handles configuring shared gateway bridge flows to steer External IP, Node Port, Ingress LB traffic into OVN
func (npw *nodePortWatcher) AddService(service *kapi.Service) {

	// don't process headless service or services that doesn't have NodePorts or ExternalIPs
	if !util.ServiceTypeHasClusterIP(service) || !util.IsClusterIPSet(service) {
		return
	}
	npw.updateServiceFlowCache(service, true)
	npw.ofm.requestFlowSync()
	addSharedGatewayIptRules(service)
}

func (npw *nodePortWatcher) UpdateService(old, new *kapi.Service) {
	if reflect.DeepEqual(new.Spec.Ports, old.Spec.Ports) &&
		reflect.DeepEqual(new.Spec.ExternalIPs, old.Spec.ExternalIPs) &&
		reflect.DeepEqual(new.Spec.ClusterIP, old.Spec.ClusterIP) &&
		reflect.DeepEqual(new.Spec.Type, old.Spec.Type) &&
		reflect.DeepEqual(new.Status.LoadBalancer.Ingress, old.Status.LoadBalancer.Ingress) {
		klog.V(5).Infof("Skipping service update for: %s as change does not apply to any of .Spec.Ports, "+
			".Spec.ExternalIP, .Spec.ClusterIP, .Spec.Type, .Status.LoadBalancer.Ingress", new.Name)
		return
	}
	needFlowSync := false
	if util.ServiceTypeHasClusterIP(old) && util.IsClusterIPSet(old) {
		npw.updateServiceFlowCache(old, false)
		delSharedGatewayIptRules(old)
		needFlowSync = true
	}

	if util.ServiceTypeHasClusterIP(new) && util.IsClusterIPSet(new) {
		npw.updateServiceFlowCache(new, true)
		addSharedGatewayIptRules(new)
		needFlowSync = true
	}

	if needFlowSync {
		npw.ofm.requestFlowSync()
	}
}

func (npw *nodePortWatcher) DeleteService(service *kapi.Service) {
	// don't process headless service
	if !util.ServiceTypeHasClusterIP(service) || !util.IsClusterIPSet(service) {
		return
	}
	npw.updateServiceFlowCache(service, false)
	npw.ofm.requestFlowSync()
	delSharedGatewayIptRules(service)
}

func (npw *nodePortWatcher) SyncServices(services []interface{}) {
	for _, serviceInterface := range services {
		service, ok := serviceInterface.(*kapi.Service)
		if !ok {
			klog.Errorf("Spurious object in syncServices: %v",
				serviceInterface)
			continue
		}
		npw.updateServiceFlowCache(service, true)
	}

	npw.ofm.requestFlowSync()
	syncSharedGatewayIptRules(services)
}

// since we share the host's k8s node IP, add OpenFlow flows
// -- to steer the NodePort traffic arriving on the host to the OVN logical topology and
// -- to also connection track the outbound north-south traffic through l3 gateway so that
//    the return traffic can be steered back to OVN logical topology
// -- to also handle unDNAT return traffic back out of the host
func newSharedGatewayOpenFlowManager(patchPort, macAddress, gwBridge, gwIntf string) (*openflowManager, error) {
	// Get ofport of patchPort
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

	// table 0, we check to see if this dest mac is the shared mac, if so flood to both ports
	dftFlows = append(dftFlows,
		fmt.Sprintf("cookie=%s, priority=10, table=0, in_port=%s, dl_dst=%s, actions=output:%s,output:LOCAL",
			defaultOpenFlowCookie, ofportPhys, macAddress, ofportPatch))

	if config.IPv4Mode {
		// table 0, packets coming from pods headed externally. Commit connections
		// so that reverse direction goes back to the pods.
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=100, in_port=%s, ip, "+
				"actions=ct(commit, zone=%d), output:%s",
				defaultOpenFlowCookie, ofportPatch, config.Default.ConntrackZone, ofportPhys))

		// table 0, packets coming from external. Send it through conntrack and
		// resubmit to table 1 to know the state of the connection.
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=50, in_port=%s, ip, "+
				"actions=ct(zone=%d, table=1)", defaultOpenFlowCookie, ofportPhys, config.Default.ConntrackZone))
	}
	if config.IPv6Mode {
		// table 0, packets coming from pods headed externally. Commit connections
		// so that reverse direction goes back to the pods.
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=100, in_port=%s, ipv6, "+
				"actions=ct(commit, zone=%d), output:%s",
				defaultOpenFlowCookie, ofportPatch, config.Default.ConntrackZone, ofportPhys))

		// table 0, packets coming from external. Send it through conntrack and
		// resubmit to table 1 to know the state of the connection.
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=50, in_port=%s, ipv6, "+
				"actions=ct(zone=%d, table=1)", defaultOpenFlowCookie, ofportPhys, config.Default.ConntrackZone))
	}

	// table 1, established and related connections go to pod
	dftFlows = append(dftFlows,
		fmt.Sprintf("cookie=%s, priority=100, table=1, ct_state=+trk+est, "+
			"actions=output:%s", defaultOpenFlowCookie, ofportPatch))

	dftFlows = append(dftFlows,
		fmt.Sprintf("cookie=%s, priority=100, table=1, ct_state=+trk+rel, "+
			"actions=output:%s", defaultOpenFlowCookie, ofportPatch))

	if config.Gateway.DisableSNATMultipleGWs {
		// table 1, traffic to pod subnet go directly to OVN
		for _, clusterEntry := range config.Default.ClusterSubnets {
			cidr := clusterEntry.CIDR
			var ipPrefix string
			if utilnet.IsIPv6CIDR(cidr) {
				ipPrefix = "ipv6"
			} else {
				ipPrefix = "ip"
			}
			dftFlows = append(dftFlows,
				fmt.Sprintf("cookie=%s, priority=15, table=1, %s, %s_dst=%s, actions=output:%s",
					defaultOpenFlowCookie, ipPrefix, ipPrefix, cidr, ofportPatch))
		}
	}

	// table 1, we check to see if this dest mac is the shared mac, if so send to host
	dftFlows = append(dftFlows,
		fmt.Sprintf("cookie=%s, priority=10, table=1, dl_dst=%s, actions=output:LOCAL",
			defaultOpenFlowCookie, macAddress))

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

	// table 1, all other connections do normal processing
	dftFlows = append(dftFlows,
		fmt.Sprintf("cookie=%s, priority=0, table=1, actions=output:NORMAL", defaultOpenFlowCookie))

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

	// defer flowSync until syncService() to prevent the existing service OpenFlows being deleted
	return ofm, nil
}

func newSharedGateway(nodeName string, subnets []*net.IPNet, gwNextHops []net.IP, gwIntf string, nodeAnnotator kube.Annotator) (*gateway, error) {
	klog.Info("Creating new shared gateway")
	gw := &gateway{}

	bridgeName, uplinkName, macAddress, _, err := gatewayInitInternal(
		nodeName, gwIntf, subnets, gwNextHops, nodeAnnotator)
	if err != nil {
		return nil, err
	}

	// the name of the patch port created by ovn-controller is of the form
	// patch-<logical_port_name_of_localnet_port>-to-br-int
	patchPort := "patch-" + bridgeName + "_" + nodeName + "-to-br-int"

	gw.readyFunc = func() (bool, error) {
		return gatewayReady(patchPort)
	}

	gw.initFunc = func() error {
		// Program cluster.GatewayIntf to let non-pod traffic to go to host
		// stack
		klog.Info("Creating Shared Gateway Openflow Manager")
		var err error

		gw.openflowManager, err = newSharedGatewayOpenFlowManager(patchPort, macAddress.String(), bridgeName, uplinkName)
		if err != nil {
			return err
		}

		if config.Gateway.NodeportEnable {
			klog.Info("Creating Shared Gateway Node Port Watcher")
			gw.nodePortWatcher, err = newNodePortWatcher(patchPort, bridgeName, uplinkName, gw.openflowManager)
			if err != nil {
				return err
			}
		} else {
			// no service OpenFlows, request to sync flows now.
			gw.openflowManager.requestFlowSync()
		}
		return nil
	}

	klog.Info("Shared Gateway Creation Complete")
	return gw, nil
}

func checkSharedGatewayIPTables(kClient kube.Interface, stopChan <-chan struct{}) {
	for {
		select {
		case <-time.After(30 * time.Second):
			warnings, err := initSharedGatewayIPTables()
			for _, warning := range warnings {
				klog.Warningf(warning)
			}
			if err != nil {
				klog.Errorf("Failed to initialize ip table rules for shared gateway mode: %v", err)
				return
			}
			namespaces, err := kClient.GetNamespaces(metav1.LabelSelector{})
			if err != nil {
				klog.Errorf("Error getting existing namespaces from kube API: %v", err)
				return
			}
			for _, namespace := range namespaces.Items {
				svcs, err := kClient.GetServices(namespace.Name)
				if err != nil {
					klog.Errorf("Error getting existing services in namespace %s from kube API: %v", namespace.Name, err)
					return
				}
				warnings, err := verifySharedGatewayIptRules(svcs)
				for _, warning := range warnings {
					klog.Warningf(warning)
				}
				if err != nil {
					klog.Errorf(err.Error())
					return
				}
			}
		case <-stopChan:
			return
		}
	}
}

func newNodePortWatcher(patchPort, gwBridge, gwIntf string, ofm *openflowManager) (*nodePortWatcher, error) {
	// Get ofport of patchPort
	ofportPatch, stderr, err := util.RunOVSVsctl("--if-exists", "get",
		"interface", patchPort, "ofport")
	if err != nil {
		return nil, fmt.Errorf("failed to get ofport of %s, stderr: %q, error: %v",
			patchPort, stderr, err)
	}

	// Get ofport of physical interface
	ofportPhys, stderr, err := util.RunOVSVsctl("--if-exists", "get",
		"interface", gwIntf, "ofport")
	if err != nil {
		return nil, fmt.Errorf("failed to get ofport of %s, stderr: %q, error: %v",
			gwIntf, stderr, err)
	}

	// In the shared gateway mode, the NodePort service is handled by the OpenFlow flows configured
	// on the OVS bridge in the host. These flows act only on the packets coming in from outside
	// of the node. If someone on the node is trying to access the NodePort service, those packets
	// will not be processed by the OpenFlow flows, so we need to add iptable rules that DNATs the
	// NodePortIP:NodePort to ClusterServiceIP:Port.
	if _, err := initSharedGatewayIPTables(); err != nil {
		return nil, err
	}

	npw := &nodePortWatcher{
		ofportPhys:  ofportPhys,
		ofportPatch: ofportPatch,
		gwBridge:    gwBridge,
		ofm:         ofm,
	}
	return npw, nil
}

func cleanupSharedGateway() error {
	// NicToBridge() may be created before-hand, only delete the patch port here
	stdout, stderr, err := util.RunOVSVsctl("--columns=name", "--no-heading", "find", "port",
		"external_ids:ovn-localnet-port!=_")
	if err != nil {
		return fmt.Errorf("failed to get ovn-localnet-port port stderr:%s (%v)", stderr, err)
	}
	ports := strings.Fields(strings.Trim(stdout, "\""))
	for _, port := range ports {
		_, stderr, err := util.RunOVSVsctl("--if-exists", "del-port", strings.Trim(port, "\""))
		if err != nil {
			return fmt.Errorf("failed to delete port %s stderr:%s (%v)", port, stderr, err)
		}
	}

	// Get the OVS bridge name from ovn-bridge-mappings
	stdout, stderr, err = util.RunOVSVsctl("--if-exists", "get", "Open_vSwitch", ".",
		"external_ids:ovn-bridge-mappings")
	if err != nil {
		return fmt.Errorf("failed to get ovn-bridge-mappings stderr:%s (%v)", stderr, err)
	}
	// skip the existing mapping setting for the specified physicalNetworkName
	bridgeName := ""
	bridgeMappings := strings.Split(stdout, ",")
	for _, bridgeMapping := range bridgeMappings {
		m := strings.Split(bridgeMapping, ":")
		if network := m[0]; network == types.PhysicalNetworkName {
			bridgeName = m[1]
			break
		}
	}
	if len(bridgeName) == 0 {
		return nil
	}

	_, stderr, err = util.AddOFFlowWithSpecificAction(bridgeName, util.NormalAction)
	if err != nil {
		return fmt.Errorf("failed to replace-flows on bridge %q stderr:%s (%v)", bridgeName, stderr, err)
	}

	cleanupSharedGatewayIPTChains()
	return nil
}

func svcToCookie(namespace string, name string, token string, port int32) (string, error) {
	id := fmt.Sprintf("%s%s%s%d", namespace, name, token, port)
	h := fnv.New64a()
	_, err := h.Write([]byte(id))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("0x%x", h.Sum64()), nil
}
