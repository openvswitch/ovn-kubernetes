package node

import (
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
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
	nodeName    string
	nodeIPs     []string
	ofportPhys  string
	ofportPatch string
	gwBridge    string
	// The services Map is required to decide if we care about a given Endpoint event
	services map[ktypes.NamespacedName]*kapi.Service
	ofm      *openflowManager
}

// With The external Traffic policy feature this logic got much more complicated
// Now we have Multiple K8s Object tiggers (i.e Services and Endpoints) That must
// Prompt a single event function -->
// func updateServiceFlowCache(service *kapi.Service, add bool, epLocal bool)
//
// To handle this, two signal variables are used, add and epLocal
// If add==false all br-ex flows are deleted for the service
// If add==true br-ex flows are created for the service +
// 		if epLocal==False && ETP==Local it means the svc has no Host Endpoints
//         so we add only a single flow to on br-ex to steer traffic into OVN-K
//
//      if epLocal==True && ETP==Local it means the svc has Host endpoints
//         so we add 4 flows onto br-ex to allow external-> SVC traffic to
//         Completely bypass OVN.
//
// For Service Event functions epLocal is always FALSE since we're looking only at the service
// and know nothing about it's endpoints
//
// For endpoint Event functions...
//		An action only ever occurs (i.e epLocal=True) if
//			1. The Service Exists &&
// 			2. Svc's ETP==Local &&
//			3. Svc Has host networked Backends
//      Otherwise the endpoint event is ignored
//
//      The action ensures the correct flows and IPtables rules are programmed

// This function is used to manage the flows programmed in br-ex for OVN-K8's Nodeport, ExternalIP, and
// Loadbalancer type services. It also consumes an `epLocal` argument to signal that the specified service
// has has host-networked backends
func (npw *nodePortWatcher) updateServiceFlowCache(service *kapi.Service, add bool, epLocal bool) {
	var cookie, key string
	var err error
	var HostNodePortCTZone = config.Default.ConntrackZone + 3 //64003

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
				// Delete if needed and skip to next protocol
				if !add {
					npw.ofm.deleteFlowsByKey(key)
					continue
				}

				// This allows external traffic ingress when the svc's ExternalTraffic Policy is
				// set to Local, and the backend pod is HostNetworked. We need to add
				// Flows that will DNAT all traffic coming into nodeport to the nodeIP:Port and
				// ensure that the return traffic is UnDNATed to correct the nodeIP:Nodeport
				if epLocal {
					var nodeportFlows []string
					// Rule 0:
					// This rule matches on all traffic with dst port == NodePort and DNAT's it to the correct NodeIP
					// If ipv6 make sure to choose the ipv6 node address for rule
					if strings.Contains(flowProtocol, "6") {
						nodeportFlows = append(nodeportFlows,
							fmt.Sprintf("cookie=%s, priority=100, in_port=%s, %s, tp_dst=%d, actions=ct(commit,zone=%d,nat(dst=%s:%d),table=6)",
								cookie, npw.ofportPhys, flowProtocol, svcPort.NodePort, HostNodePortCTZone, npw.nodeIPs[1], svcPort.Port))
					} else {
						nodeportFlows = append(nodeportFlows,
							fmt.Sprintf("cookie=%s, priority=100, in_port=%s, %s, tp_dst=%d, actions=ct(commit,zone=%d,nat(dst=%s:%d),table=6)",
								cookie, npw.ofportPhys, flowProtocol, svcPort.NodePort, HostNodePortCTZone, npw.nodeIPs[0], svcPort.Port))
					}
					nodeportFlows = append(nodeportFlows,
						// Rule 1:
						// Sends the packet to the host's networking stack after rule 1 is done DNATing
						fmt.Sprintf("cookie=%s, priority=100, table=6, actions=output:LOCAL",
							cookie),
						// Rule 2:
						// Matches on return traffic, i.e traffic coming from the host networked pod's port, and unDNATs
						fmt.Sprintf("cookie=%s, priority=100, in_port=LOCAL, %s, tp_src=%d, actions=ct(commit,zone=%d nat,table=7)",
							cookie, flowProtocol, svcPort.Port, HostNodePortCTZone),
						// Rule 3:
						// Sends the packet back out eth0 to the external client
						fmt.Sprintf("cookie=%s, priority=100, table=7, "+
							"actions=output:%s", cookie, npw.ofportPhys))

					npw.ofm.updateFlowCacheEntry(key, nodeportFlows)
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
			// Delete if needed and skip to next protocol
			if !add {
				npw.ofm.deleteFlowsByKey(key)
				continue
			}

			// This allows external traffic ingress when the svc's ExternalTraffic Policy is
			// set to Local, and the backend pod is HostNetworked. We need to add
			// Flows that will DNAT all external traffic destined for the lb service
			// to the nodeIP and ensure That return traffic is UnDNATed correctly back
			// to the ingress ip
			if epLocal {
				var nodeportFlows []string
				// Rule 0:
				// This rule matches on all traffic with dst ip == LoadbalancerIP and DNAT's it to the correct NodeIP
				// If ipv6 make sure to choose the ipv6 node address for rule
				if strings.Contains(flowProtocol, "6") {
					nodeportFlows = append(nodeportFlows,
						fmt.Sprintf("cookie=%s, priority=100, in_port=%s, %s, %s=%s, tp_dst=%d, actions=ct(commit,zone=%d,nat(dst=%s),table=6)",
							cookie, npw.ofportPhys, flowProtocol, nwDst, ing.IP, svcPort.Port, HostNodePortCTZone, npw.nodeIPs[1]))
				} else {
					nodeportFlows = append(nodeportFlows,
						fmt.Sprintf("cookie=%s, priority=100, in_port=%s, %s, %s=%s, tp_dst=%d, actions=ct(commit,zone=%d,nat(dst=%s),table=6)",
							cookie, npw.ofportPhys, flowProtocol, nwDst, ing.IP, svcPort.Port, HostNodePortCTZone, npw.nodeIPs[0]))
				}
				nodeportFlows = append(nodeportFlows,
					// Rule 1:
					// Sends the packet to the host's networking stack after rule 1 is done DNATing
					fmt.Sprintf("cookie=%s, priority=100, table=6, actions=output:LOCAL",
						cookie),
					// Rule 2:
					// Matches on return traffic, i.e traffic coming from the host networked pod's port, and unDNATs
					fmt.Sprintf("cookie=%s, priority=100, in_port=LOCAL, %s, tp_src=%d, actions=ct(commit,zone=%d nat,table=7)",
						cookie, flowProtocol, svcPort.Port, HostNodePortCTZone),
					// Rule 3:
					// Sends the packet back out eth0 to the external client
					fmt.Sprintf("cookie=%s, priority=100, table=7, "+
						"actions=output:%s", cookie, npw.ofportPhys))

				npw.ofm.updateFlowCacheEntry(key, nodeportFlows)
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
			// Delete if needed and skip to next protocol
			if !add {
				npw.ofm.deleteFlowsByKey(key)
				continue
			}
			// This allows external traffic ingress when the svc's ExternalTraffic Policy is
			// set to Local, and the backend pod is HostNetworked. We need to add
			// Flows that will DNAT all external traffic destined for externalIP service
			// to the nodeIP:port of the host networked backend. And Then ensure That return
			// traffic is UnDNATed correctly back to the external IP
			if epLocal {
				var nodeportFlows []string
				// Rule 0:
				// This rule matches on all traffic with dst ip == externalIP and DNAT's it to the correct NodeIP
				// If ipv6 make sure to choose the ipv6 node address for rule
				if strings.Contains(flowProtocol, "6") {
					nodeportFlows = append(nodeportFlows,
						fmt.Sprintf("cookie=%s, priority=100, in_port=%s, %s, %s=%s, tp_dst=%d, actions=ct(commit,zone=%d,nat(dst=%s),table=6)",
							cookie, npw.ofportPhys, flowProtocol, nwDst, externalIP, svcPort.Port, HostNodePortCTZone, npw.nodeIPs[1]))
				} else {
					nodeportFlows = append(nodeportFlows,
						fmt.Sprintf("cookie=%s, priority=100, in_port=%s, %s, %s=%s, tp_dst=%d, actions=ct(commit,zone=%d,nat(dst=%s),table=6)",
							cookie, npw.ofportPhys, flowProtocol, nwDst, externalIP, svcPort.Port, HostNodePortCTZone, npw.nodeIPs[0]))
				}
				nodeportFlows = append(nodeportFlows,
					// Rule 1:
					// Sends the packet to the host's networking stack after rule 1 is done DNATing
					fmt.Sprintf("cookie=%s, priority=100, table=6, actions=output:LOCAL",
						cookie),
					// Rule 2:
					// Matches on return traffic, i.e traffic coming from the host networked pod's port, and unDNATs
					fmt.Sprintf("cookie=%s, priority=100, in_port=LOCAL, %s, tp_src=%d, actions=ct(commit,zone=%d nat,table=7)",
						cookie, flowProtocol, svcPort.Port, HostNodePortCTZone),
					// Rule 3:
					// Sends the packet back out eth0 to the external client
					fmt.Sprintf("cookie=%s, priority=100, table=7, "+
						"actions=output:%s", cookie, npw.ofportPhys))

				npw.ofm.updateFlowCacheEntry(key, nodeportFlows)
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

	name := ktypes.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	npw.services[name] = service

	npw.updateServiceFlowCache(service, true, false)
	npw.ofm.requestFlowSync()
	addSharedGatewayIptRules(service, false, npw.nodeIPs)
}

// TODO: Account for updates to ETP?
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
		npw.updateServiceFlowCache(old, false, false)
		delSharedGatewayIptRules(old, false, npw.nodeIPs)
		needFlowSync = true
	}

	if util.ServiceTypeHasClusterIP(new) && util.IsClusterIPSet(new) {
		npw.updateServiceFlowCache(new, true, false)
		addSharedGatewayIptRules(new, false, npw.nodeIPs)
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
	npw.updateServiceFlowCache(service, false, false)
	npw.ofm.requestFlowSync()
	delSharedGatewayIptRules(service, false, npw.nodeIPs)
	name := ktypes.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	delete(npw.services, name)
}

func (npw *nodePortWatcher) SyncServices(services []interface{}) {
	for _, serviceInterface := range services {
		service, ok := serviceInterface.(*kapi.Service)
		if !ok {
			klog.Errorf("Spurious object in syncServices: %v",
				serviceInterface)
			continue
		}
		npw.updateServiceFlowCache(service, true, false)
	}

	npw.ofm.requestFlowSync()
	syncSharedGatewayIptRules(services, false, npw.nodeIPs)
}

// The only information needed here is does the np service have any local EPS
// Add new Local Traffic flows if endpoints are local
func (npw *nodePortWatcher) AddEndpoints(ep *kapi.Endpoints) {
	name := ktypes.NamespacedName{Namespace: ep.Namespace, Name: ep.Name}
	// Do nothing if service dosn't exist yet
	if _, exists := npw.services[name]; exists {
		// If ETP isn't Local Do nothing
		if util.ServiceExternalTrafficPolicyLocal(npw.services[name]) {
			// Only update flows if node local ep state changed from false -> true
			// Don't care about true -> true or false -> false since correct flows should already be in place
			if countLocalEndpoints(ep, npw.nodeName) > 0 {
				klog.V(5).Infof("Nodeport Service %s has local Endpoints Updating flow Cache", ep.Name)
				// Update Service Cache with special flows
				npw.updateServiceFlowCache(npw.services[name], true, true)
				npw.ofm.requestFlowSync()
				//Service was already created so now delete old rules and add correct IPtables rules
				delSharedGatewayIptRules(npw.services[name], false, npw.nodeIPs)
				addSharedGatewayIptRules(npw.services[name], true, npw.nodeIPs)
			}
		}
	}
}

// Most likely the Service functions will have already taken care of this
func (npw *nodePortWatcher) DeleteEndpoints(ep *kapi.Endpoints) {
	name := ktypes.NamespacedName{Namespace: ep.Namespace, Name: ep.Name}
	if _, exists := npw.services[name]; exists {
		if util.ServiceExternalTrafficPolicyLocal(npw.services[name]) {
			if countLocalEndpoints(ep, npw.nodeName) == 0 {
				klog.V(5).Infof("Nodeport Service %s has no local Endpoints, deleting flows", ep.Name)
				npw.updateServiceFlowCache(npw.services[name], false, true)
				npw.ofm.requestFlowSync()
				delSharedGatewayIptRules(npw.services[name], true, npw.nodeIPs)
			}
		}
	}
}

func (npw *nodePortWatcher) UpdateEndpoints(old, new *kapi.Endpoints) {
	name := ktypes.NamespacedName{Namespace: new.Namespace, Name: new.Name}
	if _, exists := npw.services[name]; exists {
		if util.ServiceExternalTrafficPolicyLocal(npw.services[name]) {
			needFlowSync := false
			// We had special ETP flows but now we don't
			if countLocalEndpoints(old, npw.nodeName) > 0 && countLocalEndpoints(new, npw.nodeName) == 0 {
				// Delete ETP flows
				npw.updateServiceFlowCache(npw.services[name], false, true)
				needFlowSync = true
				// Delete Special Iptables Rules
				delSharedGatewayIptRules(npw.services[name], true, npw.nodeIPs)
				// If There are still non-local eps Re-sync with normal nodeport service flows
				if len(new.Subsets) > 0 {
					// Update flow cache with standard flows
					npw.updateServiceFlowCache(npw.services[name], true, false)
					addSharedGatewayIptRules(npw.services[name], false, npw.nodeIPs)
				}
			}
			// Add Special ETP flows if there are now host endpoints
			if countLocalEndpoints(old, npw.nodeName) == 0 && countLocalEndpoints(new, npw.nodeName) > 0 {
				// Update flow cache with special ones
				npw.updateServiceFlowCache(npw.services[name], true, true)
				needFlowSync = true
				// delete standard IpTRules to add special ones
				delSharedGatewayIptRules(npw.services[name], false, npw.nodeIPs)
				addSharedGatewayIptRules(npw.services[name], true, npw.nodeIPs)
			}

			if needFlowSync {
				npw.ofm.requestFlowSync()
			}
		}

	}
}

// since we share the host's k8s node IP, add OpenFlow flows to br-ex
// -- to steer the NodePort traffic arriving on the host to the OVN logical topology and
// -- to also connection track the outbound north-south traffic through l3 gateway so that
//    the return traffic can be steered back to OVN logical topology
// -- to handle host -> service access, via masquerading from the host to OVN GR
// -- to handle host -> service(ExternalTrafficPolicy: Local) -> host access without SNAT
func newSharedGatewayOpenFlowManager(patchPort, macAddress, gwBridge, gwIntf string, ips []*net.IPNet) (*openflowManager, error) {
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

	HostMasqCTZone := config.Default.ConntrackZone + 1
	OVNMasqCTZone := HostMasqCTZone + 1
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

		// table0, Geneve packets coming from external. Skip conntrack and go directly to host
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=55, in_port=%s, udp, udp_dst=%d"+
				"actions=LOCAL", defaultOpenFlowCookie, ofportPhys, config.Default.EncapPort))

		// table 0, packets coming from external. Send it through conntrack and
		// resubmit to table 1 to know the state of the connection.
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=50, in_port=%s, ip, "+
				"actions=ct(zone=%d, table=1)", defaultOpenFlowCookie, ofportPhys, config.Default.ConntrackZone))

		physicalIP, err := util.MatchIPNetFamily(false, ips)
		if err != nil {
			return nil, fmt.Errorf("unable to determine IPv4 physical IP of host: %v", err)
		}
		// table 0, SVC Hairpin from OVN destined to local host, DNAT and go to table 4
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=500, in_port=%s, ip, ip_dst=%s, ip_src=%s,"+
				"actions=ct(commit,zone=%d,nat(dst=%s),table=4)",
				defaultOpenFlowCookie, ofportPatch, types.V4HostMasqueradeIP, physicalIP.IP,
				HostMasqCTZone, physicalIP.IP))

		// table 0, Reply SVC traffic from Host -> OVN, unSNAT and goto table 5
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=500, in_port=LOCAL, ip, ip_dst=%s,"+
				"actions=ct(zone=%d,nat,table=5)",
				defaultOpenFlowCookie, types.V4OVNMasqueradeIP, OVNMasqCTZone))
	}
	if config.IPv6Mode {
		// table 0, packets coming from pods headed externally. Commit connections
		// so that reverse direction goes back to the pods.
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=100, in_port=%s, ipv6, "+
				"actions=ct(commit, zone=%d), output:%s",
				defaultOpenFlowCookie, ofportPatch, config.Default.ConntrackZone, ofportPhys))

		// table0, Geneve packets coming from external. Skip conntrack and go directly to host
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=55, in_port=%s, udp6, udp_dst=%d"+
				"actions=LOCAL", defaultOpenFlowCookie, ofportPhys, config.Default.EncapPort))

		// table 0, packets coming from external. Send it through conntrack and
		// resubmit to table 1 to know the state of the connection.
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=50, in_port=%s, ipv6, "+
				"actions=ct(zone=%d, table=1)", defaultOpenFlowCookie, ofportPhys, config.Default.ConntrackZone))

		physicalIP, err := util.MatchIPNetFamily(true, ips)
		if err != nil {
			return nil, fmt.Errorf("unable to determine IPv6 physical IP of host: %v", err)
		}
		// table 0, SVC Hairpin from OVN destined to local host, DNAT to host, send to table 4
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=500, in_port=%s, ipv6, ipv6_dst=%s, ipv6_src=%s,"+
				"actions=ct(commit,zone=%d,nat(dst=%s),table=4)",
				defaultOpenFlowCookie, ofportPatch, types.V6HostMasqueradeIP, physicalIP.IP,
				HostMasqCTZone, physicalIP.IP))

		// table 0, Reply SVC traffic from Host -> OVN, unSNAT and goto table 5
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=500, in_port=LOCAL, ipv6, ipv6_dst=%s,"+
				"actions=ct(zone=%d,nat,table=5)",
				defaultOpenFlowCookie, types.V6OVNMasqueradeIP, OVNMasqCTZone))
	}

	var protoPrefix string
	var masqIP string

	// table 0, packets coming from Host -> Service
	for _, svcCIDR := range config.Kubernetes.ServiceCIDRs {
		if utilnet.IsIPv4CIDR(svcCIDR) {
			protoPrefix = "ip"
			masqIP = types.V4HostMasqueradeIP
		} else {
			protoPrefix = "ipv6"
			masqIP = types.V6HostMasqueradeIP
		}

		// table 0, Host -> OVN towards SVC, SNAT to special IP
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=500, in_port=LOCAL, %s, %s_dst=%s,"+
				"actions=ct(commit,zone=%d,nat(src=%s),table=2)",
				defaultOpenFlowCookie, protoPrefix, protoPrefix, svcCIDR, HostMasqCTZone, masqIP))

		// table 0, Reply hairpin traffic to host, coming from OVN, unSNAT
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=500, in_port=%s, %s, %s_src=%s, %s_dst=%s,"+
				"actions=ct(zone=%d,nat,table=3)",
				defaultOpenFlowCookie, ofportPatch, protoPrefix, protoPrefix, svcCIDR,
				protoPrefix, masqIP, HostMasqCTZone))
	}

	if config.IPv4Mode {
		// table 1, established and related connections in zone 64000 go to OVN
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=100, table=1, ip, ct_state=+trk+est, "+
				"actions=output:%s", defaultOpenFlowCookie, ofportPatch))

		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=100, table=1, ip, ct_state=+trk+rel, "+
				"actions=output:%s", defaultOpenFlowCookie, ofportPatch))
	}

	if config.IPv6Mode {
		// table 1, established and related connections in zone 64000 go to OVN
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=100, table=1, ipv6, ct_state=+trk+est, "+
				"actions=output:%s", defaultOpenFlowCookie, ofportPatch))

		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, priority=100, table=1, ipv6, ct_state=+trk+rel, "+
				"actions=output:%s", defaultOpenFlowCookie, ofportPatch))
	}

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

	// table 2, dispatch from Host -> OVN
	dftFlows = append(dftFlows,
		fmt.Sprintf("cookie=%s, table=2, "+
			"actions=mod_dl_dst=%s,output:%s", defaultOpenFlowCookie, macAddress, ofportPatch))

	// table 3, dispatch from OVN -> Host
	dftFlows = append(dftFlows,
		fmt.Sprintf("cookie=%s, table=3, "+
			"actions=move:NXM_OF_ETH_DST[]->NXM_OF_ETH_SRC[],mod_dl_dst=%s,output:LOCAL",
			defaultOpenFlowCookie, macAddress))

	// table 4, hairpinned pkts that need to go from OVN -> Host
	// We need to SNAT and masquerade OVN GR IP, send to table 3 for dispatch to Host
	if config.IPv4Mode {
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, table=4,ip,"+
				"actions=ct(commit,zone=%d,nat(src=%s),table=3)",
				defaultOpenFlowCookie, OVNMasqCTZone, types.V4OVNMasqueradeIP))
	}
	if config.IPv6Mode {
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, table=4,ipv6, "+
				"actions=ct(commit,zone=%d,nat(src=%s),table=3)",
				defaultOpenFlowCookie, OVNMasqCTZone, types.V6OVNMasqueradeIP))
	}
	// table 5, Host Reply traffic to hairpinned svc, need to unDNAT, send to table 2
	if config.IPv4Mode {
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, table=5, ip, "+
				"actions=ct(commit,zone=%d,nat,table=2)",
				defaultOpenFlowCookie, HostMasqCTZone))
	}
	if config.IPv6Mode {
		dftFlows = append(dftFlows,
			fmt.Sprintf("cookie=%s, table=5, ipv6, "+
				"actions=ct(commit,zone=%d,nat,table=2)",
				defaultOpenFlowCookie, HostMasqCTZone))
	}

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

	bridgeName, uplinkName, macAddress, ips, err := gatewayInitInternal(
		nodeName, gwIntf, subnets, gwNextHops, nodeAnnotator)
	if err != nil {
		return nil, err
	}

	// the name of the patch port created by ovn-controller is of the form
	// patch-<logical_port_name_of_localnet_port>-to-br-int
	patchPort := "patch-" + bridgeName + "_" + nodeName + "-to-br-int"

	// add masquerade subnet route to avoid zeroconf routes
	if config.IPv4Mode {
		bridgeLink, err := util.LinkSetUp(bridgeName)
		if err != nil {
			return nil, fmt.Errorf("unable to find shared gw bridge interface: %s", bridgeName)
		}
		v4nextHops, err := util.MatchIPFamily(false, gwNextHops)
		if err != nil {
			return nil, fmt.Errorf("no valid ipv4 next hop exists: %v", err)
		}
		_, masqIPNet, _ := net.ParseCIDR(types.V4MasqueradeSubnet)
		if exists, err := util.LinkRouteExists(bridgeLink, v4nextHops[0], masqIPNet); err == nil && !exists {
			err = util.LinkRoutesAdd(bridgeLink, v4nextHops[0], []*net.IPNet{masqIPNet})
			if err != nil {
				if os.IsExist(err) {
					klog.V(5).Infof("Ignoring error %s from 'route add %s via %s'",
						err.Error(), masqIPNet, v4nextHops[0])
				} else {
					return nil, fmt.Errorf("unable to add OVN masquerade route to host, error: %v", err)
				}
			}
		} else if err != nil {
			return nil, fmt.Errorf("failed to check if route exists for masquerade subnet, error: %v", err)
		}
	}

	gw.readyFunc = func() (bool, error) {
		return gatewayReady(patchPort)
	}

	gw.initFunc = func() error {
		// Program cluster.GatewayIntf to let non-pod traffic to go to host
		// stack
		klog.Info("Creating Shared Gateway Openflow Manager")
		var err error

		gw.openflowManager, err = newSharedGatewayOpenFlowManager(patchPort, macAddress.String(), bridgeName, uplinkName, ips)
		if err != nil {
			return err
		}

		if config.Gateway.NodeportEnable {
			klog.Info("Creating Shared Gateway Node Port Watcher")
			gw.nodePortWatcher, err = newNodePortWatcher(nodeName, patchPort, bridgeName, uplinkName, ips, gw.openflowManager)
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

func newNodePortWatcher(nodeName string, patchPort, gwBridge, gwIntf string, ips []*net.IPNet, ofm *openflowManager) (*nodePortWatcher, error) {
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
	if err := initSharedGatewayIPTables(); err != nil {
		return nil, err
	}

	// Get Physical IPs of Node, Can be IPV4 IPV6 or both
	var nodeIPs = []string{}

	if config.IPv4Mode {
		physicalIPv4, err := util.MatchIPNetFamily(false, ips)
		if err != nil {
			return nil, fmt.Errorf("Failed to get IPv4 nodeIP")
		}
		nodeIPs = append(nodeIPs, physicalIPv4.IP.String())
	}
	if config.IPv6Mode {
		physicalIPv6, err := util.MatchIPNetFamily(true, ips)
		if err != nil {
			return nil, fmt.Errorf("Failed to get IPv6 nodeIP")
		}
		nodeIPs = append(nodeIPs, physicalIPv6.IP.String())
	}

	npw := &nodePortWatcher{
		nodeName:    nodeName,
		nodeIPs:     nodeIPs,
		ofportPhys:  ofportPhys,
		ofportPatch: ofportPatch,
		gwBridge:    gwBridge,
		services:    make(map[ktypes.NamespacedName]*kapi.Service),
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
