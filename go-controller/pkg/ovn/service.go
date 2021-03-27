package ovn

import (
	"encoding/json"
	"fmt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"net"
	"reflect"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	metrics "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/gateway"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/reference"
	"k8s.io/klog/v2"
)

func addRejectACLs(rejectACLs map[string]map[string]bool, lb, ip string, port int32, hasEndpoints bool) {
	if ip != "" {
		name := generateACLName(lb, ip, port)
		if _, ok := rejectACLs[name]; !ok {
			rejectACLs[name] = make(map[string]bool)
		}
		rejectACLs[name][lb] = hasEndpoints
	}
}

func (ovn *Controller) syncServices(services []interface{}) {
	// For all clusterIP in k8s, we will populate the below slice with
	// IP:port. In OVN's database those are the keys. We need to
	// have separate slice for TCP, SCTP, and UDP load-balancers (hence the dict).
	clusterServices := make(map[kapi.Protocol][]string)

	// For all nodePorts in k8s, we will populate the below slice with
	// nodePort. In OVN's database, nodeIP:nodePort is the key.
	// We have separate slice for TCP, SCTP, and UDP nodePort load-balancers.
	// We will get nodeIP separately later.
	nodeportServices := make(map[kapi.Protocol][]string)

	// For all externalIPs in k8s, we will populate the below map of slices
	// with load balancer type services based on each protocol.
	lbServices := make(map[kapi.Protocol][]string)

	// Track which services found should have reject ACLs. Format is name, load balancer, and value is if service has endpoints
	svcRejectACLs := make(map[string]map[string]bool)

	// Go through the k8s services and populate 'clusterServices',
	// 'nodeportServices' and 'lbServices'
	for _, serviceInterface := range services {
		service, ok := serviceInterface.(*kapi.Service)
		if !ok {
			klog.Errorf("Spurious object in syncServices: %v", serviceInterface)
			continue
		}

		if !util.ServiceTypeHasClusterIP(service) {
			continue
		}

		if !util.IsClusterIPSet(service) {
			klog.V(5).Infof("Skipping service %s due to clusterIP = %q", service.Name, service.Spec.ClusterIP)
			continue
		}

		// detect if service has endpoints for stale reject ACL check. If there are endpoints, we need to wipe any
		// old stale ACLs
		ep, err := ovn.watchFactory.GetEndpoint(service.Namespace, service.Name)
		hasEndpoints := false
		if err == nil {
			if len(ep.Subsets) > 0 {
				hasEndpoints = true
			}
		}

		for _, svcPort := range service.Spec.Ports {
			if err := util.ValidatePort(svcPort.Protocol, svcPort.Port); err != nil {
				klog.Errorf("Error validating port %s: %v", svcPort.Name, err)
				continue
			}

			if util.ServiceTypeHasNodePort(service) {
				port := fmt.Sprintf("%d", svcPort.NodePort)
				nodeportServices[svcPort.Protocol] = append(nodeportServices[svcPort.Protocol], port)
				gatewayRouters, _, err := ovn.getOvnGateways()
				if err == nil {
					for _, gatewayRouter := range gatewayRouters {
						lb, err := ovn.getGatewayLoadBalancer(gatewayRouter, svcPort.Protocol)
						if err != nil {
							klog.Warningf("Service Sync: Gateway router %s does not have load balancer (%v)",
								gatewayRouter, err)
							continue
						}
						physicalIPs, err := ovn.getGatewayPhysicalIPs(gatewayRouter)
						if err != nil {
							klog.Warningf("Service Sync: Gateway router %s does not have physical ips: %v",
								gatewayRouter, err)
							continue
						}
						for _, physicalIP := range physicalIPs {
							addRejectACLs(svcRejectACLs, lb, physicalIP, svcPort.NodePort, hasEndpoints)
						}
					}
				}
			}

			key := util.JoinHostPortInt32(service.Spec.ClusterIP, svcPort.Port)
			clusterServices[svcPort.Protocol] = append(clusterServices[svcPort.Protocol], key)
			lb, err := ovn.getLoadBalancer(svcPort.Protocol)
			if err != nil {
				klog.Warningf("Unable to get existing load balancer from ovn. Reject ACLs may not be synced!")
			} else {
				addRejectACLs(svcRejectACLs, lb, service.Spec.ClusterIP, svcPort.Port, hasEndpoints)

				// Cloud load balancers: directly load balance that traffic from pods
				for _, ing := range service.Status.LoadBalancer.Ingress {
					addRejectACLs(svcRejectACLs, lb, ing.IP, svcPort.Port, hasEndpoints)
				}
			}
			for _, extIP := range service.Spec.ExternalIPs {
				key := util.JoinHostPortInt32(extIP, svcPort.Port)
				lbServices[svcPort.Protocol] = append(lbServices[svcPort.Protocol], key)
				gateways, _, err := ovn.getOvnGateways()
				if err != nil {
					continue
				}
				for _, gateway := range gateways {
					lb, err := ovn.getGatewayLoadBalancer(gateway, svcPort.Protocol)
					if err != nil {
						klog.Errorf("Service Sync: Gateway router %s does not have load balancer (%v)",
							gateway, err)
						continue
					}
					addRejectACLs(svcRejectACLs, lb, extIP, svcPort.Port, hasEndpoints)
				}
			}
		}
	}

	// Get OVN's current reject ACLs. Note, currently only services use reject ACLs.
	type ovnACLData struct {
		Data [][]interface{}
	}
	data, stderr, err := util.RunOVNNbctl("--columns=name,_uuid", "--format=json", "find", "acl", "action=reject")
	if err != nil {
		klog.Errorf("Error while querying ACLs with reject action: %s, %v", stderr, err)
	} else {
		x := ovnACLData{}
		if err := json.Unmarshal([]byte(data), &x); err != nil {
			klog.Errorf("Unable to get current OVN reject ACLs. Unable to sync reject ACLs!: %v", err)
		} else if len(x.Data) == 0 {
			klog.Infof("Service Sync: No reject ACLs currently configured in OVN")
		} else {
			for _, entry := range x.Data {
				// ACL entry format is a slice: [<aclName>, ["_uuid", <uuid>]]
				if len(entry) != 2 {
					continue
				}
				name, ok := entry[0].(string)
				if !ok {
					continue
				}
				uuidData, ok := entry[1].([]interface{})
				if !ok || len(uuidData) != 2 {
					continue
				}
				uuid, ok := uuidData[1].(string)
				if !ok {
					continue
				}
				if svcCacheEntry, ok := svcRejectACLs[name]; ok {
					for lb, hasEps := range svcCacheEntry {
						if hasEps {
							klog.Infof("Service Sync: Removing OVN stale reject ACL: %s", name)
							ovn.removeACLFromPortGroup(lb, uuid)
							var foundSwitches []string
							// For upgrade from a non-port group Reject ACL implementation
							// Deprecated: remove in the future
							switches, err := ovn.getLogicalSwitchesForLoadBalancer(lb)
							if err != nil {
								klog.Errorf("Error finding node logical switches for load balancer "+
									"%s: %v", lb, err)
							} else {
								foundSwitches = append(foundSwitches, switches...)
							}
							// Look for load balancer on join/external switches
							grExtSwitches, err := ovn.getGRLogicalSwitchesForLoadBalancer(lb)
							if err != nil {
								klog.Errorf("Error finding GR logical switches for load balancer "+
									"%s: %v", lb, err)
							} else {
								// For upgrade from a previous implementation the ACL may also be on join switch
								for _, grExtSwitch := range grExtSwitches {
									routerName := strings.TrimPrefix(grExtSwitch, types.ExternalSwitchPrefix)
									grJoinSwitch := types.JoinSwitchPrefix + routerName
									foundSwitches = append(foundSwitches, grExtSwitch, grJoinSwitch)
								}
							}
							if len(foundSwitches) > 0 {
								klog.V(5).Infof("Service Sync: Removing OVN stale reject ACL (%s) "+
									"from logical switches that contains load balancer %s, switches: %s", name, lb,
									foundSwitches)
								ovn.removeACLFromNodeSwitches(foundSwitches, uuid)
							}
						}
					}
				}
			}
		}
	}

	// Get OVN's current cluster load balancer VIPs and delete them if they
	// are stale.
	for _, protocol := range []kapi.Protocol{kapi.ProtocolTCP, kapi.ProtocolUDP, kapi.ProtocolSCTP} {
		loadBalancer, err := ovn.getLoadBalancer(protocol)
		if err != nil {
			klog.Errorf("Failed to get load balancer for %s (%v)", kapi.Protocol(protocol), err)
			continue
		}

		loadBalancerVIPs, err := ovn.getLoadBalancerVIPs(loadBalancer)
		if err != nil {
			klog.Errorf("Failed to get load balancer vips for %s (%v)", loadBalancer, err)
			continue
		}
		for vip := range loadBalancerVIPs {
			if !stringSliceMembership(clusterServices[protocol], vip) {
				klog.V(5).Infof("Deleting stale cluster vip %s in load balancer %s", vip, loadBalancer)
				if err := ovn.deleteLoadBalancerVIP(loadBalancer, vip); err != nil {
					klog.Error(err)
				}
			}
		}
	}

	// For each gateway, remove any VIP that does not exist in
	// 'nodeportServices'.
	gateways, stderr, err := ovn.getOvnGateways()
	if err != nil {
		klog.Errorf("Failed to get ovn gateways. Not syncing nodeport stdout: %q, stderr: %q (%v)", gateways, stderr, err)
		return
	}

	for _, gateway := range gateways {
		for _, protocol := range []kapi.Protocol{kapi.ProtocolTCP, kapi.ProtocolUDP, kapi.ProtocolSCTP} {
			loadBalancer, err := ovn.getGatewayLoadBalancer(gateway, protocol)
			if err != nil {
				klog.Errorf("Gateway router %s does not have load balancer (%v)", gateway, err)
				continue
			}
			loadBalancerVIPs, err := ovn.getLoadBalancerVIPs(loadBalancer)
			if err != nil {
				klog.Errorf("Failed to get load balancer vips for %s (%v)", loadBalancer, err)
				continue
			}
			for vip := range loadBalancerVIPs {
				_, port, err := net.SplitHostPort(vip)
				if err != nil {
					// In a OVN load-balancer, we should always have vip:port.
					// In the unlikely event that it is not the case, skip it.
					klog.Errorf("Failed to split %s to vip and port (%v)", vip, err)
					continue
				}

				if !stringSliceMembership(nodeportServices[protocol], port) && !stringSliceMembership(lbServices[protocol], vip) {
					klog.V(5).Infof("Deleting stale nodeport vip %s in load balancer %s", vip, loadBalancer)
					if err := ovn.deleteLoadBalancerVIP(loadBalancer, vip); err != nil {
						klog.Error(err)
					}
				}
			}
		}
	}
}

func (ovn *Controller) createService(service *kapi.Service) error {
	klog.Infof("Creating service %s", service.Name)

	//Obtain the service instance to update metrics
	metricsService := metrics.GetServiceMetricsInstance()
	metricsService.Increment(service)

	if !util.IsClusterIPSet(service) {
		klog.V(5).Infof("Skipping service create: No cluster IP for service %s found", service.Name)
		return nil
	} else if len(service.Spec.Ports) == 0 {
		klog.V(5).Info("Skipping service create: No Ports specified for service")
		return nil
	}

	// We can end up in a situation where the endpoint creation is triggered before the service creation,
	// we should not be creating the reject ACLs if this endpoint exists, because that would result in an unreachable service
	// eventough the endpoint exists.
	// NOTE: we can also end up in a situation where a service matching no pods is created. Such a service still has an endpoint, but with no subsets.
	// make sure to treat that service as an ACL reject.
	ep, err := ovn.watchFactory.GetEndpoint(service.Namespace, service.Name)
	if err == nil {
		if len(ep.Subsets) > 0 {
			klog.V(5).Infof("service: %s has endpoint, will create load balancer VIPs", service.Name)
		} else {
			klog.V(5).Infof("service: %s has empty endpoint", service.Name)
			ep = nil
		}
	}

	for _, svcPort := range service.Spec.Ports {
		var port int32
		if util.ServiceTypeHasNodePort(service) {
			port = svcPort.NodePort
		} else {
			port = svcPort.Port
		}

		if err := util.ValidatePort(svcPort.Protocol, port); err != nil {
			klog.Errorf("Error validating port %s: %v", svcPort.Name, err)
			continue
		}

		if !ovn.SCTPSupport && svcPort.Protocol == kapi.ProtocolSCTP {
			ref, err := reference.GetReference(scheme.Scheme, service)
			if err != nil {
				klog.Errorf("Could not get reference for pod %v: %v\n", service.Name, err)
			} else {
				ovn.recorder.Event(ref, kapi.EventTypeWarning, "Unsupported protocol error", "SCTP protocol is unsupported by this version of OVN")
			}
			return fmt.Errorf("invalid service port %s: SCTP is unsupported by this version of OVN", svcPort.Name)
		}

		if util.ServiceTypeHasNodePort(service) {
			// Each gateway has a separate load-balancer for N/S traffic

			gatewayRouters, _, err := ovn.getOvnGateways()
			if err != nil {
				return err
			}

			for _, gatewayRouter := range gatewayRouters {
				loadBalancer, err := ovn.getGatewayLoadBalancer(gatewayRouter, svcPort.Protocol)
				if err != nil {
					klog.Errorf("Gateway router %s does not have load balancer (%v)", gatewayRouter, err)
					continue
				}
				physicalIPs, err := ovn.getGatewayPhysicalIPs(gatewayRouter)
				if err != nil {
					klog.Errorf("Gateway router %s does not have physical ip (%v)", gatewayRouter, err)
					continue
				}
				for _, physicalIP := range physicalIPs {
					// With the physical_ip:port as the VIP, add an entry in
					// 'load balancer'.
					vip := util.JoinHostPortInt32(physicalIP, port)
					// Skip creating LB if endpoints watcher already did it
					if _, hasEps := ovn.getServiceLBInfo(loadBalancer, vip); hasEps {
						klog.V(5).Infof("Load balancer already configured for %s, %s", loadBalancer, vip)
					} else if ep != nil {
						if err := ovn.AddEndpoints(ep, true); err != nil {
							return err
						}
					} else if svcQualifiesForReject(service) {
						aclDenyLogging := ovn.GetNetworkPolicyACLLogging(service.Namespace).Deny
						aclUUID, err := ovn.createLoadBalancerRejectACL(loadBalancer, physicalIP, port,
							svcPort.Protocol, aclDenyLogging)
						if err != nil {
							return fmt.Errorf("failed to create service ACL: %v", err)
						}
						klog.Infof("Service Reject ACL created for NodePort service: %s, namespace: %s, via "+
							"gateway router: %s:%s:%d, ACL UUID:%s", service.Name, service.Namespace,
							svcPort.Protocol, physicalIP, port, aclUUID)
					}
				}
			}
		}
		if util.ServiceTypeHasClusterIP(service) {
			loadBalancer, err := ovn.getLoadBalancer(svcPort.Protocol)
			if err != nil {
				klog.Errorf("Failed to get load balancer for %s (%v)", svcPort.Protocol, err)
				break
			}
			if svcQualifiesForReject(service) {
				gateways, _, err := ovn.getOvnGateways()
				if err != nil {
					return err
				}
				vip := util.JoinHostPortInt32(service.Spec.ClusterIP, svcPort.Port)
				// Skip creating LB if endpoints watcher already did it
				if _, hasEps := ovn.getServiceLBInfo(loadBalancer, vip); hasEps {
					klog.V(5).Infof("Load balancer already configured for %s, %s", loadBalancer, vip)
				} else if ep != nil {
					if err := ovn.AddEndpoints(ep, true); err != nil {
						return err
					}
				} else {
					aclDenyLogging := ovn.GetNetworkPolicyACLLogging(service.Namespace).Deny
					aclUUID, err := ovn.createLoadBalancerRejectACL(loadBalancer, service.Spec.ClusterIP,
						svcPort.Port, svcPort.Protocol, aclDenyLogging)
					if err != nil {
						return fmt.Errorf("failed to create service ACL: %v", err)
					}
					klog.Infof("Service Reject ACL created for ClusterIP service: %s, namespace: %s, via: "+
						"%s:%s:%d, ACL UUID: %s", service.Name, service.Namespace, svcPort.Protocol,
						service.Spec.ClusterIP, svcPort.Port, aclUUID)
					// Cloud load balancers reject ACLs
					for _, ing := range service.Status.LoadBalancer.Ingress {
						if ing.IP == "" {
							continue
						}
						for _, gateway := range gateways {
							loadBalancer, err := ovn.getGatewayLoadBalancer(gateway, svcPort.Protocol)
							if err != nil {
								klog.Errorf("Gateway router %s does not have load balancer (%v)", gateway, err)
								continue
							}
							aclUUID, err := ovn.createLoadBalancerRejectACL(loadBalancer, ing.IP, svcPort.Port, svcPort.Protocol, aclDenyLogging)
							if err != nil {
								klog.Errorf("Failed to create reject ACL for Ingress IP: %s, load balancer: %s, error: %v",
									ing.IP, loadBalancer, err)
							} else {
								klog.Infof("Reject ACL created for Ingress IP: %s, load balancer: %s, %s", ing.IP,
									loadBalancer, aclUUID)
							}
						}
					}
				}
				if len(service.Spec.ExternalIPs) > 0 {
					for _, extIP := range service.Spec.ExternalIPs {
						for _, gateway := range gateways {
							loadBalancer, err := ovn.getGatewayLoadBalancer(gateway, svcPort.Protocol)
							if err != nil {
								klog.Errorf("Gateway router %s does not have load balancer (%v)", gateway, err)
								continue
							}
							vip := util.JoinHostPortInt32(extIP, svcPort.Port)
							// Skip creating LB if endpoints watcher already did it
							if _, hasEps := ovn.getServiceLBInfo(loadBalancer, vip); hasEps {
								klog.V(5).Infof("Load Balancer already configured for %s, %s", loadBalancer, vip)
							} else {
								aclDenyLogging := ovn.GetNetworkPolicyACLLogging(service.Namespace).Deny
								aclUUID, err := ovn.createLoadBalancerRejectACL(loadBalancer, extIP, svcPort.Port,
									svcPort.Protocol, aclDenyLogging)
								if err != nil {
									return fmt.Errorf("failed to create service ACL for external IP")
								}
								klog.Infof("Service Reject ACL created for ExternalIP service: %s, namespace: %s,"+
									"via: %s:%s:%d, ACL UUID: %s", service.Name, service.Namespace, svcPort.Protocol,
									extIP, svcPort.Port, aclUUID)
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func (ovn *Controller) updateService(oldSvc, newSvc *kapi.Service) error {
	if reflect.DeepEqual(newSvc.Spec.Ports, oldSvc.Spec.Ports) &&
		reflect.DeepEqual(newSvc.Spec.ExternalIPs, oldSvc.Spec.ExternalIPs) &&
		reflect.DeepEqual(newSvc.Spec.ClusterIP, oldSvc.Spec.ClusterIP) &&
		reflect.DeepEqual(newSvc.Spec.Type, oldSvc.Spec.Type) &&
		reflect.DeepEqual(newSvc.Status.LoadBalancer.Ingress, oldSvc.Status.LoadBalancer.Ingress) {
		klog.V(5).Infof("Skipping service update for: %s as change does not apply to any of .Spec.Ports, "+
			".Spec.ExternalIP, .Spec.ClusterIP, .Spec.Type, .Status.LoadBalancer.Ingress", newSvc.Name)
		return nil
	}

	klog.V(5).Infof("Updating service from: %v to: %v", oldSvc, newSvc)

	ovn.deleteService(oldSvc)
	return ovn.createService(newSvc)
}

func (ovn *Controller) deleteService(service *kapi.Service) {
	klog.Infof("Deleting service %s", service.Name)

	//Obtain the service instance to update metrics
	metricsService := metrics.GetServiceMetricsInstance()
	metricsService.Decrement(service)

	if !util.IsClusterIPSet(service) {
		return
	}
	for _, svcPort := range service.Spec.Ports {
		var port int32
		if util.ServiceTypeHasNodePort(service) {
			port = svcPort.NodePort
		} else {
			port = svcPort.Port
		}

		if err := util.ValidatePort(svcPort.Protocol, port); err != nil {
			klog.Errorf("Skipping delete for service port %s: %v", svcPort.Name, err)
			continue
		}

		if util.ServiceTypeHasNodePort(service) {
			// Delete the 'NodePort' service from a load balancer instantiated in gateways.
			ovn.deleteNodeVIPs(nil, svcPort.Protocol, port)
		}
		if util.ServiceTypeHasClusterIP(service) {
			loadBalancer, err := ovn.getLoadBalancer(svcPort.Protocol)
			if err != nil {
				klog.Errorf("Failed to get load balancer for %s (%v)", svcPort.Protocol, err)
				continue
			}
			vip := util.JoinHostPortInt32(service.Spec.ClusterIP, svcPort.Port)
			if err := ovn.deleteLoadBalancerVIP(loadBalancer, vip); err != nil {
				klog.Error(err)
			}
			ovn.deleteNodeVIPs([]string{service.Spec.ClusterIP}, svcPort.Protocol, svcPort.Port)
			// Cloud load balancers
			if err := ovn.deleteIngressVIPs(service, svcPort); err != nil {
				klog.Error(err)
			}
			if err := ovn.deleteExternalVIPs(service, svcPort); err != nil {
				klog.Error(err)
			}
		}
	}
}

// svcQualifiesForReject determines if a service should have a reject ACL on it when it has no endpoints
// The reject ACL is only applied to terminate incoming connections immediately when idling is not used
// or OVNEmptyLbEvents are not enabled. When idilng or empty LB events are enabled, we want to ensure we
// receive these packets and not reject them.
func svcQualifiesForReject(service *kapi.Service) bool {
	_, ok := service.Annotations[OvnServiceIdledAt]
	return !(config.Kubernetes.OVNEmptyLbEvents && ok)
}

// SVC can be of types 1. clusterIP, 2. NodePort, 3. LoadBalancer,
// or 4.ExternalIP
// TODO adjust for upstream patch when it lands:
// https://bugzilla.redhat.com/show_bug.cgi?id=1908540
func getSvcVips(service *kapi.Service) []net.IP {
	ips := make([]net.IP, 0)

	if util.ServiceTypeHasNodePort(service) {
		gatewayRouters, _, err := gateway.GetOvnGateways()
		if err != nil {
			klog.Errorf("Cannot get gateways: %s", err)
		}
		for _, gatewayRouter := range gatewayRouters {
			// VIPs would be the physical IPS of the GRs(IPs of the node) in this case
			physicalIPs, err := gateway.GetGatewayPhysicalIPs(gatewayRouter)
			if err != nil {
				klog.Errorf("Unable to get gateway router %s physical ip, error: %v", gatewayRouter, err)
				continue
			}

			for _, physicalIP := range physicalIPs {
				ip := net.ParseIP(physicalIP)
				if ip == nil {
					klog.Errorf("Failed to parse pod IP %q", physicalIP)
					continue
				}
				ips = append(ips, ip)
			}
		}
	}
	if util.ServiceTypeHasClusterIP(service) {
		if util.IsClusterIPSet(service) {
			ip := net.ParseIP(service.Spec.ClusterIP)
			if ip == nil {
				klog.Errorf("Failed to parse pod IP %q", service.Spec.ClusterIP)
			}
			ips = append(ips, ip)
		}

		for _, ing := range service.Status.LoadBalancer.Ingress {
			ip := net.ParseIP(ing.IP)
			if ip == nil {
				klog.Errorf("Failed to parse pod IP %q", ing)
				continue
			}
			klog.V(5).Infof("Adding ingress IPs from Service: %s to VIP set", service.Name)
			ips = append(ips, ip)
		}

		if len(service.Spec.ExternalIPs) > 0 {
			for _, extIP := range service.Spec.ExternalIPs {
				ip := net.ParseIP(extIP)
				if ip == nil {
					klog.Errorf("Failed to parse pod IP %q", extIP)
					continue
				}
				klog.V(5).Infof("Adding external IPs from Service: %s to VIP set", service.Name)
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		klog.V(5).Infof("Service has no VIPs")
		return nil
	}
	return ips
}
