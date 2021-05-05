package services

import (
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/gateway"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/loadbalancer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
)

func deleteVIPsFromAllOVNBalancers(vips sets.String, name, namespace string) error {
	err := deleteVIPsFromNonIdlingOVNBalancers(vips, name, namespace)
	if err != nil {
		return errors.Wrapf(err, "Failed to delete vips from ovn balancers %s %s", name, namespace)
	}
	err = deleteVIPsFromIdlingBalancer(vips, name, namespace)
	if err != nil {
		return errors.Wrapf(err, "Failed to delete vips from idling balancers %s %s", name, namespace)
	}
	return nil
}

// deleteVIPsFromNonIdlingOVNBalancers removes the given vips for all the loadbalancers but
// the idling ones. This includes the cluster loadbalancer, the gateway routers loadbalancers
// and the node switch ones.
func deleteVIPsFromNonIdlingOVNBalancers(vips sets.String, name, namespace string) error {
	if len(vips) == 0 {
		return nil
	}
	// NodePort and ExternalIPs use loadbalancers in each node
	gatewayRouters, _, err := gateway.GetOvnGateways()
	if err != nil {
		return errors.Wrapf(err, "failed to retrieve OVN gateway routers")
	}

	// Obtain the VIPs associated to the Service from the Service Tracker
	for vipKey := range vips {
		// the VIP is stored with the format IP:Port/Protocol
		vip, proto := splitVirtualIPKey(vipKey)
		// ClusterIP use a global load balancer per protocol
		lbID, err := loadbalancer.GetOVNKubeLoadBalancer(proto)
		if err != nil {
			klog.Errorf("Error getting OVN LoadBalancer for protocol %s", proto)
			return err
		}
		// Delete the Service VIP from OVN
		klog.Infof("Deleting service %s on namespace %s from OVN", name, namespace)
		if err := loadbalancer.DeleteLoadBalancerVIP(lbID, vip); err != nil {
			klog.Errorf("Error deleting VIP %s on OVN LoadBalancer %s", vip, lbID)
			return err
		}

		// Configure the NodePort in each Node Gateway Router
		for _, gatewayRouter := range gatewayRouters {
			gatewayLB, err := gateway.GetGatewayLoadBalancer(gatewayRouter, proto)
			if err != nil {
				klog.Warningf("Service Sync: Gateway router %s does not have load balancer (%v)",
					gatewayRouter, err)
				// TODO: why continue? should we error and requeue and retry?
				continue
			}
			workerNode := util.GetWorkerFromGatewayRouter(gatewayRouter)
			workerLB, err := loadbalancer.GetWorkerLoadBalancer(workerNode, proto)
			if err != nil {
				klog.Errorf("Worker switch %s does not have load balancer (%v)", workerNode, err)
				continue
			}
			// Delete the Service VIP from OVN
			klog.Infof("Deleting service %s on namespace %s from OVN", name, namespace)
			for _, lb := range []string{gatewayLB, workerLB} {
				if err := loadbalancer.DeleteLoadBalancerVIP(lb, vip); err != nil {
					klog.Errorf("Error deleting VIP %s on OVN LoadBalancer %s", vip, lbID)
					return err
				}
			}
		}
	}
	return nil
}

func deleteVIPsFromIdlingBalancer(vipProtocols sets.String, name, namespace string) error {
	// The idling lb is enabled only when configured
	if !config.Kubernetes.OVNEmptyLbEvents {
		return nil
	}

	// Obtain the VIPs associated to the Service
	for vipKey := range vipProtocols {
		// the VIP is stored with the format IP:Port/Protocol
		vip, proto := splitVirtualIPKey(vipKey)
		klog.Infof("Deleting VIP: %s from idling OVN LoadBalancer for service %s on namespace %s",
			vip, name, namespace)
		lbID, err := loadbalancer.GetOVNKubeIdlingLoadBalancer(proto)
		if err != nil {
			klog.Errorf("Error getting OVN idling LoadBalancer for protocol %s %v", proto, err)
			return err
		}
		if err := loadbalancer.DeleteLoadBalancerVIP(lbID, vip); err != nil {
			klog.Errorf("Error deleting VIP %s on idling OVN LoadBalancer %s %v", vip, lbID, err)
			return err
		}
	}
	return nil
}

// createPerNodeVIPs adds load balancers on a per node basis for GR and worker switch LBs using service IPs
func createPerNodeVIPs(svcIPs []string, protocol v1.Protocol, sourcePort int32, targetIPs []string, targetPort int32) error {
	if len(svcIPs) == 0 {
		return fmt.Errorf("unable to create per node VIPs...no service IPs provided")
	}
	klog.V(5).Infof("Creating Node VIPs - %s, %d, [%v], %d", protocol, sourcePort, targetIPs, targetPort)
	// Each gateway has a separate load-balancer for N/S traffic
	gatewayRouters, _, err := gateway.GetOvnGateways()
	if err != nil {
		return err
	}

	for _, gatewayRouter := range gatewayRouters {
		gatewayLB, err := gateway.GetGatewayLoadBalancer(gatewayRouter, protocol)
		if err != nil {
			klog.Errorf("Gateway router %s does not have load balancer (%v)",
				gatewayRouter, err)
			continue
		}
		physicalIPs, err := gateway.GetGatewayPhysicalIPs(gatewayRouter)
		if err != nil {
			klog.Errorf("Gateway router %s does not have physical ip (%v)", gatewayRouter, err)
			continue
		}

		var newTargets []string

		if config.Gateway.Mode == config.GatewayModeShared {
			// If self ip is in target list, we need to use special IP to allow hairpin back to host
			newTargets = util.UpdateIPsSlice(targetIPs, physicalIPs, []string{types.V4HostMasqueradeIP, types.V6HostMasqueradeIP})
		} else {
			newTargets = targetIPs
		}

		err = loadbalancer.CreateLoadBalancerVIPs(gatewayLB, svcIPs, sourcePort, newTargets, targetPort)
		if err != nil {
			klog.Errorf("Failed to create VIP in load balancer %s - %v", gatewayLB, err)
			return err
		}

		if config.Gateway.Mode == config.GatewayModeShared {
			workerNode := util.GetWorkerFromGatewayRouter(gatewayRouter)
			workerLB, err := loadbalancer.GetWorkerLoadBalancer(workerNode, protocol)
			if err != nil {
				klog.Errorf("Worker switch %s does not have load balancer (%v)", workerNode, err)
				return err
			}
			err = loadbalancer.CreateLoadBalancerVIPs(workerLB, svcIPs, sourcePort, targetIPs, targetPort)
			if err != nil {
				klog.Errorf("Failed to create VIP in load balancer %s - %v", workerLB, err)
				return err
			}
		}
	}
	return nil
}

// createPerNodePhysicalVIPs adds load balancers on a per node basis for GR and worker switch LBs using physical IPs
func createPerNodePhysicalVIPs(isIPv6 bool, protocol v1.Protocol, sourcePort int32, targetIPs []string, targetPort int32) error {
	klog.V(5).Infof("Creating Node VIPs - %s, %d, [%v], %d", protocol, sourcePort, targetIPs, targetPort)
	// Each gateway has a separate load-balancer for N/S traffic
	gatewayRouters, _, err := gateway.GetOvnGateways()
	if err != nil {
		return err
	}

	for _, gatewayRouter := range gatewayRouters {
		gatewayLB, err := gateway.GetGatewayLoadBalancer(gatewayRouter, protocol)
		if err != nil {
			klog.Errorf("Gateway router %s does not have load balancer (%v)",
				gatewayRouter, err)
			continue
		}
		physicalIPs, err := gateway.GetGatewayPhysicalIPs(gatewayRouter)
		if err != nil {
			klog.Errorf("Gateway router %s does not have physical ip (%v)", gatewayRouter, err)
			continue
		}
		// Filter only phyiscal IPs of the same family
		physicalIPs, err = util.MatchAllIPStringFamily(isIPv6, physicalIPs)
		if err != nil {
			klog.Errorf("Failed to find node physical IPs, for gateway: %s, error: %v", gatewayRouter, err)
			return err
		}

		var newTargets []string

		if config.Gateway.Mode == config.GatewayModeShared {
			// If self ip is in target list, we need to use special IP to allow hairpin back to host
			newTargets = util.UpdateIPsSlice(targetIPs, physicalIPs, []string{types.V4HostMasqueradeIP, types.V6HostMasqueradeIP})
		} else {
			newTargets = targetIPs
		}

		err = loadbalancer.CreateLoadBalancerVIPs(gatewayLB, physicalIPs, sourcePort, newTargets, targetPort)
		if err != nil {
			klog.Errorf("Failed to create VIP in load balancer %s - %v", gatewayLB, err)
			return err
		}

		if config.Gateway.Mode == config.GatewayModeShared {
			workerNode := util.GetWorkerFromGatewayRouter(gatewayRouter)
			workerLB, err := loadbalancer.GetWorkerLoadBalancer(workerNode, protocol)
			if err != nil {
				klog.Errorf("Worker switch %s does not have load balancer (%v)", workerNode, err)
				return err
			}
			err = loadbalancer.CreateLoadBalancerVIPs(workerLB, physicalIPs, sourcePort, targetIPs, targetPort)
			if err != nil {
				klog.Errorf("Failed to create VIP in load balancer %s - %v", workerLB, err)
				return err
			}
		}
	}
	return nil
}

// deleteNodeVIPs removes load balancers on a per node basis for GR and worker switch LBs
// if empty svcIP is provided, then the physical IPs will be used for the node
func deleteNodeVIPs(svcIPs []string, protocol v1.Protocol, sourcePort int32) error {
	klog.V(5).Infof("Searching to remove Gateway VIPs - %s, %d", protocol, sourcePort)
	gatewayRouters, _, err := gateway.GetOvnGateways()
	if err != nil {
		klog.Errorf("Error while searching for gateways: %v", err)
		return err
	}

	for _, gatewayRouter := range gatewayRouters {
		var loadBalancers []string
		gatewayLB, err := gateway.GetGatewayLoadBalancer(gatewayRouter, protocol)
		if err != nil {
			klog.Errorf("Gateway router %s does not have load balancer (%v)", gatewayRouter, err)
			continue
		}
		ips := svcIPs
		if len(ips) == 0 {
			ips, err = gateway.GetGatewayPhysicalIPs(gatewayRouter)
			if err != nil {
				klog.Errorf("Gateway router %s does not have physical ip (%v)", gatewayRouter, err)
				continue
			}
		}
		loadBalancers = append(loadBalancers, gatewayLB)
		if config.Gateway.Mode == config.GatewayModeShared {
			workerNode := util.GetWorkerFromGatewayRouter(gatewayRouter)
			workerLB, err := loadbalancer.GetWorkerLoadBalancer(workerNode, protocol)
			if err != nil {
				klog.Errorf("Worker switch %s does not have load balancer (%v)", workerNode, err)
				continue
			}
			loadBalancers = append(loadBalancers, workerLB)
		}
		for _, loadBalancer := range loadBalancers {
			for _, ip := range ips {
				// With the physical_ip:sourcePort as the VIP, delete an entry in 'load_balancer'.
				vip := util.JoinHostPortInt32(ip, sourcePort)
				klog.V(5).Infof("Removing gateway VIP: %s from load balancer: %s", vip, loadBalancer)
				if err := loadbalancer.DeleteLoadBalancerVIP(loadBalancer, vip); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// hasHostEndpoints determines if a slice of endpoints contains a host networked pod
func hasHostEndpoints(endpointIPs []string) bool {
	for _, endpointIP := range endpointIPs {
		found := false
		for _, clusterNet := range config.Default.ClusterSubnets {
			if clusterNet.CIDR.Contains(net.ParseIP(endpointIP)) {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}

// getNodeIPs returns the IPs for every node in the cluster for a specific IP family
func getNodeIPs(isIPv6 bool) ([]string, error) {
	nodeIPs := []string{}
	gatewayRouters, _, err := gateway.GetOvnGateways()
	if err != nil {
		return nil, err
	}
	for _, gatewayRouter := range gatewayRouters {
		physicalIPs, err := gateway.GetGatewayPhysicalIPs(gatewayRouter)
		if err != nil {
			klog.Errorf("Gateway router %s does not have physical ip (%v)", gatewayRouter, err)
			continue
		}
		physicalIPs, err = util.MatchAllIPStringFamily(isIPv6, physicalIPs)
		if err != nil {
			klog.Errorf("Failed to find node ips for gateway: %s that match IP family, error: %v",
				gatewayRouter, err)
			continue
		}
		nodeIPs = append(nodeIPs, physicalIPs...)
	}
	return nodeIPs, nil
}

// collectServiceVIPs collects all the vips associated to a given service
// and returns them as a set.
func collectServiceVIPs(service *v1.Service) sets.String {
	res := sets.NewString()
	for _, ip := range util.GetClusterIPs(service) {
		for _, svcPort := range service.Spec.Ports {
			vip := util.JoinHostPortInt32(ip, svcPort.Port)
			key := virtualIPKey(vip, svcPort.Protocol)
			res.Insert(key)
		}
	}
	for _, svcPort := range service.Spec.Ports {
		// Node Port
		if svcPort.NodePort != 0 {
			for _, isIPv6 := range []bool{false, true} {
				nodeIPs, err := getNodeIPs(isIPv6)
				if err != nil {
					klog.Error(err)
				}
				for _, ip := range nodeIPs {
					vip := util.JoinHostPortInt32(ip, svcPort.NodePort)
					key := virtualIPKey(vip, svcPort.Protocol)
					res.Insert(key)
				}
			}
		}

		for _, extIP := range service.Spec.ExternalIPs {
			vip := util.JoinHostPortInt32(extIP, svcPort.Port)
			key := virtualIPKey(vip, svcPort.Protocol)
			res.Insert(key)
		}
		// LoadBalancer
		for _, ingress := range service.Status.LoadBalancer.Ingress {
			if ingress.IP == "" {
				continue
			}
			vip := util.JoinHostPortInt32(ingress.IP, svcPort.Port)
			key := virtualIPKey(vip, svcPort.Protocol)
			res.Insert(key)
		}
	}
	return res
}

const OvnServiceIdledSuffix = "idled-at"

// When idling or empty LB events are enabled, we want to ensure we receive these packets and not reject them.
func svcNeedsIdling(annotations map[string]string) bool {
	if !config.Kubernetes.OVNEmptyLbEvents {
		return false
	}

	for annotationKey := range annotations {
		if strings.HasSuffix(annotationKey, OvnServiceIdledSuffix) {
			return true
		}
	}
	return false
}
