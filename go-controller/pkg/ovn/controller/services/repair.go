package services

import (
	"time"

	"github.com/pkg/errors"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/acl"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/gateway"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/loadbalancer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
)

// Repair is a controller loop that can work as in one-shot or periodic mode
// it checks the OVN Load Balancers and delete the ones that doesn't exist in
// the Kubernetes Service Informer cache.
// Based on:
// https://raw.githubusercontent.com/kubernetes/kubernetes/release-1.19/pkg/registry/core/service/ipallocator/controller/repair.go
type Repair struct {
	interval time.Duration
	// serviceTracker tracks services and maps them to OVN LoadBalancers
	serviceLister        corelisters.ServiceLister
	clusterPortGroupUUID string
}

// NewRepair creates a controller that periodically ensures that there is no stale data in OVN
func NewRepair(interval time.Duration, serviceLister corelisters.ServiceLister, clusterPortGroupUUID string) *Repair {
	return &Repair{
		interval:             interval,
		serviceLister:        serviceLister,
		clusterPortGroupUUID: clusterPortGroupUUID,
	}
}

// runOnce verifies the state of the cluster OVN LB VIP allocations and returns an error if an unrecoverable problem occurs.
func (r *Repair) runOnce() error {
	startTime := time.Now()
	klog.V(4).Infof("Starting repairing loop for services")
	defer func() {
		klog.V(4).Infof("Finished repairing loop for services: %v", time.Since(startTime))
		metrics.MetricSyncServiceLatency.WithLabelValues("repair-loop").Observe(time.Since(startTime).Seconds())
	}()

	// Obtain all the load balancers UUID
	ovnLBCache := make(map[v1.Protocol][]string)
	// We have different loadbalancers per protocol
	protocols := []v1.Protocol{v1.ProtocolSCTP, v1.ProtocolTCP, v1.ProtocolUDP}
	// ClusterIP OVN load balancers
	for _, p := range protocols {
		lbUUID, err := loadbalancer.GetOVNKubeLoadBalancer(p)
		if err != nil {
			return errors.Wrapf(err, "Failed to get Cluster IP OVN load balancer for protocol %s", p)
		}
		ovnLBCache[p] = append(ovnLBCache[p], lbUUID)
	}
	// NodePort, ExternalIPs, Ingress OVN load balancers as well as worker load balancers
	gatewayRouters, _, err := gateway.GetOvnGateways()
	if err != nil {
		klog.V(4).Infof("Failed to get gateway routers due to (%v). Skipping repairing OVN GR Load balancers", err)
	} else {
		for _, p := range protocols {
			for _, gatewayRouter := range gatewayRouters {
				lbUUID, err := gateway.GetGatewayLoadBalancer(gatewayRouter, p)
				if err != nil {
					if err != gateway.OVNGatewayLBIsEmpty {
						klog.V(5).Infof("Failed to get OVN GR: %s load balancer for protocol %s, err: %v",
							gatewayRouter, p, err)
					}
				} else {
					ovnLBCache[p] = append(ovnLBCache[p], lbUUID)
				}
				workerNode := util.GetWorkerFromGatewayRouter(gatewayRouter)
				workerLB, err := loadbalancer.GetWorkerLoadBalancer(workerNode, p)
				if err != nil {
					if err != gateway.OVNGatewayLBIsEmpty {
						klog.V(5).Infof("Failed to get OVN Worker: %s load balancer for protocol %s, err: %v",
							workerNode, p, err)
					}
					continue
				}
				ovnLBCache[p] = append(ovnLBCache[p], workerLB)
			}
		}
	}

	// Idling load balancers
	for _, p := range protocols {
		lb, err := loadbalancer.GetOVNKubeIdlingLoadBalancer(p)
		if err != nil {
			return errors.Wrapf(err, "Failed to get Idling OVN load balancer for protocol %s", p)
		}
		ovnLBCache[p] = append(ovnLBCache[p], lb)
	}

	// Get Kubernetes Service state
	svcVIPsProtocolMap := sets.NewString()
	services, err := r.serviceLister.List(labels.Everything())
	if err != nil {
		return errors.Wrapf(err, "Failed to list Services from the cache")
	}
	for _, svc := range services {
		for _, ip := range util.GetClusterIPs(svc) {
			for _, svcPort := range svc.Spec.Ports {
				vip := util.JoinHostPortInt32(ip, svcPort.Port)
				key := virtualIPKey(vip, svcPort.Protocol)
				svcVIPsProtocolMap.Insert(key)
			}
		}
	}

	// Reconcile with OVN state
	// Obtain all the VIPs present in the OVN LoadBalancers
	// and delete the ones that are not present in Kubernetes
	for _, p := range protocols {
		for _, lb := range ovnLBCache[p] {
			vips, err := loadbalancer.GetLoadBalancerVIPs(lb)
			if err != nil {
				klog.V(4).Infof("Failed to get vips for %s load balancer %s, err: %v", p, lb, err)
				continue
			}
			for vip := range vips {
				key := virtualIPKey(vip, p)
				// Virtual IP and protocol doesn't belong to a Kubernetes service
				if !svcVIPsProtocolMap.Has(key) {
					klog.Infof("Deleting non-existing Kubernetes vip %s from OVN %s load balancer %s", vip, p, lb)
					if err := loadbalancer.DeleteLoadBalancerVIP(lb, vip); err != nil {
						klog.V(4).Infof("Failed to delete %s load balancer vips %s for %s, err: %v", p, vip, lb, err)
					}
				}
			}
		}
	}

	// Remove existing reject rules. They are not used anymore
	// given the introduction of idling loadbalancers
	err = acl.PurgeRejectRules(r.clusterPortGroupUUID)
	if err != nil {
		klog.Errorf("Failed to purge existing reject rules: %v", err)
		return err
	}
	return nil
}
