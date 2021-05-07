package node

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube/healthcheck"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
)

// initLoadBalancerHealthChecker initializes the health check server for
// ServiceTypeLoadBalancer services

type loadBalancerHealthChecker struct {
	nodeName  string
	server    healthcheck.Server
	services  map[ktypes.NamespacedName]uint16
	endpoints map[ktypes.NamespacedName]int
}

func newLoadBalancerHealthChecker(nodeName string) *loadBalancerHealthChecker {
	return &loadBalancerHealthChecker{
		nodeName:  nodeName,
		server:    healthcheck.NewServer(nodeName, nil, nil, nil),
		services:  make(map[ktypes.NamespacedName]uint16),
		endpoints: make(map[ktypes.NamespacedName]int),
	}
}

func (l *loadBalancerHealthChecker) AddService(svc *kapi.Service) {
	if svc.Spec.HealthCheckNodePort != 0 {
		name := ktypes.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}
		l.services[name] = uint16(svc.Spec.HealthCheckNodePort)
		_ = l.server.SyncServices(l.services)
	}
}

func (l *loadBalancerHealthChecker) UpdateService(old, new *kapi.Service) {
	// HealthCheckNodePort can't be changed on update
}

func (l *loadBalancerHealthChecker) DeleteService(svc *kapi.Service) {
	if svc.Spec.HealthCheckNodePort != 0 {
		name := ktypes.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}
		delete(l.services, name)
		delete(l.endpoints, name)
		_ = l.server.SyncServices(l.services)
	}
}

func (l *loadBalancerHealthChecker) SyncServices(svcs []interface{}) {}

func (l *loadBalancerHealthChecker) AddEndpoints(ep *kapi.Endpoints) {
	name := ktypes.NamespacedName{Namespace: ep.Namespace, Name: ep.Name}
	if _, exists := l.services[name]; exists {
		l.endpoints[name] = countLocalEndpoints(ep, l.nodeName)
		_ = l.server.SyncEndpoints(l.endpoints)
	}
}

func (l *loadBalancerHealthChecker) UpdateEndpoints(old, new *kapi.Endpoints) {
	name := ktypes.NamespacedName{Namespace: new.Namespace, Name: new.Name}
	if _, exists := l.services[name]; exists {
		l.endpoints[name] = countLocalEndpoints(new, l.nodeName)
		_ = l.server.SyncEndpoints(l.endpoints)
	}

}

func (l *loadBalancerHealthChecker) DeleteEndpoints(ep *kapi.Endpoints) {
	name := ktypes.NamespacedName{Namespace: ep.Namespace, Name: ep.Name}
	delete(l.endpoints, name)
	_ = l.server.SyncEndpoints(l.endpoints)
}

func countLocalEndpoints(ep *kapi.Endpoints, nodeName string) int {
	num := 0
	for i := range ep.Subsets {
		ss := &ep.Subsets[i]
		for i := range ss.Addresses {
			addr := &ss.Addresses[i]
			if addr.NodeName != nil && *addr.NodeName == nodeName {
				num++
			}
		}
	}
	return num
}

// check for OVS internal ports without any ofport assigned, they are stale ports that must be deleted
func checkForStaleOVSInterfaces() {
	stdout, _, err := util.RunOVSVsctl("--data=bare", "--no-headings", "--columns=name", "find",
		"interface", "ofport=-1")
	if err != nil {
		klog.Errorf("Failed to list OVS interfaces with ofport set to -1")
		return
	}
	if len(stdout) == 0 {
		return
	}
	values := strings.Split(stdout, "\n\n")
	for _, val := range values {
		klog.Warningf("Found stale interface %s, so deleting it", val)
		_, stderr, err := util.RunOVSVsctl("--if-exists", "--with-iface", "del-port", val)
		if err != nil {
			klog.Errorf("Failed to delete OVS port/interface %s: stderr: %s (%v)",
				val, stderr, err)
		}
	}
}

type openflowManager struct {
	gwBridge    string
	physIntf    string
	patchIntf   string
	ofportPhys  string
	ofportPatch string
	// flow cache, use map instead of array for readability when debugging
	flowCache map[string][]string
	flowMutex sync.Mutex
	// channel to indicate we need to update flows immediately
	flowChan chan struct{}
}

func (c *openflowManager) updateFlowCacheEntry(key string, flows []string) {
	c.flowMutex.Lock()
	defer c.flowMutex.Unlock()
	c.flowCache[key] = flows
}

func (c *openflowManager) deleteFlowsByKey(key string) {
	c.flowMutex.Lock()
	defer c.flowMutex.Unlock()
	delete(c.flowCache, key)
}

func (c *openflowManager) requestFlowSync() {
	select {
	case c.flowChan <- struct{}{}:
		klog.V(5).Infof("Gateway OpenFlow sync requested")
	default:
		klog.V(5).Infof("Gateway OpenFlow sync already requested")
	}
}

func (c *openflowManager) syncFlows() {
	c.flowMutex.Lock()
	defer c.flowMutex.Unlock()

	flows := []string{}
	for _, entry := range c.flowCache {
		flows = append(flows, entry...)
	}

	_, stderr, err := util.ReplaceOFFlows(c.gwBridge, flows)
	if err != nil {
		klog.Errorf("Failed to add flows, error: %v, stderr, %s, flows: %s", err, stderr, c.flowCache)
	}
}

// checkDefaultOpenFlow checks for the existence of default OpenFlow rules and
// exits if the output is not as expected
func (c *openflowManager) Run(stopChan <-chan struct{}) {
	for {
		select {
		case <-time.After(15 * time.Second):
			// it could be that the ovn-controller recreated the patch between the host OVS bridge and
			// the integration bridge, as a result the ofport number changed for that patch interface
			curOfportPatch, stderr, err := util.RunOVSVsctl("--if-exists", "get", "Interface", c.patchIntf, "ofport")
			if err != nil {
				klog.Errorf("Failed to get ofport of %s, stderr: %q, error: %v", c.patchIntf, stderr, err)
				continue
			}
			if c.ofportPatch != curOfportPatch {
				klog.Errorf("Fatal error: ofport of %s has changed from %s to %s",
					c.patchIntf, c.ofportPatch, curOfportPatch)
				os.Exit(1)
			}

			// it could be that someone removed the physical interface and added it back on the OVS host
			// bridge, as a result the ofport number changed for that physical interface
			curOfportPhys, stderr, err := util.RunOVSVsctl("--if-exists", "get", "interface", c.physIntf, "ofport")
			if err != nil {
				klog.Errorf("Failed to get ofport of %s, stderr: %q, error: %v", c.physIntf, stderr, err)
				continue
			}
			if c.ofportPhys != curOfportPhys {
				klog.Errorf("Fatal error: ofport of %s has changed from %s to %s",
					c.physIntf, c.ofportPhys, curOfportPhys)
				os.Exit(1)
			}

			c.syncFlows()
		case <-c.flowChan:
			c.syncFlows()
		case <-stopChan:
			return
		}
	}
}
