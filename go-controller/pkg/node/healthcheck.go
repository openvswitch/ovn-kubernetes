package node

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube/healthcheck"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
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

// checkForStaleOVSInternalPorts checks for OVS internal ports without any ofport assigned,
// they are stale ports that must be deleted
func checkForStaleOVSInternalPorts() {
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

// checkForStaleOVSRepresentorInterfaces checks for stale OVS ports backed by Repreresentor interfaces,
// derrive iface-id from pod name and namespace then remove any interfaces assoicated with a sandbox that are
// not scheduled to the node.
func checkForStaleOVSRepresentorInterfaces(nodeName string, k kube.Interface) {
	// list Ports on br-int and find out the current ports that have iface-ids
	currentIfaceIds := make(map[string]string)
	ports, stderr, err := util.RunOVSVsctl("list-ports", "br-int")
	if err != nil {
		klog.Errorf("failed to get list of ports on br-int:, stderr: %q, error: %v", stderr, err)
		return
	}

	for _, port := range strings.Split(ports, "\n") {
		stdout, stderr, err := util.RunOVSVsctl("get", "Port", port, "Interfaces")
		if err != nil {
			klog.Errorf("failed to get port %q on br-int:, stderr: %q, error: %v", port, stderr, err)
			continue
		}
		// remove brackets on list of interfaces
		ifaces := strings.TrimPrefix(strings.TrimSuffix(stdout, "]"), "[")
		for _, iface := range strings.Split(ifaces, ",") {
			// check that interface is associated with a sandbox
			sandbox, stderr, err := util.RunOVSVsctl("get", "Interface", strings.TrimSpace(iface),
				"external_ids:sandbox")
			if err != nil {
				if !strings.Contains(stderr, "no key") {
					klog.Errorf("failed to get Interface %q external_ids:sandbox. stderr: %q, error: %v",
						iface, stderr, err)
				}
				continue
			}
			if sandbox == "" {
				continue
			}
			// get iface ID
			ifaceId, stderr, err := util.RunOVSVsctl("get", "Interface", strings.TrimSpace(iface),
				"external_ids:iface-id")
			if err != nil {
				klog.Errorf("failed to get Interface %q external_ids:iface-id. stderr: %q, error: %v",
					iface, stderr, err)
				continue
			}
			if ifaceId == "" {
				continue
			}
			currentIfaceIds[ifaceId] = port
		}
	}

	if len(currentIfaceIds) == 0 {
		return
	}

	// list Pods and calculate the expected iface-ids.
	// Note: we do this after scanning ovs ports to avoid deleting ports of pods that where just scheduled
	// on the node.
	pods, err := k.GetPods("", metav1.LabelSelector{}, fields.OneTermEqualSelector(
		"spec.nodeName", nodeName).String())
	if err != nil {
		klog.Errorf("Failed to list pods assigned to node. %v", err)
		return
	}
	expectedIfaceIds := make(map[string]bool)
	for _, pod := range pods.Items {
		expectedIfaceIds[strings.Join([]string{pod.Namespace, pod.Name}, "_")] = true
	}

	// Remove any stale representor ports
	for ifaceId, port := range currentIfaceIds {
		if _, ok := expectedIfaceIds[ifaceId]; !ok {
			// TODO(adrianc): To make this more strict we can check if the interface is a VF representor
			// interface via sriovnet.
			klog.Warningf("found stale OVS port, deleting %s from br-int", port)
			_, stderr, err := util.RunOVSVsctl("--if-exists", "del-port", "br-int", port)
			if err != nil {
				klog.Errorf("failed to get delete port %q from br-int. stderr: %q, error: %v",
					port, stderr, err)
				continue
			}
		}
	}
}

// checkForStaleOVSInterfaces periodically checks for stale OVS interfaces
func checkForStaleOVSInterfaces(stopChan chan struct{}, nodeName string, k kube.Interface) {
	for {
		select {
		case <-time.After(60 * time.Second):
			checkForStaleOVSInternalPorts()
			checkForStaleOVSRepresentorInterfaces(nodeName, k)
		case <-stopChan:
			return
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
