package node

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube/healthcheck"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

// initLoadBalancerHealthChecker initializes the health check server for
// ServiceTypeLoadBalancer services
func initLoadBalancerHealthChecker(nodeName string, wf *factory.WatchFactory) {
	server := healthcheck.NewServer(nodeName, nil, nil, nil)
	services := make(map[ktypes.NamespacedName]uint16)
	endpoints := make(map[ktypes.NamespacedName]int)

	wf.AddServiceHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			svc := obj.(*kapi.Service)
			if svc.Spec.HealthCheckNodePort != 0 {
				name := ktypes.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}
				services[name] = uint16(svc.Spec.HealthCheckNodePort)
				_ = server.SyncServices(services)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			// HealthCheckNodePort can't be changed on update
		},
		DeleteFunc: func(obj interface{}) {
			svc := obj.(*kapi.Service)
			if svc.Spec.HealthCheckNodePort != 0 {
				name := ktypes.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}
				delete(services, name)
				delete(endpoints, name)
				_ = server.SyncServices(services)
			}
		},
	}, nil)

	wf.AddEndpointsHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ep := obj.(*kapi.Endpoints)
			name := ktypes.NamespacedName{Namespace: ep.Namespace, Name: ep.Name}
			if _, exists := services[name]; exists {
				endpoints[name] = countLocalEndpoints(ep, nodeName)
				_ = server.SyncEndpoints(endpoints)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			ep := new.(*kapi.Endpoints)
			name := ktypes.NamespacedName{Namespace: ep.Namespace, Name: ep.Name}
			if _, exists := services[name]; exists {
				endpoints[name] = countLocalEndpoints(ep, nodeName)
				_ = server.SyncEndpoints(endpoints)
			}
		},
		DeleteFunc: func(obj interface{}) {
			ep := obj.(*kapi.Endpoints)
			name := ktypes.NamespacedName{Namespace: ep.Namespace, Name: ep.Name}
			delete(endpoints, name)
			_ = server.SyncEndpoints(endpoints)
		},
	}, nil)
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
func checkForStaleOVSInterfaces(exec util.ExecHelper, stopChan chan struct{}) {
	for {
		select {
		case <-time.After(60 * time.Second):
			stdout, _, err := exec.RunOVSVsctl("--data=bare", "--no-headings", "--columns=name", "find",
				"interface", "ofport=-1")
			if err != nil {
				klog.Errorf("Failed to list OVS interfaces with ofport set to -1")
				continue
			}
			if len(stdout) == 0 {
				continue
			}
			values := strings.Split(stdout, "\n\n")
			for _, val := range values {
				klog.Warningf("Found stale interface %s, so deleting it", val)
				_, stderr, err := exec.RunOVSVsctl("--if-exists", "--with-iface", "del-port", val)
				if err != nil {
					klog.Errorf("Failed to delete OVS port/interface %s: stderr: %s (%v)",
						val, stderr, err)
				}
			}
		case <-stopChan:
			return
		}
	}
}

// checkDefaultOpenFlow checks for the existence of default OpenFlow rules and
// exits if the output is not as expected
func checkDefaultConntrackRules(exec util.ExecHelper, gwBridge string, physIntf, patchIntf, ofportPhys, ofportPatch string,
	nFlows int, stopChan chan struct{}) {
	flowCount := fmt.Sprintf("flow_count=%d", nFlows)
	for {
		select {
		case <-time.After(15 * time.Second):
			out, _, err := exec.RunOVSOfctl("dump-aggregate", gwBridge,
				fmt.Sprintf("cookie=%s/-1", defaultOpenFlowCookie))
			if err != nil {
				klog.Errorf("Failed to dump aggregate statistics of the default OpenFlow rules: %v", err)
				continue
			}

			if !strings.Contains(out, flowCount) {
				klog.Errorf("Fatal error: unexpected default OpenFlows count, expect %d output: %v\n",
					nFlows, out)
				os.Exit(1)
			}

			// it could be that the ovn-controller recreated the patch between the host OVS bridge and
			// the integration bridge, as a result the ofport number changed for that patch interface
			curOfportPatch, stderr, err := exec.RunOVSVsctl("--if-exists", "get", "Interface", patchIntf, "ofport")
			if err != nil {
				klog.Errorf("Failed to get ofport of %s, stderr: %q, error: %v", patchIntf, stderr, err)
				continue
			}
			if ofportPatch != curOfportPatch {
				klog.Errorf("Fatal error: ofport of %s has changed from %s to %s",
					patchIntf, ofportPatch, curOfportPatch)
				os.Exit(1)
			}

			// it could be that someone removed the physical interface and added it back on the OVS host
			// bridge, as a result the ofport number changed for that physical interface
			curOfportPhys, stderr, err := exec.RunOVSVsctl("--if-exists", "get", "interface", physIntf, "ofport")
			if err != nil {
				klog.Errorf("Failed to get ofport of %s, stderr: %q, error: %v", physIntf, stderr, err)
				continue
			}
			if ofportPhys != curOfportPhys {
				klog.Errorf("Fatal error: ofport of %s has changed from %s to %s",
					physIntf, ofportPhys, curOfportPhys)
				os.Exit(1)
			}
		case <-stopChan:
			return
		}
	}
}
