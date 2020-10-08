package controller

import (
	"fmt"
	"net"
	"sync"
	"time"

	goovn "github.com/ebay/go-ovn"
	"github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	hotypes "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	houtil "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/subnetallocator"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
	utilnet "k8s.io/utils/net"
)

// MasterController is the master hybrid overlay controller
type MasterController struct {
	kube                  kube.Interface
	exec                  util.ExecHelper
	allocator             *subnetallocator.SubnetAllocator
	nodeEventHandler      informer.EventHandler
	namespaceEventHandler informer.EventHandler
	podEventHandler       informer.EventHandler
	ovnNBClient           goovn.Client
	ovnSBClient           goovn.Client
}

// NewMaster a new master controller that listens for node events
func NewMaster(kube kube.Interface,
	exec util.ExecHelper,
	nodeInformer cache.SharedIndexInformer,
	namespaceInformer cache.SharedIndexInformer,
	podInformer cache.SharedIndexInformer,
	ovnNBClient goovn.Client,
	ovnSBClient goovn.Client,
	eventHandlerCreateFunction informer.EventHandlerCreateFunction,
) (*MasterController, error) {

	m := &MasterController{
		kube:        kube,
		exec:        exec,
		allocator:   subnetallocator.NewSubnetAllocator(),
		ovnNBClient: ovnNBClient,
		ovnSBClient: ovnSBClient,
	}

	m.nodeEventHandler = eventHandlerCreateFunction("node", nodeInformer,
		func(obj interface{}) error {
			node, ok := obj.(*kapi.Node)
			if !ok {
				return fmt.Errorf("object is not a node")
			}
			return m.AddNode(node)
		},
		func(obj interface{}) error {
			node, ok := obj.(*kapi.Node)
			if !ok {
				return fmt.Errorf("object is not a node")
			}
			return m.DeleteNode(node)
		},
		informer.ReceiveAllUpdates,
	)

	m.namespaceEventHandler = eventHandlerCreateFunction("namespace", namespaceInformer,
		func(obj interface{}) error {
			ns, ok := obj.(*kapi.Namespace)
			if !ok {
				return fmt.Errorf("object is not a namespace")
			}
			return m.AddNamespace(ns)
		},
		func(obj interface{}) error {
			// discard deletes
			return nil
		},
		nsHybridAnnotationChanged,
	)

	m.podEventHandler = eventHandlerCreateFunction("pod", podInformer,
		func(obj interface{}) error {
			pod, ok := obj.(*kapi.Pod)
			if !ok {
				return fmt.Errorf("object is not a pod")
			}
			return m.AddPod(pod)
		},
		func(obj interface{}) error {
			// discard deletes
			return nil
		},
		informer.DiscardAllUpdates,
	)

	// Add our hybrid overlay CIDRs to the subnetallocator
	for _, clusterEntry := range config.HybridOverlay.ClusterSubnets {
		err := m.allocator.AddNetworkRange(clusterEntry.CIDR, clusterEntry.HostSubnetLength)
		if err != nil {
			return nil, err
		}
	}

	// Mark existing hostsubnets as already allocated
	existingNodes, err := m.kube.GetNodes()
	if err != nil {
		return nil, fmt.Errorf("error in initializing/fetching subnets: %v", err)
	}
	for _, node := range existingNodes.Items {
		hostsubnet, err := houtil.ParseHybridOverlayHostSubnet(&node)
		if err != nil {
			klog.Warningf(err.Error())
		} else if hostsubnet != nil {
			klog.V(5).Infof("Marking existing node %s hybrid overlay NodeSubnet %s as allocated", node.Name, hostsubnet)
			if err := m.allocator.MarkAllocatedNetwork(hostsubnet); err != nil {
				utilruntime.HandleError(err)
			}
		}
	}

	return m, nil
}

// Run starts the controller
func (m *MasterController) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	klog.Info("Starting Hybrid Overlay Master Controller")

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := m.nodeEventHandler.Run(informer.DefaultNodeInformerThreadiness, stopCh)
		if err != nil {
			klog.Error(err)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := m.namespaceEventHandler.Run(informer.DefaultInformerThreadiness, stopCh)
		if err != nil {
			klog.Error(err)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := m.podEventHandler.Run(informer.DefaultInformerThreadiness, stopCh)
		if err != nil {
			klog.Error(err)
		}
	}()
	<-stopCh
	klog.Info("Shutting down Hybrid Overlay Master workers")
	wg.Wait()
	klog.Info("Shut down Hybrid Overlay Master workers")
}

// hybridOverlayNodeEnsureSubnet allocates a subnet and sets the
// hybrid overlay subnet annotation. It returns any newly allocated subnet
// or an error. If an error occurs, the newly allocated subnet will be released.
func (m *MasterController) hybridOverlayNodeEnsureSubnet(node *kapi.Node, annotator kube.Annotator) (*net.IPNet, error) {
	// Do not allocate a subnet if the node already has one
	if subnet, _ := houtil.ParseHybridOverlayHostSubnet(node); subnet != nil {
		return nil, nil
	}

	// Allocate a new host subnet for this node
	hostsubnets, err := m.allocator.AllocateNetworks()
	if err != nil {
		return nil, fmt.Errorf("error allocating hybrid overlay HostSubnet for node %s: %v", node.Name, err)
	}

	if err := annotator.Set(types.HybridOverlayNodeSubnet, hostsubnets[0].String()); err != nil {
		_ = m.allocator.ReleaseNetwork(hostsubnets[0])
		return nil, err
	}

	klog.Infof("Allocated hybrid overlay HostSubnet %s for node %s", hostsubnets[0], node.Name)
	return hostsubnets[0], nil
}

func (m *MasterController) releaseNodeSubnet(nodeName string, subnet *net.IPNet) error {
	if err := m.allocator.ReleaseNetwork(subnet); err != nil {
		return fmt.Errorf("error deleting hybrid overlay HostSubnet %s for node %q: %s", subnet, nodeName, err)
	}
	klog.Infof("Deleted hybrid overlay HostSubnet %s for node %s", subnet, nodeName)
	return nil
}

// handleOverlayPort reconciles the node's overlay port with OVN.
// It needs to handle the following cases:
//   - no subnet allocated: unset MAC annotation
//   - no MAC annotation, no lsp: configure lsp, set annotation
//   - annotation, no lsp: configure lsp
//   - annotation, lsp: ensure lsp matches annotation
//   - no annotation, lsp: set annotation from lsp
func (m *MasterController) handleOverlayPort(node *kapi.Node, annotator kube.Annotator) error {
	var err error
	var annotationMAC, portMAC net.HardwareAddr
	portName := util.GetHybridOverlayPortName(node.Name)

	// retrieve mac annotation
	am, annotationOK := node.Annotations[types.HybridOverlayDRMAC]
	if annotationOK {
		annotationMAC, err = net.ParseMAC(am)
		if err != nil {
			klog.Errorf("MAC annotation %s on node %s is invalid, ignoring.", annotationMAC, node.Name)
			annotationOK = false
		}
	}

	// no subnet allocated? unset mac annotation, be done.
	subnets, err := util.ParseNodeHostSubnetAnnotation(node)
	if subnets == nil || err != nil {
		// No subnet allocated yet; clean up
		klog.V(5).Infof("No subnet allocation yet for %s", node.Name)
		if annotationOK {
			m.deleteOverlayPort(node)
			annotator.Delete(types.HybridOverlayDRMAC)
		}
		return nil
	}

	// retrieve port configuration. If port isn't set up, portMAC will be nil
	portMAC, _, _ = util.GetPortAddresses(portName, m.ovnNBClient)

	// compare port configuration to annotation MAC, reconcile as needed
	lspOK := false

	// nothing allocated, allocate default mac
	if portMAC == nil && annotationMAC == nil {
		for _, subnet := range subnets {
			ip := util.GetNodeHybridOverlayIfAddr(subnet).IP
			portMAC = util.IPAddrToHWAddr(ip)
			annotationMAC = portMAC
			if !utilnet.IsIPv6(ip) {
				break
			}
		}
		klog.V(5).Infof("Allocating MAC %s to node %s", portMAC.String(), node.Name)
	} else if portMAC == nil && annotationMAC != nil { // annotation, no port
		portMAC = annotationMAC
	} else if portMAC != nil && annotationMAC == nil { // port, no annotation
		lspOK = true
		annotationMAC = portMAC
	} else if portMAC != nil && annotationMAC != nil { // port & annotation: anno wins
		if portMAC.String() != annotationMAC.String() {
			klog.V(2).Infof("Warning: node %s lsp %s has mismatching hybrid port mac, correcting", node.Name, portName)
			portMAC = annotationMAC
		} else {
			lspOK = true
		}
	}

	if !lspOK {
		klog.Infof("Creating / updating node %s hybrid overlay port with mac %s", node.Name, portMAC.String())

		var stderr string
		// create / update lsps
		_, stderr, err = m.exec.RunOVNNbctl("--", "--may-exist", "lsp-add", node.Name, portName,
			"--", "lsp-set-addresses", portName, portMAC.String())
		if err != nil {
			return fmt.Errorf("failed to add hybrid overlay port for node %s"+
				", stderr:%s: %v", node.Name, stderr, err)
		}
		for _, subnet := range subnets {
			if err := util.UpdateNodeSwitchExcludeIPs(m.exec, node.Name, subnet); err != nil {
				return err
			}
		}
	}

	if !annotationOK {
		klog.Infof("Setting node %s hybrid overlay mac annotation to %s", node.Name, annotationMAC.String())
		if err := annotator.Set(types.HybridOverlayDRMAC, portMAC.String()); err != nil {
			return fmt.Errorf("failed to set node %s hybrid overlay DRMAC annotation: %v", node.Name, err)
		}
	}

	return nil
}

func (m *MasterController) deleteOverlayPort(node *kapi.Node) {
	klog.Infof("Removing node %s hybrid overlay port", node.Name)
	portName := util.GetHybridOverlayPortName(node.Name)
	_, _, _ = m.exec.RunOVNNbctl("--", "--if-exists", "lsp-del", portName)
}

// AddNode handles node additions
func (m *MasterController) AddNode(node *kapi.Node) error {
	klog.V(5).Infof("Processing add event for node %s", node.Name)
	annotator := kube.NewNodeAnnotator(m.kube, node)

	var allocatedSubnet *net.IPNet
	if houtil.IsHybridOverlayNode(node) {
		var err error
		allocatedSubnet, err = m.hybridOverlayNodeEnsureSubnet(node, annotator)
		if err != nil {
			return fmt.Errorf("failed to update node %q hybrid overlay subnet annotation: %v", node.Name, err)
		}
	} else {
		if err := m.handleOverlayPort(node, annotator); err != nil {
			return fmt.Errorf("failed to set up hybrid overlay logical switch port for %s: %v", node.Name, err)
		}
	}

	if err := annotator.Run(); err != nil {
		// Release allocated subnet if any errors occurred
		if allocatedSubnet != nil {
			_ = m.releaseNodeSubnet(node.Name, allocatedSubnet)
		}
		return fmt.Errorf("failed to set hybrid overlay annotations for %s: %v", node.Name, err)
	}
	return nil
}

// DeleteNode handles node deletions
func (m *MasterController) DeleteNode(node *kapi.Node) error {
	klog.V(5).Infof("Processing node delete for %s", node.Name)
	if subnet, _ := houtil.ParseHybridOverlayHostSubnet(node); subnet != nil {
		if err := m.releaseNodeSubnet(node.Name, subnet); err != nil {
			return err
		}
	}

	if _, ok := node.Annotations[types.HybridOverlayDRMAC]; ok && !houtil.IsHybridOverlayNode(node) {
		m.deleteOverlayPort(node)
	}
	klog.V(5).Infof("Node delete for %s completed", node.Name)
	return nil
}

// AddNamespace copies namespace annotations to all pods in the namespace
func (m *MasterController) AddNamespace(ns *kapi.Namespace) error {
	podLister := listers.NewPodLister(m.podEventHandler.GetIndexer())
	pods, err := podLister.Pods(ns.Name).List(labels.Everything())
	if err != nil {
		return err
	}
	for _, pod := range pods {
		if err := houtil.CopyNamespaceAnnotationsToPod(m.kube, ns, pod); err != nil {
			klog.Errorf("Unable to copy hybrid-overlay namespace annotations to pod %s", pod.Name)
		}
	}
	return nil
}

// waitForNamespace fetches a namespace from the cache, or waits until it's available
func (m *MasterController) waitForNamespace(name string) (*kapi.Namespace, error) {
	var namespaceBackoff = wait.Backoff{Duration: 1 * time.Second, Steps: 7, Factor: 1.5, Jitter: 0.1}
	var namespace *kapi.Namespace
	if err := wait.ExponentialBackoff(namespaceBackoff, func() (bool, error) {
		var err error
		namespaceLister := listers.NewNamespaceLister(m.namespaceEventHandler.GetIndexer())
		namespace, err = namespaceLister.Get(name)
		if err != nil {
			if errors.IsNotFound(err) {
				// Namespace not found; retry
				return false, nil
			}
			klog.Warningf("Error getting namespace: %v", err)
			return false, err
		}
		return true, nil
	}); err != nil {
		return nil, fmt.Errorf("failed to get namespace object: %v", err)
	}
	return namespace, nil
}

// AddPod ensures that hybrid overlay annotations are copied to a
// pod when it's created. This allows the nodes to set up the appropriate
// flows
func (m *MasterController) AddPod(pod *kapi.Pod) error {
	namespace, err := m.waitForNamespace(pod.Namespace)
	if err != nil {
		return err
	}

	namespaceExternalGw := namespace.Annotations[hotypes.HybridOverlayExternalGw]
	namespaceVTEP := namespace.Annotations[hotypes.HybridOverlayVTEP]

	podExternalGw := pod.Annotations[hotypes.HybridOverlayExternalGw]
	podVTEP := pod.Annotations[hotypes.HybridOverlayVTEP]

	if namespaceExternalGw != podExternalGw || namespaceVTEP != podVTEP {
		// copy namespace annotations to the pod and return
		return houtil.CopyNamespaceAnnotationsToPod(m.kube, namespace, pod)
	}
	return nil
}

// nsHybridAnnotationChanged returns true if any relevant NS attributes changed
func nsHybridAnnotationChanged(old, new interface{}) bool {
	oldNs := old.(*kapi.Namespace)
	newNs := new.(*kapi.Namespace)

	nsExGwOld := oldNs.GetAnnotations()[hotypes.HybridOverlayExternalGw]
	nsVTEPOld := oldNs.GetAnnotations()[hotypes.HybridOverlayVTEP]
	nsExGwNew := newNs.GetAnnotations()[hotypes.HybridOverlayExternalGw]
	nsVTEPNew := newNs.GetAnnotations()[hotypes.HybridOverlayVTEP]
	if nsExGwOld != nsExGwNew || nsVTEPOld != nsVTEPNew {
		return true
	}
	return false
}
