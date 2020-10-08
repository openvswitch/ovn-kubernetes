package controller

import (
	"fmt"
	"net"
	"reflect"
	"sync"

	"github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	hotypes "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	houtil "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

// The nodeController interface is implemented by the os-specific code
type nodeController interface {
	AddPod(*kapi.Pod) error
	DeletePod(*kapi.Pod) error
	AddNode(*kapi.Node) error
	DeleteNode(*kapi.Node) error
	RunFlowSync(<-chan struct{})
	EnsureHybridOverlayBridge(node *kapi.Node) error
}

// Node is a node controller and it's informers
type Node struct {
	ready            bool
	controller       nodeController
	nodeEventHandler informer.EventHandler
	podEventHandler  informer.EventHandler
}

func nodeChanged(old, new interface{}) bool {
	oldNode := old.(*kapi.Node)
	newNode := new.(*kapi.Node)

	oldCidrs, oldNodeIPs, oldDrMAC, _ := getNodeDetails(oldNode)
	newCidrs, newNodeIPs, newDrMAC, _ := getNodeDetails(newNode)
	return !houtil.MatchIPNets(oldCidrs, newCidrs) || !houtil.MatchIPs(oldNodeIPs, newNodeIPs) || !reflect.DeepEqual(oldDrMAC, newDrMAC)
}

// podChanged returns true if any relevant pod attributes changed
func podChanged(old, new interface{}) bool {
	oldPod := old.(*kapi.Pod)
	newPod := new.(*kapi.Pod)

	oldIPs, oldMAC, _ := getPodDetails(oldPod)
	newIPs, newMAC, _ := getPodDetails(newPod)
	oldExGw := oldPod.Annotations[hotypes.HybridOverlayExternalGw]
	oldVTEP := oldPod.Annotations[hotypes.HybridOverlayVTEP]
	newExGw := newPod.Annotations[hotypes.HybridOverlayExternalGw]
	newVTEP := newPod.Annotations[hotypes.HybridOverlayVTEP]

	if len(oldIPs) != len(newIPs) || !reflect.DeepEqual(oldMAC, newMAC) || !reflect.DeepEqual(oldExGw, newExGw) || !reflect.DeepEqual(oldVTEP, newVTEP) {
		return true
	}
	for i := range oldIPs {
		if oldIPs[i].String() != newIPs[i].String() {
			return true
		}
	}
	return false
}

// NewNode Returns a new Node
func NewNode(
	kube kube.Interface,
	nodeName string,
	nodeInformer cache.SharedIndexInformer,
	podInformer cache.SharedIndexInformer,
	eventHandlerCreateFunction informer.EventHandlerCreateFunction,
) (*Node, error) {

	nodeLister := listers.NewNodeLister(nodeInformer.GetIndexer())
	podLister := listers.NewPodLister(podInformer.GetIndexer())

	controller, err := newNodeController(kube, nodeName, nodeLister, podLister)
	if err != nil {
		return nil, err
	}
	n := &Node{controller: controller}
	n.nodeEventHandler = eventHandlerCreateFunction("node", nodeInformer,
		func(obj interface{}) error {
			node, ok := obj.(*kapi.Node)
			if !ok {
				return fmt.Errorf("object is not a node")
			}
			return n.controller.AddNode(node)
		},
		func(obj interface{}) error {
			node, ok := obj.(*kapi.Node)
			if !ok {
				return fmt.Errorf("object is not a node")
			}
			return n.controller.DeleteNode(node)
		},
		nodeChanged,
	)
	n.podEventHandler = eventHandlerCreateFunction("pod", podInformer,
		func(obj interface{}) error {
			pod, ok := obj.(*kapi.Pod)
			if !ok {
				return fmt.Errorf("object is not a pod")
			}
			if pod.Spec.NodeName != nodeName {
				return nil
			}
			return n.controller.AddPod(pod)
		},
		func(obj interface{}) error {
			pod, ok := obj.(*kapi.Pod)
			if !ok {
				return fmt.Errorf("object is not a pod")
			}
			if pod.Spec.NodeName != nodeName {
				return nil
			}
			return n.controller.DeletePod(pod)
		},
		podChanged,
	)
	return n, nil
}

// Run starts the controller and does not return until all operations have
// terminated after the stop channel is closed
func (n *Node) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	klog.Info("Starting Hybrid Overlay Node Controller")

	wg := &sync.WaitGroup{}

	klog.Info("Starting Hybrid Overlay Node workers")
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := n.nodeEventHandler.Run(informer.DefaultNodeInformerThreadiness, stopCh)
		if err != nil {
			klog.Error(err)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := n.podEventHandler.Run(informer.DefaultInformerThreadiness, stopCh)
		if err != nil {
			klog.Error(err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		n.controller.RunFlowSync(stopCh)
	}()

	klog.Info("Started Hybrid Overlay Node workers")
	n.ready = true
	<-stopCh
	klog.Info("Shutting down Hybrid Overlay Node workers")
	wg.Wait()
	klog.Info("Shut down Hybrid Overlay Node workers")
}

// getNodeSubnetAndIP returns the node's hybrid overlay subnet and the node's
// first InternalIP, or nil if the subnet or node IP is invalid
func getNodeSubnetAndIP(node *kapi.Node) ([]*net.IPNet, []net.IP) {
	var ips []net.IP

	// Parse Linux node OVN hostsubnet annotation first
	cidrs, _ := util.ParseNodeHostSubnetAnnotation(node)
	if cidrs == nil {
		// Otherwise parse the hybrid overlay node subnet annotation
		// TODO : DUAL-STACK change the code when HO annotations for multiple subnets are in
		subnet, ok := node.Annotations[types.HybridOverlayNodeSubnet]
		if !ok {
			klog.V(5).Infof("Missing node %q node subnet annotation", node.Name)
			return nil, nil
		}
		_, cidr, err := net.ParseCIDR(subnet)
		if err != nil {
			klog.Errorf("Error parsing node %q subnet %q: %v", node.Name, subnet, err)
			return nil, nil
		}
		cidrs = append(cidrs, cidr)
	}

	ipAddrs, err := houtil.GetNodeInternalIPs(node)
	if err != nil {
		klog.Errorf("Error getting node %q internal IP: %v", node.Name, err)
		return nil, nil
	}
	// Return an error if any of the internal addresses are missing in case of dual stack
	if len(cidrs) == 2 && len(ipAddrs) != 2 {
		klog.Errorf("Error getting node %q internal IP: %v", node.Name, err)
		return nil, nil
	}

	ips = make([]net.IP, 0)
	for _, ipAddr := range ipAddrs {
		ips = append(ips, net.ParseIP(ipAddr))
	}
	return cidrs, ips
}

// getNodeDetails returns the node's hybrid overlay subnets, first InternalIPs,
// and the distributed router MAC (DRMAC), or nil if any of the addresses are
// missing or invalid.
func getNodeDetails(node *kapi.Node) ([]*net.IPNet, []net.IP, net.HardwareAddr, error) {
	cidrs, ips := getNodeSubnetAndIP(node)
	if cidrs == nil || ips == nil {
		return nil, nil, nil, fmt.Errorf("missing node subnet and/or node IP")
	}

	drMACString, ok := node.Annotations[types.HybridOverlayDRMAC]
	if !ok {
		return nil, nil, nil, fmt.Errorf("missing distributed router MAC annotation")
	}
	drMAC, err := net.ParseMAC(drMACString)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid distributed router MAC %q: %v", drMACString, err)
	}

	return cidrs, ips, drMAC, nil
}

func getPodDetails(pod *kapi.Pod) ([]*net.IPNet, net.HardwareAddr, error) {
	podInfo, err := util.UnmarshalPodAnnotation(pod.Annotations)
	if err != nil {
		return nil, nil, err
	}
	return podInfo.IPs, podInfo.MAC, nil
}
