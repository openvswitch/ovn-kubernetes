package util

import (
	"fmt"
	"net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"

	kapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	utilnet "k8s.io/utils/net"
)

// ParseHybridOverlayHostSubnet returns the parsed hybrid overlay hostsubnet if
// the annotations included a valid one, or nil if they did not include one. If
// one was included, but it is invalid, an error is returned.
func ParseHybridOverlayHostSubnet(node *kapi.Node) (*net.IPNet, error) {
	sub, ok := node.Annotations[types.HybridOverlayNodeSubnet]
	if !ok {
		return nil, nil
	}
	_, subnet, err := net.ParseCIDR(sub)
	if err != nil {
		return nil, fmt.Errorf("error parsing node %s annotation %s value %q: %v",
			node.Name, types.HybridOverlayNodeSubnet, sub, err)
	}
	return subnet, nil
}

// IsHybridOverlayNode returns true if the node has been labeled as a
// node which does not participate in the ovn-kubernetes overlay network
func IsHybridOverlayNode(node *kapi.Node) bool {
	if config.Kubernetes.NoHostSubnetNodes != nil {
		nodeSelector, _ := metav1.LabelSelectorAsSelector(config.Kubernetes.NoHostSubnetNodes)
		return nodeSelector.Matches(labels.Set(node.Labels))
	}
	return false
}

// SameIPNet returns true if both inputs are nil or if both inputs have the
// same value
func SameIPNet(a, b *net.IPNet) bool {
	if a == b {
		return true
	} else if a == nil || b == nil {
		return false
	}
	return a.String() == b.String()
}

// GetNodeInternalIPs returns the first v4 and/or v6 NodeInternalIP address of the node
func GetNodeInternalIPs(node *kapi.Node) ([]string, error) {
	var v4AddrFound, v6AddrFound bool
	var ipAddrs []string
	for _, addr := range node.Status.Addresses {
		if !v4AddrFound && addr.Type == kapi.NodeInternalIP && !utilnet.IsIPv6String(addr.Address) {
			ipAddrs = append(ipAddrs, addr.Address)
			v4AddrFound = true
		}
		if !v6AddrFound && addr.Type == kapi.NodeInternalIP && utilnet.IsIPv6String(addr.Address) {
			ipAddrs = append(ipAddrs, addr.Address)
			v6AddrFound = true
		}
	}

	if ipAddrs != nil {
		return ipAddrs, nil
	}
	return nil, fmt.Errorf("failed to read node %q InternalIP", node.Name)
}

// StartNodeWatch starts a node event handler
func StartNodeWatch(h types.NodeHandler, wf *factory.WatchFactory) {
	wf.AddNodeHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node := obj.(*kapi.Node)
			h.Add(node)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldNode := oldObj.(*kapi.Node)
			newNode := newObj.(*kapi.Node)
			h.Update(oldNode, newNode)
		},
		DeleteFunc: func(obj interface{}) {
			node := obj.(*kapi.Node)
			h.Delete(node)
		},
	}, nil)
}

// CopyNamespaceAnnotationsToPod copies annotations from a namespace to a pod
func CopyNamespaceAnnotationsToPod(k kube.Interface, ns *kapi.Namespace, pod *kapi.Pod) error {
	nsGw, nsGwExists := ns.Annotations[types.HybridOverlayExternalGw]
	nsVTEP, nsVTEPExists := ns.Annotations[types.HybridOverlayVTEP]
	annotator := kube.NewPodAnnotator(k, pod)
	if nsGwExists {
		if err := annotator.Set(types.HybridOverlayExternalGw, nsGw); err != nil {
			return err
		}
	}
	if nsVTEPExists {
		if err := annotator.Set(types.HybridOverlayVTEP, nsVTEP); err != nil {
			return err
		}
	}
	return annotator.Run()
}

// MatchIPNets compares two IPNet slices and return true if they are equal.
// The elements need not be in the same order.
func MatchIPNets(a, b []*net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}
	var matchFound bool
	for _, firstIPNet := range a {
		matchFound = false
		for _, secondIPNet := range b {
			if SameIPNet(firstIPNet, secondIPNet) {
				matchFound = true
				break
			}
		}
		if !matchFound {
			return false
		}
	}
	return true
}

// MatchIPs compares two IP slices and return true if they are equal.
// The elements need not be in the same order.
func MatchIPs(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	var matchFound bool
	for _, firstIP := range a {
		matchFound = false
		for _, secondIP := range b {
			if firstIP.Equal(secondIP) {
				matchFound = true
				break
			}
		}
		if !matchFound {
			return false
		}
	}
	return true
}
