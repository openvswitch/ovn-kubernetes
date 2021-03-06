package util

import (
	"encoding/json"
	"fmt"
	"net"

	kapi "k8s.io/api/core/v1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
)

// This handles the annotations related to subnets assigned to a node. The annotations are
// created by the master, and then read by the node. In a single-stack cluster, they look
// like:
//
//   annotations:
//     k8s.ovn.org/node-subnets: |
//       {
//         "default": "10.130.0.0/23",
//         "nw1":     "10.132.0.0/23"
//       }
//     k8s.ovn.org/node-local-nat-ip: |
//       {
//         "default": ["169.254.16.21", "fd99::10:21"]
//       }
//
// (This allows for specifying multiple network attachments
//
// In a dual-stack cluster, the values are lists:
//
//   annotations:
//     k8s.ovn.org/node-subnets: |
//       {
//         "default": ["10.130.0.0/23", "fd01:0:0:2::/64"],
//         "nw1":     ["10.132.0.0/23", "fd03:0:0:2::/64"],
//       }

const (
	// ovnNodeSubnets is the constant string representing the node subnets annotation key
	ovnNodeSubnets = "k8s.ovn.org/node-subnets"
	// ovnNodeLocalNatIP is the constant string representing the node management port's NAT IP
	// used in the case of the shared gateway mode
	ovnNodeLocalNatIP = "k8s.ovn.org/node-local-nat-ip"
)

// updateSubnetAnnotation add the hostSubnets of the given network to the input node annotations;
// if hostSubnets is empty, it delete the existing subnet annotation for given network from the input node annotations.
func updateSubnetAnnotation(annotations map[string]string, annotationName, netName string, hostSubnets []*net.IPNet) error {
	var bytes []byte
	var err error

	// First get the all host subnets for all existing networks
	subnetsMap := map[string][]*net.IPNet{}
	_, ok := annotations[annotationName]
	if ok {
		subnetsMap, err = parseSubnetAnnotation(annotations, annotationName)
		if err != nil {
			return fmt.Errorf("failed to parse node subnet annotation %q: %v",
				annotations, err)
		}
	}

	// add or delete host subnet of the specified network
	if len(hostSubnets) != 0 {
		subnetsMap[netName] = hostSubnets
	} else {
		delete(subnetsMap, netName)
	}

	// if no host subnet left, just delete the host subnet annotation from node annotations.
	if len(subnetsMap) == 0 {
		delete(annotations, annotationName)
		return nil
	}

	// Marshall all host subnets of all networks back to annotations.
	subnetsStrMap := make(map[string][]string)
	for n, subnets := range subnetsMap {
		subnetsStr := make([]string, len(subnets))
		for i, subnet := range subnets {
			subnetsStr[i] = subnet.String()
		}
		subnetsStrMap[n] = subnetsStr
	}
	bytes, err = json.Marshal(subnetsStrMap)
	if err != nil {
		return err
	}
	annotations[annotationName] = string(bytes)
	return nil
}

func createSubnetAnnotation(annotationName string, defaultSubnets []*net.IPNet) (map[string]interface{}, error) {
	var bytes []byte
	var err error

	if len(defaultSubnets) == 1 {
		bytes, err = json.Marshal(map[string]string{
			types.DefaultNetworkName: defaultSubnets[0].String(),
		})
	} else {
		defaultSubnetStrs := make([]string, len(defaultSubnets))
		for i := range defaultSubnets {
			defaultSubnetStrs[i] = defaultSubnets[i].String()
		}
		bytes, err = json.Marshal(map[string][]string{
			types.DefaultNetworkName: defaultSubnetStrs,
		})
	}
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		annotationName: string(bytes),
	}, nil
}

func setSubnetAnnotation(nodeAnnotator kube.Annotator, annotationName string, defaultSubnets []*net.IPNet) error {
	annotation, err := createSubnetAnnotation(annotationName, defaultSubnets)
	if err != nil {
		return err
	}
	return nodeAnnotator.Set(annotationName, annotation[annotationName])
}

func parseSubnetAnnotation(nodeAnnotations map[string]string, annotationName string) (map[string][]*net.IPNet, error) {
	annotation := nodeAnnotations[annotationName]
	subnetsStrMap := map[string][]string{}
	subnetsDual := make(map[string][]string)
	if err := json.Unmarshal([]byte(annotation), &subnetsDual); err == nil {
		subnetsStrMap = subnetsDual
	} else {
		subnetsSingle := make(map[string]string)
		if err := json.Unmarshal([]byte(annotation), &subnetsSingle); err != nil {
			return nil, fmt.Errorf("could not parse %q annotation %q as either single-stack or dual-stack: %v",
				annotationName, annotation, err)
		}
		for netName, v := range subnetsSingle {
			subnetsStrMap[netName] = make([]string, 1)
			subnetsStrMap[netName][0] = v
		}
	}

	if len(subnetsStrMap) == 0 {
		return nil, fmt.Errorf("unexpected empty %s annotation", annotationName)
	}

	subnetMap := make(map[string][]*net.IPNet)
	for netName, subnetsStr := range subnetsStrMap {
		var ipnets []*net.IPNet
		for _, subnet := range subnetsStr {
			_, ipnet, err := net.ParseCIDR(subnet)
			if err != nil {
				return nil, fmt.Errorf("error parsing %q value: %v", annotationName, err)
			}
			ipnets = append(ipnets, ipnet)
		}
		subnetMap[netName] = ipnets
	}

	return subnetMap, nil
}

// UpdateNodeHostSubnetAnnotation update a "k8s.ovn.org/node-subnets" annotation for network "netName",
// with the specified network, suitable for passing to kube.SetAnnotationsOnNode. If hostSubnets is empty,
// it deleted the "k8s.ovn.org/node-subnets" annotation for network "netName"
func UpdateNodeHostSubnetAnnotation(annotations map[string]string, hostSubnets []*net.IPNet, netName string) error {
	return updateSubnetAnnotation(annotations, ovnNodeSubnets, netName, hostSubnets)
}

// SetNodeHostSubnetAnnotation sets a "k8s.ovn.org/[netName_]node-subnets" annotation
// using a kube.Annotator
func SetNodeHostSubnetAnnotation(nodeAnnotator kube.Annotator, defaultSubnets []*net.IPNet) error {
	return setSubnetAnnotation(nodeAnnotator, ovnNodeSubnets, defaultSubnets)
}

// DeleteNodeHostSubnetAnnotation removes a "k8s.ovn.org/[netName_]node-subnets" annotation
// using a kube.Annotator
func DeleteNodeHostSubnetAnnotation(nodeAnnotator kube.Annotator, netName string) {
	nodeAnnotator.Delete(ovnNodeSubnets)
}

// ParseNodeHostSubnetAnnotation parses the "k8s.ovn.org/node-subnets" annotation
// on a node and returns the host subnet for the given network.
func ParseNodeHostSubnetAnnotation(node *kapi.Node, netName string) ([]*net.IPNet, error) {
	_, ok := node.Annotations[ovnNodeSubnets]
	if !ok {
		return nil, newAnnotationNotSetError("node %q has no %q annotation", node.Name, ovnNodeSubnets)
	}

	subnetsMap, err := parseSubnetAnnotation(node.Annotations, ovnNodeSubnets)
	if err != nil {
		return nil, err
	}
	subnets, ok := subnetsMap[netName]
	if !ok {
		return nil, newAnnotationNotSetError("node %q has no %q annotation for network %s", node.Name, ovnNodeSubnets, netName)
	}

	return subnets, nil
}

// CreateNodeLocalNatAnnotation creates a "k8s.ovn.org/node-local-nat-ip" annotation,
// with a single "default" network, suitable for passing to kube.SetAnnotationsOnNode
func CreateNodeLocalNatAnnotation(nodeLocalNatIPs []net.IP) (map[string]interface{}, error) {
	nodeLocalNatIPStrs := make([]string, len(nodeLocalNatIPs))
	for i := range nodeLocalNatIPs {
		nodeLocalNatIPStrs[i] = nodeLocalNatIPs[i].String()
	}
	bytes, err := json.Marshal(map[string][]string{
		types.DefaultNetworkName: nodeLocalNatIPStrs,
	})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		ovnNodeLocalNatIP: string(bytes),
	}, nil
}

// SetNodeLocalNatAnnotation sets a "k8s.ovn.org/node-local-nat-ip" annotation
// using a kube.Annotator
func SetNodeLocalNatAnnotation(nodeAnnotator kube.Annotator, defaultNodeLocalNatIPs []net.IP) error {
	annotation, err := CreateNodeLocalNatAnnotation(defaultNodeLocalNatIPs)
	if err != nil {
		return err
	}
	return nodeAnnotator.Set(ovnNodeLocalNatIP, annotation[ovnNodeLocalNatIP])
}

func ParseNodeLocalNatIPAnnotation(node *kapi.Node) ([]net.IP, error) {
	annotationJson, ok := node.Annotations[ovnNodeLocalNatIP]
	if !ok {
		return nil, newAnnotationNotSetError("node %q has no %q annotation", node.Name, ovnNodeLocalNatIP)
	}

	annotationMap := make(map[string][]string)
	var ips []string
	if err := json.Unmarshal([]byte(annotationJson), &annotationMap); err == nil {
		ips, ok = annotationMap[types.DefaultNetworkName]
	} else {
		return nil, fmt.Errorf("could not parse %q from annotation %q for node %s",
			ovnNodeLocalNatIP, annotationJson, node.Name)
	}
	if !ok {
		return nil, fmt.Errorf("%q annotation doesn't have default network value for %s",
			annotationJson, ovnNodeLocalNatIP)
	}

	var nodeLocalNatIPs []net.IP
	for _, ip := range ips {
		nodeLocalNatIP := net.ParseIP(ip)
		if nodeLocalNatIP == nil {
			return nil, fmt.Errorf("error parsing %s's value %s: annotation is (%s)",
				ovnNodeLocalNatIP, ip, annotationJson)
		}
		nodeLocalNatIPs = append(nodeLocalNatIPs, nodeLocalNatIP)
	}

	return nodeLocalNatIPs, nil
}
