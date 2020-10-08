package cni

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	"github.com/containernetworking/cni/pkg/types/current"
	"k8s.io/apimachinery/pkg/api/resource"
	utilnet "k8s.io/utils/net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

var minRsrc = resource.MustParse("1k")
var maxRsrc = resource.MustParse("1P")

func validateBandwidthIsReasonable(rsrc *resource.Quantity) error {
	if rsrc.Value() < minRsrc.Value() {
		return fmt.Errorf("resource is unreasonably small (< 1kbit)")
	}
	if rsrc.Value() > maxRsrc.Value() {
		return fmt.Errorf("resoruce is unreasonably large (> 1Pbit)")
	}
	return nil
}

func extractPodBandwidthResources(podAnnotations map[string]string) (int64, int64, error) {
	ingress := int64(-1)
	egress := int64(-1)
	str, found := podAnnotations["kubernetes.io/ingress-bandwidth"]
	if found {
		ingressVal, err := resource.ParseQuantity(str)
		if err != nil {
			return -1, -1, err
		}
		if err := validateBandwidthIsReasonable(&ingressVal); err != nil {
			return -1, -1, err
		}
		ingress = ingressVal.Value()
	}
	str, found = podAnnotations["kubernetes.io/egress-bandwidth"]
	if found {
		egressVal, err := resource.ParseQuantity(str)
		if err != nil {
			return -1, -1, err
		}
		if err := validateBandwidthIsReasonable(&egressVal); err != nil {
			return -1, -1, err
		}
		egress = egressVal.Value()
	}
	return ingress, egress, nil
}

func (pr *PodRequest) String() string {
	return fmt.Sprintf("[%s/%s %s]", pr.PodNamespace, pr.PodName, pr.SandboxID)
}

func (pr *PodRequest) cmdAdd(podLister corev1listers.PodLister) ([]byte, error) {
	namespace := pr.PodNamespace
	podName := pr.PodName
	if namespace == "" || podName == "" {
		return nil, fmt.Errorf("required CNI variable missing")
	}
	netName := types.DefaultNetworkName
	mtu := config.Default.MTU
	if pr.CNIConf.NotDefault {
		netName = pr.CNIConf.Name
		if pr.CNIConf.MTU != 0 {
			mtu = pr.CNIConf.MTU
		}
	}

	// Get the IP address and MAC address of the pod
	annotations, err := getPodAnnotations(pr.ctx, podLister, pr.PodNamespace, pr.PodName)
	if err != nil {
		return nil, err
	}

	podInfo, err := util.UnmarshalPodAnnotation(annotations, netName)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ovn annotation for network %s: %v", netName, err)
	}

	ingress, egress, err := extractPodBandwidthResources(annotations)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bandwidth request for network %s: %v", netName, err)
	}
	podInterfaceInfo := &PodInterfaceInfo{
		PodAnnotation: *podInfo,
		MTU:           mtu,
		Ingress:       ingress,
		Egress:        egress,
		NetworkName:   netName,
	}
	response := &Response{}
	if !config.UnprivilegedMode {
		response.Result, err = pr.getCNIResult(podInterfaceInfo)
		if err != nil {
			return nil, err
		}
	} else {
		response.PodIFInfo = podInterfaceInfo
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pod request response for network %s: %v", netName, err)
	}

	return responseBytes, nil
}

func (pr *PodRequest) cmdDel() ([]byte, error) {
	if err := pr.PlatformSpecificCleanup(); err != nil {
		return nil, err
	}
	return []byte{}, nil
}

func (pr *PodRequest) cmdCheck(podLister corev1listers.PodLister) ([]byte, error) {
	namespace := pr.PodNamespace
	podName := pr.PodName
	if namespace == "" || podName == "" {
		return nil, fmt.Errorf("required CNI variable missing")
	}

	// Get the IP address and MAC address of the pod
	annotations, err := getPodAnnotations(pr.ctx, podLister, pr.PodNamespace, pr.PodName)
	if err != nil {
		return nil, err
	}

	ingress, egress, err := extractPodBandwidthResources(annotations)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bandwidth request: %v", err)
	}

	if pr.CNIConf.PrevResult != nil {
		result, err := current.NewResultFromResult(pr.CNIConf.PrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
		hostIfaceName := ""
		for _, interf := range result.Interfaces {
			if len(interf.Sandbox) == 0 {
				hostIfaceName = interf.Name
				break
			}
		}
		if len(hostIfaceName) == 0 {
			return nil, fmt.Errorf("could not find host interface in the prevResult: %v", result)
		}
		ifaceID := fmt.Sprintf("%s_%s", namespace, podName)
		ofPort, err := getIfaceOFPort(hostIfaceName)
		if err != nil {
			return nil, err
		}
		for _, ip := range result.IPs {
			if err = waitForPodFlows(pr.ctx, result.Interfaces[*ip.Interface].Mac, []*net.IPNet{&ip.Address}, hostIfaceName, ifaceID, ofPort); err != nil {
				return nil, fmt.Errorf("error while checkoing on flows for pod: %s ip: %v, error: %v", ifaceID, ip, err)
			}
		}
		ingressBPS, egressBPS, err := getPodBandwidth(hostIfaceName)
		if err != nil {
			return nil, err
		}
		if ingress != ingressBPS {
			return nil, fmt.Errorf("defined ingress bandwidth restriction %d is not equals to the set one %d", ingress, ingressBPS)
		}
		if egress != egressBPS {
			return nil, fmt.Errorf("defined egress bandwidth restriction %d is not equals to the set one %d", egress, egressBPS)
		}
	}
	return []byte{}, nil
}

// HandleCNIRequest is the callback for all the requests
// coming to the cniserver after being procesed into PodRequest objects
// Argument '*PodRequest' encapsulates all the necessary information
// kclient is passed in so that clientset can be reused from the server
// Return value is the actual bytes to be sent back without further processing.
func HandleCNIRequest(request *PodRequest, podLister corev1listers.PodLister) ([]byte, error) {
	var result []byte
	var err error

	klog.Infof("%s %s starting CNI request %+v", request, request.Command, request)
	switch request.Command {
	case CNIAdd:
		result, err = request.cmdAdd(podLister)
	case CNIDel:
		result, err = request.cmdDel()
	case CNICheck:
		result, err = request.cmdCheck(podLister)
	default:
	}
	klog.Infof("%s %s finished CNI request %+v, result %q, err %v", request, request.Command, request, string(result), err)

	if err != nil {
		// Prefix errors with request info for easier failure debugging
		return nil, fmt.Errorf("%s %v", request, err)
	}
	return result, nil
}

// getCNIResult get result from pod interface info.
func (pr *PodRequest) getCNIResult(podInterfaceInfo *PodInterfaceInfo) (*current.Result, error) {
	interfacesArray, err := pr.ConfigureInterface(pr.PodNamespace, pr.PodName, podInterfaceInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to configure pod interface: %v", err)
	}

	gateways := map[string]net.IP{}
	for _, gw := range podInterfaceInfo.Gateways {
		if gw.To4() != nil && gateways["4"] == nil {
			gateways["4"] = gw
		} else if gw.To4() == nil && gateways["6"] == nil {
			gateways["6"] = gw
		}
	}

	// Build the result structure to pass back to the runtime
	ips := []*current.IPConfig{}
	for _, ipcidr := range podInterfaceInfo.IPs {
		ip := &current.IPConfig{
			Interface: current.Int(1),
			Address:   *ipcidr,
		}
		if utilnet.IsIPv6CIDR(ipcidr) {
			ip.Version = "6"
		} else {
			ip.Version = "4"
		}
		ip.Gateway = gateways[ip.Version]
		ips = append(ips, ip)
	}

	return &current.Result{
		Interfaces: interfacesArray,
		IPs:        ips,
	}, nil
}

// getPodAnnotations obtains the pod annotation from the cache
func getPodAnnotations(ctx context.Context, podLister corev1listers.PodLister, namespace, name string) (map[string]string, error) {
	timeout := time.After(30 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("canceled waiting for annotations")
		case <-timeout:
			return nil, fmt.Errorf("timed out waiting for annotations")
		default:
			pod, err := podLister.Pods(namespace).Get(name)
			if err != nil {
				return nil, fmt.Errorf("failed to get annotations: %v", err)
			}
			annotations := pod.ObjectMeta.Annotations
			if _, ok := annotations[util.OvnPodAnnotationName]; ok {
				return annotations, nil
			}
			// try again later
			time.Sleep(200 * time.Millisecond)
		}
	}
}
