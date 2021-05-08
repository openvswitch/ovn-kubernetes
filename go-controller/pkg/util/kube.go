package util

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	kapi "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1beta1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/pkg/version"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	egressfirewallclientset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned"
	egressipclientset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
)

// OVNClientset is a wrapper around all clientsets used by OVN-Kubernetes
type OVNClientset struct {
	KubeClient           kubernetes.Interface
	EgressIPClient       egressipclientset.Interface
	EgressFirewallClient egressfirewallclientset.Interface
}

func adjustCommit() string {
	if len(config.Commit) < 12 {
		return "unknown"
	}
	return config.Commit[:12]
}

func adjustNodeName() string {
	hostName, err := os.Hostname()
	if err != nil {
		hostName = "unknown"
	}
	return hostName
}

// newKubernetesRestConfig create a Kubernetes rest config from either a kubeconfig,
// TLS properties, or an apiserver URL
func newKubernetesRestConfig(conf *config.KubernetesConfig) (*rest.Config, error) {
	var kconfig *rest.Config
	var err error

	if conf.Kubeconfig != "" {
		// uses the current context in kubeconfig
		kconfig, err = clientcmd.BuildConfigFromFlags("", conf.Kubeconfig)
	} else if strings.HasPrefix(conf.APIServer, "https") {
		// TODO: Looks like the check conf.APIServer is redundant and can be removed
		if conf.APIServer == "" || conf.Token == "" {
			return nil, fmt.Errorf("TLS-secured apiservers require token and CA certificate")
		}
		kconfig = &rest.Config{
			Host:        conf.APIServer,
			BearerToken: conf.Token,
		}
		if conf.CACert != "" {
			if _, err := cert.NewPool(conf.CACert); err != nil {
				return nil, err
			}
			kconfig.TLSClientConfig = rest.TLSClientConfig{CAFile: conf.CACert}
		}
	} else if strings.HasPrefix(conf.APIServer, "http") {
		kconfig, err = clientcmd.BuildConfigFromFlags(conf.APIServer, "")
	} else {
		// Assume we are running from a container managed by kubernetes
		// and read the apiserver address and tokens from the
		// container's environment.
		kconfig, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}
	kconfig.QPS = 25
	kconfig.Burst = 25
	// if all the clients are behind HA-Proxy, then on the K8s API server side we only
	// see the HAProxy's IP and we can't tell the actual client making the request.
	kconfig.UserAgent = fmt.Sprintf("%s/%s@%s (%s/%s) kubernetes/%s",
		adjustNodeName(), filepath.Base(os.Args[0]), adjustCommit(), runtime.GOOS, runtime.GOARCH,
		version.Get().GitVersion)
	return kconfig, nil
}

// NewKubernetesClientset creates a Kubernetes clientset from a KubernetesConfig
func NewKubernetesClientset(conf *config.KubernetesConfig) (*kubernetes.Clientset, error) {
	kconfig, err := newKubernetesRestConfig(conf)
	if err != nil {
		return nil, fmt.Errorf("unable to create kubernetes rest config, err: %v", err)
	}
	kconfig.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	kconfig.ContentType = "application/vnd.kubernetes.protobuf"
	clientset, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}

// NewOVNClientset creates a OVNClientset from a KubernetesConfig
func NewOVNClientset(conf *config.KubernetesConfig) (*OVNClientset, error) {
	kclientset, err := NewKubernetesClientset(conf)
	if err != nil {
		return nil, err
	}
	kconfig, err := newKubernetesRestConfig(conf)
	if err != nil {
		return nil, fmt.Errorf("unable to create kubernetes rest config, err: %v", err)
	}
	egressFirewallClientset, err := egressfirewallclientset.NewForConfig(kconfig)
	if err != nil {
		return nil, err
	}
	egressIPClientset, err := egressipclientset.NewForConfig(kconfig)
	if err != nil {
		return nil, err
	}
	return &OVNClientset{
		KubeClient:           kclientset,
		EgressIPClient:       egressIPClientset,
		EgressFirewallClient: egressFirewallClientset,
	}, nil
}

// IsClusterIPSet checks if the service is an headless service or not
func IsClusterIPSet(service *kapi.Service) bool {
	return service.Spec.ClusterIP != kapi.ClusterIPNone && service.Spec.ClusterIP != ""
}

// GetClusterIPs return an array with the ClusterIPs present in the service
// for backward compatibility with versions < 1.20
// we need to handle the case where only ClusterIP exist
func GetClusterIPs(service *kapi.Service) []string {
	if len(service.Spec.ClusterIPs) > 0 {
		return service.Spec.ClusterIPs
	}
	if len(service.Spec.ClusterIP) > 0 && service.Spec.ClusterIP != kapi.ClusterIPNone {
		return []string{service.Spec.ClusterIP}
	}
	return []string{}
}

// ValidatePort checks if the port is non-zero and port protocol is valid
func ValidatePort(proto kapi.Protocol, port int32) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port number: %v", port)
	}
	return ValidateProtocol(proto)
}

// ValidateProtocol checks if the protocol is a valid kapi.Protocol type (TCP, UDP, or SCTP) or returns an error
func ValidateProtocol(proto kapi.Protocol) error {
	if proto == kapi.ProtocolTCP || proto == kapi.ProtocolUDP || proto == kapi.ProtocolSCTP {
		return nil
	}
	return fmt.Errorf("protocol %s is not a valid protocol", proto)
}

// ServiceTypeHasClusterIP checks if the service has an associated ClusterIP or not
func ServiceTypeHasClusterIP(service *kapi.Service) bool {
	return service.Spec.Type == kapi.ServiceTypeClusterIP || service.Spec.Type == kapi.ServiceTypeNodePort || service.Spec.Type == kapi.ServiceTypeLoadBalancer
}

// ServiceTypeHasNodePort checks if the service has an associated NodePort or not
func ServiceTypeHasNodePort(service *kapi.Service) bool {
	return service.Spec.Type == kapi.ServiceTypeNodePort || service.Spec.Type == kapi.ServiceTypeLoadBalancer
}

func ServiceExternalTrafficPolicyLocal(service *kapi.Service) bool {
	return service.Spec.ExternalTrafficPolicy == kapi.ServiceExternalTrafficPolicyTypeLocal
}

// GetNodePrimaryIP extracts the primary IP address from the node status in the  API
func GetNodePrimaryIP(node *kapi.Node) (string, error) {
	if node == nil {
		return "", fmt.Errorf("invalid node object")
	}
	for _, addr := range node.Status.Addresses {
		if addr.Type == kapi.NodeInternalIP {
			return addr.Address, nil
		}
	}
	for _, addr := range node.Status.Addresses {
		if addr.Type == kapi.NodeExternalIP {
			return addr.Address, nil
		}
	}
	return "", fmt.Errorf("%s doesn't have an address with type %s or %s", node.GetName(),
		kapi.NodeInternalIP, kapi.NodeExternalIP)
}

// PodWantsNetwork returns if the given pod is hostNetworked or not to determine if networking
// needs to be setup
func PodWantsNetwork(pod *kapi.Pod) bool {
	return !pod.Spec.HostNetwork
}

// PodScheduled returns if the given pod is scheduled
func PodScheduled(pod *kapi.Pod) bool {
	return pod.Spec.NodeName != ""
}

const (
	// DefNetworkAnnotation is the pod annotation for the cluster-wide default network
	DefNetworkAnnotation = "v1.multus-cni.io/default-network"

	// NetworkAttachmentAnnotation is the pod annotation for network-attachment-definition
	NetworkAttachmentAnnotation = "k8s.v1.cni.cncf.io/networks"
)

// GetPodNetSelAnnotation returns the pod's Network Attachment Selection Annotation either for
// the cluster-wide default network or the additional networks.
//
// This function is a simplified version of parsePodNetworkAnnotation() function in multus-cni
// repository. We need to revisit once there is a library that we can share.
//
// Note that the changes below is based on following assumptions, which is true today.
// - a pod's default network is OVN managed
func GetPodNetSelAnnotation(pod *kapi.Pod, netAttachAnnot string) ([]*types.NetworkSelectionElement, error) {
	var networkAnnotation string
	var networks []*types.NetworkSelectionElement

	networkAnnotation = pod.Annotations[netAttachAnnot]
	if networkAnnotation == "" {
		// nothing special to do
		return nil, nil
	}

	// it is possible the default network is defined in the form of comma-delimited list of
	// network attachment resource names (i.e. list of <namespace>/<network name>@<ifname>), but
	// we are only interested in the NetworkSelectionElement json form that has custom MAC/IP
	if json.Valid([]byte(networkAnnotation)) {
		if err := json.Unmarshal([]byte(networkAnnotation), &networks); err != nil {
			return nil, fmt.Errorf("failed to parse pod's net-attach-definition JSON %q: %v", networkAnnotation, err)
		}
	} else {
		// nothing special to do
		return nil, nil
	}

	return networks, nil
}

// EventRecorder returns an EventRecorder type that can be
// used to post Events to different object's lifecycles.
func EventRecorder(kubeClient kubernetes.Interface) record.EventRecorder {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(
		&typedcorev1.EventSinkImpl{
			Interface: kubeClient.CoreV1().Events(""),
		})
	recorder := eventBroadcaster.NewRecorder(
		scheme.Scheme,
		kapi.EventSource{Component: "controlplane"})
	return recorder
}

// UseEndpointSlices detect if Endpoints Slices are enabled in the cluster
func UseEndpointSlices(kubeClient kubernetes.Interface) bool {
	if _, err := kubeClient.Discovery().ServerResourcesForGroupVersion(discovery.SchemeGroupVersion.String()); err == nil {
		klog.V(2).Infof("Kubernetes Endpoint Slices enabled on the cluster: %s", discovery.SchemeGroupVersion.String())
		return true
	}
	return false
}

type LbEndpoints struct {
	EPs  []discovery.Endpoint
	Port int32
}

func (e LbEndpoints) IPs() []string {
	ipsSet := sets.NewString()
	for _, endpoint := range e.EPs {
		for _, ip := range endpoint.Addresses {
			ipsSet.Insert(ip)
		}
	}
	return ipsSet.List()
}

func (e LbEndpoints) LocalToNode(grName string) LbEndpoints {
	res := LbEndpoints{Port: e.Port, EPs: make([]discovery.Endpoint, 0)}

	for _, ep := range e.EPs {
		if GetWorkerFromGatewayRouter(grName) == ep.Topology["kubernetes.io/hostname"] {
			res.EPs = append(res.EPs, ep)
		}
	}
	return res
}

// GetLbEndpoints return the endpoints that belong to the IPFamily as a slice of IPs
func GetLbEndpoints(slices []*discovery.EndpointSlice, svcPort kapi.ServicePort, family kapi.IPFamily) LbEndpoints {
	lbEps := LbEndpoints{[]discovery.Endpoint{}, 0}
	// return an empty object so the caller don't have to check for nil and can use it as an iterator
	if len(slices) == 0 {
		return lbEps
	}

	for _, slice := range slices {
		klog.V(4).Infof("Getting endpoints for slice %s", slice.Name)
		// Only return addresses that belong to the requested IP family
		if slice.AddressType != discovery.AddressType(family) {
			klog.V(4).Infof("Slice %s with different IP Family endpoints, requested: %s received: %s",
				slice.Name, slice.AddressType, family)
			continue
		}

		// build the list of endpoints in the slice
		for _, port := range slice.Ports {
			// If Service port name set it must match the name field in the endpoint
			// If Service port name is not set we just use the endpoint port
			if svcPort.Name != "" && svcPort.Name != *port.Name {
				klog.V(5).Infof("Slice %s with different Port name, requested: %s received: %s",
					slice.Name, svcPort.Name, *port.Name)
				continue
			}

			// Skip ports that doesn't match the protocol
			if *port.Protocol != svcPort.Protocol {
				klog.V(5).Infof("Slice %s with different Port protocol, requested: %s received: %s",
					slice.Name, svcPort.Protocol, *port.Protocol)
				continue
			}

			lbEps.Port = *port.Port
			for _, endpoint := range slice.Endpoints {
				// Skip endpoints that are not ready
				if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
					klog.V(4).Infof("Slice endpoints Not Ready")
					continue
				}
				lbEps.EPs = append(lbEps.EPs, endpoint)
			}
		}
	}

	klog.V(4).Infof("LB Endpoints for %s are: %v on port: %d", slices[0].Labels[discovery.LabelServiceName],
		lbEps.IPs(), lbEps.Port)
	return lbEps
}

// HasValidEndpoint returns true if at least one valid endpoint is contained in the given
// slices
func HasValidEndpoint(service *kapi.Service, slices []*discovery.EndpointSlice) bool {
	if slices == nil {
		return false
	}
	if len(slices) == 0 {
		return false
	}
	for _, ip := range GetClusterIPs(service) {
		family := kapi.IPv4Protocol
		if utilnet.IsIPv6String(ip) {
			family = kapi.IPv6Protocol
		}
		for _, svcPort := range service.Spec.Ports {
			eps := GetLbEndpoints(slices, svcPort, family)
			if len(eps.IPs()) > 0 {
				return true
			}
		}
	}
	return false
}
