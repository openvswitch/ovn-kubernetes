package util

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	kapi "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/pkg/version"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"

	networkattachmentdefinitionapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	networkattchmentdefclientset "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	egressfirewallclientset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned"
	egressipclientset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned"
	discovery "k8s.io/api/discovery/v1beta1"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
)

// OVNClientset is a wrapper around all clientsets used by OVN-Kubernetes
type OVNClientset struct {
	KubeClient            kubernetes.Interface
	EgressIPClient        egressipclientset.Interface
	EgressFirewallClient  egressfirewallclientset.Interface
	APIExtensionsClient   apiextensionsclientset.Interface
	NetworkAttchDefClient networkattchmentdefclientset.Interface
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
	crdClientset, err := apiextensionsclientset.NewForConfig(kconfig)
	if err != nil {
		return nil, err
	}
	egressFirewallClientset, err := egressfirewallclientset.NewForConfig(kconfig)
	if err != nil {
		return nil, err
	}
	egressIPClientset, err := egressipclientset.NewForConfig(kconfig)
	if err != nil {
		return nil, err
	}
	networkAttchmntDefClientset, err := networkattchmentdefclientset.NewForConfig(kconfig)
	if err != nil {
		return nil, err
	}
	return &OVNClientset{
		KubeClient:            kclientset,
		EgressIPClient:        egressIPClientset,
		EgressFirewallClient:  egressFirewallClientset,
		APIExtensionsClient:   crdClientset,
		NetworkAttchDefClient: networkAttchmntDefClientset,
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

const (
	// DefNetworkAnnotation is the pod annotation for the cluster-wide default network
	DefNetworkAnnotation = "v1.multus-cni.io/default-network"
)

// GetPodNetSelAnnotation returns the pod's Network Attachment Selection Annotation either for
// the cluster-wide default network or the additional networks.
//
// This function is a simplified version of parsePodNetworkAnnotation() function in multus-cni
// repository. We need to revisit once there is a library that we can share.
//
// Note that the changes below is based on following assumptions, which is true today.
// - a pod's default network is OVN managed
func GetPodNetSelAnnotation(pod *kapi.Pod, netAttachAnnot string) ([]*networkattachmentdefinitionapi.NetworkSelectionElement, error) {
	var networkAnnotation string
	var networks []*networkattachmentdefinitionapi.NetworkSelectionElement

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
