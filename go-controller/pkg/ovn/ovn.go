package ovn

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/allocator"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"
	kapisnetworking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	kv1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"
)

// ServiceVIPKey is used for looking up service namespace information for a
// particular load balancer
type ServiceVIPKey struct {
	// Load balancer VIP in the form "ip:port"
	vip string
	// Protocol used by the load balancer
	protocol kapi.Protocol
}

// Controller structure is the object which holds the controls for starting
// and reacting upon the watched resources (e.g. pods, endpoints)
type Controller struct {
	kube         kube.Interface
	watchFactory *factory.WatchFactory

	masterSubnetAllocator *allocator.SubnetAllocator
	joinSubnetAllocator   *allocator.SubnetAllocator

	TCPLoadBalancerUUID string
	UDPLoadBalancerUUID string

	// For TCP and UDP type traffic, cache OVN load-balancers used for the
	// cluster's east-west traffic.
	loadbalancerClusterCache map[string]string

	// For TCP and UDP type traffice, cache OVN load balancer that exists on the
	// default gateway
	loadbalancerGWCache map[string]string
	defGatewayRouter    string

	// A cache of all logical switches seen by the watcher and their subnets
	logicalSwitchCache map[string]*net.IPNet

	// A cache of all logical ports known to the controller
	logicalPortCache *portCache

	// For each namespace, a map from pod IP address to logical port name
	// for all pods in that namespace.
	namespaceAddressSet map[string]map[string]string

	// For each namespace, a lock to protect critical regions
	namespaceMutex map[string]*sync.Mutex

	// Need to make calls to namespaceMutex also thread-safe
	namespaceMutexMutex sync.Mutex

	// For each namespace, a map of policy name to 'namespacePolicy'.
	namespacePolicies map[string]map[string]*namespacePolicy

	// Port group for ingress deny rule
	portGroupIngressDeny string

	// Port group for egress deny rule
	portGroupEgressDeny string

	// For each logical port, the number of network policies that want
	// to add a ingress deny rule.
	lspIngressDenyCache map[string]int

	// For each logical port, the number of network policies that want
	// to add a egress deny rule.
	lspEgressDenyCache map[string]int

	// A mutex for lspIngressDenyCache and lspEgressDenyCache
	lspMutex *sync.Mutex

	// A mutex for logicalSwitchCache which holds logicalSwitch information
	lsMutex *sync.Mutex

	// Per namespace multicast enabled?
	multicastEnabled map[string]bool

	// Supports port_group?
	portGroupSupport bool

	// Supports multicast?
	multicastSupport bool

	// Map of load balancers to service namespace
	serviceVIPToName map[ServiceVIPKey]types.NamespacedName

	serviceVIPToNameLock sync.Mutex
}

const (
	// TCP is the constant string for the string "TCP"
	TCP = "TCP"

	// UDP is the constant string for the string "UDP"
	UDP = "UDP"
)

// NewOvnController creates a new OVN controller for creating logical network
// infrastructure and policy
func NewOvnController(kubeClient kubernetes.Interface, wf *factory.WatchFactory, stopChan <-chan struct{}) *Controller {
	return &Controller{
		kube:                     &kube.Kube{KClient: kubeClient},
		watchFactory:             wf,
		masterSubnetAllocator:    allocator.NewSubnetAllocator(),
		logicalSwitchCache:       make(map[string]*net.IPNet),
		joinSubnetAllocator:      allocator.NewSubnetAllocator(),
		logicalPortCache:         newPortCache(stopChan),
		namespaceAddressSet:      make(map[string]map[string]string),
		namespacePolicies:        make(map[string]map[string]*namespacePolicy),
		namespaceMutex:           make(map[string]*sync.Mutex),
		namespaceMutexMutex:      sync.Mutex{},
		lspIngressDenyCache:      make(map[string]int),
		lspEgressDenyCache:       make(map[string]int),
		lspMutex:                 &sync.Mutex{},
		lsMutex:                  &sync.Mutex{},
		loadbalancerClusterCache: make(map[string]string),
		loadbalancerGWCache:      make(map[string]string),
		multicastEnabled:         make(map[string]bool),
		multicastSupport:         config.EnableMulticast,
		serviceVIPToName:         make(map[ServiceVIPKey]types.NamespacedName),
		serviceVIPToNameLock:     sync.Mutex{},
	}
}

// Run starts the actual watching.
func (oc *Controller) Run(stopChan chan struct{}) error {
	startOvnUpdater()

	// WatchNodes must be started first so that its initial Add will
	// create all node logical switches, which other watches may depend on.
	// https://github.com/ovn-org/ovn-kubernetes/pull/859
	if err := oc.WatchNodes(); err != nil {
		return err
	}

	for _, f := range []func() error{oc.WatchPods, oc.WatchServices, oc.WatchEndpoints,
		oc.WatchNamespaces, oc.WatchNetworkPolicy} {
		if err := f(); err != nil {
			return err
		}
	}

	if config.Kubernetes.OVNEmptyLbEvents {
		go oc.ovnControllerEventChecker(stopChan)
	}

	return nil
}

type eventRecord struct {
	Data     [][]interface{} `json:"Data"`
	Headings []string        `json:"Headings"`
}

type emptyLBBackendEvent struct {
	vip      string
	protocol kapi.Protocol
	uuid     string
}

func extractEmptyLBBackendsEvents(out []byte) ([]emptyLBBackendEvent, error) {
	events := make([]emptyLBBackendEvent, 0, 4)

	var f eventRecord
	err := json.Unmarshal(out, &f)
	if err != nil {
		return events, err
	}
	if len(f.Data) == 0 {
		return events, nil
	}

	var eventInfoIndex int
	var eventTypeIndex int
	var uuidIndex int
	for idx, val := range f.Headings {
		switch val {
		case "event_info":
			eventInfoIndex = idx
		case "event_type":
			eventTypeIndex = idx
		case "_uuid":
			uuidIndex = idx
		}
	}

	for _, val := range f.Data {
		if len(val) <= eventTypeIndex {
			return events, errors.New("Mismatched Data and Headings in controller event")
		}
		if val[eventTypeIndex] != "empty_lb_backends" {
			continue
		}

		uuidArray, ok := val[uuidIndex].([]interface{})
		if !ok {
			return events, errors.New("Unexpected '_uuid' data in controller event")
		}
		if len(uuidArray) < 2 {
			return events, errors.New("Malformed UUID presented in controller event")
		}
		uuid, ok := uuidArray[1].(string)
		if !ok {
			return events, errors.New("Failed to parse UUID in controller event")
		}

		// Unpack the data. There's probably a better way to do this.
		info, ok := val[eventInfoIndex].([]interface{})
		if !ok {
			return events, errors.New("Unexpected 'event_info' data in controller event")
		}
		if len(info) < 2 {
			return events, errors.New("Malformed event_info in controller event")
		}
		eventMap, ok := info[1].([]interface{})
		if !ok {
			return events, errors.New("'event_info' data is not the expected type")
		}

		var vip string
		var protocol kapi.Protocol
		for _, x := range eventMap {
			tuple, ok := x.([]interface{})
			if !ok {
				return events, errors.New("event map item failed to parse")
			}
			if len(tuple) < 2 {
				return events, errors.New("event map contains malformed data")
			}
			switch tuple[0] {
			case "vip":
				vip, ok = tuple[1].(string)
				if !ok {
					return events, errors.New("Failed to parse vip in controller event")
				}
			case "protocol":
				prot, ok := tuple[1].(string)
				if !ok {
					return events, errors.New("Failed to parse protocol in controller event")
				}
				if prot == "udp" {
					protocol = kapi.ProtocolUDP
				} else {
					protocol = kapi.ProtocolTCP
				}
			}
		}
		events = append(events, emptyLBBackendEvent{vip, protocol, uuid})
	}

	return events, nil
}

func (oc *Controller) ovnControllerEventChecker(stopChan chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)

	_, _, err := util.RunOVNNbctl("set", "nb_global", ".", "options:controller_event=true")
	if err != nil {
		klog.Error("Unable to enable controller events. Unidling not possible")
		return
	}

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartRecordingToSink(&kv1core.EventSinkImpl{Interface: oc.kube.Events()})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, kapi.EventSource{Component: "kube-proxy"})

	for {
		select {
		case <-ticker.C:
			out, _, err := util.RunOVNSbctl("--format=json", "list", "controller_event")
			if err != nil {
				continue
			}

			events, err := extractEmptyLBBackendsEvents([]byte(out))
			if err != nil || len(events) == 0 {
				continue
			}

			for _, event := range events {
				_, _, err := util.RunOVNSbctl("destroy", "controller_event", event.uuid)
				if err != nil {
					// Don't unidle until we are able to remove the controller event
					klog.Errorf("Unable to remove controller event %s", event.uuid)
					continue
				}
				if serviceName, ok := oc.GetServiceVIPToName(event.vip, event.protocol); ok {
					serviceRef := kapi.ObjectReference{
						Kind:      "Service",
						Namespace: serviceName.Namespace,
						Name:      serviceName.Name,
					}
					klog.V(5).Infof("Sending a NeedPods event for service %s in namespace %s.", serviceName.Name, serviceName.Namespace)
					recorder.Eventf(&serviceRef, kapi.EventTypeNormal, "NeedPods", "The service %s needs pods", serviceName.Name)
				}
			}
		case <-stopChan:
			return
		}
	}
}

func podWantsNetwork(pod *kapi.Pod) bool {
	return !pod.Spec.HostNetwork
}

func podScheduled(pod *kapi.Pod) bool {
	return pod.Spec.NodeName != ""
}

// WatchPods starts the watching of Pod resource and calls back the appropriate handler logic
func (oc *Controller) WatchPods() error {
	var retryPods sync.Map
	var completedPods sync.Map
	_, err := oc.watchFactory.AddPodHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*kapi.Pod)
			if !podWantsNetwork(pod) {
				return
			}

			if podScheduled(pod) {
				if err := oc.addLogicalPort(pod); err != nil {
					klog.Errorf(err.Error())
					retryPods.Store(pod.UID, true)
				}
			} else {
				// Handle unscheduled pods later in UpdateFunc
				retryPods.Store(pod.UID, true)
			}
			completedPods.Store(pod.UID, false)
		},
		UpdateFunc: func(old, newer interface{}) {
			pod := newer.(*kapi.Pod)
			if !podWantsNetwork(pod) {
				return
			}

			_, retry := retryPods.Load(pod.UID)
			if podScheduled(pod) && retry {
				if err := oc.addLogicalPort(pod); err != nil {
					klog.Errorf(err.Error())
				} else {
					retryPods.Delete(pod.UID)
				}
			}
			completed, found := completedPods.Load(pod.UID)
			if pod.Status.Phase == kapi.PodSucceeded && found && completed == false {
				oc.deleteLogicalPort(pod)
				completedPods.Store(pod.UID, true)
			}
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*kapi.Pod)
			oc.deleteLogicalPort(pod)
			retryPods.Delete(pod.UID)
			completedPods.Delete(pod.UID)
		},
	}, oc.syncPods)
	return err
}

// WatchServices starts the watching of Service resource and calls back the
// appropriate handler logic
func (oc *Controller) WatchServices() error {
	_, err := oc.watchFactory.AddServiceHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) {},
		UpdateFunc: func(old, new interface{}) {},
		DeleteFunc: func(obj interface{}) {
			service := obj.(*kapi.Service)
			oc.deleteService(service)
		},
	}, oc.syncServices)
	return err
}

// WatchEndpoints starts the watching of Endpoint resource and calls back the appropriate handler logic
func (oc *Controller) WatchEndpoints() error {
	_, err := oc.watchFactory.AddEndpointsHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ep := obj.(*kapi.Endpoints)
			err := oc.AddEndpoints(ep)
			if err != nil {
				klog.Errorf("Error in adding load balancer: %v", err)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			epNew := new.(*kapi.Endpoints)
			epOld := old.(*kapi.Endpoints)
			if reflect.DeepEqual(epNew.Subsets, epOld.Subsets) {
				return
			}
			if len(epNew.Subsets) == 0 {
				err := oc.deleteEndpoints(epNew)
				if err != nil {
					klog.Errorf("Error in deleting endpoints - %v", err)
				}
			} else {
				err := oc.AddEndpoints(epNew)
				if err != nil {
					klog.Errorf("Error in modifying endpoints: %v", err)
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			ep := obj.(*kapi.Endpoints)
			err := oc.deleteEndpoints(ep)
			if err != nil {
				klog.Errorf("Error in deleting endpoints - %v", err)
			}
		},
	}, nil)
	return err
}

// WatchNetworkPolicy starts the watching of network policy resource and calls
// back the appropriate handler logic
func (oc *Controller) WatchNetworkPolicy() error {
	_, err := oc.watchFactory.AddPolicyHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			policy := obj.(*kapisnetworking.NetworkPolicy)
			oc.addNetworkPolicy(policy)
		},
		UpdateFunc: func(old, newer interface{}) {
			oldPolicy := old.(*kapisnetworking.NetworkPolicy)
			newPolicy := newer.(*kapisnetworking.NetworkPolicy)
			if !reflect.DeepEqual(oldPolicy, newPolicy) {
				oc.deleteNetworkPolicy(oldPolicy)
				oc.addNetworkPolicy(newPolicy)
			}
		},
		DeleteFunc: func(obj interface{}) {
			policy := obj.(*kapisnetworking.NetworkPolicy)
			oc.deleteNetworkPolicy(policy)
		},
	}, oc.syncNetworkPolicies)
	return err
}

// WatchNamespaces starts the watching of namespace resource and calls
// back the appropriate handler logic
func (oc *Controller) WatchNamespaces() error {
	_, err := oc.watchFactory.AddNamespaceHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ns := obj.(*kapi.Namespace)
			oc.AddNamespace(ns)
		},
		UpdateFunc: func(old, newer interface{}) {
			oldNs, newNs := old.(*kapi.Namespace), newer.(*kapi.Namespace)
			oc.updateNamespace(oldNs, newNs)
		},
		DeleteFunc: func(obj interface{}) {
			ns := obj.(*kapi.Namespace)
			oc.deleteNamespace(ns)
		},
	}, oc.syncNamespaces)
	return err
}

func (oc *Controller) syncNodeGateway(node *kapi.Node, subnet *net.IPNet) error {
	l3GatewayConfig, err := UnmarshalNodeL3GatewayAnnotation(node)
	if err != nil {
		return err
	}
	if subnet == nil {
		subnet, _ = parseNodeHostSubnet(node)
	}
	if l3GatewayConfig[OvnNodeGatewayMode] == string(config.GatewayModeDisabled) {
		if err := util.GatewayCleanup(node.Name, subnet); err != nil {
			return fmt.Errorf("error cleaning up gateway for node %s: %v", node.Name, err)
		}
	} else if subnet != nil {
		if err := oc.syncGatewayLogicalNetwork(node, l3GatewayConfig, subnet.String()); err != nil {
			return fmt.Errorf("error creating gateway for node %s: %v", node.Name, err)
		}
	}
	return nil
}

// WatchNodes starts the watching of node resource and calls
// back the appropriate handler logic
func (oc *Controller) WatchNodes() error {
	var gatewaysFailed sync.Map
	var mgmtPortFailed sync.Map
	_, err := oc.watchFactory.AddNodeHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node := obj.(*kapi.Node)

			if noHostSubnet := noHostSubnet(node); noHostSubnet {
				oc.lsMutex.Lock()
				defer oc.lsMutex.Unlock()
				//setting the value to nil in the cache means it was not assigned a hostSubnet by ovn-kube
				oc.logicalSwitchCache[node.Name] = nil
				return
			}

			klog.V(5).Infof("Added event for Node %q", node.Name)
			hostSubnet, err := oc.addNode(node)
			if err != nil {
				klog.Errorf("error creating subnet for node %s: %v", node.Name, err)
				return
			}

			err = oc.syncNodeManagementPort(node, hostSubnet)
			if err != nil {
				klog.Errorf("error creating management port for node %s: %v", node.Name, err)
				mgmtPortFailed.Store(node.Name, true)
			}

			if err := oc.syncNodeGateway(node, hostSubnet); err != nil {
				klog.Errorf(err.Error())
				gatewaysFailed.Store(node.Name, true)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			oldNode := old.(*kapi.Node)
			node := new.(*kapi.Node)

			shouldUpdate, err := shouldUpdate(node, oldNode)
			if err != nil {
				klog.Errorf(err.Error())
			}
			if !shouldUpdate {
				// the hostsubnet is not assigned by ovn-kubernetes
				return
			}

			klog.V(5).Infof("Updated event for Node %q", node.Name)

			_, failed := mgmtPortFailed.Load(node.Name)
			if failed || macAddressChanged(oldNode, node) {
				err := oc.syncNodeManagementPort(node, nil)
				if err != nil {
					klog.Errorf("error updating management port for node %s: %v", node.Name, err)
					mgmtPortFailed.Store(node.Name, true)
				} else {
					mgmtPortFailed.Delete(node.Name)
				}
			}

			oc.clearInitialNodeNetworkUnavailableCondition(oldNode, node)

			_, failed = gatewaysFailed.Load(node.Name)
			if failed || gatewayChanged(oldNode, node) {
				err := oc.syncNodeGateway(node, nil)
				if err != nil {
					klog.Errorf(err.Error())
					gatewaysFailed.Store(node.Name, true)
				} else {
					gatewaysFailed.Delete(node.Name)
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			node := obj.(*kapi.Node)
			klog.V(5).Infof("Delete event for Node %q. Removing the node from "+
				"various caches", node.Name)

			nodeSubnet, _ := parseNodeHostSubnet(node)
			joinSubnet, _ := parseNodeJoinSubnet(node)
			err := oc.deleteNode(node.Name, nodeSubnet, joinSubnet)
			if err != nil {
				klog.Error(err)
			}
			oc.lsMutex.Lock()
			delete(oc.logicalSwitchCache, node.Name)
			oc.lsMutex.Unlock()
			mgmtPortFailed.Delete(node.Name)
			gatewaysFailed.Delete(node.Name)
			if oc.defGatewayRouter == "GR_"+node.Name {
				delete(oc.loadbalancerGWCache, TCP)
				delete(oc.loadbalancerGWCache, UDP)
				oc.defGatewayRouter = ""
				oc.handleExternalIPsLB()
			}
		},
	}, oc.syncNodes)
	return err
}

// AddServiceVIPToName associates a k8s service name with a load balancer VIP
func (oc *Controller) AddServiceVIPToName(vip string, protocol kapi.Protocol, namespace, name string) {
	oc.serviceVIPToNameLock.Lock()
	defer oc.serviceVIPToNameLock.Unlock()
	oc.serviceVIPToName[ServiceVIPKey{vip, protocol}] = types.NamespacedName{Namespace: namespace, Name: name}
}

// GetServiceVIPToName retrieves the associated k8s service name for a load balancer VIP
func (oc *Controller) GetServiceVIPToName(vip string, protocol kapi.Protocol) (types.NamespacedName, bool) {
	oc.serviceVIPToNameLock.Lock()
	defer oc.serviceVIPToNameLock.Unlock()
	namespace, ok := oc.serviceVIPToName[ServiceVIPKey{vip, protocol}]
	return namespace, ok
}

// gatewayChanged() compares old annotations to new and returns true if something has changed.
func gatewayChanged(oldNode, newNode *kapi.Node) bool {
	oldL3GatewayConfig, _ := UnmarshalNodeL3GatewayAnnotation(oldNode)
	l3GatewayConfig, _ := UnmarshalNodeL3GatewayAnnotation(newNode)

	if oldL3GatewayConfig == nil && l3GatewayConfig == nil {
		return false
	}

	return !reflect.DeepEqual(oldL3GatewayConfig, l3GatewayConfig)
}

// macAddressChanged() compares old annotations to new and returns true if something has changed.
func macAddressChanged(oldNode, node *kapi.Node) bool {
	oldMacAddress := oldNode.Annotations[OvnNodeManagementPortMacAddress]
	macAddress := node.Annotations[OvnNodeManagementPortMacAddress]
	return oldMacAddress != macAddress
}

// noHostSubnet() compares the no-hostsubenet-nodes flag with node labels to see if the node is manageing its
// own network.
func noHostSubnet(node *kapi.Node) bool {
	if config.Kubernetes.NoHostSubnetNodes == nil {
		return false
	}

	nodeSelector, _ := metav1.LabelSelectorAsSelector(config.Kubernetes.NoHostSubnetNodes)
	return nodeSelector.Matches(labels.Set(node.Labels))
}

// shouldUpdate() determines if the ovn-kubernetes plugin should update the state of the node.
// ovn-kube should not perform an update if it does not assign a hostsubnet, or if you want to change
// whether or not ovn-kubernetes assigns a hostsubnet
func shouldUpdate(node, oldNode *kapi.Node) (bool, error) {
	newNoHostSubnet := noHostSubnet(node)
	oldNoHostSubnet := noHostSubnet(oldNode)

	if oldNoHostSubnet && newNoHostSubnet {
		return false, nil
	} else if oldNoHostSubnet && !newNoHostSubnet {
		return false, fmt.Errorf("error updating node %s, cannot remove assigned hostsubnet, please delete node and recreate.", node.Name)
	} else if !oldNoHostSubnet && newNoHostSubnet {
		return false, fmt.Errorf("error updating node %s, cannot assign a hostsubnet to already created node, please delete node and recreate.", node.Name)
	}

	return true, nil
}
