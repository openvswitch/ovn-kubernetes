package ovn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	ctypes "github.com/containernetworking/cni/pkg/types"
	goovn "github.com/ebay/go-ovn"
	nettypes "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	hocontroller "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/controller"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressipv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	svccontroller "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/controller/services"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/controller/unidling"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/ipallocator"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/subnetallocator"
	ptypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	egressfirewall "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"

	apiextension "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	utilnet "k8s.io/utils/net"

	kapi "k8s.io/api/core/v1"
	kapisnetworking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	ref "k8s.io/client-go/tools/reference"
	"k8s.io/klog/v2"
)

const (
	egressfirewallCRD                string        = "egressfirewalls.k8s.ovn.org"
	netattachdefCRD                  string        = "network-attachment-definitions.k8s.cni.cncf.io"
	clusterPortGroupName             string        = "clusterPortGroup"
	clusterRtrPortGroupName          string        = "clusterRtrPortGroup"
	egressFirewallDNSDefaultDuration time.Duration = 30 * time.Minute
)

// loadBalancerConf contains the OVN based config for a LB
type loadBalancerConf struct {
	// List of endpoints as configured in OVN, ip:port
	endpoints []string
	// ACL configured for Rejecting access to the LB
	rejectACL string
}

// ACL logging severity levels
type ACLLoggingLevels struct {
	Allow string `json:"allow,omitempty"`
	Deny  string `json:"deny,omitempty"`
}

// namespaceInfo contains information related to a Namespace. Use oc.getNamespaceLocked()
// or oc.waitForNamespaceLocked() to get a locked namespaceInfo for a Namespace, and call
// nsInfo.Unlock() on it when you are done with it. (No code outside of the code that
// manages the oc.namespaces map is ever allowed to hold an unlocked namespaceInfo.)
type namespaceInfo struct {
	sync.Mutex

	// addressSet is an address set object that holds the IP addresses
	// of all pods in the namespace.
	addressSet addressset.AddressSet

	// map from NetworkPolicy name to networkPolicy. You must hold the
	// namespaceInfo's mutex to add/delete/lookup policies, but must hold the
	// networkPolicy's mutex (and not necessarily the namespaceInfo's) to work with
	// the policy itself.
	networkPolicies map[string]*networkPolicy

	// defines the namespaces egressFirewallPolicy
	egressFirewallPolicy *egressFirewall

	// routingExternalGWs is a slice of net.IP containing the values parsed from
	// annotation k8s.ovn.org/routing-external-gws
	routingExternalGWs []net.IP
	// podExternalRoutes is a cache keeping the LR routes added to the GRs when
	// the k8s.ovn.org/routing-external-gws annotation is used. The first map key
	// is the podIP, the second the GW and the third the GR
	podExternalRoutes map[string]map[string]string

	// routingExternalPodGWs contains a map of all pods serving as exgws as well as their
	// exgw IPs
	routingExternalPodGWs map[string][]net.IP

	// The UUID of the namespace-wide port group that contains all the pods in the namespace.
	portGroupUUID string

	multicastEnabled bool

	// If not empty, then it has to be set to a logging a severity level, e.g. "notice", "alert", etc
	aclLogging ACLLoggingLevels

	// Per-namespace port group default deny UUIDs
	portGroupIngressDenyUUID string // Port group for ingress deny rule
	portGroupEgressDenyUUID  string // Port group for egress deny rule
}

// multihome controller
type OvnMHController struct {
	client       clientset.Interface
	kube         kube.Interface
	watchFactory *factory.WatchFactory
	wg           *sync.WaitGroup
	stopChan     chan struct{}

	nodeName            string
	netAttachDefHandler *factory.Handler

	// event recorder used to post events to k8s
	recorder record.EventRecorder

	// go-ovn northbound client interface
	ovnNBClient goovn.Client

	// go-ovn southbound client interface
	ovnSBClient goovn.Client

	// default network controller
	ovnController *Controller
	// controller for non default networks, key is netName, value is *Controller
	nonDefaultOvnControllers sync.Map
}

// Controller structure is the object which holds the controls for starting
// and reacting upon the watched resources (e.g. pods, endpoints)
type Controller struct {
	mc                    *OvnMHController
	wg                    *sync.WaitGroup
	stopChan              chan struct{}
	egressFirewallHandler *factory.Handler
	podHandler            *factory.Handler
	nodeHandler           *factory.Handler

	netconf *ovntypes.NetConf

	// configured cluster subnets
	clusterSubnets []config.CIDRNetworkEntry
	// FIXME DUAL-STACK -  Make IP Allocators more dual-stack friendly
	masterSubnetAllocator     *subnetallocator.SubnetAllocator
	nodeLocalNatIPv4Allocator *ipallocator.Range
	nodeLocalNatIPv6Allocator *ipallocator.Range

	hoMaster *hocontroller.MasterController

	TCPLoadBalancerUUID  string
	UDPLoadBalancerUUID  string
	SCTPLoadBalancerUUID string
	SCTPSupport          bool

	// For TCP, UDP, and SCTP type traffic, cache OVN load-balancers used for the
	// cluster's east-west traffic.
	loadbalancerClusterCache map[kapi.Protocol]string

	// A cache of all logical switches seen by the watcher and their subnets
	lsManager *logicalSwitchManager

	// A cache of all logical ports known to the controller
	logicalPortCache *portCache

	// Info about known namespaces. You must use oc.getNamespaceLocked() or
	// oc.waitForNamespaceLocked() to read this map, and oc.createNamespaceLocked()
	// or oc.deleteNamespaceLocked() to modify it. namespacesMutex is only held
	// from inside those functions.
	namespaces      map[string]*namespaceInfo
	namespacesMutex sync.Mutex

	// An address set factory that creates address sets
	addressSetFactory addressset.AddressSetFactory

	// Port group for all cluster logical switch ports
	clusterPortGroupUUID string

	// Port group for all node logical switch ports connected to the cluster
	// logical router
	clusterRtrPortGroupUUID string

	// For each logical port, the number of network policies that want
	// to add a ingress deny rule.
	lspIngressDenyCache map[string]int

	// For each logical port, the number of network policies that want
	// to add a egress deny rule.
	lspEgressDenyCache map[string]int

	// A mutex for lspIngressDenyCache and lspEgressDenyCache
	lspMutex *sync.Mutex

	// Supports multicast?
	multicastSupport bool

	// Controller used for programming OVN for egress IP
	eIPC egressIPController

	egressFirewallDNS *EgressDNS

	// Is ACL logging enabled while configuring meters?
	aclLoggingEnabled bool

	// Map of load balancers, each containing a map of VIP to OVN LB Config
	serviceLBMap map[string]map[string]*loadBalancerConf

	serviceLBLock sync.Mutex

	joinSwIPManager *joinSwitchIPManager

	// v4HostSubnetsUsed keeps track of number of v4 subnets currently assigned to nodes
	v4HostSubnetsUsed float64

	// v6HostSubnetsUsed keeps track of number of v6 subnets currently assigned to nodes
	v6HostSubnetsUsed float64

	// Map of pods that need to be retried, and the timestamp of when they last failed
	retryPods     map[types.UID]retryEntry
	retryPodsLock sync.Mutex
}

type retryEntry struct {
	pod       *kapi.Pod
	timeStamp time.Time
}

const (
	// TCP is the constant string for the string "TCP"
	TCP = "TCP"

	// UDP is the constant string for the string "UDP"
	UDP = "UDP"

	// SCTP is the constant string for the string "SCTP"
	SCTP = "SCTP"
)

func GetIPFullMask(ip string) string {
	const (
		// IPv4FullMask is the maximum prefix mask for an IPv4 address
		IPv4FullMask = "/32"
		// IPv6FullMask is the maxiumum prefix mask for an IPv6 address
		IPv6FullMask = "/128"
	)

	if utilnet.IsIPv6(net.ParseIP(ip)) {
		return IPv6FullMask
	}
	return IPv4FullMask
}

func NewOvnMHController(ovnClient *util.OVNClientset, nodeName string, wf *factory.WatchFactory,
	stopChan chan struct{}, ovnNBClient goovn.Client, ovnSBClient goovn.Client,
	recorder record.EventRecorder, wg *sync.WaitGroup) *OvnMHController {
	return &OvnMHController{
		client: ovnClient.KubeClient,
		kube: &kube.Kube{
			KClient:              ovnClient.KubeClient,
			EIPClient:            ovnClient.EgressIPClient,
			EgressFirewallClient: ovnClient.EgressFirewallClient,
		},
		watchFactory: wf,
		wg:           wg,
		stopChan:     stopChan,
		recorder:     recorder,
		ovnNBClient:  ovnNBClient,
		ovnSBClient:  ovnSBClient,
		nodeName:     nodeName,
		//addressSetFactory: addressSetFactory,
	}
}

// If the default network net_attach_def does not exist, we'd need to create default OVN Controller based on config.
func (mc *OvnMHController) setDefaultOvnController(addressSetFactory addressset.AddressSetFactory) error {
	// default controller already exists, nothing to do.
	if mc.ovnController != nil {
		return nil
	}

	defaultNetConf := &ovntypes.NetConf{
		NetConf: ctypes.NetConf{
			Name: ptypes.DefaultNetworkName,
		},
		NetCidr:    config.Default.RawClusterSubnets,
		MTU:        config.Default.MTU,
		NotDefault: false,
	}
	_, err := mc.NewOvnController(defaultNetConf, addressSetFactory)
	if err != nil {
		return err
	}
	return nil
}

// NewOvnController creates a new OVN controller for creating logical network
// infrastructure and policy
func (mc *OvnMHController) NewOvnController(netconf *ovntypes.NetConf,
	addressSetFactory addressset.AddressSetFactory) (*Controller, error) {

	if addressSetFactory == nil {
		addressSetFactory = addressset.NewOvnAddressSetFactory()
	}

	if netconf.NetCidr == "" {
		return nil, fmt.Errorf("netcidr: %s is not specified for network %s", netconf.NetCidr, netconf.Name)
	}

	clusterIPNet, err := config.ParseClusterSubnetEntries(netconf.NetCidr)
	if err != nil {
		return nil, fmt.Errorf("cluster subnet %s for network %s is invalid: %v", netconf.NetCidr, netconf.Name, err)
	}

	stopChan := mc.stopChan
	if netconf.NotDefault {
		stopChan = make(chan struct{})
	}
	oc := &Controller{
		mc:                        mc,
		stopChan:                  stopChan,
		netconf:                   netconf,
		clusterSubnets:            clusterIPNet,
		masterSubnetAllocator:     subnetallocator.NewSubnetAllocator(),
		nodeLocalNatIPv4Allocator: &ipallocator.Range{},
		nodeLocalNatIPv6Allocator: &ipallocator.Range{},
		lsManager:                 newLogicalSwitchManager(),
		logicalPortCache:          newPortCache(stopChan),
		namespaces:                make(map[string]*namespaceInfo),
		namespacesMutex:           sync.Mutex{},
		addressSetFactory:         addressSetFactory,
		lspIngressDenyCache:       make(map[string]int),
		lspEgressDenyCache:        make(map[string]int),
		lspMutex:                  &sync.Mutex{},
		eIPC: egressIPController{
			assignmentRetryMutex:  &sync.Mutex{},
			assignmentRetry:       make(map[string]bool),
			namespaceHandlerMutex: &sync.Mutex{},
			namespaceHandlerCache: make(map[string]factory.Handler),
			podHandlerMutex:       &sync.Mutex{},
			podHandlerCache:       make(map[string]factory.Handler),
			allocatorMutex:        &sync.Mutex{},
			allocator:             make(map[string]*egressNode),
		},
		loadbalancerClusterCache: make(map[kapi.Protocol]string),
		multicastSupport:         config.EnableMulticast,
		aclLoggingEnabled:        true,
		serviceLBMap:             make(map[string]map[string]*loadBalancerConf),
		serviceLBLock:            sync.Mutex{},
		joinSwIPManager:          nil,
		retryPods:                make(map[types.UID]retryEntry),
	}
	if !netconf.NotDefault {
		oc.wg = mc.wg
		mc.ovnController = oc
	} else {
		oc.multicastSupport = false
		oc.wg = &sync.WaitGroup{}
		_, loaded := mc.nonDefaultOvnControllers.LoadOrStore(netconf.Name, oc)
		if loaded {
			return nil, fmt.Errorf("non default Network attachment definition %s already exists", netconf.Name)
		}
	}
	return oc, nil
}

// Run starts the actual watching.
func (oc *Controller) Run() error {
	if !oc.netconf.NotDefault {
		oc.syncPeriodic()
	}
	klog.Infof("Starting all the Watchers...")
	start := time.Now()

	// WatchNamespaces() should be started first because it has no other
	// dependencies, and WatchNodes() depends on it
	if !oc.netconf.NotDefault {
		oc.WatchNamespaces()
	}

	// WatchNodes must be started next because it creates the node switch
	// which most other watches depend on.
	// https://github.com/ovn-org/ovn-kubernetes/pull/859
	oc.WatchNodes()

	oc.WatchPods()

	if oc.netconf.NotDefault {
		klog.Infof("Completing all the Watchers for network %s took %v", oc.netconf.Name, time.Since(start))
		return nil
	}

	// We use a level triggered controller to handle services if the cluster
	// has endpoint slices enabled.
	if util.UseEndpointSlices(oc.mc.client) {
		klog.Infof("Starting OVN Service Controller: Using Endpoint Slices")
		// Create our own informers to start compartamentalizing the code
		// filter server side the things we don't care about
		noProxyName, err := labels.NewRequirement("service.kubernetes.io/service-proxy-name", selection.DoesNotExist, nil)
		if err != nil {
			return err
		}

		noHeadlessEndpoints, err := labels.NewRequirement(kapi.IsHeadlessService, selection.DoesNotExist, nil)
		if err != nil {
			return err
		}

		labelSelector := labels.NewSelector()
		labelSelector = labelSelector.Add(*noProxyName, *noHeadlessEndpoints)

		informerFactory := informers.NewSharedInformerFactoryWithOptions(oc.mc.client, 0,
			informers.WithTweakListOptions(func(options *metav1.ListOptions) {
				options.LabelSelector = labelSelector.String()
			}))

		servicesController := svccontroller.NewController(
			oc.mc.client,
			informerFactory.Core().V1().Services(),
			informerFactory.Discovery().V1beta1().EndpointSlices(),
			oc.clusterPortGroupUUID,
		)
		informerFactory.Start(oc.stopChan)
		oc.wg.Add(1)
		go func() {
			defer oc.wg.Done()
			// use 5 workers like most of the kubernetes controllers in the
			// kubernetes controller-manager
			err := servicesController.Run(5, oc.stopChan)
			if err != nil {
				klog.Errorf("Error running OVN Kubernetes Services controller: %v", err)
			}
		}()

	} else {
		klog.Infof("OVN Controller using Endpoints instead of EndpointSlices")
		oc.WatchServices()
		oc.WatchEndpoints()
	}

	oc.WatchNetworkPolicy()
	oc.WatchCRD()

	if config.OVNKubernetesFeature.EnableEgressIP {
		oc.WatchEgressNodes()
		oc.WatchEgressIP()
	}

	klog.Infof("Completing all the Watchers took %v", time.Since(start))

	if config.Kubernetes.OVNEmptyLbEvents {
		klog.Infof("Starting unidling controller")
		unidlingController := unidling.NewController(
			oc.mc.recorder,
			oc.mc.watchFactory.ServiceInformer(),
		)
		oc.wg.Add(1)
		go func() {
			defer oc.wg.Done()
			unidlingController.Run(oc.stopChan)
		}()
	}

	if oc.hoMaster != nil {
		oc.wg.Add(1)
		go func() {
			defer oc.wg.Done()
			oc.hoMaster.Run(oc.stopChan)
		}()
	}

	return nil
}

// syncPeriodic adds a goroutine that periodically does some work
// right now there is only one ticker registered
// for syncNodesPeriodic which deletes chassis records from the sbdb
// every 5 minutes
func (oc *Controller) syncPeriodic() {
	if oc.netconf.NotDefault {
		return
	}

	go func() {
		nodeSyncTicker := time.NewTicker(5 * time.Minute)
		for {
			select {
			case <-nodeSyncTicker.C:
				oc.syncNodesPeriodic()
			case <-oc.stopChan:
				return
			}
		}
	}()
}

func podScheduled(pod *kapi.Pod) bool {
	return pod.Spec.NodeName != ""
}

func (oc *Controller) recordPodEvent(addErr error, pod *kapi.Pod) {
	podRef, err := ref.GetReference(scheme.Scheme, pod)
	if err != nil {
		klog.Errorf("Couldn't get a reference to pod %s/%s to post an event: '%v'",
			pod.Namespace, pod.Name, err)
	} else {
		klog.V(5).Infof("Posting a %s event for Pod %s/%s", kapi.EventTypeWarning, pod.Namespace, pod.Name)
		oc.mc.recorder.Eventf(podRef, kapi.EventTypeWarning, "ErrorAddingLogicalPort", addErr.Error())
	}
}

// iterateRetryPods checks if any outstanding pods have been waiting for 60 seconds of last known failure
// then tries to re-add them if so
func (oc *Controller) iterateRetryPods() {
	oc.retryPodsLock.Lock()
	defer oc.retryPodsLock.Unlock()
	now := time.Now()
	for uid, podEntry := range oc.retryPods {
		pod := podEntry.pod
		podTimer := podEntry.timeStamp.Add(time.Minute)
		if now.After(podTimer) {
			podDesc := fmt.Sprintf("[%s/%s/%s]", pod.UID, pod.Namespace, pod.Name)
			klog.Infof("%s retry pod setup", podDesc)

			if oc.ensurePod(nil, pod, true) {
				klog.Infof("%s pod setup successful", podDesc)
				delete(oc.retryPods, uid)
			} else {
				klog.Infof("%s setup retry failed; will try again later", podDesc)
				oc.retryPods[uid] = retryEntry{pod, time.Now()}
			}
		}
	}
}

// checkAndDeleteRetryPod deletes a specific entry from the map, if it existed, returns true
func (oc *Controller) checkAndDeleteRetryPod(uid types.UID) bool {
	oc.retryPodsLock.Lock()
	defer oc.retryPodsLock.Unlock()
	if _, ok := oc.retryPods[uid]; ok {
		delete(oc.retryPods, uid)
		return true
	}
	return false
}

// addRetryPod tracks a failed pod to retry later
func (oc *Controller) addRetryPod(pod *kapi.Pod) {
	oc.retryPodsLock.Lock()
	defer oc.retryPodsLock.Unlock()
	oc.retryPods[pod.UID] = retryEntry{pod, time.Now()}
}

func exGatewayAnnotationsChanged(oldPod, newPod *kapi.Pod) bool {
	return oldPod.Annotations[routingNamespaceAnnotation] != newPod.Annotations[routingNamespaceAnnotation] ||
		oldPod.Annotations[routingNetworkAnnotation] != newPod.Annotations[routingNetworkAnnotation]
}

func networkStatusAnnotationsChanged(oldPod, newPod *kapi.Pod) bool {
	return oldPod.Annotations[nettypes.NetworkStatusAnnot] != newPod.Annotations[nettypes.NetworkStatusAnnot]
}

// ensurePod tries to set up a pod. It returns success or failure; failure
// indicates the pod should be retried later.
func (oc *Controller) ensurePod(oldPod, pod *kapi.Pod, addPort bool) bool {
	// Try unscheduled pods later
	if !podScheduled(pod) {
		return false
	}

	if util.PodWantsNetwork(pod) && addPort {
		if err := oc.addLogicalPort(pod); err != nil {
			klog.Errorf(err.Error())
			oc.recordPodEvent(err, pod)
			return false
		}
	} else {
		if oc.netconf.NotDefault {
			return true
		}
		if oldPod != nil && (exGatewayAnnotationsChanged(oldPod, pod) || networkStatusAnnotationsChanged(oldPod, pod)) {
			// No matter if a pod is ovn networked, or host networked, we still need to check for exgw
			// annotations. If the pod is ovn networked and is in update reschedule, addLogicalPort will take
			// care of updating the exgw updates
			oc.deletePodExternalGW(oldPod)
		}
		if err := oc.addPodExternalGW(pod); err != nil {
			klog.Errorf(err.Error())
			oc.recordPodEvent(err, pod)
			return false
		}
	}

	return true
}

// WatchPods starts the watching of Pod resource and calls back the appropriate handler logic
func (oc *Controller) WatchPods() {
	go func() {
		// track the retryPods map and every 30 seconds check if any pods need to be retried
		utilwait.Until(oc.iterateRetryPods, 30*time.Second, oc.stopChan)
	}()

	start := time.Now()
	oc.podHandler = oc.mc.watchFactory.AddPodHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*kapi.Pod)
			if !oc.ensurePod(nil, pod, true) {
				oc.addRetryPod(pod)
			}
		},
		UpdateFunc: func(old, newer interface{}) {
			oldPod := old.(*kapi.Pod)
			pod := newer.(*kapi.Pod)
			if !oc.ensurePod(oldPod, pod, oc.checkAndDeleteRetryPod(pod.UID)) {
				// add back the failed pod
				oc.addRetryPod(pod)
				return
			}
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*kapi.Pod)
			oc.checkAndDeleteRetryPod(pod.UID)
			if !util.PodWantsNetwork(pod) {
				oc.deletePodExternalGW(pod)
				return
			}
			// deleteLogicalPort will take care of removing exgw for ovn networked pods
			oc.deleteLogicalPort(pod)
		},
	}, oc.syncPods)
	klog.Infof("Bootstrapping existing pods and cleaning stale pods took %v", time.Since(start))
}

// WatchServices starts the watching of Service resource and calls back the
// appropriate handler logic
func (oc *Controller) WatchServices() {
	if oc.netconf.NotDefault {
		klog.Infof("WatchServices for network %s is a no-op", oc.netconf.Name)
		return
	}

	start := time.Now()
	oc.mc.watchFactory.AddServiceHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			service := obj.(*kapi.Service)
			err := oc.createService(service)
			if err != nil {
				klog.Errorf("Error in adding service: %v", err)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			svcOld := old.(*kapi.Service)
			svcNew := new.(*kapi.Service)
			err := oc.updateService(svcOld, svcNew)
			if err != nil {
				klog.Errorf("Error while updating service: %v", err)
			}
		},
		DeleteFunc: func(obj interface{}) {
			service := obj.(*kapi.Service)
			oc.deleteService(service)
		},
	}, oc.syncServices)
	klog.Infof("Bootstrapping existing services and cleaning stale services took %v", time.Since(start))
}

// WatchEndpoints starts the watching of Endpoint resource and calls back the appropriate handler logic
func (oc *Controller) WatchEndpoints() {
	if oc.netconf.NotDefault {
		klog.Infof("WatchEndpoints for network %s is a no-op", oc.netconf.Name)
		return
	}

	start := time.Now()
	oc.mc.watchFactory.AddEndpointsHandler(cache.ResourceEventHandlerFuncs{
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
	klog.Infof("Bootstrapping existing endpoints and cleaning stale endpoints took %v", time.Since(start))
}

// WatchNetworkPolicy starts the watching of network policy resource and calls
// back the appropriate handler logic
func (oc *Controller) WatchNetworkPolicy() {
	if oc.netconf.NotDefault {
		klog.Infof("WatchNetworkPolicy for network %s is a no-op", oc.netconf.Name)
		return
	}
	start := time.Now()
	oc.mc.watchFactory.AddPolicyHandler(cache.ResourceEventHandlerFuncs{
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
	klog.Infof("Bootstrapping existing policies and cleaning stale policies took %v", time.Since(start))
}

// WatchCRD starts the watching of the CRD resource and calls back to the
// appropriate handler logic
func (oc *Controller) WatchCRD() {
	if oc.netconf.NotDefault {
		klog.Infof("WatchCRD for network %s is a no-op", oc.netconf.Name)
		return
	}

	oc.mc.watchFactory.AddCRDHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			crd := obj.(*apiextension.CustomResourceDefinition)
			klog.Infof("Adding CRD %s to cluster", crd.Name)
			var err error
			if crd.Name == egressfirewallCRD {
				err = oc.mc.watchFactory.InitializeEgressFirewallWatchFactory()
				if err != nil {
					klog.Errorf("Error Creating WatchFactory for %s: %v", err, crd.Name)
					return
				}

				oc.egressFirewallDNS, err = NewEgressDNS(oc.addressSetFactory, oc.stopChan)
				oc.egressFirewallDNS.Run(egressFirewallDNSDefaultDuration)
				if err != nil {
					klog.Errorf("Error Creating EgressFirewallDNS: %v", err)
				}
				oc.egressFirewallHandler = oc.WatchEgressFirewall()
			}
		},
		UpdateFunc: func(old, newer interface{}) {
		},
		DeleteFunc: func(obj interface{}) {
			crd := obj.(*apiextension.CustomResourceDefinition)
			klog.Infof("Deleting CRD %s from cluster", crd.Name)
			if crd.Name == egressfirewallCRD {
				oc.egressFirewallDNS.Shutdown()
				oc.mc.watchFactory.RemoveEgressFirewallHandler(oc.egressFirewallHandler)
				oc.egressFirewallHandler = nil
				oc.mc.watchFactory.ShutdownEgressFirewallWatchFactory()
			}
		},
	}, nil)
}

// WatchEgressFirewall starts the watching of egressfirewall resource and calls
// back the appropriate handler logic
func (oc *Controller) WatchEgressFirewall() *factory.Handler {
	if oc.netconf.NotDefault {
		klog.Infof("WatchCRD for egress firewall %s is a no-op", oc.netconf.Name)
		return nil
	}

	return oc.mc.watchFactory.AddEgressFirewallHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			egressFirewall := obj.(*egressfirewall.EgressFirewall).DeepCopy()
			addErrors := oc.addEgressFirewall(egressFirewall)
			if addErrors != nil {
				klog.Error(addErrors)
				egressFirewall.Status.Status = egressFirewallAddError
			} else {

				egressFirewall.Status.Status = egressFirewallAppliedCorrectly
			}

			err := oc.updateEgressFirewallWithRetry(egressFirewall)
			if err != nil {
				klog.Error(err)
			}
		},
		UpdateFunc: func(old, newer interface{}) {
			newEgressFirewall := newer.(*egressfirewall.EgressFirewall).DeepCopy()
			oldEgressFirewall := old.(*egressfirewall.EgressFirewall)
			if !reflect.DeepEqual(oldEgressFirewall.Spec, newEgressFirewall.Spec) {
				errList := oc.updateEgressFirewall(oldEgressFirewall, newEgressFirewall)
				if errList != nil {
					newEgressFirewall.Status.Status = egressFirewallUpdateError
					klog.Error(errList)
				} else {
					newEgressFirewall.Status.Status = egressFirewallAppliedCorrectly
				}
				err := oc.updateEgressFirewallWithRetry(newEgressFirewall)
				if err != nil {
					klog.Error(err)
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			egressFirewall := obj.(*egressfirewall.EgressFirewall)
			deleteErrors := oc.deleteEgressFirewall(egressFirewall)
			if deleteErrors != nil {
				klog.Error(deleteErrors)
			}
		},
	}, nil)
}

// WatchEgressNodes starts the watching of egress assignable nodes and calls
// back the appropriate handler logic.
func (oc *Controller) WatchEgressNodes() {
	if oc.netconf.NotDefault {
		klog.Infof("WatchEgressNodes for network %s is a no-op", oc.netconf.Name)
		return
	}

	nodeEgressLabel := util.GetNodeEgressLabel()
	oc.mc.watchFactory.AddNodeHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node := obj.(*kapi.Node)
			if err := oc.addNodeForEgress(node); err != nil {
				klog.Error(err)
			}
			nodeLabels := node.GetLabels()
			if _, hasEgressLabel := nodeLabels[nodeEgressLabel]; hasEgressLabel && oc.isEgressNodeReady(node) && oc.isEgressNodeReachable(node) {
				oc.setNodeEgressAssignable(node.Name, true)
				oc.setNodeEgressReady(node.Name, true)
				oc.setNodeEgressReachable(node.Name, true)
				if err := oc.addEgressNode(node); err != nil {
					klog.Error(err)
				}
			}
		},
		UpdateFunc: func(old, new interface{}) {
			oldNode := old.(*kapi.Node)
			newNode := new.(*kapi.Node)
			if err := oc.initEgressIPAllocator(newNode); err != nil {
				klog.Error(err)
			}
			oldLabels := oldNode.GetLabels()
			newLabels := newNode.GetLabels()
			_, oldHadEgressLabel := oldLabels[nodeEgressLabel]
			_, newHasEgressLabel := newLabels[nodeEgressLabel]
			if !oldHadEgressLabel && !newHasEgressLabel {
				return
			}
			if oldHadEgressLabel && !newHasEgressLabel {
				klog.Infof("Node: %s has been un-labelled, deleting it from egress assignment", newNode.Name)
				oc.setNodeEgressAssignable(oldNode.Name, false)
				if err := oc.deleteEgressNode(oldNode); err != nil {
					klog.Error(err)
				}
				return
			}
			isOldReady := oc.isEgressNodeReady(oldNode)
			isNewReady := oc.isEgressNodeReady(newNode)
			isNewReachable := oc.isEgressNodeReachable(newNode)
			oc.setNodeEgressReady(newNode.Name, isNewReady)
			oc.setNodeEgressReachable(newNode.Name, isNewReachable)
			if !oldHadEgressLabel && newHasEgressLabel {
				klog.Infof("Node: %s has been labelled, adding it for egress assignment", newNode.Name)
				oc.setNodeEgressAssignable(newNode.Name, true)
				if isNewReady && isNewReachable {
					if err := oc.addEgressNode(newNode); err != nil {
						klog.Error(err)
					}
				} else {
					klog.Warningf("Node: %s has been labelled, but node is not ready and reachable, cannot use it for egress assignment", newNode.Name)
				}
				return
			}
			if isOldReady == isNewReady {
				return
			}
			if !isNewReady {
				klog.Warningf("Node: %s is not ready, deleting it from egress assignment", newNode.Name)
				if err := oc.deleteEgressNode(newNode); err != nil {
					klog.Error(err)
				}
			} else if isNewReady && isNewReachable {
				klog.Infof("Node: %s is ready and reachable, adding it for egress assignment", newNode.Name)
				if err := oc.addEgressNode(newNode); err != nil {
					klog.Error(err)
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			node := obj.(*kapi.Node)
			if err := oc.deleteNodeForEgress(node); err != nil {
				klog.Error(err)
			}
			nodeLabels := node.GetLabels()
			if _, hasEgressLabel := nodeLabels[nodeEgressLabel]; hasEgressLabel {
				if err := oc.deleteEgressNode(node); err != nil {
					klog.Error(err)
				}
			}
		},
	}, oc.initClusterEgressPolicies)
}

// WatchEgressIP starts the watching of egressip resource and calls
// back the appropriate handler logic.
func (oc *Controller) WatchEgressIP() {
	if oc.netconf.NotDefault {
		klog.Infof("WatchEgressIP for network %s is a no-op", oc.netconf.Name)
		return
	}

	oc.mc.watchFactory.AddEgressIPHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			eIP := obj.(*egressipv1.EgressIP).DeepCopy()
			oc.eIPC.assignmentRetryMutex.Lock()
			if err := oc.addEgressIP(eIP); err != nil {
				klog.Error(err)
			}
			oc.eIPC.assignmentRetryMutex.Unlock()
			if err := oc.updateEgressIPWithRetry(eIP); err != nil {
				klog.Error(err)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			oldEIP := old.(*egressipv1.EgressIP)
			newEIP := new.(*egressipv1.EgressIP).DeepCopy()
			if !reflect.DeepEqual(oldEIP.Spec, newEIP.Spec) {
				if err := oc.deleteEgressIP(oldEIP); err != nil {
					klog.Error(err)
				}
				newEIP.Status = egressipv1.EgressIPStatus{
					Items: []egressipv1.EgressIPStatusItem{},
				}
				oc.eIPC.assignmentRetryMutex.Lock()
				if err := oc.addEgressIP(newEIP); err != nil {
					klog.Error(err)
				}
				oc.eIPC.assignmentRetryMutex.Unlock()
				if err := oc.updateEgressIPWithRetry(newEIP); err != nil {
					klog.Error(err)
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			eIP := obj.(*egressipv1.EgressIP)
			if err := oc.deleteEgressIP(eIP); err != nil {
				klog.Error(err)
			}
		},
	}, oc.syncEgressIPs)
}

// WatchNamespaces starts the watching of namespace resource and calls
// back the appropriate handler logic
func (oc *Controller) WatchNamespaces() {
	if oc.netconf.NotDefault {
		klog.Infof("WatchNamespaces for network %s is a no-op", oc.netconf.Name)
		return
	}

	start := time.Now()
	oc.mc.watchFactory.AddNamespaceHandler(cache.ResourceEventHandlerFuncs{
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
	klog.Infof("Bootstrapping existing namespaces and cleaning stale namespaces took %v", time.Since(start))
}

func (oc *Controller) syncNodeGateway(node *kapi.Node, hostSubnets []*net.IPNet) error {
	if oc.netconf.NotDefault {
		klog.Infof("WatchNamespaces for network %s is a no-op", oc.netconf.Name)
		return nil
	}

	l3GatewayConfig, err := util.ParseNodeL3GatewayAnnotation(node)
	if err != nil {
		return err
	}

	if hostSubnets == nil {
		hostSubnets, _ = util.ParseNodeHostSubnetAnnotation(node, oc.netconf.Name)
	}
	if l3GatewayConfig.Mode == config.GatewayModeDisabled {
		if err := gatewayCleanup(node.Name); err != nil {
			return fmt.Errorf("error cleaning up gateway for node %s: %v", node.Name, err)
		}
		if err := oc.joinSwIPManager.releaseJoinLRPIPs(node.Name); err != nil {
			return err
		}
	} else if hostSubnets != nil {
		if err := oc.syncGatewayLogicalNetwork(node, l3GatewayConfig, hostSubnets); err != nil {
			return fmt.Errorf("error creating gateway for node %s: %v", node.Name, err)
		}
	}
	return nil
}

// WatchNodes starts the watching of node resource and calls
// back the appropriate handler logic
func (oc *Controller) WatchNodes() {
	var gatewaysFailed sync.Map
	var mgmtPortFailed sync.Map
	var addNodeFailed sync.Map

	start := time.Now()
	oc.nodeHandler = oc.mc.watchFactory.AddNodeHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node := obj.(*kapi.Node)
			if noHostSubnet := noHostSubnet(node); noHostSubnet {
				err := oc.lsManager.AddNoHostSubnetNode(node.Name)
				if err != nil {
					klog.Errorf("Error creating logical switch cache for node %s: %v", node.Name, err)
				}
				return
			}

			klog.V(5).Infof("Added event for Node %q", node.Name)
			hostSubnets, err := oc.addNode(node)
			if err != nil {
				klog.Errorf("NodeAdd: error creating subnet for node %s: %v", node.Name, err)
				addNodeFailed.Store(node.Name, true)
				mgmtPortFailed.Store(node.Name, true)
				gatewaysFailed.Store(node.Name, true)
				return
			}

			if oc.netconf.NotDefault {
				return
			}
			err = oc.syncNodeManagementPort(node, hostSubnets)
			if err != nil {
				if !util.IsAnnotationNotSetError(err) {
					klog.Warningf("Error creating management port for node %s: %v", node.Name, err)
				}
				mgmtPortFailed.Store(node.Name, true)
			}

			if err := oc.syncNodeGateway(node, hostSubnets); err != nil {
				if !util.IsAnnotationNotSetError(err) {
					klog.Warningf(err.Error())
				}
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

			var hostSubnets []*net.IPNet
			_, failed := addNodeFailed.Load(node.Name)
			if failed {
				hostSubnets, err = oc.addNode(node)
				if err != nil {
					klog.Errorf("NodeUpdate: error creating subnet for node %s: %v", node.Name, err)
					return
				}
				addNodeFailed.Delete(node.Name)
			}

			if oc.netconf.NotDefault {
				return
			}

			_, failed = mgmtPortFailed.Load(node.Name)
			if failed || macAddressChanged(oldNode, node) || nodeSubnetChanged(oldNode, node, oc.netconf.Name) {
				err := oc.syncNodeManagementPort(node, hostSubnets)
				if err != nil {
					if !util.IsAnnotationNotSetError(err) {
						klog.Errorf("Error updating management port for node %s: %v", node.Name, err)
					}
					mgmtPortFailed.Store(node.Name, true)
				} else {
					mgmtPortFailed.Delete(node.Name)
				}
			}

			oc.clearInitialNodeNetworkUnavailableCondition(oldNode, node)

			_, failed = gatewaysFailed.Load(node.Name)
			if failed || oc.gatewayChanged(oldNode, node) {
				err := oc.syncNodeGateway(node, nil)
				if err != nil {
					if !util.IsAnnotationNotSetError(err) {
						klog.Errorf(err.Error())
					}
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

			nodeSubnets, _ := util.ParseNodeHostSubnetAnnotation(node, oc.netconf.Name)
			dnatSnatIPs, _ := util.ParseNodeLocalNatIPAnnotation(node)
			err := oc.deleteNode(node.Name, nodeSubnets, dnatSnatIPs)
			if err != nil {
				klog.Error(err)
			}
			oc.lsManager.DeleteNode(node.Name)
			addNodeFailed.Delete(node.Name)
			mgmtPortFailed.Delete(node.Name)
			gatewaysFailed.Delete(node.Name)
		},
	}, oc.syncNodes)
	klog.Infof("Bootstrapping existing nodes and cleaning stale nodes took %v", time.Since(start))
}

// GetNetworkPolicyACLLogging retrieves ACL deny policy logging setting for the Namespace
func (oc *Controller) GetNetworkPolicyACLLogging(ns string) *ACLLoggingLevels {
	nsInfo := oc.getNamespaceLocked(ns)
	if nsInfo == nil {
		return &ACLLoggingLevels{
			Allow: "",
			Deny:  "",
		}
	}
	defer nsInfo.Unlock()
	return &nsInfo.aclLogging
}

// Verify if controller can support ACL logging and validate annotation
func (oc *Controller) aclLoggingCanEnable(annotation string, nsInfo *namespaceInfo) bool {
	if !oc.aclLoggingEnabled || annotation == "" {
		nsInfo.aclLogging.Deny = ""
		nsInfo.aclLogging.Allow = ""
		return false
	}
	var aclLevels ACLLoggingLevels
	err := json.Unmarshal([]byte(annotation), &aclLevels)
	if err != nil {
		return false
	}
	okCnt := 0
	for _, s := range []string{"alert", "warning", "notice", "info", "debug"} {
		if aclLevels.Deny != "" && s == aclLevels.Deny {
			nsInfo.aclLogging.Deny = aclLevels.Deny
			okCnt++
		}
		if aclLevels.Allow != "" && s == aclLevels.Allow {
			nsInfo.aclLogging.Allow = aclLevels.Allow
			okCnt++
		}
	}
	return okCnt > 0
}

// setServiceLBToACL associates an empty load balancer with its associated ACL reject rule
func (oc *Controller) setServiceACLToLB(lb, vip, acl string) {
	if oc.netconf.NotDefault {
		return
	}

	if _, ok := oc.serviceLBMap[lb]; !ok {
		oc.serviceLBMap[lb] = make(map[string]*loadBalancerConf)
		oc.serviceLBMap[lb][vip] = &loadBalancerConf{rejectACL: acl}
		return
	}
	if _, ok := oc.serviceLBMap[lb][vip]; !ok {
		oc.serviceLBMap[lb][vip] = &loadBalancerConf{rejectACL: acl}
		return
	}
	oc.serviceLBMap[lb][vip].rejectACL = acl
}

// setServiceEndpointsToLB associates a load balancer with endpoints
func (oc *Controller) setServiceEndpointsToLB(lb, vip string, eps []string) {
	if oc.netconf.NotDefault {
		return
	}

	if _, ok := oc.serviceLBMap[lb]; !ok {
		oc.serviceLBMap[lb] = make(map[string]*loadBalancerConf)
		oc.serviceLBMap[lb][vip] = &loadBalancerConf{endpoints: eps}
		return
	}
	if _, ok := oc.serviceLBMap[lb][vip]; !ok {
		oc.serviceLBMap[lb][vip] = &loadBalancerConf{endpoints: eps}
		return
	}
	oc.serviceLBMap[lb][vip].endpoints = eps
}

// getServiceLBInfo returns the reject ACL and whether the number of endpoints for the service is greater than zero
func (oc *Controller) getServiceLBInfo(lb, vip string) (string, bool) {
	if oc.netconf.NotDefault {
		return "", false
	}

	oc.serviceLBLock.Lock()
	defer oc.serviceLBLock.Unlock()
	conf, ok := oc.serviceLBMap[lb][vip]
	if !ok {
		conf = &loadBalancerConf{}
	}
	return conf.rejectACL, len(conf.endpoints) > 0
}

// removeServiceLB removes the entire LB entry for a VIP
func (oc *Controller) removeServiceLB(lb, vip string) {
	if oc.netconf.NotDefault {
		return
	}
	oc.serviceLBLock.Lock()
	defer oc.serviceLBLock.Unlock()
	delete(oc.serviceLBMap[lb], vip)
}

// removeServiceACL removes a specific ACL associated with a load balancer and ip:port
func (oc *Controller) removeServiceACL(lb, vip string) {
	if oc.netconf.NotDefault {
		return
	}
	oc.serviceLBLock.Lock()
	defer oc.serviceLBLock.Unlock()
	if _, ok := oc.serviceLBMap[lb][vip]; ok {
		oc.serviceLBMap[lb][vip].rejectACL = ""
	}
}

// removeServiceEndpoints removes endpoints associated with a load balancer and ip:port
func (oc *Controller) removeServiceEndpoints(lb, vip string) {
	if oc.netconf.NotDefault {
		return
	}
	oc.serviceLBLock.Lock()
	defer oc.serviceLBLock.Unlock()
	if _, ok := oc.serviceLBMap[lb][vip]; ok {
		oc.serviceLBMap[lb][vip].endpoints = []string{}
	}
}

func (mc *OvnMHController) addNetworkAttachDefinition(netattachdef *nettypes.NetworkAttachmentDefinition) {

	netconf := &ovntypes.NetConf{}

	// looking for network attachment definition that use OVN K8S CNI only
	err := json.Unmarshal([]byte(netattachdef.Spec.Config), &netconf)
	if err != nil {
		klog.Errorf("Error parsing Network Attachment Definition %s: %v", netattachdef.Name, err)
		return
	}

	if netconf.Type != "ovn-k8s-cni-overlay" {
		klog.V(5).Infof("Network Attachment Definition %s is not based on OVN plugin", netattachdef.Name)
		return
	}

	if netconf.Name == "" {
		netconf.Name = netattachdef.Name
	}

	if !netconf.NotDefault {
		if mc.ovnController != nil {
			klog.Errorf("Default network net_attach_def can only be added when master is first initialized")
			return
		}
		// overide default network name
		netconf.Name = ptypes.DefaultNetworkName
	}

	klog.Infof("DEBUG AddNetworkAttachDefinition: %s netconf %v", netconf.Name, netconf)
	oc, err := mc.NewOvnController(netconf, nil)
	if err != nil {
		klog.Errorf(err.Error())
		return
	}

	if !netconf.NotDefault {
		return
	}

	// run the cluster controller to init the master
	err = oc.StartClusterMaster(mc.nodeName)
	if err != nil {
		klog.Errorf(err.Error())
		return
	}

	err = oc.Run()
	if err != nil {
		klog.Errorf(err.Error())
	}
}

func (mc *OvnMHController) deleteNetworkAttachDefinition(netattachdef *nettypes.NetworkAttachmentDefinition) {
	netconf := &ovntypes.NetConf{}
	err := json.Unmarshal([]byte(netattachdef.Spec.Config), &netconf)
	if err != nil && netconf.Type != "ovn-k8s-cni-overlay" {
		return
	}

	if netconf.Type != "ovn-k8s-cni-overlay" {
		klog.V(5).Infof("Network Attachment Definition %s is not based on OVN plugin", netattachdef.Name)
		return
	}

	if !netconf.NotDefault {
		// delete default network is a no-op
		return
	}

	if netconf.Name == "" {
		netconf.Name = netattachdef.Name
	}

	klog.Infof("DEBUG deleteNetworkAttachDefinition: %s netconf %v", netconf.Name, netconf)
	v, ok := mc.nonDefaultOvnControllers.Load(netconf.Name)
	if !ok {
		klog.Errorf("Failed to find network controller for network %s", netconf.Name)
		return
	}

	oc := v.(*Controller)
	oc.wg.Wait()
	close(oc.stopChan)
	oc.deleteMaster()

	existingNodes, err := oc.mc.kube.GetNodes()
	if err != nil {
		klog.Errorf("Error in initializing/fetching subnets: %v", err)
		return
	}
	// remove hostsubnet annoation for this network
	for _, node := range existingNodes.Items {
		err := oc.deleteNodeLogicalNetwork(node.Name)
		if err != nil {
			klog.Error("Failed to delete node %s for network %s: %v", node.Name, oc.netconf.Name, err)
		}
		_ = oc.updateNodeAnnotationWithRetry(node.Name, []*net.IPNet{})
		oc.lsManager.DeleteNode(node.Name)
	}

	if oc.podHandler != nil {
		oc.mc.watchFactory.RemovePodHandler(oc.podHandler)
	}

	if oc.nodeHandler != nil {
		oc.mc.watchFactory.RemoveNodeHandler(oc.nodeHandler)
	}

	mc.nonDefaultOvnControllers.Delete(netconf.Name)
}

// syncNetworkAttachDefinition() delete OVN logical entities of the obsoleted netNames.
func (mc *OvnMHController) syncNetworkAttachDefinition(netattachdefs []interface{}) {
	// Get all the existing non-default netNames
	expectedNetworks := make(map[string]bool)
	for _, netattachdefIntf := range netattachdefs {
		netattachdef, ok := netattachdefIntf.(*nettypes.NetworkAttachmentDefinition)
		if !ok {
			klog.Errorf("Spurious object in syncNetworkAttachDefinition: %v", netattachdefIntf)
			continue
		}
		netConf := &ovntypes.NetConf{}
		err := json.Unmarshal([]byte(netattachdef.Spec.Config), &netConf)
		if err != nil {
			klog.Errorf("Unrecognized Spec.Config of NetworkAttachmentDefinition %s: %v", netattachdef.Name, err)
			continue
		}
		if netConf.Type != "ovn-k8s-cni-overlay" {
			klog.V(5).Infof("Network Attachment Definition %s is not based on OVN plugin", netattachdef.Name)
			return
		}
		// If this is the NetworkAttachmentDefinition for the default network, skip it
		if !netConf.NotDefault {
			continue
		}
		expectedNetworks[netattachdef.Name] = true
	}

	// Find all the logical node switches for the non-default networks and delete the ones that belong to the
	// obsolete networks
	nodeSwitches, stderr, err := util.RunOVNNbctl("--data=bare", "--format=csv", "--no-heading",
		"--columns=name,external_ids", "find", "logical_switch", "external_ids:network_name!=_")
	if err != nil {
		klog.Errorf("No logical switches with non-default network: stderr: %q, error: %v", stderr, err)
		return
	}
	for _, result := range strings.Split(nodeSwitches, "\n") {
		items := strings.Split(result, ",")
		if len(items) != 2 || len(items[0]) == 0 {
			continue
		}

		netName := util.GetNetworkNameFromExternalId(items[1])
		if _, ok := expectedNetworks[netName]; ok {
			// network still exists, no cleanup to do
			continue
		}

		// items[0] is the switch name, which should be prefixed with netName
		if netName == ptypes.DefaultNetworkName || !strings.HasPrefix(items[0], netName) {
			klog.Warningf("Unexpected logical switch %s for network %s during sync external_id %s", items[0], netName, items[1])
			continue
		}

		nodeName := strings.TrimPrefix(items[0], util.GetNetworkPrefix(netName))

		oc := &Controller{netconf: &ovntypes.NetConf{NetConf: ctypes.NetConf{Name: netName}}}
		if err := oc.deleteNodeLogicalNetwork(nodeName); err != nil {
			klog.Errorf("Error deleting node %s logical network: %v", nodeName, err)
		}
		_ = oc.updateNodeAnnotationWithRetry(nodeName, []*net.IPNet{})
	}
	clusterRouters, stderr, err := util.RunOVNNbctl("--data=bare", "--format=csv", "--no-heading",
		"--columns=name,external_ids", "find", "logical_router", "external_ids:network_name!=_")
	if err != nil {
		klog.Errorf("Failed to get logical routers with non-default network name: stderr: %q, error: %v",
			stderr, err)
		return
	}
	for _, result := range strings.Split(clusterRouters, "\n") {
		items := strings.Split(result, ",")
		if len(items) != 2 || len(items[0]) == 0 {
			continue
		}

		netName := util.GetNetworkNameFromExternalId(items[1])
		if _, ok := expectedNetworks[netName]; ok {
			// network still exists, no cleanup to do
			continue
		}

		// items[0] is the router name, which should be prefixed with netName
		if netName == ptypes.DefaultNetworkName || !strings.HasPrefix(items[0], netName) {
			klog.Warningf("Unexpected logical router %s for network %s during sync, external_ids: %s", items[0], netName, items[1])
			continue
		}

		oc := &Controller{netconf: &ovntypes.NetConf{NetConf: ctypes.NetConf{Name: netName}}}
		oc.deleteMaster()
	}
}

// watchCRD starts the watching of network attachment definition
// resource and calls back the appropriate handler logic
func (mc *OvnMHController) watchCRD() {
	mc.watchFactory.AddCRDHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			crd := obj.(*apiextension.CustomResourceDefinition)
			klog.Infof("Adding CRD %s to cluster", crd.Name)
			if crd.Name == netattachdefCRD {
				err := mc.watchFactory.InitializeNetAttachDefWatchFactory()
				if err != nil {
					klog.Errorf("Error Creating EgressFirewallWatchFactory: %v", err)
					return
				}

				mc.netAttachDefHandler = mc.watchNetworkAttachmentDefinitions()
			}
		},
		UpdateFunc: func(old, newer interface{}) {
		},
		DeleteFunc: func(obj interface{}) {
			crd := obj.(*apiextension.CustomResourceDefinition)
			klog.Infof("Deleting CRD %s from cluster", crd.Name)
			if crd.Name == netattachdefCRD {
				mc.watchFactory.RemoveNetworkattachmentdefinitionHandler(mc.netAttachDefHandler)
				mc.netAttachDefHandler = nil
				mc.watchFactory.ShutdownNetAttachDefWatchFactory()

			}
		},
	}, nil)
}

// watchNetworkAttachmentDefinitions starts the watching of network attachment definition
// resource and calls back the appropriate handler logic
func (mc *OvnMHController) watchNetworkAttachmentDefinitions() *factory.Handler {
	return mc.watchFactory.AddNetworkattachmentdefinitionHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			netattachdef := obj.(*nettypes.NetworkAttachmentDefinition)
			mc.addNetworkAttachDefinition(netattachdef)
		},
		UpdateFunc: func(old, new interface{}) {},
		DeleteFunc: func(obj interface{}) {
			netattachdef := obj.(*nettypes.NetworkAttachmentDefinition)
			mc.deleteNetworkAttachDefinition(netattachdef)
		},
	}, mc.syncNetworkAttachDefinition)
}

// gatewayChanged() compares old annotations to new and returns true if something has changed.
func (oc *Controller) gatewayChanged(oldNode, newNode *kapi.Node) bool {
	if oc.netconf.NotDefault {
		return false
	}
	oldL3GatewayConfig, _ := util.ParseNodeL3GatewayAnnotation(oldNode)
	l3GatewayConfig, _ := util.ParseNodeL3GatewayAnnotation(newNode)

	if oldL3GatewayConfig == nil && l3GatewayConfig == nil {
		return false
	}

	return !reflect.DeepEqual(oldL3GatewayConfig, l3GatewayConfig)
}

// macAddressChanged() compares old annotations to new and returns true if something has changed.
func macAddressChanged(oldNode, node *kapi.Node) bool {
	oldMacAddress, _ := util.ParseNodeManagementPortMACAddress(oldNode)
	macAddress, _ := util.ParseNodeManagementPortMACAddress(node)
	return !bytes.Equal(oldMacAddress, macAddress)
}

func nodeSubnetChanged(oldNode, node *kapi.Node, netName string) bool {
	oldSubnets, _ := util.ParseNodeHostSubnetAnnotation(oldNode, netName)
	newSubnets, _ := util.ParseNodeHostSubnetAnnotation(node, netName)
	return !reflect.DeepEqual(oldSubnets, newSubnets)
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
