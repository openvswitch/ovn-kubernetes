package factory

import (
	"fmt"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	egressfirewallapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	egressfirewallclientset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned"
	egressfirewallscheme "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned/scheme"
	egressfirewallinformerfactory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/informers/externalversions"

	egressipapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	egressipscheme "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/scheme"
	egressipinformerfactory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/informers/externalversions"
	apiextensionsapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsscheme "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/scheme"
	apiextensionsinformerfactory "k8s.io/apiextensions-apiserver/pkg/client/informers/externalversions"

	kapi "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	informerfactory "k8s.io/client-go/informers"
	v1coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// WatchFactory initializes and manages common kube watches
type WatchFactory struct {
	// Must be first member in the struct due to Golang ARM/x86 32-bit
	// requirements with atomic accesses
	handlerCounter uint64

	iFactory    informerfactory.SharedInformerFactory
	eipFactory  egressipinformerfactory.SharedInformerFactory
	efFactory   egressfirewallinformerfactory.SharedInformerFactory
	efClientset egressfirewallclientset.Interface
	crdFactory  apiextensionsinformerfactory.SharedInformerFactory
	informers   map[reflect.Type]*informer

	stopChan               chan struct{}
	egressFirewallStopChan chan struct{}
}

// WatchFactory implements the ObjectCacheInterface interface.
var _ ObjectCacheInterface = &WatchFactory{}

const (
	// resync time is 0, none of the resources being watched in ovn-kubernetes have
	// any race condition where a resync may be required e.g. cni executable on node watching for
	// events on pods and assuming that an 'ADD' event will contain the annotations put in by
	// ovnkube master (currently, it is just a 'get' loop)
	// the downside of making it tight (like 10 minutes) is needless spinning on all resources
	// However, AddEventHandlerWithResyncPeriod can specify a per handler resync period
	resyncInterval        = 0
	handlerAlive   uint32 = 0
	handlerDead    uint32 = 1
	numEventQueues int    = 15
)

var (
	podType            reflect.Type = reflect.TypeOf(&kapi.Pod{})
	serviceType        reflect.Type = reflect.TypeOf(&kapi.Service{})
	endpointsType      reflect.Type = reflect.TypeOf(&kapi.Endpoints{})
	policyType         reflect.Type = reflect.TypeOf(&knet.NetworkPolicy{})
	namespaceType      reflect.Type = reflect.TypeOf(&kapi.Namespace{})
	nodeType           reflect.Type = reflect.TypeOf(&kapi.Node{})
	egressFirewallType reflect.Type = reflect.TypeOf(&egressfirewallapi.EgressFirewall{})
	crdType            reflect.Type = reflect.TypeOf(&apiextensionsapi.CustomResourceDefinition{})
	egressIPType       reflect.Type = reflect.TypeOf(&egressipapi.EgressIP{})
)

// NewMasterWatchFactory initializes a new watch factory for the master or master+node processes.
func NewMasterWatchFactory(ovnClientset *util.OVNClientset) (*WatchFactory, error) {
	// resync time is 12 hours, none of the resources being watched in ovn-kubernetes have
	// any race condition where a resync may be required e.g. cni executable on node watching for
	// events on pods and assuming that an 'ADD' event will contain the annotations put in by
	// ovnkube master (currently, it is just a 'get' loop)
	// the downside of making it tight (like 10 minutes) is needless spinning on all resources
	// However, AddEventHandlerWithResyncPeriod can specify a per handler resync period
	wf := &WatchFactory{
		iFactory:    informerfactory.NewSharedInformerFactory(ovnClientset.KubeClient, resyncInterval),
		eipFactory:  egressipinformerfactory.NewSharedInformerFactory(ovnClientset.EgressIPClient, resyncInterval),
		efClientset: ovnClientset.EgressFirewallClient,
		crdFactory:  apiextensionsinformerfactory.NewSharedInformerFactory(ovnClientset.APIExtensionsClient, resyncInterval),
		informers:   make(map[reflect.Type]*informer),
		stopChan:    make(chan struct{}),
	}
	var err error

	err = apiextensionsapi.AddToScheme(apiextensionsscheme.Scheme)
	if err != nil {
		return nil, err
	}
	err = egressipapi.AddToScheme(egressipscheme.Scheme)
	if err != nil {
		return nil, err
	}

	// For Services and Endpoints, pre-populate the shared Informer with one that
	// has a label selector excluding headless services.
	wf.iFactory.InformerFor(&kapi.Service{}, func(c kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return v1coreinformers.NewFilteredServiceInformer(
			c,
			kapi.NamespaceAll,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			noAlternateProxySelector())
	})

	wf.iFactory.InformerFor(&kapi.Endpoints{}, func(c kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return v1coreinformers.NewFilteredEndpointsInformer(
			c,
			kapi.NamespaceAll,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			noHeadlessServiceSelector())
	})

	// Create our informer-wrapper informer (and underlying shared informer) for types we need
	wf.informers[podType], err = newQueuedInformer(podType, wf.iFactory.Core().V1().Pods().Informer(), wf.stopChan)
	if err != nil {
		return nil, err
	}
	wf.informers[serviceType], err = newInformer(serviceType, wf.iFactory.Core().V1().Services().Informer())
	if err != nil {
		return nil, err
	}
	wf.informers[endpointsType], err = newInformer(endpointsType, wf.iFactory.Core().V1().Endpoints().Informer())
	if err != nil {
		return nil, err
	}
	wf.informers[policyType], err = newInformer(policyType, wf.iFactory.Networking().V1().NetworkPolicies().Informer())
	if err != nil {
		return nil, err
	}
	wf.informers[namespaceType], err = newInformer(namespaceType, wf.iFactory.Core().V1().Namespaces().Informer())
	if err != nil {
		return nil, err
	}
	wf.informers[crdType], err = newInformer(crdType, wf.crdFactory.Apiextensions().V1beta1().CustomResourceDefinitions().Informer())
	if err != nil {
		return nil, err
	}
	wf.informers[nodeType], err = newQueuedInformer(nodeType, wf.iFactory.Core().V1().Nodes().Informer(), wf.stopChan)
	if err != nil {
		return nil, err
	}

	wf.crdFactory.Start(wf.stopChan)
	for oType, synced := range wf.crdFactory.WaitForCacheSync(wf.stopChan) {
		if !synced {
			return nil, fmt.Errorf("error in syncing cache for %v informer", oType)
		}
	}
	wf.iFactory.Start(wf.stopChan)
	for oType, synced := range wf.iFactory.WaitForCacheSync(wf.stopChan) {
		if !synced {
			return nil, fmt.Errorf("error in syncing cache for %v informer", oType)
		}
	}
	if config.OVNKubernetesFeature.EnableEgressIP {
		wf.informers[egressIPType], err = newInformer(egressIPType, wf.eipFactory.K8s().V1().EgressIPs().Informer())
		if err != nil {
			return nil, err
		}
		wf.eipFactory.Start(wf.stopChan)
		for oType, synced := range wf.eipFactory.WaitForCacheSync(wf.stopChan) {
			if !synced {
				return nil, fmt.Errorf("error in syncing cache for %v informer", oType)
			}
		}
	}
	return wf, nil
}

// NewNodeWatchFactory initializes a watch factory with significantly fewer
// informers to save memory + bandwidth. It is to be used by the node-only process.
func NewNodeWatchFactory(ovnClientset *util.OVNClientset, nodeName string) (*WatchFactory, error) {
	wf := &WatchFactory{
		iFactory:    informerfactory.NewSharedInformerFactory(ovnClientset.KubeClient, resyncInterval),
		eipFactory:  egressipinformerfactory.NewSharedInformerFactory(ovnClientset.EgressIPClient, resyncInterval),
		efClientset: ovnClientset.EgressFirewallClient,
		crdFactory:  apiextensionsinformerfactory.NewSharedInformerFactory(ovnClientset.APIExtensionsClient, resyncInterval),
		informers:   make(map[reflect.Type]*informer),
		stopChan:    make(chan struct{}),
	}
	// For Services and Endpoints, pre-populate the shared Informer with one that
	// has a label selector excluding headless services.
	wf.iFactory.InformerFor(&kapi.Service{}, func(c kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return v1coreinformers.NewFilteredServiceInformer(
			c,
			kapi.NamespaceAll,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			noAlternateProxySelector())
	})

	wf.iFactory.InformerFor(&kapi.Endpoints{}, func(c kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return v1coreinformers.NewFilteredEndpointsInformer(
			c,
			kapi.NamespaceAll,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			noHeadlessServiceSelector())
	})

	// For Pods, only select pods scheduled to this node
	wf.iFactory.InformerFor(&kapi.Pod{}, func(c kubernetes.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
		return v1coreinformers.NewFilteredPodInformer(
			c,
			kapi.NamespaceAll,
			resyncPeriod,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			func(opts *metav1.ListOptions) {
				opts.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", nodeName).String()
			})
	})

	var err error
	wf.informers[podType], err = newQueuedInformer(podType, wf.iFactory.Core().V1().Pods().Informer(), wf.stopChan)
	if err != nil {
		return nil, err
	}
	wf.informers[serviceType], err = newInformer(serviceType, wf.iFactory.Core().V1().Services().Informer())
	if err != nil {
		return nil, err
	}
	wf.informers[endpointsType], err = newInformer(endpointsType, wf.iFactory.Core().V1().Endpoints().Informer())
	if err != nil {
		return nil, err
	}

	if config.HybridOverlay.Enabled {
		wf.informers[nodeType], err = newInformer(nodeType, wf.iFactory.Core().V1().Nodes().Informer())
		if err != nil {
			return nil, err
		}
	}

	wf.iFactory.Start(wf.stopChan)
	for oType, synced := range wf.iFactory.WaitForCacheSync(wf.stopChan) {
		if !synced {
			return nil, fmt.Errorf("error in syncing cache for %v informer", oType)
		}
	}

	return wf, nil
}

func (wf *WatchFactory) InitializeEgressFirewallWatchFactory() error {
	err := egressfirewallapi.AddToScheme(egressfirewallscheme.Scheme)
	if err != nil {
		return err
	}
	wf.efFactory = egressfirewallinformerfactory.NewSharedInformerFactory(wf.efClientset, resyncInterval)
	wf.informers[egressFirewallType], err = newInformer(egressFirewallType, wf.efFactory.K8s().V1().EgressFirewalls().Informer())
	if err != nil {
		return err
	}
	wf.egressFirewallStopChan = make(chan struct{})
	wf.efFactory.Start(wf.egressFirewallStopChan)
	for oType, synced := range wf.efFactory.WaitForCacheSync(wf.egressFirewallStopChan) {
		if !synced {
			return fmt.Errorf("error in syncing cache for %v informer", oType)
		}
	}
	return nil
}

func (wf *WatchFactory) ShutdownEgressFirewallWatchFactory() {
	close(wf.egressFirewallStopChan)
	wf.informers[egressFirewallType].shutdown()
}

func (wf *WatchFactory) Shutdown() {
	close(wf.stopChan)

	// Remove all informer handlers
	for _, inf := range wf.informers {
		inf.shutdown()
	}
}

func getObjectMeta(objType reflect.Type, obj interface{}) (*metav1.ObjectMeta, error) {
	switch objType {
	case podType:
		if pod, ok := obj.(*kapi.Pod); ok {
			return &pod.ObjectMeta, nil
		}
	case serviceType:
		if service, ok := obj.(*kapi.Service); ok {
			return &service.ObjectMeta, nil
		}
	case endpointsType:
		if endpoints, ok := obj.(*kapi.Endpoints); ok {
			return &endpoints.ObjectMeta, nil
		}
	case policyType:
		if policy, ok := obj.(*knet.NetworkPolicy); ok {
			return &policy.ObjectMeta, nil
		}
	case namespaceType:
		if namespace, ok := obj.(*kapi.Namespace); ok {
			return &namespace.ObjectMeta, nil
		}
	case nodeType:
		if node, ok := obj.(*kapi.Node); ok {
			return &node.ObjectMeta, nil
		}
	case egressFirewallType:
		if egressFirewall, ok := obj.(*egressfirewallapi.EgressFirewall); ok {
			return &egressFirewall.ObjectMeta, nil
		}
	case egressIPType:
		if egressIP, ok := obj.(*egressipapi.EgressIP); ok {
			return &egressIP.ObjectMeta, nil
		}
	}
	return nil, fmt.Errorf("cannot get ObjectMeta from type %v", objType)
}

func (wf *WatchFactory) addHandler(objType reflect.Type, namespace string, sel labels.Selector, funcs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	inf, ok := wf.informers[objType]
	if !ok {
		klog.Fatalf("Tried to add handler of unknown object type %v", objType)
	}

	filterFunc := func(obj interface{}) bool {
		if namespace == "" && sel == nil {
			// Unfiltered handler
			return true
		}
		meta, err := getObjectMeta(objType, obj)
		if err != nil {
			klog.Errorf("Watch handler filter error: %v", err)
			return false
		}
		if namespace != "" && meta.Namespace != namespace {
			return false
		}
		if sel != nil && !sel.Matches(labels.Set(meta.Labels)) {
			return false
		}
		return true
	}

	inf.Lock()
	defer inf.Unlock()

	items := make([]interface{}, 0)
	for _, obj := range inf.inf.GetStore().List() {
		if filterFunc(obj) {
			items = append(items, obj)
		}
	}
	if processExisting != nil {
		// Process existing items as a set so the caller can clean up
		// after a restart or whatever
		processExisting(items)
	}

	handlerID := atomic.AddUint64(&wf.handlerCounter, 1)
	handler := inf.addHandler(handlerID, filterFunc, funcs, items)
	klog.V(5).Infof("Added %v event handler %d", objType, handler.id)
	return handler
}

func (wf *WatchFactory) removeHandler(objType reflect.Type, handler *Handler) {
	wf.informers[objType].removeHandler(handler)
}

// AddPodHandler adds a handler function that will be executed on Pod object changes
func (wf *WatchFactory) AddPodHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(podType, "", nil, handlerFuncs, processExisting)
}

// AddFilteredPodHandler adds a handler function that will be executed when Pod objects that match the given filters change
func (wf *WatchFactory) AddFilteredPodHandler(namespace string, sel labels.Selector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(podType, namespace, sel, handlerFuncs, processExisting)
}

// RemovePodHandler removes a Pod object event handler function
func (wf *WatchFactory) RemovePodHandler(handler *Handler) {
	wf.removeHandler(podType, handler)
}

// AddServiceHandler adds a handler function that will be executed on Service object changes
func (wf *WatchFactory) AddServiceHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(serviceType, "", nil, handlerFuncs, processExisting)
}

// AddFilteredServiceHandler adds a handler function that will be executed on all Service object changes for a specific namespace
func (wf *WatchFactory) AddFilteredServiceHandler(namespace string, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(serviceType, namespace, nil, handlerFuncs, processExisting)
}

// RemoveServiceHandler removes a Service object event handler function
func (wf *WatchFactory) RemoveServiceHandler(handler *Handler) {
	wf.removeHandler(serviceType, handler)
}

// AddEndpointsHandler adds a handler function that will be executed on Endpoints object changes
func (wf *WatchFactory) AddEndpointsHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(endpointsType, "", nil, handlerFuncs, processExisting)
}

// AddFilteredEndpointsHandler adds a handler function that will be executed when Endpoint objects that match the given filters change
func (wf *WatchFactory) AddFilteredEndpointsHandler(namespace string, sel labels.Selector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(endpointsType, namespace, sel, handlerFuncs, processExisting)
}

// RemoveEndpointsHandler removes a Endpoints object event handler function
func (wf *WatchFactory) RemoveEndpointsHandler(handler *Handler) {
	wf.removeHandler(endpointsType, handler)
}

// AddPolicyHandler adds a handler function that will be executed on NetworkPolicy object changes
func (wf *WatchFactory) AddPolicyHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(policyType, "", nil, handlerFuncs, processExisting)
}

// RemovePolicyHandler removes a NetworkPolicy object event handler function
func (wf *WatchFactory) RemovePolicyHandler(handler *Handler) {
	wf.removeHandler(policyType, handler)
}

// AddEgressFirewallHandler adds a handler function that will be executed on EgressFirewall object changes
func (wf *WatchFactory) AddEgressFirewallHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(egressFirewallType, "", nil, handlerFuncs, processExisting)
}

// RemoveEgressFirewallHandler removes an EgressFirewall object event handler function
func (wf *WatchFactory) RemoveEgressFirewallHandler(handler *Handler) {
	wf.removeHandler(egressFirewallType, handler)
}

// AddCRDHandler adds a handler function that will be executed on CRD obje changes
func (wf *WatchFactory) AddCRDHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(crdType, "", nil, handlerFuncs, processExisting)
}

// RemoveCRDHandler removes a CRD object event handler function
func (wf *WatchFactory) RemoveCRDHandler(handler *Handler) {
	wf.removeHandler(crdType, handler)
}

// AddEgressIPHandler adds a handler function that will be executed on EgressIP object changes
func (wf *WatchFactory) AddEgressIPHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(egressIPType, "", nil, handlerFuncs, processExisting)
}

// RemoveEgressIPHandler removes an EgressIP object event handler function
func (wf *WatchFactory) RemoveEgressIPHandler(handler *Handler) {
	wf.removeHandler(egressIPType, handler)
}

// AddNamespaceHandler adds a handler function that will be executed on Namespace object changes
func (wf *WatchFactory) AddNamespaceHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(namespaceType, "", nil, handlerFuncs, processExisting)
}

// AddFilteredNamespaceHandler adds a handler function that will be executed when Namespace objects that match the given filters change
func (wf *WatchFactory) AddFilteredNamespaceHandler(namespace string, sel labels.Selector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(namespaceType, namespace, sel, handlerFuncs, processExisting)
}

// RemoveNamespaceHandler removes a Namespace object event handler function
func (wf *WatchFactory) RemoveNamespaceHandler(handler *Handler) {
	wf.removeHandler(namespaceType, handler)
}

// AddNodeHandler adds a handler function that will be executed on Node object changes
func (wf *WatchFactory) AddNodeHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(nodeType, "", nil, handlerFuncs, processExisting)
}

// AddFilteredNodeHandler dds a handler function that will be executed when Node objects that match the given label selector
func (wf *WatchFactory) AddFilteredNodeHandler(sel labels.Selector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler {
	return wf.addHandler(nodeType, "", sel, handlerFuncs, processExisting)
}

// RemoveNodeHandler removes a Node object event handler function
func (wf *WatchFactory) RemoveNodeHandler(handler *Handler) {
	wf.removeHandler(nodeType, handler)
}

// GetPod returns the pod spec given the namespace and pod name
func (wf *WatchFactory) GetPod(namespace, name string) (*kapi.Pod, error) {
	podLister := wf.informers[podType].lister.(listers.PodLister)
	return podLister.Pods(namespace).Get(name)
}

// GetPods returns all the pods in a given namespace
func (wf *WatchFactory) GetPods(namespace string) ([]*kapi.Pod, error) {
	podLister := wf.informers[podType].lister.(listers.PodLister)
	return podLister.Pods(namespace).List(labels.Everything())
}

// GetNodes returns the node specs of all the nodes
func (wf *WatchFactory) GetNodes() ([]*kapi.Node, error) {
	nodeLister := wf.informers[nodeType].lister.(listers.NodeLister)
	return nodeLister.List(labels.Everything())
}

// GetNode returns the node spec of a given node by name
func (wf *WatchFactory) GetNode(name string) (*kapi.Node, error) {
	nodeLister := wf.informers[nodeType].lister.(listers.NodeLister)
	return nodeLister.Get(name)
}

// GetService returns the service spec of a service in a given namespace
func (wf *WatchFactory) GetService(namespace, name string) (*kapi.Service, error) {
	serviceLister := wf.informers[serviceType].lister.(listers.ServiceLister)
	return serviceLister.Services(namespace).Get(name)
}

// GetEndpoints returns the endpoints list in a given namespace
func (wf *WatchFactory) GetEndpoints(namespace string) ([]*kapi.Endpoints, error) {
	endpointsLister := wf.informers[endpointsType].lister.(listers.EndpointsLister)
	return endpointsLister.Endpoints(namespace).List(labels.Everything())
}

// GetEndpoint returns a specific endpoint in a given namespace
func (wf *WatchFactory) GetEndpoint(namespace, name string) (*kapi.Endpoints, error) {
	endpointsLister := wf.informers[endpointsType].lister.(listers.EndpointsLister)
	return endpointsLister.Endpoints(namespace).Get(name)
}

// GetNamespace returns a specific namespace
func (wf *WatchFactory) GetNamespace(name string) (*kapi.Namespace, error) {
	namespaceLister := wf.informers[namespaceType].lister.(listers.NamespaceLister)
	return namespaceLister.Get(name)
}

// GetNamespaces returns a list of namespaces in the cluster
func (wf *WatchFactory) GetNamespaces() ([]*kapi.Namespace, error) {
	namespaceLister := wf.informers[namespaceType].lister.(listers.NamespaceLister)
	return namespaceLister.List(labels.Everything())
}

func (wf *WatchFactory) NodeInformer() v1coreinformers.NodeInformer {
	return wf.iFactory.Core().V1().Nodes()
}

// LocalPodInformer returns a shared Informer that may or may not only
// return pods running on the local node.
func (wf *WatchFactory) LocalPodInformer() v1coreinformers.PodInformer {
	return wf.PodInformer()
}

func (wf *WatchFactory) PodInformer() v1coreinformers.PodInformer {
	return wf.iFactory.Core().V1().Pods()
}

func (wf *WatchFactory) NamespaceInformer() v1coreinformers.NamespaceInformer {
	return wf.iFactory.Core().V1().Namespaces()
}

func (wf *WatchFactory) ServiceInformer() v1coreinformers.ServiceInformer {
	return wf.iFactory.Core().V1().Services()
}

// noHeadlessServiceSelector is a LabelSelector added to the watch for
// Endpoints (and, eventually, EndpointSlices) that excludes endpoints
// for headless services.
// This matches the behavior of kube-proxy
func noHeadlessServiceSelector() func(options *metav1.ListOptions) {
	// if the service is headless, skip it
	noHeadlessEndpoints, err := labels.NewRequirement(v1.IsHeadlessService, selection.DoesNotExist, nil)
	if err != nil {
		// cannot occur
		panic(err)
	}

	labelSelector := labels.NewSelector().Add(*noHeadlessEndpoints)

	return func(options *metav1.ListOptions) {
		options.LabelSelector = labelSelector.String()
	}
}

// noAlternateProxySelector is a LabelSelector added to the watch for
// services that excludes services with a well-known label indicating
// proxying is via an alternate proxy.
// This matches the behavior of kube-proxy
func noAlternateProxySelector() func(options *metav1.ListOptions) {
	// if the proxy-name annotation is set, skip this service
	noProxyName, err := labels.NewRequirement("service.kubernetes.io/service-proxy-name", selection.DoesNotExist, nil)
	if err != nil {
		// cannot occur
		panic(err)
	}

	labelSelector := labels.NewSelector().Add(*noProxyName)

	return func(options *metav1.ListOptions) {
		options.LabelSelector = labelSelector.String()
	}
}
