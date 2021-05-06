package podset

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	v1 "k8s.io/api/core/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

const controllerName = "ovn-pod-set"
const maxRetries = 15

// PodSetController is a controller that maps selectors of pods to address sets.
// The primary use case is for network policies - NetworkPolicy pods and the peers
// to which it applies are implemented as AddressSets in ovn. This is controller
// is responsibile for ensuring the address sets in OVN match their selector.
//
// On startup, we'll re-build each set and apply it directly to the database;
// subsequent updates will be processed as deltas.
type PodSetController struct {
	podInformer coreinformers.PodInformer
	podLister   corelisters.PodLister
	podsSynced  cache.InformerSynced

	namespaceInformer coreinformers.NamespaceInformer
	namespaceLister   corelisters.NamespaceLister
	namespacesSynced  cache.InformerSynced

	queue workqueue.RateLimitingInterface

	podSetsLock sync.RWMutex

	// all podSets we know about
	podSets map[string]*PodSet

	// any podSets that are added before our informers are synced
	podSetsToSync map[string]interface{}
}

func NewController(
	podInformer coreinformers.PodInformer,
	namespaceInformer coreinformers.NamespaceInformer,
) *PodSetController {

	psc := &PodSetController{
		podInformer: podInformer,
		podLister:   podInformer.Lister(),
		podsSynced:  podInformer.Informer().HasSynced,

		namespaceInformer: namespaceInformer,
		namespaceLister:   namespaceInformer.Lister(),
		namespacesSynced:  namespaceInformer.Informer().HasSynced,

		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), controllerName),

		podSets:       map[string]*PodSet{},
		podSetsToSync: map[string]interface{}{},
	}
	return psc
}

// Run starts the PodSetController, which syncs the caches and applies any
// PodSets that were added during that time.
func (psc *PodSetController) Run(threadiness int, stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()
	defer psc.queue.ShutDown()

	klog.Infof("Starting controller %s", controllerName)
	defer klog.Infof("Shutting down controller %s", controllerName)

	psc.podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    psc.onPodAdd,
		UpdateFunc: psc.onPodUpdate,
		DeleteFunc: psc.onPodDelete,
	})
	psc.namespaceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    psc.onNamespaceAdd,
		UpdateFunc: psc.onNamespaceUpdate,
		DeleteFunc: psc.onNamespaceDelete,
	})

	// Wait for the caches to be synced
	klog.Info("Waiting for informer caches to sync")
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, psc.podsSynced, psc.namespacesSynced) {
		return fmt.Errorf("error syncing cache")
	}

	// sync any PodSets that arrived while we were waiting for informer sync
	go psc.syncPendingPodSets(stopCh)

	// begin processing
	klog.Info("PodSetController: Starting workers")
	for i := 0; i < threadiness; i++ {
		go wait.Until(psc.worker, time.Second, stopCh)
	}

	<-stopCh
	return nil
}

// syncPendingPodSets syncs any PodSets that arrived while we were waiting for
// our informers to sync
func (psc *PodSetController) syncPendingPodSets(stopCh <-chan struct{}) {
	// cute: even though we're deleting from podSetsToSync, nothing will
	// add to it, since by the time this function is called, the informers are synced
	// and any new PodSets will be synced directly.
	psc.podSetsLock.RLock()
	defer psc.podSetsLock.RUnlock()

	first := true
	for len(psc.podSetsToSync) > 0 {
		klog.Infof("Syncing %d pending PodSets", len(psc.podSetsToSync))
		if !first {
			time.Sleep(10 * time.Second)
		}
		for psname := range psc.podSetsToSync {
			if err := psc.syncPodSet(psc.podSets[psname]); err != nil {
				klog.Errorf("Failed to sync PodSet %s (will retry): %v", psname, err)
			} else {
				delete(psc.podSetsToSync, psname)
			}

			// abort if asked to stop
			select {
			case <-stopCh:
				return
			default:
			}
		}
	}

	klog.Infof("Done syncing all pending PodSets")
}

// worker runs a worker thread that just dequeues items, processes them, and
// marks them done. You may run as many of these in parallel as you wish; the
// workqueue guarantees that they will not end up processing the same namespace or pod
// at the same time.
func (psc *PodSetController) worker() {
	for psc.processNextWorkItem() {
	}
}

func (psc *PodSetController) processNextWorkItem() bool {
	eKey, quit := psc.queue.Get()
	if quit {
		klog.V(5).Infof("PodSetController: stopping worker")
		return false
	}
	defer psc.queue.Done(eKey)
	key := eKey.(string)
	klog.V(5).Infof("PodSetController: processing key %s", key)

	// split & validate key
	invalidKey := false

	kind := ""
	namespace := ""
	name := ""

	parts := strings.Split(key, "/")
	if len(parts) < 2 {
		invalidKey = true
	}
	kind = parts[0]
	switch kind {
	case "Namespace":
		if len(parts) != 2 {
			invalidKey = true
		}
		name = parts[1]
	case "Pod":
		if len(parts) != 3 {
			invalidKey = true
		}
		namespace = parts[1]
		name = parts[2]
	default:
		invalidKey = true
	}

	if invalidKey {
		psc.queue.Forget(key)
		klog.Errorf("PodSetController: invalid key: %s", eKey)
		return true
	}

	var err error

	switch parts[0] {
	case "Namespace":
		klog.V(5).InfoS("PodSet: processing namespace update", "obj", klog.KRef("", name))
		err = psc.processNamespace(name)
	case "Pod":
		klog.V(5).InfoS("PodSet: processing pod update", "obj", klog.KRef(namespace, name))
		err = psc.processPod(namespace, name)
	default:
		panic("unreachable")
	}

	if err == nil {
		psc.queue.Forget(key)
		return true
	}

	if psc.queue.NumRequeues(key) < maxRetries {
		klog.V(2).InfoS("PodSetController: error syncing, retrying", "kind", kind, "obj", klog.KRef(namespace, name), "err", err)
		psc.queue.AddRateLimited(key)
	} else {
		klog.Warningf("Dropping %q out of the queue: %v", key, err)
		psc.queue.Forget(key)
	}
	utilruntime.HandleError(err)
	return true
}

func (psc *PodSetController) processPod(namespace, name string) error {
	pod, err := psc.podLister.Pods(namespace).Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return psc.handlePodDelete(namespace, name)
		}

		return err
	}

	return psc.handlePodUpdate(pod)
}

func (psc *PodSetController) processNamespace(name string) error {
	ns, err := psc.namespaceLister.Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return psc.handleNamespaceDelete(name)
		}
		return err
	}
	return psc.handleNamespaceUpdate(ns)
}

// AddPodSet adds an automatically-updating address set, based on one or
// more selectors. This function is synchronous; it will block until the address set
// is updated in nbdb.
func (psc *PodSetController) AddPodSet(name string,
	addressSet addressset.AddressSet,
	selectors []Selector,
) error {
	psc.podSetsLock.Lock()
	defer psc.podSetsLock.Unlock()

	for _, selector := range selectors {
		if selector.PodSelector == nil {
			selector.PodSelector = labels.Everything()
		}

		if selector.NamespaceName == "" && selector.NamespaceSelector == nil {
			// coding error, should never happen
			panic("PodSet without namespace name or selector")
		}
	}

	if len(selectors) == 0 {
		klog.V(2).Infof("BUG: AddPodSet %s called with no selectors", name)
		return nil
	}

	psc.podSets[name] = &PodSet{
		name:       name,
		addressSet: addressSet,

		selectors: selectors,
	}

	klog.V(5).Infof("Adding PodSet %+v", psc.podSets[name])

	// If the informers are still syncing, add this to the queue of
	// pending podsets and exit.
	if !(psc.podsSynced() && psc.namespacesSynced()) {
		psc.podSetsToSync[name] = nil
		return nil
	}

	return psc.syncPodSet(psc.podSets[name])
}

func (psc *PodSetController) RemovePodSet(name string) {
	psc.podSetsLock.Lock()
	defer psc.podSetsLock.Unlock()

	delete(psc.podSets, name)
}

// informer functions here

func (psc *PodSetController) onPodAdd(obj interface{}) {
	psc.enqueuePod(obj)
}

func (psc *PodSetController) onPodUpdate(old, new interface{}) {
	oldPod := old.(*v1.Pod)
	newPod := new.(*v1.Pod)

	if shouldSkipPodUpdate(oldPod, newPod) {
		return
	}
	psc.enqueuePod(new)
}

func (psc *PodSetController) onPodDelete(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		pod, ok = tombstone.Obj.(*v1.Pod)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a Pod %#v", obj))
			return
		}
	}
	psc.enqueuePod(pod)
}

func (psc *PodSetController) enqueuePod(obj interface{}) {
	m, err := meta.Accessor(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %+v: %v", obj, err))
		return
	}
	key := "Pod/" + m.GetNamespace() + "/" + m.GetName()
	psc.queue.Add(key)
}

func (psc *PodSetController) onNamespaceAdd(obj interface{}) {
	psc.enqueueNamespace(obj)
}

func (psc *PodSetController) onNamespaceUpdate(old, new interface{}) {
	oldNS := old.(*v1.Namespace)
	newNS := new.(*v1.Namespace)

	if shouldSkipNamespaceUpdate(oldNS, newNS) {
		return
	}
	psc.enqueueNamespace(new)
}

func (psc *PodSetController) onNamespaceDelete(obj interface{}) {
	ns, ok := obj.(*v1.Namespace)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		ns, ok = tombstone.Obj.(*v1.Namespace)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a Namespace: %#v", obj))
			return
		}
	}
	psc.enqueueNamespace(ns)
}

func (psc *PodSetController) enqueueNamespace(obj interface{}) {
	m, err := meta.Accessor(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %+v: %v", obj, err))
		return
	}
	key := "Namespace/" + m.GetName()
	psc.queue.Add(key)
}

// shouldSkipPodUpdate returns true if we don't care about a particular
// pod change. Specifically, if the labels and ips are the same, then
// there's nothing to do.
func shouldSkipPodUpdate(old, new *v1.Pod) bool {
	if old == nil {
		return false
	}

	oldIPs, _ := util.GetAllPodIPs(old)
	newIPs, _ := util.GetAllPodIPs(new)

	// Ignore pods with no IPs
	// This assumes pods don't go "backwards" and lose their IPs
	if len(newIPs) == 0 {
		return true
	}

	return reflect.DeepEqual(oldIPs, newIPs) && reflect.DeepEqual(old.Labels, new.Labels)
}

// shouldSkipNamespaceUpdate returns true if we don't care about a particular
// namespace update. Specifically, if the labels are the same,
// there's nothing to do.
func shouldSkipNamespaceUpdate(old, new *v1.Namespace) bool {
	if old == nil {
		return false
	}

	return reflect.DeepEqual(old.Labels, new.Labels)
}
