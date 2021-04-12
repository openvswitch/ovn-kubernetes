package factory

import (
	"fmt"
	"hash/fnv"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"

	egressfirewalllister "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/listers/egressfirewall/v1"
	nodednsinfolister "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/nodednsinfo/v1/apis/listers/nodednsinfo/v1"

	egressiplister "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/listers/egressip/v1"
	apiextensionslister "k8s.io/apiextensions-apiserver/pkg/client/listers/apiextensions/v1"

	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// Handler represents an event handler and is private to the factory module
type Handler struct {
	base cache.FilteringResourceEventHandler

	id uint64
	// tombstone is used to track the handler's lifetime. handlerAlive
	// indicates the handler can be called, while handlerDead indicates
	// it has been scheduled for removal and should not be called.
	// tombstone should only be set using atomic operations since it is
	// used from multiple goroutines.
	tombstone uint32
}

func (h *Handler) OnAdd(obj interface{}) {
	if atomic.LoadUint32(&h.tombstone) == handlerAlive {
		h.base.OnAdd(obj)
	}
}

func (h *Handler) OnUpdate(oldObj, newObj interface{}) {
	if atomic.LoadUint32(&h.tombstone) == handlerAlive {
		h.base.OnUpdate(oldObj, newObj)
	}
}

func (h *Handler) OnDelete(obj interface{}) {
	if atomic.LoadUint32(&h.tombstone) == handlerAlive {
		h.base.OnDelete(obj)
	}
}

func (h *Handler) kill() bool {
	return atomic.CompareAndSwapUint32(&h.tombstone, handlerAlive, handlerDead)
}

type event struct {
	obj     interface{}
	oldObj  interface{}
	process func(*event)
}

type listerInterface interface{}

type initialAddFn func(*Handler, []interface{})

type informer struct {
	sync.RWMutex
	oType    reflect.Type
	inf      cache.SharedIndexInformer
	handlers map[uint64]*Handler
	events   []chan *event
	lister   listerInterface
	// initialAddFunc will be called to deliver the initial list of objects
	// when a handler is added
	initialAddFunc initialAddFn
	shutdownWg     sync.WaitGroup
}

func (i *informer) forEachQueuedHandler(f func(h *Handler)) {
	i.RLock()
	curHandlers := make([]*Handler, 0, len(i.handlers))
	for _, handler := range i.handlers {
		curHandlers = append(curHandlers, handler)
	}
	i.RUnlock()

	for _, handler := range curHandlers {
		f(handler)
	}
}

func (i *informer) forEachHandler(obj interface{}, f func(h *Handler)) {
	i.RLock()
	defer i.RUnlock()

	objType := reflect.TypeOf(obj)
	if objType != i.oType {
		klog.Errorf("Object type %v did not match expected %v", objType, i.oType)
		return
	}

	for _, handler := range i.handlers {
		f(handler)
	}
}

func (i *informer) addHandler(id uint64, filterFunc func(obj interface{}) bool, funcs cache.ResourceEventHandler, existingItems []interface{}) *Handler {
	handler := &Handler{
		cache.FilteringResourceEventHandler{
			FilterFunc: filterFunc,
			Handler:    funcs,
		},
		id,
		handlerAlive,
	}

	// Send existing items to the handler's add function; informers usually
	// do this but since we share informers, it's long-since happened so
	// we must emulate that here
	i.initialAddFunc(handler, existingItems)

	i.handlers[id] = handler
	return handler
}

func (i *informer) removeHandler(handler *Handler) {
	if !handler.kill() {
		klog.Errorf("Removing already-removed %v event handler %d", i.oType, handler.id)
		return
	}

	klog.V(5).Infof("Sending %v event handler %d for removal", i.oType, handler.id)

	go func() {
		i.Lock()
		defer i.Unlock()
		if _, ok := i.handlers[handler.id]; ok {
			// Remove the handler
			delete(i.handlers, handler.id)
			klog.V(5).Infof("Removed %v event handler %d", i.oType, handler.id)
		} else {
			klog.Warningf("Tried to remove unknown object type %v event handler %d", i.oType, handler.id)
		}
	}()
}

func (i *informer) processEvents(events chan *event, stopChan <-chan struct{}) {
	defer i.shutdownWg.Done()
	for {
		select {
		case e, ok := <-events:
			if !ok {
				return
			}
			e.process(e)
		case <-stopChan:
			return
		}
	}
}

func getQueueNum(oType reflect.Type, obj interface{}) uint32 {
	meta, err := getObjectMeta(oType, obj)
	if err != nil {
		klog.Errorf("Object has no meta: %v", err)
		return 0
	}

	// Distribute the object to an event queue based on a hash of its
	// namespaced name, so that all events for a given object are
	// serialized in one queue.
	h := fnv.New32()
	if meta.Namespace != "" {
		_, _ = h.Write([]byte(meta.Namespace))
		_, _ = h.Write([]byte("/"))
	}
	_, _ = h.Write([]byte(meta.Name))
	return h.Sum32() % uint32(numEventQueues)
}

// enqueueEvent adds an event to the appropriate queue for the object
func (i *informer) enqueueEvent(oldObj, obj interface{}, processFunc func(*event)) {
	i.events[getQueueNum(i.oType, obj)] <- &event{
		obj:     obj,
		oldObj:  oldObj,
		process: processFunc,
	}
}

func ensureObjectOnDelete(obj interface{}, expectedType reflect.Type) (interface{}, error) {
	if expectedType == reflect.TypeOf(obj) {
		return obj, nil
	}
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		return nil, fmt.Errorf("couldn't get object from tombstone: %+v", obj)
	}
	obj = tombstone.Obj
	objType := reflect.TypeOf(obj)
	if expectedType != objType {
		return nil, fmt.Errorf("expected tombstone object resource type %v but got %v", expectedType, objType)
	}
	return obj, nil
}

func (i *informer) newFederatedQueuedHandler() cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			i.enqueueEvent(nil, obj, func(e *event) {
				i.forEachQueuedHandler(func(h *Handler) {
					h.OnAdd(e.obj)
				})
			})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			metrics.MetricResourceUpdateCount.WithLabelValues(i.oType.Elem().Name()).Inc()
			i.enqueueEvent(oldObj, newObj, func(e *event) {
				i.forEachQueuedHandler(func(h *Handler) {
					h.OnUpdate(e.oldObj, e.obj)
				})
			})
		},
		DeleteFunc: func(obj interface{}) {
			realObj, err := ensureObjectOnDelete(obj, i.oType)
			if err != nil {
				klog.Errorf(err.Error())
				return
			}
			i.enqueueEvent(nil, realObj, func(e *event) {
				i.forEachQueuedHandler(func(h *Handler) {
					h.OnDelete(e.obj)
				})
			})
		},
	}
}

func (i *informer) newFederatedHandler() cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			i.forEachHandler(obj, func(h *Handler) {
				h.OnAdd(obj)
			})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			name := i.oType.Elem().Name()
			metrics.MetricResourceUpdateCount.WithLabelValues(name).Inc()
			i.forEachHandler(newObj, func(h *Handler) {
				start := time.Now()
				h.OnUpdate(oldObj, newObj)
				metrics.MetricResourceUpdateLatency.WithLabelValues(name).Observe(time.Since(start).Seconds())
			})
		},
		DeleteFunc: func(obj interface{}) {
			realObj, err := ensureObjectOnDelete(obj, i.oType)
			if err != nil {
				klog.Errorf(err.Error())
				return
			}
			i.forEachHandler(realObj, func(h *Handler) {
				h.OnDelete(realObj)
			})
		},
	}
}

func (i *informer) removeAllHandlers() {
	i.Lock()
	defer i.Unlock()
	for _, handler := range i.handlers {
		i.removeHandler(handler)
	}
}

func (i *informer) shutdown() {
	i.removeAllHandlers()

	// Wait for all event processors to finish
	i.shutdownWg.Wait()
}

func newInformerLister(oType reflect.Type, sharedInformer cache.SharedIndexInformer) (listerInterface, error) {
	switch oType {
	case podType:
		return listers.NewPodLister(sharedInformer.GetIndexer()), nil
	case serviceType:
		return listers.NewServiceLister(sharedInformer.GetIndexer()), nil
	case endpointsType:
		return listers.NewEndpointsLister(sharedInformer.GetIndexer()), nil
	case namespaceType:
		return listers.NewNamespaceLister(sharedInformer.GetIndexer()), nil
	case nodeType:
		return listers.NewNodeLister(sharedInformer.GetIndexer()), nil
	case policyType:
		return nil, nil
	case egressFirewallType:
		return egressfirewalllister.NewEgressFirewallLister(sharedInformer.GetIndexer()), nil
	case crdType:
		return apiextensionslister.NewCustomResourceDefinitionLister(sharedInformer.GetIndexer()), nil
	case egressIPType:
		return egressiplister.NewEgressIPLister(sharedInformer.GetIndexer()), nil
	case nodeDNSInfoType:
		return nodednsinfolister.NewNodeDNSInfoLister(sharedInformer.GetIndexer()), nil
	}

	return nil, fmt.Errorf("cannot create lister from type %v", oType)
}

func newBaseInformer(oType reflect.Type, sharedInformer cache.SharedIndexInformer) (*informer, error) {
	lister, err := newInformerLister(oType, sharedInformer)
	if err != nil {
		klog.Errorf(err.Error())
		return nil, err
	}

	return &informer{
		oType:      oType,
		inf:        sharedInformer,
		lister:     lister,
		handlers:   make(map[uint64]*Handler),
		shutdownWg: sync.WaitGroup{},
	}, nil
}

func newInformer(oType reflect.Type, sharedInformer cache.SharedIndexInformer) (*informer, error) {
	i, err := newBaseInformer(oType, sharedInformer)
	if err != nil {
		return nil, err
	}
	i.initialAddFunc = func(h *Handler, items []interface{}) {
		for _, item := range items {
			h.OnAdd(item)
		}
	}
	i.inf.AddEventHandler(i.newFederatedHandler())
	return i, nil
}

func newQueuedInformer(oType reflect.Type, sharedInformer cache.SharedIndexInformer, stopChan chan struct{}) (*informer, error) {
	i, err := newBaseInformer(oType, sharedInformer)
	if err != nil {
		return nil, err
	}
	i.events = make([]chan *event, numEventQueues)
	i.shutdownWg.Add(len(i.events))
	for j := range i.events {
		i.events[j] = make(chan *event, 10)
		go i.processEvents(i.events[j], stopChan)
	}
	i.initialAddFunc = func(h *Handler, items []interface{}) {
		// Make a handler-specific channel array across which the
		// initial add events will be distributed. When a new handler
		// is added, only that handler should receive events for all
		// existing objects.
		adds := make([]chan interface{}, numEventQueues)
		queueWg := &sync.WaitGroup{}
		queueWg.Add(len(adds))
		for j := range adds {
			adds[j] = make(chan interface{}, 10)
			go func(addChan chan interface{}) {
				defer queueWg.Done()
				for {
					obj, ok := <-addChan
					if !ok {
						return
					}
					h.OnAdd(obj)
				}
			}(adds[j])
		}
		// Distribute the existing items into the handler-specific
		// channel array.
		for _, obj := range items {
			queueIdx := getQueueNum(i.oType, obj)
			adds[queueIdx] <- obj
		}
		// Close all the channels
		for j := range adds {
			close(adds[j])
		}
		// Wait until all the object additions have been processed
		queueWg.Wait()
	}
	i.inf.AddEventHandler(i.newFederatedQueuedHandler())
	return i, nil
}
