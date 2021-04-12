package factory

import (
	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"

	nodednsinfo "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/nodednsinfo/v1"
	apiextensionsapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// ObjectCacheInterface represents the exported methods for getting
// kubernetes resources from the informer cache
type ObjectCacheInterface interface {
	GetPod(namespace, name string) (*kapi.Pod, error)
	GetPods(namespace string) ([]*kapi.Pod, error)
	GetNodes() ([]*kapi.Node, error)
	GetNode(name string) (*kapi.Node, error)
	GetService(namespace, name string) (*kapi.Service, error)
	GetEndpoints(namespace string) ([]*kapi.Endpoints, error)
	GetEndpoint(namespace, name string) (*kapi.Endpoints, error)
	GetNamespace(name string) (*kapi.Namespace, error)
	GetNamespaces() ([]*kapi.Namespace, error)
}

// NodeWatchFactory is an interface that ensures node components only use informers available in a
// node context; under the hood, it's all the same watchFactory.
//
// If you add a new method here, make sure the underlying informer is started
// in factory.go NewNodeWatchFactory
type NodeWatchFactory interface {
	Shutdownable

	GetCRDS() ([]*apiextensionsapi.CustomResourceDefinition, error)
	GetNodeDNSInfo(name string) (*nodednsinfo.NodeDNSInfo, error)
	AddEgressFirewallHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler
	RemoveEgressFirewallHandler(handler *Handler)
	AddCRDHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler
	AddServiceHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler
	AddFilteredServiceHandler(namespace string, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler
	RemoveServiceHandler(handler *Handler)

	InitializeEgressFirewallWatchFactory() error

	AddEndpointsHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler
	AddFilteredEndpointsHandler(namespace string, sel labels.Selector, handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler
	RemoveEndpointsHandler(handler *Handler)

	AddPodHandler(handlerFuncs cache.ResourceEventHandler, processExisting func([]interface{})) *Handler
	RemovePodHandler(handler *Handler)

	NodeInformer() cache.SharedIndexInformer
	LocalPodInformer() cache.SharedIndexInformer
}

type Shutdownable interface {
	Shutdown()
}
