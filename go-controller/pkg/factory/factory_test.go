package factory

import (
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	v1 "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	core "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	egressfirewall "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	egressfirewallfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned/fake"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsfake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressip "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	egressipfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/fake"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

func TestFactory(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Watch Factory Suite")
}

func newObjectMeta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      name,
		UID:       types.UID(name),
		Namespace: namespace,
		Labels: map[string]string{
			"name": name,
		},
	}
}

func newPod(name, namespace string) *v1.Pod {
	return &v1.Pod{
		Status: v1.PodStatus{
			Phase: v1.PodRunning,
		},
		ObjectMeta: newObjectMeta(name, namespace),
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "containerName",
					Image: "containerImage",
				},
			},
			NodeName: "mynode",
		},
	}
}

func newNamespace(name string) *v1.Namespace {
	return &v1.Namespace{
		Status: v1.NamespaceStatus{
			Phase: v1.NamespaceActive,
		},
		ObjectMeta: newObjectMeta(name, name),
	}
}

func newNode(name string) *v1.Node {
	return &v1.Node{
		Status: v1.NodeStatus{
			Phase: v1.NodeRunning,
		},
		ObjectMeta: newObjectMeta(name, ""),
	}
}

func newPolicy(name, namespace string) *knet.NetworkPolicy {
	return &knet.NetworkPolicy{
		ObjectMeta: newObjectMeta(name, namespace),
	}
}

func newEndpoints(name, namespace string) *v1.Endpoints {
	return &v1.Endpoints{
		ObjectMeta: newObjectMeta(name, namespace),
	}
}

func newService(name, namespace string) *v1.Service {
	return &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			UID:       types.UID(name),
			Namespace: namespace,
			Labels: map[string]string{
				"name": name,
			},
		},
	}
}

func newEgressFirewall(name, namespace string) *egressfirewall.EgressFirewall {
	return &egressfirewall.EgressFirewall{
		ObjectMeta: newObjectMeta(name, namespace),
		Spec: egressfirewall.EgressFirewallSpec{
			[]egressfirewall.EgressFirewallRule{
				{
					Type: egressfirewall.EgressFirewallRuleAllow,
					To: egressfirewall.EgressFirewallDestination{
						CIDRSelector: "1.2.3.4/32",
					},
				},
			},
		},
	}
}

func newEgressIP(name, namespace string) *egressip.EgressIP {
	return &egressip.EgressIP{
		ObjectMeta: newObjectMeta(name, namespace),
		Spec: egressip.EgressIPSpec{
			EgressIPs: []string{
				"192.168.126.10",
			},
		},
	}

}

func newCRD(name, namespace string) *apiextensions.CustomResourceDefinition {
	return &apiextensions.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			UID:  types.UID(name),
			Labels: map[string]string{
				"name": name,
			},
		},
	}
}

func objSetup(c *fake.Clientset, objType string, listFn func(core.Action) (bool, runtime.Object, error)) *watch.FakeWatcher {
	w := watch.NewFake()
	c.AddWatchReactor(objType, core.DefaultWatchReactor(w, nil))
	c.AddReactor("list", objType, listFn)
	return w
}

func egressFirewallObjSetup(c *egressfirewallfake.Clientset, objType string, listFn func(core.Action) (bool, runtime.Object, error)) *watch.FakeWatcher {
	w := watch.NewFake()
	c.AddWatchReactor(objType, core.DefaultWatchReactor(w, nil))
	c.AddReactor("list", objType, listFn)
	return w
}

func crdObjSetup(c *apiextensionsfake.Clientset, objType string, listFn func(core.Action) (bool, runtime.Object, error)) *watch.FakeWatcher {
	w := watch.NewFake()
	c.AddWatchReactor(objType, core.DefaultWatchReactor(w, nil))
	c.AddReactor("list", objType, listFn)
	return w
}

func egressIPObjSetup(c *egressipfake.Clientset, objType string, listFn func(core.Action) (bool, runtime.Object, error)) *watch.FakeWatcher {
	w := watch.NewFake()
	c.AddWatchReactor(objType, core.DefaultWatchReactor(w, nil))
	c.AddReactor("list", objType, listFn)
	return w
}

type handlerCalls struct {
	added   int32
	updated int32
	deleted int32
}

func (c *handlerCalls) getAdded() int {
	return int(atomic.LoadInt32(&c.added))
}

func (c *handlerCalls) getUpdated() int {
	return int(atomic.LoadInt32(&c.updated))
}

func (c *handlerCalls) getDeleted() int {
	return int(atomic.LoadInt32(&c.deleted))
}

var _ = ginkgo.Describe("Watch Factory Operations", func() {
	var (
		ovnClientset                              *util.OVNClientset
		fakeClient                                *fake.Clientset
		egressIPFakeClient                        *egressipfake.Clientset
		egressFirewallFakeClient                  *egressfirewallfake.Clientset
		crdFakeClient                             *apiextensionsfake.Clientset
		podWatch, namespaceWatch, nodeWatch       *watch.FakeWatcher
		policyWatch, endpointsWatch, serviceWatch *watch.FakeWatcher
		egressFirewallWatch, crdWatch             *watch.FakeWatcher
		egressIPWatch                             *watch.FakeWatcher
		pods                                      []*v1.Pod
		namespaces                                []*v1.Namespace
		nodes                                     []*v1.Node
		policies                                  []*knet.NetworkPolicy
		endpoints                                 []*v1.Endpoints
		services                                  []*v1.Service
		egressIPs                                 []*egressip.EgressIP
		wf                                        *WatchFactory
		egressFirewalls                           []*egressfirewall.EgressFirewall
		crds                                      []*apiextensions.CustomResourceDefinition
		err                                       error
	)

	ginkgo.BeforeEach(func() {

		// Restore global default values before each testcase
		config.PrepareTestConfig()

		fakeClient = &fake.Clientset{}
		egressFirewallFakeClient = &egressfirewallfake.Clientset{}
		crdFakeClient = &apiextensionsfake.Clientset{}
		egressIPFakeClient = &egressipfake.Clientset{}

		ovnClientset = &util.OVNClientset{
			KubeClient:           fakeClient,
			EgressIPClient:       egressIPFakeClient,
			EgressFirewallClient: egressFirewallFakeClient,
			APIExtensionsClient:  crdFakeClient,
		}

		pods = make([]*v1.Pod, 0)
		podWatch = objSetup(fakeClient, "pods", func(core.Action) (bool, runtime.Object, error) {
			obj := &v1.PodList{}
			for _, p := range pods {
				obj.Items = append(obj.Items, *p)
			}
			return true, obj, nil
		})

		namespaces = make([]*v1.Namespace, 0)
		namespaceWatch = objSetup(fakeClient, "namespaces", func(core.Action) (bool, runtime.Object, error) {
			obj := &v1.NamespaceList{}
			for _, p := range namespaces {
				obj.Items = append(obj.Items, *p)
			}
			return true, obj, nil
		})

		nodes = make([]*v1.Node, 0)
		nodeWatch = objSetup(fakeClient, "nodes", func(core.Action) (bool, runtime.Object, error) {
			obj := &v1.NodeList{}
			for _, p := range nodes {
				obj.Items = append(obj.Items, *p)
			}
			return true, obj, nil
		})

		policies = make([]*knet.NetworkPolicy, 0)
		policyWatch = objSetup(fakeClient, "networkpolicies", func(core.Action) (bool, runtime.Object, error) {
			obj := &knet.NetworkPolicyList{}
			for _, p := range policies {
				obj.Items = append(obj.Items, *p)
			}
			return true, obj, nil
		})

		endpoints = make([]*v1.Endpoints, 0)
		endpointsWatch = objSetup(fakeClient, "endpoints", func(core.Action) (bool, runtime.Object, error) {
			obj := &v1.EndpointsList{}
			for _, p := range endpoints {
				obj.Items = append(obj.Items, *p)
			}
			return true, obj, nil
		})

		services = make([]*v1.Service, 0)
		serviceWatch = objSetup(fakeClient, "services", func(core.Action) (bool, runtime.Object, error) {
			obj := &v1.ServiceList{}
			for _, p := range services {
				obj.Items = append(obj.Items, *p)
			}
			return true, obj, nil
		})

		egressFirewalls = make([]*egressfirewall.EgressFirewall, 0)
		egressFirewallWatch = egressFirewallObjSetup(egressFirewallFakeClient, "egressfirewalls", func(core.Action) (bool, runtime.Object, error) {
			obj := &egressfirewall.EgressFirewallList{}
			for _, p := range egressFirewalls {
				obj.Items = append(obj.Items, *p)
			}
			return true, obj, nil
		})

		crds = make([]*apiextensions.CustomResourceDefinition, 0)
		crdWatch = crdObjSetup(crdFakeClient, "customresourcedefinitions", func(core.Action) (bool, runtime.Object, error) {
			obj := &apiextensions.CustomResourceDefinitionList{}
			for _, p := range crds {
				obj.Items = append(obj.Items, *p)
			}
			return true, obj, nil
		})

		egressIPs = make([]*egressip.EgressIP, 0)
		egressIPWatch = egressIPObjSetup(egressIPFakeClient, "egressips", func(core.Action) (bool, runtime.Object, error) {
			obj := &egressip.EgressIPList{}
			for _, p := range egressIPs {
				obj.Items = append(obj.Items, *p)
			}
			return true, obj, nil
		})
	})

	ginkgo.AfterEach(func() {
		wf.Shutdown()
		if wf.efFactory != nil {
			wf.ShutdownEgressFirewallWatchFactory()
		}
	})

	ginkgo.Context("when a processExisting is given", func() {
		testExisting := func(objType reflect.Type, namespace string, sel labels.Selector) {
			wf, err = NewMasterWatchFactory(ovnClientset)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			err = wf.InitializeEgressFirewallWatchFactory()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			h := wf.addHandler(objType, namespace, sel,
				cache.ResourceEventHandlerFuncs{},
				func(objs []interface{}) {
					defer ginkgo.GinkgoRecover()
					gomega.Expect(len(objs)).To(gomega.Equal(1))
				})
			gomega.Expect(h).NotTo(gomega.BeNil())
			wf.removeHandler(objType, h)
		}

		ginkgo.It("is called for each existing pod", func() {
			pods = append(pods, newPod("pod1", "default"))
			testExisting(podType, "", nil)
		})

		ginkgo.It("is called for each existing namespace", func() {
			namespaces = append(namespaces, newNamespace("default"))
			testExisting(namespaceType, "", nil)
		})

		ginkgo.It("is called for each existing node", func() {
			nodes = append(nodes, newNode("default"))
			testExisting(nodeType, "", nil)
		})

		ginkgo.It("is called for each existing policy", func() {
			policies = append(policies, newPolicy("denyall", "default"))
			testExisting(policyType, "", nil)
		})

		ginkgo.It("is called for each existing endpoints", func() {
			endpoints = append(endpoints, newEndpoints("myendpoint", "default"))
			testExisting(endpointsType, "", nil)
		})

		ginkgo.It("is called for each existing service", func() {
			services = append(services, newService("myservice", "default"))
			testExisting(serviceType, "", nil)
		})

		ginkgo.It("is called for each existing egressFirewall", func() {
			egressFirewalls = append(egressFirewalls, newEgressFirewall("myEgressFirewall", "default"))
			testExisting(egressFirewallType, "", nil)
		})
		ginkgo.It("is called for each existing CRDS", func() {
			crds = append(crds, newCRD("myCRD", ""))
			testExisting(crdType, "", nil)
		})
		ginkgo.It("is called for each existing egressIP", func() {
			egressIPs = append(egressIPs, newEgressIP("myEgressIP", "default"))
			testExisting(egressIPType, "", nil)
		})

		ginkgo.It("is called for each existing pod that matches a given namespace and label", func() {
			pod := newPod("pod1", "default")
			pod.ObjectMeta.Labels["blah"] = "foobar"
			pods = append(pods, pod)

			sel, err := metav1.LabelSelectorAsSelector(
				&metav1.LabelSelector{
					MatchLabels: map[string]string{"blah": "foobar"},
				},
			)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			testExisting(podType, "default", sel)
		})
	})

	ginkgo.Context("when existing items are known to the informer", func() {
		testExisting := func(objType reflect.Type) {
			wf, err = NewMasterWatchFactory(ovnClientset)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			err = wf.InitializeEgressFirewallWatchFactory()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			var addCalls int32
			h := wf.addHandler(objType, "", nil,
				cache.ResourceEventHandlerFuncs{
					AddFunc: func(obj interface{}) {
						atomic.AddInt32(&addCalls, 1)
					},
					UpdateFunc: func(old, new interface{}) {},
					DeleteFunc: func(obj interface{}) {},
				}, nil)
			gomega.Expect(int(addCalls)).To(gomega.Equal(2))
			wf.removeHandler(objType, h)
		}

		ginkgo.It("calls ADD for each existing pod", func() {
			pods = append(pods, newPod("pod1", "default"))
			pods = append(pods, newPod("pod2", "default"))
			testExisting(podType)
		})

		ginkgo.It("calls ADD for each existing namespace", func() {
			namespaces = append(namespaces, newNamespace("default"))
			namespaces = append(namespaces, newNamespace("default2"))
			testExisting(namespaceType)
		})

		ginkgo.It("calls ADD for each existing node", func() {
			nodes = append(nodes, newNode("default"))
			nodes = append(nodes, newNode("default2"))
			testExisting(nodeType)
		})

		ginkgo.It("calls ADD for each existing policy", func() {
			policies = append(policies, newPolicy("denyall", "default"))
			policies = append(policies, newPolicy("denyall2", "default"))
			testExisting(policyType)
		})

		ginkgo.It("calls ADD for each existing endpoints", func() {
			endpoints = append(endpoints, newEndpoints("myendpoint", "default"))
			endpoints = append(endpoints, newEndpoints("myendpoint2", "default"))
			testExisting(endpointsType)
		})

		ginkgo.It("calls ADD for each existing service", func() {
			services = append(services, newService("myservice", "default"))
			services = append(services, newService("myservice2", "default"))
			testExisting(serviceType)
		})
		ginkgo.It("calls ADD for each existing egressFirewall", func() {
			egressFirewalls = append(egressFirewalls, newEgressFirewall("myFirewall", "default"))
			egressFirewalls = append(egressFirewalls, newEgressFirewall("myFirewall1", "default"))
			testExisting(egressFirewallType)
		})
		ginkgo.It("calls ADD for each existing CRD", func() {
			crds = append(crds, newCRD("crd1", ""))
			crds = append(crds, newCRD("crd2", ""))
			testExisting(crdType)
		})
		ginkgo.It("calls ADD for each existing egressIP", func() {
			egressIPs = append(egressIPs, newEgressIP("myEgressIP", "default"))
			egressIPs = append(egressIPs, newEgressIP("myEgressIP1", "default"))
			testExisting(egressIPType)
		})
	})

	ginkgo.Context("when EgressIP is disabled", func() {
		testExisting := func(objType reflect.Type) {
			wf, err = NewMasterWatchFactory(ovnClientset)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(wf.informers).NotTo(gomega.HaveKey(objType))
		}
		ginkgo.It("does not contain Egress IP informer", func() {
			config.OVNKubernetesFeature.EnableEgressIP = false
			testExisting(egressIPType)
		})
	})

	addFilteredHandler := func(wf *WatchFactory, objType reflect.Type, namespace string, sel labels.Selector, funcs cache.ResourceEventHandlerFuncs) (*Handler, *handlerCalls) {
		calls := handlerCalls{}
		h := wf.addHandler(objType, namespace, sel, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				defer ginkgo.GinkgoRecover()
				atomic.AddInt32(&calls.added, 1)
				funcs.AddFunc(obj)
			},
			UpdateFunc: func(old, new interface{}) {
				defer ginkgo.GinkgoRecover()
				atomic.AddInt32(&calls.updated, 1)
				funcs.UpdateFunc(old, new)
			},
			DeleteFunc: func(obj interface{}) {
				defer ginkgo.GinkgoRecover()
				atomic.AddInt32(&calls.deleted, 1)
				funcs.DeleteFunc(obj)
			},
		}, nil)
		gomega.Expect(h).NotTo(gomega.BeNil())
		return h, &calls
	}

	addHandler := func(wf *WatchFactory, objType reflect.Type, funcs cache.ResourceEventHandlerFuncs) (*Handler, *handlerCalls) {
		return addFilteredHandler(wf, objType, "", nil, funcs)
	}

	ginkgo.It("responds to pod add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		added := newPod("pod1", "default")
		h, c := addHandler(wf, podType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				pod := obj.(*v1.Pod)
				gomega.Expect(reflect.DeepEqual(pod, added)).To(gomega.BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newPod := new.(*v1.Pod)
				gomega.Expect(reflect.DeepEqual(newPod, added)).To(gomega.BeTrue())
				gomega.Expect(newPod.Spec.NodeName).To(gomega.Equal("foobar"))
			},
			DeleteFunc: func(obj interface{}) {
				pod := obj.(*v1.Pod)
				gomega.Expect(reflect.DeepEqual(pod, added)).To(gomega.BeTrue())
			},
		})

		pods = append(pods, added)
		podWatch.Add(added)
		gomega.Eventually(c.getAdded, 2).Should(gomega.Equal(1))
		added.Spec.NodeName = "foobar"
		podWatch.Modify(added)
		gomega.Eventually(c.getUpdated, 2).Should(gomega.Equal(1))
		pods = pods[:0]
		podWatch.Delete(added)
		gomega.Eventually(c.getDeleted, 2).Should(gomega.Equal(1))

		wf.RemovePodHandler(h)
	})

	ginkgo.It("responds to multiple pod add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		const nodeName string = "mynode"
		type opTest struct {
			mu      sync.Mutex
			pod     *v1.Pod
			added   int
			updated int
			deleted int
		}
		testPods := make(map[string]*opTest)

		for i := 0; i < 5; i++ {
			name := fmt.Sprintf("mypod-%d", i)
			pod := newPod(name, fmt.Sprintf("namespace-%d", i))
			testPods[name] = &opTest{pod: pod}
		}

		h, c := addHandler(wf, podType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				pod := obj.(*v1.Pod)
				ot, ok := testPods[pod.Name]
				gomega.Expect(ok).To(gomega.BeTrue())
				ot.mu.Lock()
				defer ot.mu.Unlock()
				gomega.Expect(ot.added).To(gomega.BeNumerically("<", 2))
				ot.added++
			},
			UpdateFunc: func(old, new interface{}) {
				newPod := new.(*v1.Pod)
				ot, ok := testPods[newPod.Name]
				gomega.Expect(ok).To(gomega.BeTrue())
				ot.mu.Lock()
				defer ot.mu.Unlock()
				gomega.Expect(ot.updated).To(gomega.BeNumerically("<", 2))
				ot.updated++
				gomega.Expect(newPod.Spec.NodeName).To(gomega.Equal(nodeName))
			},
			DeleteFunc: func(obj interface{}) {
				pod := obj.(*v1.Pod)
				ot, ok := testPods[pod.Name]
				gomega.Expect(ok).To(gomega.BeTrue())
				ot.mu.Lock()
				defer ot.mu.Unlock()
				gomega.Expect(ot.deleted).To(gomega.BeNumerically("<", 2))
				ot.deleted++
			},
		})

		// Add/Update/Delete each pod twice
		for i := 0; i < 2; i++ {
			for _, ot := range testPods {
				pods = append(pods, ot.pod)
				podWatch.Add(ot.pod)
				ot.mu.Lock()
				ot.pod.Spec.NodeName = nodeName
				ot.mu.Unlock()
				podWatch.Modify(ot.pod)
				pods = pods[:0]
				podWatch.Delete(ot.pod)
			}
		}

		// Ensure total number of each operation is 10; and each
		// node's individual operation count is 2
		gomega.Eventually(c.getAdded, 2).Should(gomega.Equal(10))
		gomega.Eventually(c.getUpdated, 2).Should(gomega.Equal(10))
		gomega.Eventually(c.getDeleted, 2).Should(gomega.Equal(10))
		for _, ot := range testPods {
			ot.mu.Lock()
			gomega.Expect(ot.added).Should(gomega.Equal(2))
			gomega.Expect(ot.updated).Should(gomega.Equal(2))
			gomega.Expect(ot.deleted).Should(gomega.Equal(2))
			ot.mu.Unlock()
		}

		wf.RemovePodHandler(h)
	})

	ginkgo.It("responds to namespace add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		added := newNamespace("default")
		h, c := addHandler(wf, namespaceType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				ns := obj.(*v1.Namespace)
				gomega.Expect(reflect.DeepEqual(ns, added)).To(gomega.BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newNS := new.(*v1.Namespace)
				gomega.Expect(reflect.DeepEqual(newNS, added)).To(gomega.BeTrue())
				gomega.Expect(newNS.Status.Phase).To(gomega.Equal(v1.NamespaceTerminating))
			},
			DeleteFunc: func(obj interface{}) {
				ns := obj.(*v1.Namespace)
				gomega.Expect(reflect.DeepEqual(ns, added)).To(gomega.BeTrue())
			},
		})

		namespaces = append(namespaces, added)
		namespaceWatch.Add(added)
		gomega.Eventually(c.getAdded, 2).Should(gomega.Equal(1))
		added.Status.Phase = v1.NamespaceTerminating
		namespaceWatch.Modify(added)
		gomega.Eventually(c.getUpdated, 2).Should(gomega.Equal(1))
		namespaces = namespaces[:0]
		namespaceWatch.Delete(added)
		gomega.Eventually(c.getDeleted, 2).Should(gomega.Equal(1))

		wf.RemoveNamespaceHandler(h)
	})

	ginkgo.It("responds to node add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		added := newNode("mynode")
		h, c := addHandler(wf, nodeType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				node := obj.(*v1.Node)
				gomega.Expect(reflect.DeepEqual(node, added)).To(gomega.BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newNode := new.(*v1.Node)
				gomega.Expect(reflect.DeepEqual(newNode, added)).To(gomega.BeTrue())
				gomega.Expect(newNode.Status.Phase).To(gomega.Equal(v1.NodeTerminated))
			},
			DeleteFunc: func(obj interface{}) {
				node := obj.(*v1.Node)
				gomega.Expect(reflect.DeepEqual(node, added)).To(gomega.BeTrue())
			},
		})

		nodes = append(nodes, added)
		nodeWatch.Add(added)
		gomega.Eventually(c.getAdded, 2).Should(gomega.Equal(1))
		added.Status.Phase = v1.NodeTerminated
		nodeWatch.Modify(added)
		gomega.Eventually(c.getUpdated, 2).Should(gomega.Equal(1))
		nodes = nodes[:0]
		nodeWatch.Delete(added)
		gomega.Eventually(c.getDeleted, 2).Should(gomega.Equal(1))

		wf.RemoveNodeHandler(h)
	})

	ginkgo.It("responds to multiple node add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		type opTest struct {
			mu      sync.Mutex
			node    *v1.Node
			added   int
			updated int
			deleted int
		}
		testNodes := make(map[string]*opTest)

		for i := 0; i < 5; i++ {
			name := fmt.Sprintf("mynode-%d", i)
			node := newNode(name)
			testNodes[name] = &opTest{node: node}
		}

		h, c := addHandler(wf, nodeType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				node := obj.(*v1.Node)
				ot, ok := testNodes[node.Name]
				gomega.Expect(ok).To(gomega.BeTrue())
				ot.mu.Lock()
				defer ot.mu.Unlock()
				gomega.Expect(ot.added).To(gomega.BeNumerically("<", 2))
				ot.added++
			},
			UpdateFunc: func(old, new interface{}) {
				newNode := new.(*v1.Node)
				ot, ok := testNodes[newNode.Name]
				gomega.Expect(ok).To(gomega.BeTrue())
				ot.mu.Lock()
				defer ot.mu.Unlock()
				gomega.Expect(ot.updated).To(gomega.BeNumerically("<", 2))
				ot.updated++
				gomega.Expect(newNode.Status.Phase).To(gomega.Equal(v1.NodeTerminated))
			},
			DeleteFunc: func(obj interface{}) {
				node := obj.(*v1.Node)
				ot, ok := testNodes[node.Name]
				gomega.Expect(ok).To(gomega.BeTrue())
				ot.mu.Lock()
				gomega.Expect(ot.deleted).To(gomega.BeNumerically("<", 2))
				ot.deleted++
				ot.mu.Unlock()
			},
		})

		// Add/Update/Delete each node twice
		for i := 0; i < 2; i++ {
			for _, ot := range testNodes {
				nodes = append(nodes, ot.node)
				nodeWatch.Add(ot.node)
				ot.mu.Lock()
				ot.node.Status.Phase = v1.NodeTerminated
				ot.mu.Unlock()
				nodeWatch.Modify(ot.node)
				nodes = nodes[:0]
				nodeWatch.Delete(ot.node)
			}
		}

		// Ensure total number of each operation is 10; and each
		// node's individual operation count is 2
		gomega.Eventually(c.getAdded, 2).Should(gomega.Equal(10))
		gomega.Eventually(c.getUpdated, 2).Should(gomega.Equal(10))
		gomega.Eventually(c.getDeleted, 2).Should(gomega.Equal(10))
		for _, ot := range testNodes {
			ot.mu.Lock()
			gomega.Expect(ot.added).Should(gomega.Equal(2))
			gomega.Expect(ot.updated).Should(gomega.Equal(2))
			gomega.Expect(ot.deleted).Should(gomega.Equal(2))
			ot.mu.Unlock()
		}

		wf.RemoveNodeHandler(h)
	})

	ginkgo.It("correctly orders queued informer initial add events and subsequent update events", func() {
		type opTest struct {
			mu      sync.Mutex
			node    *v1.Node
			added   int
			updated int
		}
		testNodes := make(map[string]*opTest)

		for i := 0; i < 600; i++ {
			name := fmt.Sprintf("mynode-%d", i)
			node := newNode(name)
			testNodes[name] = &opTest{node: node}
			// Add all nodes to the initial list
			nodes = append(nodes, node)
		}

		wf, err = NewMasterWatchFactory(ovnClientset)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		startWg := sync.WaitGroup{}
		startWg.Add(1)
		doneWg := sync.WaitGroup{}
		doneWg.Add(1)
		go func() {
			startWg.Done()
			// Send an update event for each node
			for _, n := range nodes {
				n.Status.Phase = v1.NodeTerminated
				nodeWatch.Modify(n)
			}
			doneWg.Done()
		}()
		startWg.Wait()

		h, c := addHandler(wf, nodeType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				defer ginkgo.GinkgoRecover()
				node := obj.(*v1.Node)
				ot, ok := testNodes[node.Name]
				gomega.Expect(ok).To(gomega.BeTrue())
				ot.mu.Lock()
				defer ot.mu.Unlock()
				gomega.Expect(ot.added).To(gomega.Equal(0), "add for node %s already run", node.Name)
				ot.added++
			},
			UpdateFunc: func(old, new interface{}) {
				defer ginkgo.GinkgoRecover()
				newNode := new.(*v1.Node)
				ot, ok := testNodes[newNode.Name]
				gomega.Expect(ok).To(gomega.BeTrue())
				// Expect updates to be processed after Add
				ot.mu.Lock()
				defer ot.mu.Unlock()
				gomega.Expect(ot.added).To(gomega.Equal(1), "update for node %s processed before initial add!", newNode.Name)
				gomega.Expect(ot.updated).To(gomega.Equal(0))
				ot.updated++
				gomega.Expect(newNode.Status.Phase).To(gomega.Equal(v1.NodeTerminated))
			},
			DeleteFunc: func(obj interface{}) {},
		})
		doneWg.Wait()

		// Adds are done synchronously at handler addition time
		for _, ot := range testNodes {
			ot.mu.Lock()
			gomega.Expect(ot.added).To(gomega.Equal(1), "missing add for node %s", ot.node.Name)
			ot.mu.Unlock()
		}
		gomega.Expect(c.getAdded()).To(gomega.Equal(len(testNodes)))

		// Updates are async and may take a bit longer to finish
		gomega.Eventually(c.getUpdated, 10).Should(gomega.Equal(len(testNodes)))
		for _, ot := range testNodes {
			ot.mu.Lock()
			gomega.Expect(ot.updated).To(gomega.Equal(1), "missing update for node %s", ot.node.Name)
			ot.mu.Unlock()
		}

		wf.RemoveNodeHandler(h)
	})

	ginkgo.It("correctly orders serialized informer initial add events and subsequent update events", func() {
		type opTest struct {
			mu        sync.Mutex
			namespace *v1.Namespace
			added     int
			updated   int
		}
		testNamespaces := make(map[string]*opTest)

		for i := 0; i < 598; i++ {
			name := fmt.Sprintf("mynamespace-%d", i)
			namespace := newNamespace(name)
			testNamespaces[name] = &opTest{namespace: namespace}
			// Add all namespaces to the initial list
			namespaces = append(namespaces, namespace)
		}

		wf, err = NewMasterWatchFactory(ovnClientset)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		startWg := sync.WaitGroup{}
		startWg.Add(1)
		doneWg := sync.WaitGroup{}
		doneWg.Add(1)
		go func() {
			startWg.Done()
			// Send an update event for each namespace
			for _, n := range namespaces {
				n.Status.Phase = v1.NamespaceTerminating
				namespaceWatch.Modify(n)
			}
			doneWg.Done()
		}()
		startWg.Wait()

		h, c := addHandler(wf, namespaceType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				defer ginkgo.GinkgoRecover()
				namespace := obj.(*v1.Namespace)
				ot, ok := testNamespaces[namespace.Name]
				gomega.Expect(ok).To(gomega.BeTrue())
				ot.mu.Lock()
				defer ot.mu.Unlock()
				gomega.Expect(ot.added).To(gomega.Equal(0))
				ot.added++
			},
			UpdateFunc: func(old, new interface{}) {
				defer ginkgo.GinkgoRecover()
				newNamespace := new.(*v1.Namespace)
				ot, ok := testNamespaces[newNamespace.Name]
				gomega.Expect(ok).To(gomega.BeTrue())
				// Expect updates to be processed after Add
				ot.mu.Lock()
				defer ot.mu.Unlock()
				gomega.Expect(ot.added).To(gomega.Equal(1), "update for namespace %s processed before initial add!", newNamespace.Name)
				gomega.Expect(ot.updated).To(gomega.Equal(0))
				ot.updated++
				gomega.Expect(newNamespace.Status.Phase).To(gomega.Equal(v1.NamespaceTerminating))
			},
			DeleteFunc: func(obj interface{}) {},
		})
		doneWg.Wait()

		// Adds are done synchronously at handler addition time
		for _, ot := range testNamespaces {
			ot.mu.Lock()
			gomega.Expect(ot.added).To(gomega.Equal(1), "missing add for namespace %s", ot.namespace.Name)
			ot.mu.Unlock()
		}
		gomega.Expect(c.getAdded()).To(gomega.Equal(len(testNamespaces)))

		// Updates are async and may take a bit longer to finish
		gomega.Eventually(c.getUpdated, 10).Should(gomega.Equal(len(testNamespaces)))
		for _, ot := range testNamespaces {
			ot.mu.Lock()
			gomega.Expect(ot.updated).To(gomega.Equal(1), "missing update for namespace %s", ot.namespace.Name)
			ot.mu.Unlock()
		}

		wf.RemoveNamespaceHandler(h)
	})

	ginkgo.It("responds to policy add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		added := newPolicy("mypolicy", "default")
		h, c := addHandler(wf, policyType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				np := obj.(*knet.NetworkPolicy)
				gomega.Expect(reflect.DeepEqual(np, added)).To(gomega.BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newNP := new.(*knet.NetworkPolicy)
				gomega.Expect(reflect.DeepEqual(newNP, added)).To(gomega.BeTrue())
				gomega.Expect(newNP.Spec.PolicyTypes).To(gomega.Equal([]knet.PolicyType{knet.PolicyTypeIngress}))
			},
			DeleteFunc: func(obj interface{}) {
				np := obj.(*knet.NetworkPolicy)
				gomega.Expect(reflect.DeepEqual(np, added)).To(gomega.BeTrue())
			},
		})

		policies = append(policies, added)
		policyWatch.Add(added)
		gomega.Eventually(c.getAdded, 2).Should(gomega.Equal(1))
		added.Spec.PolicyTypes = []knet.PolicyType{knet.PolicyTypeIngress}
		policyWatch.Modify(added)
		gomega.Eventually(c.getUpdated, 2).Should(gomega.Equal(1))
		policies = policies[:0]
		policyWatch.Delete(added)
		gomega.Eventually(c.getDeleted, 2).Should(gomega.Equal(1))

		wf.RemovePolicyHandler(h)
	})

	ginkgo.It("responds to endpoints add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		added := newEndpoints("myendpoints", "default")
		h, c := addHandler(wf, endpointsType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				eps := obj.(*v1.Endpoints)
				gomega.Expect(reflect.DeepEqual(eps, added)).To(gomega.BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newEPs := new.(*v1.Endpoints)
				gomega.Expect(reflect.DeepEqual(newEPs, added)).To(gomega.BeTrue())
				gomega.Expect(len(newEPs.Subsets)).To(gomega.Equal(1))
			},
			DeleteFunc: func(obj interface{}) {
				eps := obj.(*v1.Endpoints)
				gomega.Expect(reflect.DeepEqual(eps, added)).To(gomega.BeTrue())
			},
		})

		endpoints = append(endpoints, added)
		endpointsWatch.Add(added)
		gomega.Eventually(c.getAdded, 2).Should(gomega.Equal(1))
		added.Subsets = append(added.Subsets, v1.EndpointSubset{
			Ports: []v1.EndpointPort{
				{
					Name: "foobar",
					Port: 1234,
				},
			},
		})
		endpointsWatch.Modify(added)
		gomega.Eventually(c.getUpdated, 2).Should(gomega.Equal(1))
		endpoints = endpoints[:0]
		endpointsWatch.Delete(added)
		gomega.Eventually(c.getDeleted, 2).Should(gomega.Equal(1))

		wf.RemoveEndpointsHandler(h)
	})

	ginkgo.It("responds to service add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		added := newService("myservice", "default")
		h, c := addHandler(wf, serviceType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				service := obj.(*v1.Service)
				gomega.Expect(reflect.DeepEqual(service, added)).To(gomega.BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newService := new.(*v1.Service)
				gomega.Expect(reflect.DeepEqual(newService, added)).To(gomega.BeTrue())
				gomega.Expect(newService.Spec.ClusterIP).To(gomega.Equal("1.1.1.1"))
			},
			DeleteFunc: func(obj interface{}) {
				service := obj.(*v1.Service)
				gomega.Expect(reflect.DeepEqual(service, added)).To(gomega.BeTrue())
			},
		})

		services = append(services, added)
		serviceWatch.Add(added)
		gomega.Eventually(c.getAdded, 2).Should(gomega.Equal(1))
		added.Spec.ClusterIP = "1.1.1.1"
		serviceWatch.Modify(added)
		gomega.Eventually(c.getUpdated, 2).Should(gomega.Equal(1))
		services = services[:0]
		serviceWatch.Delete(added)
		gomega.Eventually(c.getDeleted, 2).Should(gomega.Equal(1))

		wf.RemoveServiceHandler(h)
	})

	ginkgo.It("responds to egressFirewall add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		err = wf.InitializeEgressFirewallWatchFactory()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		added := newEgressFirewall("myEgressFirewall", "default")
		h, c := addHandler(wf, egressFirewallType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				egressFirewall := obj.(*egressfirewall.EgressFirewall)
				gomega.Expect(reflect.DeepEqual(egressFirewall, added)).To(gomega.BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newEgressFirewall := new.(*egressfirewall.EgressFirewall)
				gomega.Expect(reflect.DeepEqual(newEgressFirewall, added)).To(gomega.BeTrue())
				gomega.Expect(newEgressFirewall.Spec.Egress[0].Type).To(gomega.Equal(egressfirewall.EgressFirewallRuleDeny))
			},
			DeleteFunc: func(obj interface{}) {
				egressFirewall := obj.(*egressfirewall.EgressFirewall)
				gomega.Expect(reflect.DeepEqual(egressFirewall, added)).To(gomega.BeTrue())
			},
		})

		egressFirewalls = append(egressFirewalls, added)
		egressFirewallWatch.Add(added)
		gomega.Eventually(c.getAdded, 2).Should(gomega.Equal(1))
		added.Spec.Egress[0].Type = egressfirewall.EgressFirewallRuleDeny
		egressFirewallWatch.Modify(added)
		gomega.Eventually(c.getUpdated, 2).Should(gomega.Equal(1))
		egressFirewalls = egressFirewalls[:0]
		egressFirewallWatch.Delete(added)
		gomega.Eventually(c.getDeleted, 2).Should(gomega.Equal(1))

		wf.RemoveEgressFirewallHandler(h)
	})
	ginkgo.It("responds to crd add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		added := newCRD("crd1", "")
		h, c := addHandler(wf, crdType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				crd := obj.(*apiextensions.CustomResourceDefinition)
				gomega.Expect(reflect.DeepEqual(crd, added)).To(gomega.BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newcrd := new.(*apiextensions.CustomResourceDefinition)
				gomega.Expect(reflect.DeepEqual(newcrd, added)).To(gomega.BeTrue())
				gomega.Expect(newcrd.Spec.Group).To(gomega.Equal("my-test"))
			},
			DeleteFunc: func(obj interface{}) {
				crd := obj.(*apiextensions.CustomResourceDefinition)
				gomega.Expect(reflect.DeepEqual(crd, added)).To(gomega.BeTrue())
			},
		})

		crds = append(crds, added)
		crdWatch.Add(added)
		gomega.Eventually(c.getAdded, 2).Should(gomega.Equal(1))
		added.Spec.Group = "my-test"
		crdWatch.Modify(added)
		gomega.Eventually(c.getUpdated, 2).Should(gomega.Equal(1))
		crds = crds[:0]
		crdWatch.Delete(added)
		gomega.Eventually(c.getDeleted, 2).Should(gomega.Equal(1))

		wf.RemoveCRDHandler(h)

	})
	ginkgo.It("responds to egressIP add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		added := newEgressIP("myEgressIP", "default")
		h, c := addHandler(wf, egressIPType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				egressIP := obj.(*egressip.EgressIP)
				gomega.Expect(reflect.DeepEqual(egressIP, added)).To(gomega.BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newEgressIP := new.(*egressip.EgressIP)
				gomega.Expect(reflect.DeepEqual(newEgressIP, added)).To(gomega.BeTrue())
				gomega.Expect(newEgressIP.Spec.EgressIPs).To(gomega.Equal([]string{"192.168.126.10"}))
			},
			DeleteFunc: func(obj interface{}) {
				egressIP := obj.(*egressip.EgressIP)
				gomega.Expect(reflect.DeepEqual(egressIP, added)).To(gomega.BeTrue())
			},
		})

		egressIPs = append(egressIPs, added)
		egressIPWatch.Add(added)
		gomega.Eventually(c.getAdded, 2).Should(gomega.Equal(1))
		added.Spec.EgressIPs = []string{"192.168.126.10"}
		egressIPWatch.Modify(added)
		gomega.Eventually(c.getUpdated, 2).Should(gomega.Equal(1))
		egressIPs = egressIPs[:0]
		egressIPWatch.Delete(added)
		gomega.Eventually(c.getDeleted, 2).Should(gomega.Equal(1))

		wf.RemoveEgressIPHandler(h)
	})
	ginkgo.It("stops processing events after the handler is removed", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		added := newNamespace("default")
		h, c := addHandler(wf, namespaceType, cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) {},
			UpdateFunc: func(old, new interface{}) {},
			DeleteFunc: func(obj interface{}) {},
		})

		namespaces = append(namespaces, added)
		namespaceWatch.Add(added)
		gomega.Eventually(c.getAdded, 2).Should(gomega.Equal(1))
		wf.RemoveNamespaceHandler(h)

		added2 := newNamespace("other")
		namespaces = append(namespaces, added2)
		namespaceWatch.Add(added2)
		gomega.Consistently(c.getAdded, 2).Should(gomega.Equal(1))

		added2.Status.Phase = v1.NamespaceTerminating
		namespaceWatch.Modify(added2)
		gomega.Consistently(c.getUpdated, 2).Should(gomega.Equal(0))
		namespaces = []*v1.Namespace{added}
		namespaceWatch.Delete(added2)
		gomega.Consistently(c.getDeleted, 2).Should(gomega.Equal(0))
	})

	ginkgo.It("filters correctly by label and namespace", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		passesFilter := newPod("pod1", "default")
		passesFilter.ObjectMeta.Labels["blah"] = "foobar"
		failsFilter := newPod("pod2", "default")
		failsFilter.ObjectMeta.Labels["blah"] = "baz"
		failsFilter2 := newPod("pod3", "otherns")
		failsFilter2.ObjectMeta.Labels["blah"] = "foobar"

		sel, err := metav1.LabelSelectorAsSelector(
			&metav1.LabelSelector{
				MatchLabels: map[string]string{"blah": "foobar"},
			},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		_, c := addFilteredHandler(wf,
			podType,
			"default",
			sel,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					pod := obj.(*v1.Pod)
					gomega.Expect(reflect.DeepEqual(pod, passesFilter)).To(gomega.BeTrue())
				},
				UpdateFunc: func(old, new interface{}) {
					newPod := new.(*v1.Pod)
					gomega.Expect(reflect.DeepEqual(newPod, passesFilter)).To(gomega.BeTrue())
				},
				DeleteFunc: func(obj interface{}) {
					pod := obj.(*v1.Pod)
					gomega.Expect(reflect.DeepEqual(pod, passesFilter)).To(gomega.BeTrue())
				},
			})

		pods = append(pods, passesFilter)
		podWatch.Add(passesFilter)
		gomega.Eventually(c.getAdded, 2).Should(gomega.Equal(1))

		// numAdded should remain 1
		pods = append(pods, failsFilter)
		podWatch.Add(failsFilter)
		gomega.Consistently(c.getAdded, 2).Should(gomega.Equal(1))

		// numAdded should remain 1
		pods = append(pods, failsFilter2)
		podWatch.Add(failsFilter2)
		gomega.Consistently(c.getAdded, 2).Should(gomega.Equal(1))

		passesFilter.Status.Phase = v1.PodFailed
		podWatch.Modify(passesFilter)
		gomega.Eventually(c.getUpdated, 2).Should(gomega.Equal(1))

		// numAdded should remain 1
		failsFilter.Status.Phase = v1.PodFailed
		podWatch.Modify(failsFilter)
		gomega.Consistently(c.getUpdated, 2).Should(gomega.Equal(1))

		failsFilter2.Status.Phase = v1.PodFailed
		podWatch.Modify(failsFilter2)
		gomega.Consistently(c.getUpdated, 2).Should(gomega.Equal(1))

		pods = []*v1.Pod{failsFilter, failsFilter2}
		podWatch.Delete(passesFilter)
		gomega.Eventually(c.getDeleted, 2).Should(gomega.Equal(1))
	})

	ginkgo.It("correctly handles object updates that cause filter changes", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		pod := newPod("pod1", "default")
		pod.ObjectMeta.Labels["blah"] = "baz"

		sel, err := metav1.LabelSelectorAsSelector(
			&metav1.LabelSelector{
				MatchLabels: map[string]string{"blah": "foobar"},
			},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		equalPod := pod
		h, c := addFilteredHandler(wf,
			podType,
			"default",
			sel,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					p := obj.(*v1.Pod)
					gomega.Expect(reflect.DeepEqual(p, equalPod)).To(gomega.BeTrue())
				},
				UpdateFunc: func(old, new interface{}) {},
				DeleteFunc: func(obj interface{}) {
					p := obj.(*v1.Pod)
					gomega.Expect(reflect.DeepEqual(p, equalPod)).To(gomega.BeTrue())
				},
			})

		pods = append(pods, pod)

		// Pod doesn't pass filter; shouldn't be added
		podWatch.Add(pod)
		gomega.Consistently(c.getAdded, 2).Should(gomega.Equal(0))

		// Update pod to pass filter; should be treated as add.  Need
		// to deep-copy pod when modifying because it's a pointer all
		// the way through when using FakeClient
		podCopy := pod.DeepCopy()
		podCopy.ObjectMeta.Labels["blah"] = "foobar"
		pods = []*v1.Pod{podCopy}
		equalPod = podCopy
		podWatch.Modify(podCopy)
		gomega.Eventually(c.getAdded, 2).Should(gomega.Equal(1))

		// Update pod to fail filter; should be treated as delete
		pod.ObjectMeta.Labels["blah"] = "baz"
		podWatch.Modify(pod)
		gomega.Eventually(c.getDeleted, 2).Should(gomega.Equal(1))
		gomega.Consistently(c.getAdded, 2).Should(gomega.Equal(1))
		gomega.Consistently(c.getUpdated, 2).Should(gomega.Equal(0))

		wf.RemovePodHandler(h)
	})
})
