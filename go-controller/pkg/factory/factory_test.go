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

	nodednsinfo "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/nodednsinfo/v1"
	nodednsinfofake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/nodednsinfo/v1/apis/clientset/versioned/fake"

	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsfake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressip "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	egressipfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/fake"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestFactory(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Watch Factory Suite")
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

func newNodeDNSInfo(name string) *nodednsinfo.NodeDNSInfo {
	return &nodednsinfo.NodeDNSInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			UID:  types.UID(name),
			Labels: map[string]string{
				"name": name,
			},
		},
		Status: nodednsinfo.NodeDNSInfoStatus{
			DNSEntries: make(map[string]nodednsinfo.DNSEntry),
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

func nodeDNSInfoObjSetup(c *nodednsinfofake.Clientset, objType string, listFn func(core.Action) (bool, runtime.Object, error)) *watch.FakeWatcher {
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

var _ = Describe("Watch Factory Operations", func() {
	var (
		ovnClientset                              *util.OVNClientset
		fakeClient                                *fake.Clientset
		egressIPFakeClient                        *egressipfake.Clientset
		egressFirewallFakeClient                  *egressfirewallfake.Clientset
		nodeDNSInfoFakeClient                     *nodednsinfofake.Clientset
		crdFakeClient                             *apiextensionsfake.Clientset
		podWatch, namespaceWatch, nodeWatch       *watch.FakeWatcher
		policyWatch, endpointsWatch, serviceWatch *watch.FakeWatcher
		egressFirewallWatch, nodeDNSInfoWatch     *watch.FakeWatcher
		crdWatch, egressIPWatch                   *watch.FakeWatcher
		pods                                      []*v1.Pod
		namespaces                                []*v1.Namespace
		nodes                                     []*v1.Node
		policies                                  []*knet.NetworkPolicy
		endpoints                                 []*v1.Endpoints
		services                                  []*v1.Service
		egressIPs                                 []*egressip.EgressIP
		wf                                        *WatchFactory
		egressFirewalls                           []*egressfirewall.EgressFirewall
		nodeDNSInfos                              []*nodednsinfo.NodeDNSInfo
		crds                                      []*apiextensions.CustomResourceDefinition
		err                                       error
	)

	BeforeEach(func() {

		// Restore global default values before each testcase
		config.PrepareTestConfig()
		config.OVNKubernetesFeature.EnableEgressIP = true

		fakeClient = &fake.Clientset{}
		egressFirewallFakeClient = &egressfirewallfake.Clientset{}
		nodeDNSInfoFakeClient = &nodednsinfofake.Clientset{}
		crdFakeClient = &apiextensionsfake.Clientset{}
		egressIPFakeClient = &egressipfake.Clientset{}

		ovnClientset = &util.OVNClientset{
			KubeClient:           fakeClient,
			EgressIPClient:       egressIPFakeClient,
			EgressFirewallClient: egressFirewallFakeClient,
			NodeDNSInfoClient:    nodeDNSInfoFakeClient,
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
		nodeDNSInfos = make([]*nodednsinfo.NodeDNSInfo, 0)
		nodeDNSInfoWatch = nodeDNSInfoObjSetup(nodeDNSInfoFakeClient, "nodednsinfos", func(core.Action) (bool, runtime.Object, error) {
			obj := &nodednsinfo.NodeDNSInfoList{}
			for _, p := range nodeDNSInfos {
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

	AfterEach(func() {
		wf.Shutdown()
		if wf.efFactory != nil {
			wf.ShutdownEgressFirewallWatchFactory()
		}
	})

	Context("when a processExisting is given", func() {
		testExisting := func(objType reflect.Type, namespace string, sel labels.Selector) {
			wf, err = NewMasterWatchFactory(ovnClientset)
			Expect(err).NotTo(HaveOccurred())
			err = wf.InitializeEgressFirewallWatchFactory()
			Expect(err).NotTo(HaveOccurred())
			h := wf.addHandler(objType, namespace, sel,
				cache.ResourceEventHandlerFuncs{},
				func(objs []interface{}) {
					defer GinkgoRecover()
					Expect(len(objs)).To(Equal(1))
				})
			Expect(h).NotTo(BeNil())
			wf.removeHandler(objType, h)
		}

		It("is called for each existing pod", func() {
			pods = append(pods, newPod("pod1", "default"))
			testExisting(podType, "", nil)
		})

		It("is called for each existing namespace", func() {
			namespaces = append(namespaces, newNamespace("default"))
			testExisting(namespaceType, "", nil)
		})

		It("is called for each existing node", func() {
			nodes = append(nodes, newNode("default"))
			testExisting(nodeType, "", nil)
		})

		It("is called for each existing policy", func() {
			policies = append(policies, newPolicy("denyall", "default"))
			testExisting(policyType, "", nil)
		})

		It("is called for each existing endpoints", func() {
			endpoints = append(endpoints, newEndpoints("myendpoint", "default"))
			testExisting(endpointsType, "", nil)
		})

		It("is called for each existing service", func() {
			services = append(services, newService("myservice", "default"))
			testExisting(serviceType, "", nil)
		})

		It("is called for each existing egressFirewall", func() {
			egressFirewalls = append(egressFirewalls, newEgressFirewall("myEgressFirewall", "default"))
			testExisting(egressFirewallType, "", nil)
		})
		It("is called for each existing CRDS", func() {
			crds = append(crds, newCRD("myCRD", ""))
			testExisting(crdType, "", nil)
		})
		It("is called for each existing NodeDNSInfo", func() {
			nodeDNSInfos = append(nodeDNSInfos, newNodeDNSInfo("myNodeDNSInfo"))
			testExisting(nodeDNSInfoType, "", nil)
		})
		It("is called for each existing egressIP", func() {
			egressIPs = append(egressIPs, newEgressIP("myEgressIP", "default"))
			testExisting(egressIPType, "", nil)
		})

		It("is called for each existing pod that matches a given namespace and label", func() {
			pod := newPod("pod1", "default")
			pod.ObjectMeta.Labels["blah"] = "foobar"
			pods = append(pods, pod)

			sel, err := metav1.LabelSelectorAsSelector(
				&metav1.LabelSelector{
					MatchLabels: map[string]string{"blah": "foobar"},
				},
			)
			Expect(err).NotTo(HaveOccurred())

			testExisting(podType, "default", sel)
		})
	})

	Context("when existing items are known to the informer", func() {
		testExisting := func(objType reflect.Type) {
			wf, err = NewMasterWatchFactory(ovnClientset)
			Expect(err).NotTo(HaveOccurred())
			err = wf.InitializeEgressFirewallWatchFactory()
			Expect(err).NotTo(HaveOccurred())
			var addCalls int32
			h := wf.addHandler(objType, "", nil,
				cache.ResourceEventHandlerFuncs{
					AddFunc: func(obj interface{}) {
						atomic.AddInt32(&addCalls, 1)
					},
					UpdateFunc: func(old, new interface{}) {},
					DeleteFunc: func(obj interface{}) {},
				}, nil)
			Expect(int(addCalls)).To(Equal(2))
			wf.removeHandler(objType, h)
		}

		It("calls ADD for each existing pod", func() {
			pods = append(pods, newPod("pod1", "default"))
			pods = append(pods, newPod("pod2", "default"))
			testExisting(podType)
		})

		It("calls ADD for each existing namespace", func() {
			namespaces = append(namespaces, newNamespace("default"))
			namespaces = append(namespaces, newNamespace("default2"))
			testExisting(namespaceType)
		})

		It("calls ADD for each existing node", func() {
			nodes = append(nodes, newNode("default"))
			nodes = append(nodes, newNode("default2"))
			testExisting(nodeType)
		})

		It("calls ADD for each existing policy", func() {
			policies = append(policies, newPolicy("denyall", "default"))
			policies = append(policies, newPolicy("denyall2", "default"))
			testExisting(policyType)
		})

		It("calls ADD for each existing endpoints", func() {
			endpoints = append(endpoints, newEndpoints("myendpoint", "default"))
			endpoints = append(endpoints, newEndpoints("myendpoint2", "default"))
			testExisting(endpointsType)
		})

		It("calls ADD for each existing service", func() {
			services = append(services, newService("myservice", "default"))
			services = append(services, newService("myservice2", "default"))
			testExisting(serviceType)
		})
		It("calls ADD for each existing egressFirewall", func() {
			egressFirewalls = append(egressFirewalls, newEgressFirewall("myFirewall", "default"))
			egressFirewalls = append(egressFirewalls, newEgressFirewall("myFirewall1", "default"))
			testExisting(egressFirewallType)
		})
		It("calls ADD for each existing CRD", func() {
			crds = append(crds, newCRD("crd1", ""))
			crds = append(crds, newCRD("crd2", ""))
			testExisting(crdType)
		})
		It("calls ADD for each existing NodeDNSInfo", func() {
			nodeDNSInfos = append(nodeDNSInfos, newNodeDNSInfo("node1"))
			nodeDNSInfos = append(nodeDNSInfos, newNodeDNSInfo("node2"))
			testExisting(nodeDNSInfoType)
		})
		It("calls ADD for each existing egressIP", func() {
			egressIPs = append(egressIPs, newEgressIP("myEgressIP", "default"))
			egressIPs = append(egressIPs, newEgressIP("myEgressIP1", "default"))
			testExisting(egressIPType)
		})
	})

	Context("when EgressIP is disabled", func() {
		testExisting := func(objType reflect.Type) {
			wf, err = NewMasterWatchFactory(ovnClientset)
			Expect(err).NotTo(HaveOccurred())
			Expect(wf.informers).NotTo(HaveKey(objType))
		}
		It("does not contain Egress IP informer", func() {
			config.OVNKubernetesFeature.EnableEgressIP = false
			testExisting(egressIPType)
		})
	})

	addFilteredHandler := func(wf *WatchFactory, objType reflect.Type, namespace string, sel labels.Selector, funcs cache.ResourceEventHandlerFuncs) (*Handler, *handlerCalls) {
		calls := handlerCalls{}
		h := wf.addHandler(objType, namespace, sel, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				defer GinkgoRecover()
				atomic.AddInt32(&calls.added, 1)
				funcs.AddFunc(obj)
			},
			UpdateFunc: func(old, new interface{}) {
				defer GinkgoRecover()
				atomic.AddInt32(&calls.updated, 1)
				funcs.UpdateFunc(old, new)
			},
			DeleteFunc: func(obj interface{}) {
				defer GinkgoRecover()
				atomic.AddInt32(&calls.deleted, 1)
				funcs.DeleteFunc(obj)
			},
		}, nil)
		Expect(h).NotTo(BeNil())
		return h, &calls
	}

	addHandler := func(wf *WatchFactory, objType reflect.Type, funcs cache.ResourceEventHandlerFuncs) (*Handler, *handlerCalls) {
		return addFilteredHandler(wf, objType, "", nil, funcs)
	}

	It("responds to pod add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		Expect(err).NotTo(HaveOccurred())

		added := newPod("pod1", "default")
		h, c := addHandler(wf, podType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				pod := obj.(*v1.Pod)
				Expect(reflect.DeepEqual(pod, added)).To(BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newPod := new.(*v1.Pod)
				Expect(reflect.DeepEqual(newPod, added)).To(BeTrue())
				Expect(newPod.Spec.NodeName).To(Equal("foobar"))
			},
			DeleteFunc: func(obj interface{}) {
				pod := obj.(*v1.Pod)
				Expect(reflect.DeepEqual(pod, added)).To(BeTrue())
			},
		})

		pods = append(pods, added)
		podWatch.Add(added)
		Eventually(c.getAdded, 2).Should(Equal(1))
		added.Spec.NodeName = "foobar"
		podWatch.Modify(added)
		Eventually(c.getUpdated, 2).Should(Equal(1))
		pods = pods[:0]
		podWatch.Delete(added)
		Eventually(c.getDeleted, 2).Should(Equal(1))

		wf.RemovePodHandler(h)
	})

	It("responds to multiple pod add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		Expect(err).NotTo(HaveOccurred())

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
				Expect(ok).To(BeTrue())
				ot.mu.Lock()
				defer ot.mu.Unlock()
				Expect(ot.added).To(BeNumerically("<", 2))
				ot.added++
			},
			UpdateFunc: func(old, new interface{}) {
				newPod := new.(*v1.Pod)
				ot, ok := testPods[newPod.Name]
				Expect(ok).To(BeTrue())
				ot.mu.Lock()
				defer ot.mu.Unlock()
				Expect(ot.updated).To(BeNumerically("<", 2))
				ot.updated++
				Expect(newPod.Spec.NodeName).To(Equal(nodeName))
			},
			DeleteFunc: func(obj interface{}) {
				pod := obj.(*v1.Pod)
				ot, ok := testPods[pod.Name]
				Expect(ok).To(BeTrue())
				ot.mu.Lock()
				defer ot.mu.Unlock()
				Expect(ot.deleted).To(BeNumerically("<", 2))
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
		Eventually(c.getAdded, 2).Should(Equal(10))
		Eventually(c.getUpdated, 2).Should(Equal(10))
		Eventually(c.getDeleted, 2).Should(Equal(10))
		for _, ot := range testPods {
			ot.mu.Lock()
			Expect(ot.added).Should(Equal(2))
			Expect(ot.updated).Should(Equal(2))
			Expect(ot.deleted).Should(Equal(2))
			ot.mu.Unlock()
		}

		wf.RemovePodHandler(h)
	})

	It("responds to namespace add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		Expect(err).NotTo(HaveOccurred())

		added := newNamespace("default")
		h, c := addHandler(wf, namespaceType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				ns := obj.(*v1.Namespace)
				Expect(reflect.DeepEqual(ns, added)).To(BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newNS := new.(*v1.Namespace)
				Expect(reflect.DeepEqual(newNS, added)).To(BeTrue())
				Expect(newNS.Status.Phase).To(Equal(v1.NamespaceTerminating))
			},
			DeleteFunc: func(obj interface{}) {
				ns := obj.(*v1.Namespace)
				Expect(reflect.DeepEqual(ns, added)).To(BeTrue())
			},
		})

		namespaces = append(namespaces, added)
		namespaceWatch.Add(added)
		Eventually(c.getAdded, 2).Should(Equal(1))
		added.Status.Phase = v1.NamespaceTerminating
		namespaceWatch.Modify(added)
		Eventually(c.getUpdated, 2).Should(Equal(1))
		namespaces = namespaces[:0]
		namespaceWatch.Delete(added)
		Eventually(c.getDeleted, 2).Should(Equal(1))

		wf.RemoveNamespaceHandler(h)
	})

	It("responds to node add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		Expect(err).NotTo(HaveOccurred())

		added := newNode("mynode")
		h, c := addHandler(wf, nodeType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				node := obj.(*v1.Node)
				Expect(reflect.DeepEqual(node, added)).To(BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newNode := new.(*v1.Node)
				Expect(reflect.DeepEqual(newNode, added)).To(BeTrue())
				Expect(newNode.Status.Phase).To(Equal(v1.NodeTerminated))
			},
			DeleteFunc: func(obj interface{}) {
				node := obj.(*v1.Node)
				Expect(reflect.DeepEqual(node, added)).To(BeTrue())
			},
		})

		nodes = append(nodes, added)
		nodeWatch.Add(added)
		Eventually(c.getAdded, 2).Should(Equal(1))
		added.Status.Phase = v1.NodeTerminated
		nodeWatch.Modify(added)
		Eventually(c.getUpdated, 2).Should(Equal(1))
		nodes = nodes[:0]
		nodeWatch.Delete(added)
		Eventually(c.getDeleted, 2).Should(Equal(1))

		wf.RemoveNodeHandler(h)
	})

	It("responds to multiple node add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		Expect(err).NotTo(HaveOccurred())

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
				Expect(ok).To(BeTrue())
				ot.mu.Lock()
				defer ot.mu.Unlock()
				Expect(ot.added).To(BeNumerically("<", 2))
				ot.added++
			},
			UpdateFunc: func(old, new interface{}) {
				newNode := new.(*v1.Node)
				ot, ok := testNodes[newNode.Name]
				Expect(ok).To(BeTrue())
				ot.mu.Lock()
				defer ot.mu.Unlock()
				Expect(ot.updated).To(BeNumerically("<", 2))
				ot.updated++
				Expect(newNode.Status.Phase).To(Equal(v1.NodeTerminated))
			},
			DeleteFunc: func(obj interface{}) {
				node := obj.(*v1.Node)
				ot, ok := testNodes[node.Name]
				Expect(ok).To(BeTrue())
				ot.mu.Lock()
				Expect(ot.deleted).To(BeNumerically("<", 2))
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
		Eventually(c.getAdded, 2).Should(Equal(10))
		Eventually(c.getUpdated, 2).Should(Equal(10))
		Eventually(c.getDeleted, 2).Should(Equal(10))
		for _, ot := range testNodes {
			ot.mu.Lock()
			Expect(ot.added).Should(Equal(2))
			Expect(ot.updated).Should(Equal(2))
			Expect(ot.deleted).Should(Equal(2))
			ot.mu.Unlock()
		}

		wf.RemoveNodeHandler(h)
	})

	It("correctly orders queued informer initial add events and subsequent update events", func() {
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
		Expect(err).NotTo(HaveOccurred())

		h, c := addHandler(wf, nodeType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				defer GinkgoRecover()
				node := obj.(*v1.Node)
				ot, ok := testNodes[node.Name]
				Expect(ok).To(BeTrue())
				ot.mu.Lock()
				defer ot.mu.Unlock()
				Expect(ot.added).To(Equal(0), "add for node %s already run", node.Name)
				ot.added++
			},
			UpdateFunc: func(old, new interface{}) {
				defer GinkgoRecover()
				newNode := new.(*v1.Node)
				ot, ok := testNodes[newNode.Name]
				Expect(ok).To(BeTrue())
				// Expect updates to be processed after Add
				ot.mu.Lock()
				defer ot.mu.Unlock()
				Expect(ot.added).To(Equal(1), "update for node %s processed before initial add!", newNode.Name)
				Expect(ot.updated).To(Equal(0))
				ot.updated++
				Expect(newNode.Status.Phase).To(Equal(v1.NodeTerminated))
			},
			DeleteFunc: func(obj interface{}) {},
		})

		done := make(chan bool)
		go func() {
			// Send an update event for each node
			for _, n := range nodes {
				n.Status.Phase = v1.NodeTerminated
				nodeWatch.Modify(n)
			}
			done <- true
		}()

		// Adds are done synchronously at handler addition time
		for _, ot := range testNodes {
			ot.mu.Lock()
			Expect(ot.added).To(Equal(1), "missing add for node %s", ot.node.Name)
			ot.mu.Unlock()
		}
		Expect(c.getAdded()).To(Equal(len(testNodes)))

		<-done
		// Updates are async and may take a bit longer to finish
		Eventually(c.getUpdated, 10).Should(Equal(len(testNodes)))
		for _, ot := range testNodes {
			ot.mu.Lock()
			Expect(ot.updated).To(Equal(1), "missing update for node %s", ot.node.Name)
			ot.mu.Unlock()
		}

		wf.RemoveNodeHandler(h)
	})

	It("correctly orders serialized informer initial add events and subsequent update events", func() {
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
		Expect(err).NotTo(HaveOccurred())

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
				defer GinkgoRecover()
				namespace := obj.(*v1.Namespace)
				ot, ok := testNamespaces[namespace.Name]
				Expect(ok).To(BeTrue())
				ot.mu.Lock()
				defer ot.mu.Unlock()
				Expect(ot.added).To(Equal(0))
				ot.added++
			},
			UpdateFunc: func(old, new interface{}) {
				defer GinkgoRecover()
				newNamespace := new.(*v1.Namespace)
				ot, ok := testNamespaces[newNamespace.Name]
				Expect(ok).To(BeTrue())
				// Expect updates to be processed after Add
				ot.mu.Lock()
				defer ot.mu.Unlock()
				Expect(ot.added).To(Equal(1), "update for namespace %s processed before initial add!", newNamespace.Name)
				Expect(ot.updated).To(Equal(0))
				ot.updated++
				Expect(newNamespace.Status.Phase).To(Equal(v1.NamespaceTerminating))
			},
			DeleteFunc: func(obj interface{}) {},
		})
		doneWg.Wait()

		// Adds are done synchronously at handler addition time
		for _, ot := range testNamespaces {
			ot.mu.Lock()
			Expect(ot.added).To(Equal(1), "missing add for namespace %s", ot.namespace.Name)
			ot.mu.Unlock()
		}
		Expect(c.getAdded()).To(Equal(len(testNamespaces)))

		// Updates are async and may take a bit longer to finish
		Eventually(c.getUpdated, 10).Should(Equal(len(testNamespaces)))
		for _, ot := range testNamespaces {
			ot.mu.Lock()
			Expect(ot.updated).To(Equal(1), "missing update for namespace %s", ot.namespace.Name)
			ot.mu.Unlock()
		}

		wf.RemoveNamespaceHandler(h)
	})

	It("responds to policy add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		Expect(err).NotTo(HaveOccurred())

		added := newPolicy("mypolicy", "default")
		h, c := addHandler(wf, policyType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				np := obj.(*knet.NetworkPolicy)
				Expect(reflect.DeepEqual(np, added)).To(BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newNP := new.(*knet.NetworkPolicy)
				Expect(reflect.DeepEqual(newNP, added)).To(BeTrue())
				Expect(newNP.Spec.PolicyTypes).To(Equal([]knet.PolicyType{knet.PolicyTypeIngress}))
			},
			DeleteFunc: func(obj interface{}) {
				np := obj.(*knet.NetworkPolicy)
				Expect(reflect.DeepEqual(np, added)).To(BeTrue())
			},
		})

		policies = append(policies, added)
		policyWatch.Add(added)
		Eventually(c.getAdded, 2).Should(Equal(1))
		added.Spec.PolicyTypes = []knet.PolicyType{knet.PolicyTypeIngress}
		policyWatch.Modify(added)
		Eventually(c.getUpdated, 2).Should(Equal(1))
		policies = policies[:0]
		policyWatch.Delete(added)
		Eventually(c.getDeleted, 2).Should(Equal(1))

		wf.RemovePolicyHandler(h)
	})

	It("responds to endpoints add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		Expect(err).NotTo(HaveOccurred())

		added := newEndpoints("myendpoints", "default")
		h, c := addHandler(wf, endpointsType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				eps := obj.(*v1.Endpoints)
				Expect(reflect.DeepEqual(eps, added)).To(BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newEPs := new.(*v1.Endpoints)
				Expect(reflect.DeepEqual(newEPs, added)).To(BeTrue())
				Expect(len(newEPs.Subsets)).To(Equal(1))
			},
			DeleteFunc: func(obj interface{}) {
				eps := obj.(*v1.Endpoints)
				Expect(reflect.DeepEqual(eps, added)).To(BeTrue())
			},
		})

		endpoints = append(endpoints, added)
		endpointsWatch.Add(added)
		Eventually(c.getAdded, 2).Should(Equal(1))
		added.Subsets = append(added.Subsets, v1.EndpointSubset{
			Ports: []v1.EndpointPort{
				{
					Name: "foobar",
					Port: 1234,
				},
			},
		})
		endpointsWatch.Modify(added)
		Eventually(c.getUpdated, 2).Should(Equal(1))
		endpoints = endpoints[:0]
		endpointsWatch.Delete(added)
		Eventually(c.getDeleted, 2).Should(Equal(1))

		wf.RemoveEndpointsHandler(h)
	})

	It("responds to service add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		Expect(err).NotTo(HaveOccurred())

		added := newService("myservice", "default")
		h, c := addHandler(wf, serviceType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				service := obj.(*v1.Service)
				Expect(reflect.DeepEqual(service, added)).To(BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newService := new.(*v1.Service)
				Expect(reflect.DeepEqual(newService, added)).To(BeTrue())
				Expect(newService.Spec.ClusterIP).To(Equal("1.1.1.1"))
			},
			DeleteFunc: func(obj interface{}) {
				service := obj.(*v1.Service)
				Expect(reflect.DeepEqual(service, added)).To(BeTrue())
			},
		})

		services = append(services, added)
		serviceWatch.Add(added)
		Eventually(c.getAdded, 2).Should(Equal(1))
		added.Spec.ClusterIP = "1.1.1.1"
		serviceWatch.Modify(added)
		Eventually(c.getUpdated, 2).Should(Equal(1))
		services = services[:0]
		serviceWatch.Delete(added)
		Eventually(c.getDeleted, 2).Should(Equal(1))

		wf.RemoveServiceHandler(h)
	})

	It("responds to egressFirewall add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		err = wf.InitializeEgressFirewallWatchFactory()
		Expect(err).NotTo(HaveOccurred())

		added := newEgressFirewall("myEgressFirewall", "default")
		h, c := addHandler(wf, egressFirewallType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				egressFirewall := obj.(*egressfirewall.EgressFirewall)
				Expect(reflect.DeepEqual(egressFirewall, added)).To(BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newEgressFirewall := new.(*egressfirewall.EgressFirewall)
				Expect(reflect.DeepEqual(newEgressFirewall, added)).To(BeTrue())
				Expect(newEgressFirewall.Spec.Egress[0].Type).To(Equal(egressfirewall.EgressFirewallRuleDeny))
			},
			DeleteFunc: func(obj interface{}) {
				egressFirewall := obj.(*egressfirewall.EgressFirewall)
				Expect(reflect.DeepEqual(egressFirewall, added)).To(BeTrue())
			},
		})

		egressFirewalls = append(egressFirewalls, added)
		egressFirewallWatch.Add(added)
		Eventually(c.getAdded, 2).Should(Equal(1))
		added.Spec.Egress[0].Type = egressfirewall.EgressFirewallRuleDeny
		egressFirewallWatch.Modify(added)
		Eventually(c.getUpdated, 2).Should(Equal(1))
		egressFirewalls = egressFirewalls[:0]
		egressFirewallWatch.Delete(added)
		Eventually(c.getDeleted, 2).Should(Equal(1))

		wf.RemoveEgressFirewallHandler(h)
	})
	It("responds to nodeDNSInfo add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		err = wf.InitializeEgressFirewallWatchFactory()
		Expect(err).NotTo(HaveOccurred())

		added := newNodeDNSInfo("myNodeDNSInfo")
		h, c := addHandler(wf, nodeDNSInfoType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				nodeDNSInfo := obj.(*nodednsinfo.NodeDNSInfo)
				Expect(reflect.DeepEqual(nodeDNSInfo, added)).To(BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newNodeDNSInfo := new.(*nodednsinfo.NodeDNSInfo)
				Expect(reflect.DeepEqual(newNodeDNSInfo, added)).To(BeTrue())

			},
			DeleteFunc: func(obj interface{}) {
				nodeDNSInfo := obj.(*nodednsinfo.NodeDNSInfo)
				Expect(reflect.DeepEqual(nodeDNSInfo, added)).To(BeTrue())
			},
		})

		nodeDNSInfos = append(nodeDNSInfos, added)
		nodeDNSInfoWatch.Add(added)
		Eventually(c.getAdded, 2).Should(Equal(1))
		added.Status.DNSEntries["www.test.com"] = nodednsinfo.DNSEntry{
			IPAddresses: []string{"1.1.1.1"},
		}
		nodeDNSInfoWatch.Modify(added)
		Eventually(c.getUpdated, 2).Should(Equal(1))
		nodeDNSInfos = nodeDNSInfos[:0]
		nodeDNSInfoWatch.Delete(added)
		Eventually(c.getDeleted, 2).Should(Equal(1))
		wf.RemoveNodeDNSInfoHandler(h)
	})
	It("responds to crd add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		Expect(err).NotTo(HaveOccurred())

		added := newCRD("crd1", "")
		h, c := addHandler(wf, crdType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				crd := obj.(*apiextensions.CustomResourceDefinition)
				Expect(reflect.DeepEqual(crd, added)).To(BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newcrd := new.(*apiextensions.CustomResourceDefinition)
				Expect(reflect.DeepEqual(newcrd, added)).To(BeTrue())
				Expect(newcrd.Spec.Group).To(Equal("my-test"))
			},
			DeleteFunc: func(obj interface{}) {
				crd := obj.(*apiextensions.CustomResourceDefinition)
				Expect(reflect.DeepEqual(crd, added)).To(BeTrue())
			},
		})

		crds = append(crds, added)
		crdWatch.Add(added)
		Eventually(c.getAdded, 2).Should(Equal(1))
		added.Spec.Group = "my-test"
		crdWatch.Modify(added)
		Eventually(c.getUpdated, 2).Should(Equal(1))
		crds = crds[:0]
		crdWatch.Delete(added)
		Eventually(c.getDeleted, 2).Should(Equal(1))

		wf.RemoveCRDHandler(h)

	})
	It("responds to egressIP add/update/delete events", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		Expect(err).NotTo(HaveOccurred())

		added := newEgressIP("myEgressIP", "default")
		h, c := addHandler(wf, egressIPType, cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				egressIP := obj.(*egressip.EgressIP)
				Expect(reflect.DeepEqual(egressIP, added)).To(BeTrue())
			},
			UpdateFunc: func(old, new interface{}) {
				newEgressIP := new.(*egressip.EgressIP)
				Expect(reflect.DeepEqual(newEgressIP, added)).To(BeTrue())
				Expect(newEgressIP.Spec.EgressIPs).To(Equal([]string{"192.168.126.10"}))
			},
			DeleteFunc: func(obj interface{}) {
				egressIP := obj.(*egressip.EgressIP)
				Expect(reflect.DeepEqual(egressIP, added)).To(BeTrue())
			},
		})

		egressIPs = append(egressIPs, added)
		egressIPWatch.Add(added)
		Eventually(c.getAdded, 2).Should(Equal(1))
		added.Spec.EgressIPs = []string{"192.168.126.10"}
		egressIPWatch.Modify(added)
		Eventually(c.getUpdated, 2).Should(Equal(1))
		egressIPs = egressIPs[:0]
		egressIPWatch.Delete(added)
		Eventually(c.getDeleted, 2).Should(Equal(1))

		wf.RemoveEgressIPHandler(h)
	})
	It("stops processing events after the handler is removed", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		Expect(err).NotTo(HaveOccurred())

		added := newNamespace("default")
		h, c := addHandler(wf, namespaceType, cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) {},
			UpdateFunc: func(old, new interface{}) {},
			DeleteFunc: func(obj interface{}) {},
		})

		namespaces = append(namespaces, added)
		namespaceWatch.Add(added)
		Eventually(c.getAdded, 2).Should(Equal(1))
		wf.RemoveNamespaceHandler(h)

		added2 := newNamespace("other")
		namespaces = append(namespaces, added2)
		namespaceWatch.Add(added2)
		Consistently(c.getAdded, 2).Should(Equal(1))

		added2.Status.Phase = v1.NamespaceTerminating
		namespaceWatch.Modify(added2)
		Consistently(c.getUpdated, 2).Should(Equal(0))
		namespaces = []*v1.Namespace{added}
		namespaceWatch.Delete(added2)
		Consistently(c.getDeleted, 2).Should(Equal(0))
	})

	It("filters correctly by label and namespace", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		Expect(err).NotTo(HaveOccurred())

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
		Expect(err).NotTo(HaveOccurred())

		_, c := addFilteredHandler(wf,
			podType,
			"default",
			sel,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					pod := obj.(*v1.Pod)
					Expect(reflect.DeepEqual(pod, passesFilter)).To(BeTrue())
				},
				UpdateFunc: func(old, new interface{}) {
					newPod := new.(*v1.Pod)
					Expect(reflect.DeepEqual(newPod, passesFilter)).To(BeTrue())
				},
				DeleteFunc: func(obj interface{}) {
					pod := obj.(*v1.Pod)
					Expect(reflect.DeepEqual(pod, passesFilter)).To(BeTrue())
				},
			})

		pods = append(pods, passesFilter)
		podWatch.Add(passesFilter)
		Eventually(c.getAdded, 2).Should(Equal(1))

		// numAdded should remain 1
		pods = append(pods, failsFilter)
		podWatch.Add(failsFilter)
		Consistently(c.getAdded, 2).Should(Equal(1))

		// numAdded should remain 1
		pods = append(pods, failsFilter2)
		podWatch.Add(failsFilter2)
		Consistently(c.getAdded, 2).Should(Equal(1))

		passesFilter.Status.Phase = v1.PodFailed
		podWatch.Modify(passesFilter)
		Eventually(c.getUpdated, 2).Should(Equal(1))

		// numAdded should remain 1
		failsFilter.Status.Phase = v1.PodFailed
		podWatch.Modify(failsFilter)
		Consistently(c.getUpdated, 2).Should(Equal(1))

		failsFilter2.Status.Phase = v1.PodFailed
		podWatch.Modify(failsFilter2)
		Consistently(c.getUpdated, 2).Should(Equal(1))

		pods = []*v1.Pod{failsFilter, failsFilter2}
		podWatch.Delete(passesFilter)
		Eventually(c.getDeleted, 2).Should(Equal(1))
	})

	It("correctly handles object updates that cause filter changes", func() {
		wf, err = NewMasterWatchFactory(ovnClientset)
		Expect(err).NotTo(HaveOccurred())

		pod := newPod("pod1", "default")
		pod.ObjectMeta.Labels["blah"] = "baz"

		sel, err := metav1.LabelSelectorAsSelector(
			&metav1.LabelSelector{
				MatchLabels: map[string]string{"blah": "foobar"},
			},
		)
		Expect(err).NotTo(HaveOccurred())

		equalPod := pod
		h, c := addFilteredHandler(wf,
			podType,
			"default",
			sel,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					p := obj.(*v1.Pod)
					Expect(reflect.DeepEqual(p, equalPod)).To(BeTrue())
				},
				UpdateFunc: func(old, new interface{}) {},
				DeleteFunc: func(obj interface{}) {
					p := obj.(*v1.Pod)
					Expect(reflect.DeepEqual(p, equalPod)).To(BeTrue())
				},
			})

		pods = append(pods, pod)

		// Pod doesn't pass filter; shouldn't be added
		podWatch.Add(pod)
		Consistently(c.getAdded, 2).Should(Equal(0))

		// Update pod to pass filter; should be treated as add.  Need
		// to deep-copy pod when modifying because it's a pointer all
		// the way through when using FakeClient
		podCopy := pod.DeepCopy()
		podCopy.ObjectMeta.Labels["blah"] = "foobar"
		pods = []*v1.Pod{podCopy}
		equalPod = podCopy
		podWatch.Modify(podCopy)
		Eventually(c.getAdded, 2).Should(Equal(1))

		// Update pod to fail filter; should be treated as delete
		pod.ObjectMeta.Labels["blah"] = "baz"
		podWatch.Modify(pod)
		Eventually(c.getDeleted, 2).Should(Equal(1))
		Consistently(c.getAdded, 2).Should(Equal(1))
		Consistently(c.getUpdated, 2).Should(Equal(0))

		wf.RemovePodHandler(h)
	})
})
