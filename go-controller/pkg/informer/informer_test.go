package informer

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	kapi "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

func TestEventHandler(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Event Handler Suite")
}

func newPod(name, namespace string) *kapi.Pod {
	return &kapi.Pod{
		Status: kapi.PodStatus{
			Phase: v1.PodRunning,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			UID:       types.UID(name),
			Namespace: namespace,
			Labels: map[string]string{
				"name": name,
			},
		},
		Spec: kapi.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "containerName",
					Image: "containerImage",
				},
			},
			NodeName: "node1",
		},
	}
}

var _ = ginkgo.Describe("Informer Event Handler Tests", func() {
	const (
		namespace string = "test"
	)
	var (
		stopChan chan struct{}
		wg       *sync.WaitGroup
	)

	ginkgo.BeforeEach(func() {
		stopChan = make(chan struct{})
		wg = &sync.WaitGroup{}
	})

	ginkgo.AfterEach(func() {
		close(stopChan)
		wg.Wait()
	})

	ginkgo.It("processes an add event", func() {
		adds := int32(0)
		deletes := int32(0)

		k := fake.NewSimpleClientset(
			&v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					UID:  types.UID(namespace),
					Name: namespace,
				},
				Spec:   v1.NamespaceSpec{},
				Status: v1.NamespaceStatus{},
			},
		)

		f := informers.NewSharedInformerFactory(k, 0)

		e := NewDefaultEventHandler(
			"test",
			f.Core().V1().Pods().Informer(),
			func(obj interface{}) error {
				atomic.AddInt32(&adds, 1)
				return nil
			},
			func(obj interface{}) error {
				atomic.AddInt32(&deletes, 1)
				return nil
			},
			ReceiveAllUpdates,
		)

		f.Start(stopChan)
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.Run(1, stopChan)
		}()

		wait.PollImmediate(
			500*time.Millisecond,
			5*time.Second,
			func() (bool, error) {
				return e.Synced(), nil
			},
		)

		gomega.Eventually(func() (bool, error) {
			ns, err := k.CoreV1().Namespaces().Get(context.TODO(), namespace, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			return ns != nil, nil
		}, 2).Should(gomega.BeTrue())

		pod := newPod("foo", namespace)
		_, err := k.CoreV1().Pods(namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Consistently(func() int32 { return atomic.LoadInt32(&deletes) }).Should(gomega.Equal(int32(0)), "deletes")
		gomega.Eventually(func() int32 { return atomic.LoadInt32(&adds) }).Should(gomega.Equal(int32(1)), "adds")
	})

	ginkgo.It("do not processes an add event if the pod is set for deletion", func() {
		adds := int32(0)
		deletes := int32(0)

		k := fake.NewSimpleClientset(
			&v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					UID:  types.UID(namespace),
					Name: namespace,
				},
				Spec:   v1.NamespaceSpec{},
				Status: v1.NamespaceStatus{},
			},
		)

		f := informers.NewSharedInformerFactory(k, 0)

		e := NewDefaultEventHandler(
			"test",
			f.Core().V1().Pods().Informer(),
			func(obj interface{}) error {
				atomic.AddInt32(&adds, 1)
				return nil
			},
			func(obj interface{}) error {
				atomic.AddInt32(&deletes, 1)
				return nil
			},
			ReceiveAllUpdates,
		)

		f.Start(stopChan)
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.Run(1, stopChan)
		}()

		wait.PollImmediate(
			500*time.Millisecond,
			5*time.Second,
			func() (bool, error) {
				return e.Synced(), nil
			},
		)

		gomega.Eventually(func() (bool, error) {
			ns, err := k.CoreV1().Namespaces().Get(context.TODO(), namespace, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			return ns != nil, nil
		}, 2).Should(gomega.BeTrue())

		pod := newPod("foo", namespace)
		now := metav1.Now()
		pod.SetDeletionTimestamp(&now)

		_, err := k.CoreV1().Pods(namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Consistently(func() int32 { return atomic.LoadInt32(&deletes) }).Should(gomega.Equal(int32(0)), "deletes")
		gomega.Eventually(func() int32 { return atomic.LoadInt32(&adds) }).Should(gomega.Equal(int32(0)), "adds")
	})

	ginkgo.It("adds existing pod and processes an update event", func() {
		adds := int32(0)
		deletes := int32(0)

		pod := newPod("foo", namespace)
		k := fake.NewSimpleClientset(
			[]runtime.Object{
				&v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						UID:  types.UID(namespace),
						Name: namespace,
					},
					Spec:   v1.NamespaceSpec{},
					Status: v1.NamespaceStatus{},
				},
				pod,
			}...,
		)

		f := informers.NewSharedInformerFactory(k, 0)

		e := NewDefaultEventHandler(
			"test",
			f.Core().V1().Pods().Informer(),
			func(obj interface{}) error {
				atomic.AddInt32(&adds, 1)
				return nil
			},
			func(obj interface{}) error {
				atomic.AddInt32(&deletes, 1)
				return nil
			},
			ReceiveAllUpdates,
		)

		f.Start(stopChan)
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.Run(1, stopChan)
		}()

		wait.PollImmediate(
			500*time.Millisecond,
			5*time.Second,
			func() (bool, error) {
				return e.Synced(), nil
			},
		)

		gomega.Eventually(func() (bool, error) {
			pod, err := k.CoreV1().Pods(namespace).Get(context.TODO(), "foo", metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			return pod != nil, nil
		}, 2).Should(gomega.BeTrue())

		pod.Annotations = map[string]string{"bar": "baz"}
		pod.ResourceVersion = "11"

		_, err := k.CoreV1().Pods(namespace).Update(context.TODO(), pod, metav1.UpdateOptions{})

		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Eventually(func() (bool, error) {
			pod, err := k.CoreV1().Pods(namespace).Get(context.TODO(), "foo", metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			return pod.ResourceVersion == "11", nil
		}, 2).Should(gomega.BeTrue())

		// no deletes
		gomega.Consistently(func() int32 { return atomic.LoadInt32(&deletes) }).Should(gomega.Equal(int32(0)), "deletes")
		// two updates, initial add from cache + update event
		gomega.Eventually(func() int32 { return atomic.LoadInt32(&adds) }).Should(gomega.Equal(int32(2)), "adds")
	})

	ginkgo.It("adds existing pod and do not processes an update event if it was set for deletion", func() {
		adds := int32(0)
		deletes := int32(0)

		pod := newPod("foo", namespace)
		k := fake.NewSimpleClientset(
			[]runtime.Object{
				&v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						UID:  types.UID(namespace),
						Name: namespace,
					},
					Spec:   v1.NamespaceSpec{},
					Status: v1.NamespaceStatus{},
				},
				pod,
			}...,
		)

		f := informers.NewSharedInformerFactory(k, 0)

		e := NewDefaultEventHandler(
			"test",
			f.Core().V1().Pods().Informer(),
			func(obj interface{}) error {
				atomic.AddInt32(&adds, 1)
				return nil
			},
			func(obj interface{}) error {
				atomic.AddInt32(&deletes, 1)
				return nil
			},
			ReceiveAllUpdates,
		)

		f.Start(stopChan)
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.Run(1, stopChan)
		}()

		wait.PollImmediate(
			500*time.Millisecond,
			5*time.Second,
			func() (bool, error) {
				return e.Synced(), nil
			},
		)

		gomega.Eventually(func() (bool, error) {
			pod, err := k.CoreV1().Pods(namespace).Get(context.TODO(), "foo", metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			return pod != nil, nil
		}, 2).Should(gomega.BeTrue())

		pod.Annotations = map[string]string{"bar": "baz"}
		pod.ResourceVersion = "11"
		now := metav1.Now()
		pod.SetDeletionTimestamp(&now)

		_, err := k.CoreV1().Pods(namespace).Update(context.TODO(), pod, metav1.UpdateOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		// no deletes
		gomega.Consistently(func() int32 { return atomic.LoadInt32(&deletes) }).Should(gomega.Equal(int32(0)), "deletes")
		// only initial add from cache event
		gomega.Eventually(func() int32 { return atomic.LoadInt32(&adds) }).Should(gomega.Equal(int32(1)), "adds")
	})

	ginkgo.It("adds existing pod and processes a delete event", func() {
		adds := int32(0)
		deletes := int32(0)

		k := fake.NewSimpleClientset(
			[]runtime.Object{
				&v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						UID:  types.UID(namespace),
						Name: namespace,
					},
					Spec:   v1.NamespaceSpec{},
					Status: v1.NamespaceStatus{},
				},
				newPod("foo", namespace),
			}...,
		)

		f := informers.NewSharedInformerFactory(k, 0)

		e := NewDefaultEventHandler(
			"test",
			f.Core().V1().Pods().Informer(),
			func(obj interface{}) error {
				atomic.AddInt32(&adds, 1)
				return nil
			},
			func(obj interface{}) error {
				atomic.AddInt32(&deletes, 1)
				return nil
			},
			ReceiveAllUpdates,
		)

		f.Start(stopChan)
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.Run(1, stopChan)
		}()

		wait.PollImmediate(
			500*time.Millisecond,
			5*time.Second,
			func() (bool, error) {
				return e.Synced(), nil
			},
		)

		gomega.Eventually(func() (bool, error) {
			pod, err := k.CoreV1().Pods(namespace).Get(context.TODO(), "foo", metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			return pod != nil, nil
		}, 2).Should(gomega.BeTrue())

		err := k.CoreV1().Pods(namespace).Delete(context.TODO(), "foo", *metav1.NewDeleteOptions(0))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		// initial add from the cache
		gomega.Consistently(func() int32 { return atomic.LoadInt32(&adds) }).Should(gomega.Equal(int32(1)), "adds")
		// one delete event
		gomega.Eventually(func() int32 { return atomic.LoadInt32(&deletes) }).Should(gomega.Equal(int32(1)), "deletes")
	})

	ginkgo.It("ignores updates using DiscardAllUpdates", func() {
		adds := int32(0)
		deletes := int32(0)

		pod := newPod("foo", namespace)
		k := fake.NewSimpleClientset(
			[]runtime.Object{
				&v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						UID:  types.UID(namespace),
						Name: namespace,
					},
					Spec:   v1.NamespaceSpec{},
					Status: v1.NamespaceStatus{},
				},
				pod,
			}...,
		)

		f := informers.NewSharedInformerFactory(k, 0)

		e := NewDefaultEventHandler(
			"test",
			f.Core().V1().Pods().Informer(),
			func(obj interface{}) error {
				atomic.AddInt32(&adds, 1)
				return nil
			},
			func(obj interface{}) error {
				atomic.AddInt32(&deletes, 1)
				return nil
			},
			DiscardAllUpdates,
		)

		f.Start(stopChan)
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.Run(1, stopChan)
		}()

		wait.PollImmediate(
			500*time.Millisecond,
			5*time.Second,
			func() (bool, error) {
				return e.Synced(), nil
			},
		)

		gomega.Eventually(func() (bool, error) {
			pod, err := k.CoreV1().Pods(namespace).Get(context.TODO(), "foo", metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			return pod != nil, nil
		}, 2).Should(gomega.BeTrue())

		pod.Annotations = map[string]string{"bar": "baz"}
		pod.ResourceVersion = "1"
		_, err := k.CoreV1().Pods(namespace).Update(context.TODO(), pod, metav1.UpdateOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		// no deletes
		gomega.Consistently(func() int32 { return atomic.LoadInt32(&deletes) }).Should(gomega.Equal(int32(0)), "deletes")
		// only initial add, no further updates
		gomega.Eventually(func() int32 { return atomic.LoadInt32(&adds) }).Should(gomega.Equal(int32(1)), "adds")
	})

})

var _ = ginkgo.Describe("Event Handler Internals", func() {
	ginkgo.It("should enqueue a well formed event", func() {
		k := fake.NewSimpleClientset()
		factory := informers.NewSharedInformerFactory(k, 0)
		e := eventHandler{
			name:           "test",
			informer:       factory.Core().V1().Pods().Informer(),
			deletedIndexer: cache.NewIndexer(cache.DeletionHandlingMetaNamespaceKeyFunc, cache.Indexers{}),
			workqueue:      workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
			add: func(obj interface{}) error {
				return nil
			},
			delete: func(obj interface{}) error {
				return nil
			},
			updateFilter: ReceiveAllUpdates,
		}

		obj := newPod("bar", "foo")

		e.enqueue(obj)

		gomega.Expect(e.workqueue.Len()).To(gomega.Equal(1))
	})

	ginkgo.It("should enqueue a well formed delete event", func() {
		k := fake.NewSimpleClientset()
		factory := informers.NewSharedInformerFactory(k, 0)
		e := eventHandler{
			name:           "test",
			informer:       factory.Core().V1().Pods().Informer(),
			deletedIndexer: cache.NewIndexer(cache.DeletionHandlingMetaNamespaceKeyFunc, cache.Indexers{}),
			workqueue:      workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
			add: func(obj interface{}) error {
				return nil
			},
			delete: func(obj interface{}) error {
				return nil
			},
			updateFilter: ReceiveAllUpdates,
		}

		obj := newPod("bar", "foo")

		e.enqueueDelete(obj)

		gomega.Expect(e.workqueue.Len()).To(gomega.Equal(1))

		_, exists, err := e.deletedIndexer.GetByKey("foo/bar")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(exists).To(gomega.BeTrue())
	})

	ginkgo.It("should not enqueue object set for deletion", func() {
		k := fake.NewSimpleClientset()
		factory := informers.NewSharedInformerFactory(k, 0)
		e := eventHandler{
			name:           "test",
			informer:       factory.Core().V1().Pods().Informer(),
			deletedIndexer: cache.NewIndexer(cache.DeletionHandlingMetaNamespaceKeyFunc, cache.Indexers{}),
			workqueue:      workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
			add: func(obj interface{}) error {
				return nil
			},
			delete: func(obj interface{}) error {
				return nil
			},
			updateFilter: ReceiveAllUpdates,
		}

		obj := newPod("bar", "foo")
		now := metav1.Now()
		obj.SetDeletionTimestamp(&now)

		e.enqueue(obj)

		gomega.Expect(e.workqueue.Len()).To(gomega.Equal(0))
	})
})
