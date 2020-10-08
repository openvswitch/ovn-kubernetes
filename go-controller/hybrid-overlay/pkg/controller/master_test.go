package controller

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"

	goovn "github.com/ebay/go-ovn"
	"github.com/urfave/cli/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const hoNodeCliArg string = "-no-hostsubnet-nodes=" + v1.LabelOSStable + "=windows"

func populatePortAddresses(nodeName, hybMAC, hybIP string, ovnClient goovn.Client) {
	lsp := "int-" + nodeName
	cmd, err := ovnClient.LSPAdd(nodeName, lsp)
	Expect(err).NotTo(HaveOccurred())
	err = cmd.Execute()
	Expect(err).NotTo(HaveOccurred())
	addresses := hybMAC + " " + hybIP
	addresses = strings.TrimSpace(addresses)
	cmd, err = ovnClient.LSPSetDynamicAddresses(lsp, addresses)
	Expect(err).NotTo(HaveOccurred())
	err = cmd.Execute()
	Expect(err).NotTo(HaveOccurred())
}

func newTestNode(name, os, ovnHostSubnet, hybridHostSubnet, drMAC string) v1.Node {
	annotations := make(map[string]string)
	if ovnHostSubnet != "" {
		subnetAnnotations, err := util.CreateNodeHostSubnetAnnotation(ovntest.MustParseIPNets(ovnHostSubnet))
		Expect(err).NotTo(HaveOccurred())
		for k, v := range subnetAnnotations {
			annotations[k] = fmt.Sprintf("%s", v)
		}
	}
	if hybridHostSubnet != "" {
		annotations[types.HybridOverlayNodeSubnet] = hybridHostSubnet
	}
	if drMAC != "" {
		annotations[types.HybridOverlayDRMAC] = drMAC
	}
	return v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      map[string]string{v1.LabelOSStable: os},
			Annotations: annotations,
		},
	}
}

var _ = Describe("Hybrid SDN Master Operations", func() {
	var (
		app      *cli.App
		stopChan chan struct{}
		wg       *sync.WaitGroup
		fexec    *ovntest.FakeExec
		exec     util.ExecHelper
	)

	BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags
		stopChan = make(chan struct{})
		wg = &sync.WaitGroup{}
		fexec = ovntest.NewFakeExec()

		var err error
		exec, err = util.NewExecHelper(fexec)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		close(stopChan)
		wg.Wait()
	})

	const hybridOverlayClusterCIDR string = "11.1.0.0/16/24"
	It("allocates and assigns a hybrid-overlay subnet to a Windows node that doesn't have one", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				nodeName   string = "node1"
				nodeSubnet string = "11.1.0.0/24"
			)

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{
					newTestNode(nodeName, "windows", "", "", ""),
				},
			})

			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)
			mockOVNNBClient := ovntest.NewMockOVNClient(goovn.DBNB)
			mockOVNSBClient := ovntest.NewMockOVNClient(goovn.DBSB)

			m, err := NewMaster(
				&kube.Kube{KClient: fakeClient},
				exec,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Namespaces().Informer(),
				f.Core().V1().Pods().Informer(),
				mockOVNNBClient,
				mockOVNSBClient,
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			f.Start(stopChan)
			wg.Add(1)
			go func() {
				defer wg.Done()
				m.Run(stopChan)
			}()
			f.WaitForCacheSync(stopChan)

			// Windows node should be allocated a subnet
			Eventually(func() (map[string]string, error) {
				updatedNode, err := fakeClient.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
				if err != nil {
					return nil, err
				}
				return updatedNode.Annotations, nil
			}, 2).Should(HaveKeyWithValue(types.HybridOverlayNodeSubnet, nodeSubnet))

			Eventually(func() error {
				updatedNode, err := fakeClient.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
				if err != nil {
					return err
				}
				_, err = util.ParseNodeHostSubnetAnnotation(updatedNode)
				return err
			}, 2).Should(MatchError(fmt.Sprintf("node %q has no \"k8s.ovn.org/node-subnets\" annotation", nodeName)))

			Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			return nil
		}

		err := app.Run([]string{
			app.Name,
			"-loglevel=5",
			"-no-hostsubnet-nodes=" + v1.LabelOSStable + "=windows",
			"-enable-hybrid-overlay",
			"-hybrid-overlay-cluster-subnets=" + hybridOverlayClusterCIDR,
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("sets up and cleans up a Linux node with a OVN hostsubnet annotation", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				nodeName   string = "node1"
				nodeSubnet string = "10.1.2.0/24"
				nodeHOIP   string = "10.1.2.3"
				nodeHOMAC  string = "0a:58:0a:01:02:03"
			)

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{
					newTestNode(nodeName, "linux", nodeSubnet, "", ""),
				},
			})

			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			mockOVNNBClient := ovntest.NewMockOVNClient(goovn.DBNB)
			mockOVNSBClient := ovntest.NewMockOVNClient(goovn.DBSB)

			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)
			m, err := NewMaster(
				&kube.Kube{KClient: fakeClient},
				exec,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Namespaces().Informer(),
				f.Core().V1().Pods().Informer(),
				mockOVNNBClient,
				mockOVNSBClient,
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			// #1 node add
			addLinuxNodeCommands(fexec, nodeHOMAC, nodeName, nodeHOIP)
			// #2 comes because we set the ho dr gw mac annotation in #1
			addLinuxNodeCommands(fexec, nodeHOMAC, nodeName, nodeHOIP)

			f.Start(stopChan)
			wg.Add(1)
			go func() {
				defer wg.Done()
				m.Run(stopChan)
			}()
			f.WaitForCacheSync(stopChan)

			Eventually(func() (map[string]string, error) {
				updatedNode, err := fakeClient.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
				if err != nil {
					return nil, err
				}
				return updatedNode.Annotations, nil
			}, 2).Should(HaveKeyWithValue(types.HybridOverlayDRMAC, nodeHOMAC))

			// Test that deleting the node cleans up the OVN objects
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 -- --if-exists lsp-del int-node1",
			})

			err = fakeClient.CoreV1().Nodes().Delete(context.TODO(), nodeName, *metav1.NewDeleteOptions(0))
			Expect(err).NotTo(HaveOccurred())

			Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			return nil
		}

		err := app.Run([]string{
			app.Name,
			"-loglevel=5",
			"-enable-hybrid-overlay",
			"-hybrid-overlay-cluster-subnets=" + hybridOverlayClusterCIDR,
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("handles a Linux node with no annotation but an existing port", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				nodeName   string = "node1"
				nodeSubnet string = "10.1.2.0/24"
				nodeHOIP   string = "10.1.2.3"
				nodeHOMAC  string = "00:00:00:52:19:d2"
			)

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{
					newTestNode(nodeName, "linux", nodeSubnet, "", ""),
				},
			})

			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			mockOVNNBClient := ovntest.NewMockOVNClient(goovn.DBNB)
			mockOVNSBClient := ovntest.NewMockOVNClient(goovn.DBSB)

			populatePortAddresses(nodeName, nodeHOMAC, nodeHOIP, mockOVNNBClient)

			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)
			m, err := NewMaster(
				&kube.Kube{KClient: fakeClient},
				exec,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Namespaces().Informer(),
				f.Core().V1().Pods().Informer(),
				mockOVNNBClient,
				mockOVNSBClient,
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			f.Start(stopChan)
			wg.Add(1)
			go func() {
				defer wg.Done()
				m.Run(stopChan)
			}()
			f.WaitForCacheSync(stopChan)

			Eventually(func() (map[string]string, error) {
				updatedNode, err := fakeClient.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
				if err != nil {
					return nil, err
				}
				return updatedNode.Annotations, nil
			}, 2).Should(HaveKeyWithValue(types.HybridOverlayDRMAC, nodeHOMAC))
			return nil
		}
		err := app.Run([]string{
			app.Name,
			"-loglevel=5",
			"-enable-hybrid-overlay",
			"-hybrid-overlay-cluster-subnets=" + hybridOverlayClusterCIDR,
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("cleans up a Linux node when the OVN hostsubnet annotation is removed", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				nodeName   string = "node1"
				nodeSubnet string = "10.1.2.0/24"
				nodeHOIP   string = "10.1.2.3"
				nodeHOMAC  string = "00:00:00:52:19:d2"
			)

			fakeClient := fake.NewSimpleClientset(&v1.NodeList{
				Items: []v1.Node{
					newTestNode(nodeName, "linux", nodeSubnet, "", nodeHOMAC),
				},
			})

			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 -- --if-exists lsp-del int-node1",
			})

			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)
			mockOVNNBClient := ovntest.NewMockOVNClient(goovn.DBNB)
			mockOVNSBClient := ovntest.NewMockOVNClient(goovn.DBSB)
			m, err := NewMaster(
				&kube.Kube{KClient: fakeClient},
				exec,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Namespaces().Informer(),
				f.Core().V1().Pods().Informer(),
				mockOVNNBClient,
				mockOVNSBClient,
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			populatePortAddresses(nodeName, nodeHOMAC, nodeHOIP, mockOVNNBClient)

			f.Start(stopChan)
			wg.Add(1)
			go func() {
				defer wg.Done()
				m.Run(stopChan)
			}()
			f.WaitForCacheSync(stopChan)

			k := &kube.Kube{KClient: fakeClient}
			updatedNode, err := k.GetNode(nodeName)
			Expect(err).NotTo(HaveOccurred())

			nodeAnnotator := kube.NewNodeAnnotator(k, updatedNode)
			util.DeleteNodeHostSubnetAnnotation(nodeAnnotator)
			err = nodeAnnotator.Run()
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() (map[string]string, error) {
				updatedNode, err = k.GetNode(nodeName)
				if err != nil {
					return nil, err
				}
				return updatedNode.Annotations, nil
			}, 5).ShouldNot(HaveKey(types.HybridOverlayDRMAC))

			Eventually(fexec.CalledMatchesExpected, 2).Should(BeTrue(), fexec.ErrorDesc)
			return nil
		}

		err := app.Run([]string{
			app.Name,
			"-loglevel=5",
			"-enable-hybrid-overlay",
			"-hybrid-overlay-cluster-subnets=" + hybridOverlayClusterCIDR,
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("copies namespace annotations when a pod is added", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				nsName     string = "nstest"
				nsVTEP            = "1.1.1.1"
				nsExGw            = "2.2.2.2"
				nodeName   string = "node1"
				nodeSubnet string = "10.1.2.0/24"
				nodeHOIP   string = "10.1.2.3"
				nodeHOMAC  string = "00:00:00:52:19:d2"
				pod1Name   string = "pod1"
				pod1IP     string = "1.2.3.5"
				pod1CIDR   string = pod1IP + "/24"
				pod1MAC    string = "aa:bb:cc:dd:ee:ff"
			)

			ns := &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					UID:  k8stypes.UID(nsName),
					Name: nsName,
					Annotations: map[string]string{
						types.HybridOverlayVTEP:       nsVTEP,
						types.HybridOverlayExternalGw: nsExGw,
					},
				},
				Spec:   v1.NamespaceSpec{},
				Status: v1.NamespaceStatus{},
			}
			fakeClient := fake.NewSimpleClientset([]runtime.Object{
				ns,
				createPod(nsName, pod1Name, nodeName, pod1CIDR, pod1MAC),
				&v1.NodeList{Items: []v1.Node{newTestNode(nodeName, "linux", nodeSubnet, "", nodeHOMAC)}},
			}...)

			fexec := ovntest.NewFakeExec()
			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())
			exec, err := util.NewExecHelper(fexec)
			Expect(err).NotTo(HaveOccurred())

			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)
			mockOVNNBClient := ovntest.NewMockOVNClient(goovn.DBNB)
			mockOVNSBClient := ovntest.NewMockOVNClient(goovn.DBSB)
			m, err := NewMaster(
				&kube.Kube{KClient: fakeClient},
				exec,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Namespaces().Informer(),
				f.Core().V1().Pods().Informer(),
				mockOVNNBClient,
				mockOVNSBClient,
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			populatePortAddresses(nodeName, nodeHOMAC, nodeHOIP, mockOVNNBClient)

			f.Start(stopChan)
			wg.Add(1)
			go func() {
				defer wg.Done()
				m.Run(stopChan)
			}()
			f.WaitForCacheSync(stopChan)

			Eventually(func() error {
				pod, err := fakeClient.CoreV1().Pods(nsName).Get(context.TODO(), pod1Name, metav1.GetOptions{})
				if err != nil {
					return err
				}
				if pod.Annotations[types.HybridOverlayVTEP] != nsVTEP {
					return fmt.Errorf("error with annotation %s. expected: %s, got: %s", types.HybridOverlayVTEP, nsVTEP, pod.Annotations[types.HybridOverlayVTEP])
				}
				if pod.Annotations[types.HybridOverlayExternalGw] != nsExGw {
					return fmt.Errorf("error with annotation %s. expected: %s, got: %s", types.HybridOverlayVTEP, nsExGw, pod.Annotations[types.HybridOverlayExternalGw])
				}
				return nil
			}, 2).Should(Succeed())

			return nil
		}

		err := app.Run([]string{
			app.Name,
			"-loglevel=5",
			"-enable-hybrid-overlay",
			"-hybrid-overlay-cluster-subnets=" + hybridOverlayClusterCIDR,
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("update pod annotations when a namespace is updated", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				nsName        string = "nstest"
				nsVTEP        string = "1.1.1.1"
				nsVTEPUpdated string = "3.3.3.3"
				nsExGw        string = "2.2.2.2"
				nsExGwUpdated string = "4.4.4.4"
				nodeName      string = "node1"
				nodeSubnet    string = "10.1.2.0/24"
				nodeHOMAC     string = "00:00:00:52:19:d2"
				nodeHOIP      string = "10.1.2.3"
				pod1Name      string = "pod1"
				pod1IP        string = "1.2.3.5"
				pod1CIDR      string = pod1IP + "/24"
				pod1MAC       string = "aa:bb:cc:dd:ee:ff"
			)

			ns := &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					UID:  k8stypes.UID(nsName),
					Name: nsName,
					Annotations: map[string]string{
						types.HybridOverlayVTEP:       nsVTEP,
						types.HybridOverlayExternalGw: nsExGw,
					},
				},
				Spec:   v1.NamespaceSpec{},
				Status: v1.NamespaceStatus{},
			}
			fakeClient := fake.NewSimpleClientset([]runtime.Object{
				ns,
				&v1.NodeList{Items: []v1.Node{newTestNode(nodeName, "linux", nodeSubnet, "", nodeHOMAC)}},
				createPod(nsName, pod1Name, nodeName, pod1CIDR, pod1MAC),
			}...)

			addLinuxNodeCommands(fexec, nodeHOMAC, nodeName, nodeHOIP)
			_, err := config.InitConfig(ctx, nil, nil)
			Expect(err).NotTo(HaveOccurred())

			f := informers.NewSharedInformerFactory(fakeClient, informer.DefaultResyncInterval)

			k := &kube.Kube{KClient: fakeClient}
			mockOVNNBClient := ovntest.NewMockOVNClient(goovn.DBNB)
			mockOVNSBClient := ovntest.NewMockOVNClient(goovn.DBSB)
			m, err := NewMaster(
				k,
				exec,
				f.Core().V1().Nodes().Informer(),
				f.Core().V1().Namespaces().Informer(),
				f.Core().V1().Pods().Informer(),
				mockOVNNBClient,
				mockOVNSBClient,
				informer.NewTestEventHandler,
			)
			Expect(err).NotTo(HaveOccurred())

			f.Start(stopChan)
			wg.Add(1)
			go func() {
				defer wg.Done()
				m.Run(stopChan)
			}()
			f.WaitForCacheSync(stopChan)

			updatedNs, err := fakeClient.CoreV1().Namespaces().Get(context.TODO(), nsName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			nsAnnotator := kube.NewNamespaceAnnotator(k, updatedNs)
			nsAnnotator.Set(types.HybridOverlayVTEP, nsVTEPUpdated)
			nsAnnotator.Set(types.HybridOverlayExternalGw, nsExGwUpdated)
			err = nsAnnotator.Run()
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() error {
				pod, err := fakeClient.CoreV1().Pods(nsName).Get(context.TODO(), pod1Name, metav1.GetOptions{})
				if err != nil {
					return err
				}
				if reflect.DeepEqual(pod.Annotations[types.HybridOverlayVTEP], nsVTEP) {
					return fmt.Errorf("error with annotation %s. expected: %s, got: %s", types.HybridOverlayVTEP, nsVTEPUpdated, pod.Annotations[types.HybridOverlayVTEP])
				}
				if reflect.DeepEqual(pod.Annotations[types.HybridOverlayExternalGw], nsExGw) {
					return fmt.Errorf("error with annotation %s. expected: %s, got: %s", types.HybridOverlayExternalGw, nsExGwUpdated, pod.Annotations[types.HybridOverlayExternalGw])
				}
				return nil
			}, 2).Should(Succeed())

			return nil
		}

		err := app.Run([]string{
			app.Name,
			"-loglevel=5",
			"-enable-hybrid-overlay",
			"-hybrid-overlay-cluster-subnets=" + hybridOverlayClusterCIDR,
		})
		Expect(err).NotTo(HaveOccurred())
	})
})

func addLinuxNodeCommands(fexec *ovntest.FakeExec, nodeHOMAC, nodeName, nodeHOIP string) {
	fexec.AddFakeCmdsNoOutputNoError([]string{
		// Setting the mac on the lsp
		"ovn-nbctl --timeout=15 -- " +
			"--may-exist lsp-add node1 int-node1 -- " +
			"lsp-set-addresses int-node1 " + nodeHOMAC,
	})

	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 lsp-list " + nodeName,
		Output: "29df5ce5-2802-4ee5-891f-4fb27ca776e9 (" + util.K8sPrefix + nodeName + ")",
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 -- --if-exists set logical_switch " + nodeName + " other-config:exclude_ips=" + nodeHOIP,
	})
}
