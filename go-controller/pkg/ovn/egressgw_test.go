package ovn

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	nettypes "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"

	"github.com/urfave/cli/v2"

	v1 "k8s.io/api/core/v1"

	"github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("OVN Egress Gateway Operations", func() {
	const (
		namespaceName = "namespace1"
	)
	var (
		app     *cli.App
		fakeOvn *FakeOVN
		fExec   *ovntest.FakeExec
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fExec = ovntest.NewLooseCompareFakeExec()
		fakeOvn = NewFakeOVN(fExec)
	})

	ginkgo.AfterEach(func() {
		fakeOvn.shutdown()
	})

	ginkgo.Context("on setting namespace gateway annotations", func() {

		table.DescribeTable("reconciles an new pod with namespace single exgw annotation already set", func(bfd bool, expectedNbctl string) {
			app.Action = func(ctx *cli.Context) error {

				namespaceT := *newNamespace("namespace1")
				namespaceT.Annotations = map[string]string{"k8s.ovn.org/routing-external-gws": "9.0.0.1"}
				if bfd {
					namespaceT.Annotations["k8s.ovn.org/bfd-enabled"] = ""
				}
				t := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespaceT.Name,
				)

				t.baseCmds(fExec)
				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespaceT,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(t.namespace, t.podName, t.nodeName, t.podIP),
						},
					},
				)
				t.populateLogicalSwitchCache(fakeOvn)
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    expectedNbctl,
					Output: "\n",
				})
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods(&sync.WaitGroup{})

				gomega.Eventually(func() string { return getPodAnnotations(fakeOvn.fakeClient.KubeClient, t.namespace, t.podName) }, 2).Should(gomega.MatchJSON(`{"default": {"ip_addresses":["` + t.podIP + `/24"], "mac_address":"` + t.podMAC + `", "gateway_ips": ["` + t.nodeGWIP + `"], "ip_address":"` + t.podIP + `/24", "gateway_ip": "` + t.nodeGWIP + `"}}`))
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}, table.Entry("No BFD", false, "ovn-nbctl --timeout=15 --may-exist --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.1"),
			table.Entry("BFD Enabled", true, "ovn-nbctl --timeout=15 --may-exist --bfd --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.1 rtoe-GR_node1"))

		table.DescribeTable("reconciles an new pod with namespace double exgw annotation already set", func(bfd bool, expectedNbctl []string) {

			app.Action = func(ctx *cli.Context) error {

				namespaceT := *newNamespace("namespace1")
				namespaceT.Annotations = map[string]string{"k8s.ovn.org/routing-external-gws": "9.0.0.1,9.0.0.2"}
				if bfd {
					namespaceT.Annotations["k8s.ovn.org/bfd-enabled"] = ""
				}
				t := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespaceT.Name,
				)

				t.baseCmds(fExec)
				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespaceT,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(t.namespace, t.podName, t.nodeName, t.podIP),
						},
					},
				)
				t.populateLogicalSwitchCache(fakeOvn)
				for _, cmd := range expectedNbctl {
					fExec.AddFakeCmd(&ovntest.ExpectedCmd{
						Cmd:    cmd,
						Output: "\n",
					})
				}

				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods(&sync.WaitGroup{})

				gomega.Eventually(func() string { return getPodAnnotations(fakeOvn.fakeClient.KubeClient, t.namespace, t.podName) }, 2).Should(gomega.MatchJSON(`{"default": {"ip_addresses":["` + t.podIP + `/24"], "mac_address":"` + t.podMAC + `", "gateway_ips": ["` + t.nodeGWIP + `"], "ip_address":"` + t.podIP + `/24", "gateway_ip": "` + t.nodeGWIP + `"}}`))
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		},
			table.Entry("No BFD", false, []string{
				"ovn-nbctl --timeout=15 --may-exist --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.1",
				"ovn-nbctl --timeout=15 --may-exist --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.2",
			}),
			table.Entry("BFD Enabled", true, []string{
				"ovn-nbctl --timeout=15 --may-exist --bfd --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.1 rtoe-GR_node1",
				"ovn-nbctl --timeout=15 --may-exist --bfd --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.2 rtoe-GR_node1",
			}),
		)

		table.DescribeTable("reconciles deleting a pod with namespace double exgw annotation already set",
			func(bfd bool,
				nbctlOnAddCommands []string,
				nbctlOnDelCommands []struct {
					command string
					res     string
				}) {
				app.Action = func(ctx *cli.Context) error {

					namespaceT := *newNamespace("namespace1")
					namespaceT.Annotations = map[string]string{"k8s.ovn.org/routing-external-gws": "9.0.0.1,9.0.0.2"}
					if bfd {
						namespaceT.Annotations["k8s.ovn.org/bfd-enabled"] = ""
					}
					t := newTPod(
						"node1",
						"10.128.1.0/24",
						"10.128.1.2",
						"10.128.1.1",
						"myPod",
						"10.128.1.3",
						"0a:58:0a:80:01:03",
						namespaceT.Name,
					)

					t.baseCmds(fExec)
					fakeOvn.start(ctx,
						&v1.NamespaceList{
							Items: []v1.Namespace{
								namespaceT,
							},
						},
						&v1.PodList{
							Items: []v1.Pod{
								*newPod(t.namespace, t.podName, t.nodeName, t.podIP),
							},
						},
					)
					t.populateLogicalSwitchCache(fakeOvn)
					for _, cmd := range nbctlOnAddCommands {
						fExec.AddFakeCmd(&ovntest.ExpectedCmd{
							Cmd:    cmd,
							Output: "\n",
						})
					}
					fakeOvn.controller.WatchNamespaces()
					fakeOvn.controller.WatchPods(&sync.WaitGroup{})

					gomega.Eventually(func() string { return getPodAnnotations(fakeOvn.fakeClient.KubeClient, t.namespace, t.podName) }, 2).Should(gomega.MatchJSON(`{"default": {"ip_addresses":["` + t.podIP + `/24"], "mac_address":"` + t.podMAC + `", "gateway_ips": ["` + t.nodeGWIP + `"], "ip_address":"` + t.podIP + `/24", "gateway_ip": "` + t.nodeGWIP + `"}}`))
					gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

					for _, cmd := range nbctlOnDelCommands {
						fExec.AddFakeCmd(&ovntest.ExpectedCmd{
							Cmd:    cmd.command,
							Output: cmd.res,
						})
					}

					err := fakeOvn.fakeClient.KubeClient.CoreV1().Pods(t.namespace).Delete(context.TODO(), t.podName, *metav1.NewDeleteOptions(0))
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
					return nil
				}
				err := app.Run([]string{app.Name})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			},
			table.Entry("No BFD", false, []string{
				"ovn-nbctl --timeout=15 --may-exist --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.1",
				"ovn-nbctl --timeout=15 --may-exist --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.2",
			},
				[]struct {
					command string
					res     string
				}{
					{"ovn-nbctl --timeout=15 --if-exists --policy=src-ip lr-route-del GR_node1 10.128.1.3/32 9.0.0.1", "\n"},
					{"ovn-nbctl --timeout=15 --if-exists --policy=src-ip lr-route-del GR_node1 10.128.1.3/32 9.0.0.2", "\n"},
					{"ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=bfd find Logical_Router_Static_Route output_port=rtoe-GR_node1 nexthop=9.0.0.1 bfd!=[]", "\n"},
					{"ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=bfd find Logical_Router_Static_Route output_port=rtoe-GR_node1 nexthop=9.0.0.2 bfd!=[]", "\n"},
					{"ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=_uuid find BFD logical_port=rtoe-GR_node1 dst_ip=9.0.0.1", "\n"},
					{"ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=_uuid find BFD logical_port=rtoe-GR_node1 dst_ip=9.0.0.2", "\n"},
				},
			),
			table.Entry("BFD", true, []string{
				"ovn-nbctl --timeout=15 --may-exist --bfd --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.1 rtoe-GR_node1",
				"ovn-nbctl --timeout=15 --may-exist --bfd --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.2 rtoe-GR_node1",
			},
				[]struct {
					command string
					res     string
				}{
					{"ovn-nbctl --timeout=15 --if-exists --policy=src-ip lr-route-del GR_node1 10.128.1.3/32 9.0.0.1", "\n"},
					{"ovn-nbctl --timeout=15 --if-exists --policy=src-ip lr-route-del GR_node1 10.128.1.3/32 9.0.0.2", "\n"},
					{"ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=bfd find Logical_Router_Static_Route output_port=rtoe-GR_node1 nexthop=9.0.0.1 bfd!=[]", "foouid\n"},
					{"ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=bfd find Logical_Router_Static_Route output_port=rtoe-GR_node1 nexthop=9.0.0.2 bfd!=[]", "\n"},
					{"ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=_uuid find BFD logical_port=rtoe-GR_node1 dst_ip=9.0.0.2", "bfduuid\n"},
					{"ovn-nbctl --timeout=15 --if-exists destroy BFD bfduuid", ""},
				}),
		)

		table.DescribeTable("reconciles deleting a exgw namespace with active pod",
			func(bfd bool,
				nbctlCommands []string,
				nbctlOnDelCommands []struct {
					command string
					res     string
				}) {
				app.Action = func(ctx *cli.Context) error {

					namespaceT := *newNamespace("namespace1")
					namespaceT.Annotations = map[string]string{"k8s.ovn.org/routing-external-gws": "9.0.0.1,9.0.0.2"}
					if bfd {
						namespaceT.Annotations["k8s.ovn.org/bfd-enabled"] = ""
					}
					t := newTPod(
						"node1",
						"10.128.1.0/24",
						"10.128.1.2",
						"10.128.1.1",
						"myPod",
						"10.128.1.3",
						"0a:58:0a:80:01:03",
						namespaceT.Name,
					)

					t.baseCmds(fExec)
					fakeOvn.start(ctx,
						&v1.NamespaceList{
							Items: []v1.Namespace{
								namespaceT,
							},
						},
						&v1.PodList{
							Items: []v1.Pod{
								*newPod(t.namespace, t.podName, t.nodeName, t.podIP),
							},
						},
					)
					t.populateLogicalSwitchCache(fakeOvn)
					for _, cmd := range nbctlCommands {
						fExec.AddFakeCmd(&ovntest.ExpectedCmd{
							Cmd:    cmd,
							Output: "\n",
						})
					}

					fakeOvn.controller.WatchNamespaces()
					fakeOvn.controller.WatchPods(&sync.WaitGroup{})

					gomega.Eventually(func() string { return getPodAnnotations(fakeOvn.fakeClient.KubeClient, t.namespace, t.podName) }, 2).Should(gomega.MatchJSON(`{"default": {"ip_addresses":["` + t.podIP + `/24"], "mac_address":"` + t.podMAC + `", "gateway_ips": ["` + t.nodeGWIP + `"], "ip_address":"` + t.podIP + `/24", "gateway_ip": "` + t.nodeGWIP + `"}}`))
					gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

					for _, cmd := range nbctlOnDelCommands {
						fExec.AddFakeCmd(&ovntest.ExpectedCmd{
							Cmd:    cmd.command,
							Output: cmd.res,
						})
					}

					err := fakeOvn.fakeClient.KubeClient.CoreV1().Namespaces().Delete(context.TODO(), t.namespace, *metav1.NewDeleteOptions(0))
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
					return nil
				}

				err := app.Run([]string{app.Name})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			},
			table.Entry("No BFD", false, []string{
				"ovn-nbctl --timeout=15 --may-exist --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.1",
				"ovn-nbctl --timeout=15 --may-exist --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.2",
			}, []struct {
				command string
				res     string
			}{
				{"ovn-nbctl --timeout=15 --if-exists --policy=src-ip lr-route-del GR_node1 10.128.1.3/32 9.0.0.1", "\n"},
				{"ovn-nbctl --timeout=15 --if-exists --policy=src-ip lr-route-del GR_node1 10.128.1.3/32 9.0.0.2", "\n"},
				{"ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=bfd find Logical_Router_Static_Route output_port=rtoe-GR_node1 nexthop=9.0.0.1 bfd!=[]", "\n"},
				{"ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=bfd find Logical_Router_Static_Route output_port=rtoe-GR_node1 nexthop=9.0.0.2 bfd!=[]", "\n"},
				{"ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=_uuid find BFD logical_port=rtoe-GR_node1 dst_ip=9.0.0.1", "\n"},
				{"ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=_uuid find BFD logical_port=rtoe-GR_node1 dst_ip=9.0.0.2", "\n"},
			}),
			table.Entry("BFD", true, []string{
				"ovn-nbctl --timeout=15 --may-exist --bfd --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.1 rtoe-GR_node1",
				"ovn-nbctl --timeout=15 --may-exist --bfd --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.2 rtoe-GR_node1",
			}, []struct {
				command string
				res     string
			}{
				{"ovn-nbctl --timeout=15 --if-exists --policy=src-ip lr-route-del GR_node1 10.128.1.3/32 9.0.0.1", "\n"},
				{"ovn-nbctl --timeout=15 --if-exists --policy=src-ip lr-route-del GR_node1 10.128.1.3/32 9.0.0.2", "\n"},
				{"ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=bfd find Logical_Router_Static_Route output_port=rtoe-GR_node1 nexthop=9.0.0.1 bfd!=[]", "foouid\n"},
				{"ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=bfd find Logical_Router_Static_Route output_port=rtoe-GR_node1 nexthop=9.0.0.2 bfd!=[]", "\n"},
				{"ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=_uuid find BFD logical_port=rtoe-GR_node1 dst_ip=9.0.0.2", "bfduuid\n"},
				{"ovn-nbctl --timeout=15 --if-exists destroy BFD bfduuid", ""},
			}))
	})

	ginkgo.Context("on setting pod gateway annotations", func() {
		table.DescribeTable("reconciles a host networked pod acting as a exgw for another namespace for new pod", func(bfd bool, nbctlCommand string) {
			app.Action = func(ctx *cli.Context) error {

				namespaceT := *newNamespace("namespace1")
				namespaceX := *newNamespace("namespace2")
				t := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespaceT.Name,
				)
				gwPod := *newPod(namespaceX.Name, "gwPod", "node2", "9.0.0.1")
				gwPod.Annotations = map[string]string{"k8s.ovn.org/routing-namespaces": namespaceT.Name}
				if bfd {
					gwPod.Annotations["k8s.ovn.org/bfd-enabled"] = ""
				}
				gwPod.Spec.HostNetwork = true
				t.baseCmds(fExec)
				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespaceT, namespaceX,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							gwPod,
						},
					},
				)
				t.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods(&sync.WaitGroup{})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    nbctlCommand,
					Output: "\n",
				})
				_, err := fakeOvn.fakeClient.KubeClient.CoreV1().Pods(t.namespace).Create(context.TODO(), newPod(t.namespace, t.podName, t.nodeName, t.podIP), metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(func() string { return getPodAnnotations(fakeOvn.fakeClient.KubeClient, t.namespace, t.podName) }, 2).Should(gomega.MatchJSON(`{"default": {"ip_addresses":["` + t.podIP + `/24"], "mac_address":"` + t.podMAC + `", "gateway_ips": ["` + t.nodeGWIP + `"], "ip_address":"` + t.podIP + `/24", "gateway_ip": "` + t.nodeGWIP + `"}}`))
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}, table.Entry("No BFD", false, "ovn-nbctl --timeout=15 --may-exist --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.1"),
			table.Entry("BFD", true, "ovn-nbctl --timeout=15 --may-exist --bfd --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.1 rtoe-GR_node1"),
		)

		table.DescribeTable("reconciles a host networked pod acting as a exgw for another namespace for existing pod", func(bfd bool, nbctlCommand string) {
			app.Action = func(ctx *cli.Context) error {

				namespaceT := *newNamespace("namespace1")
				namespaceX := *newNamespace("namespace2")
				t := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespaceT.Name,
				)
				gwPod := *newPod(namespaceX.Name, "gwPod", "node2", "9.0.0.1")
				gwPod.Annotations = map[string]string{"k8s.ovn.org/routing-namespaces": namespaceT.Name}
				if bfd {
					gwPod.Annotations["k8s.ovn.org/bfd-enabled"] = ""
				}
				gwPod.Spec.HostNetwork = true
				t.baseCmds(fExec)
				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespaceT, namespaceX,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(t.namespace, t.podName, t.nodeName, t.podIP),
						},
					},
				)
				t.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods(&sync.WaitGroup{})
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    nbctlCommand,
					Output: "\n",
				})
				_, err := fakeOvn.fakeClient.KubeClient.CoreV1().Pods(namespaceX.Name).Create(context.TODO(), &gwPod, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}, table.Entry("No BFD", false, "ovn-nbctl --timeout=15 --may-exist --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.1"),
			table.Entry("BFD", true, "ovn-nbctl --timeout=15 --may-exist --bfd --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.1 rtoe-GR_node1"),
		)

		table.DescribeTable("reconciles a multus networked pod acting as a exgw for another namespace for new pod", func(bfd bool, nbctlCommand string) {
			app.Action = func(ctx *cli.Context) error {
				ns := nettypes.NetworkStatus{Name: "dummy", IPs: []string{"11.0.0.1"}}
				networkStatuses := []nettypes.NetworkStatus{ns}
				nsEncoded, err := json.Marshal(networkStatuses)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				namespaceT := *newNamespace("namespace1")
				namespaceX := *newNamespace("namespace2")
				t := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespaceT.Name,
				)
				gwPod := *newPod(namespaceX.Name, "gwPod", "node2", "9.0.0.1")
				gwPod.Annotations = map[string]string{
					"k8s.ovn.org/routing-namespaces":    namespaceT.Name,
					"k8s.ovn.org/routing-network":       "dummy",
					"k8s.v1.cni.cncf.io/network-status": string(nsEncoded),
				}
				if bfd {
					gwPod.Annotations["k8s.ovn.org/bfd-enabled"] = ""
				}
				gwPod.Spec.HostNetwork = true
				t.baseCmds(fExec)
				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespaceT, namespaceX,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							gwPod,
						},
					},
				)
				t.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods(&sync.WaitGroup{})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    nbctlCommand,
					Output: "\n",
				})
				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(t.namespace).Create(context.TODO(), newPod(t.namespace, t.podName, t.nodeName, t.podIP), metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(func() string { return getPodAnnotations(fakeOvn.fakeClient.KubeClient, t.namespace, t.podName) }, 2).Should(gomega.MatchJSON(`{"default": {"ip_addresses":["` + t.podIP + `/24"], "mac_address":"` + t.podMAC + `", "gateway_ips": ["` + t.nodeGWIP + `"], "ip_address":"` + t.podIP + `/24", "gateway_ip": "` + t.nodeGWIP + `"}}`))
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}, table.Entry("No BFD", false, "ovn-nbctl --timeout=15 --may-exist --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 11.0.0.1"),
			table.Entry("BFD", true, "ovn-nbctl --timeout=15 --may-exist --bfd --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 11.0.0.1 rtoe-GR_node1"),
		)

		table.DescribeTable("reconciles deleting a host networked pod acting as a exgw for another namespace for existing pod",
			func(bfd bool,
				nbctlCommand string,
				nbctlOnDelCommands []struct {
					command string
					res     string
				}) {
				app.Action = func(ctx *cli.Context) error {

					namespaceT := *newNamespace("namespace1")
					namespaceX := *newNamespace("namespace2")
					t := newTPod(
						"node1",
						"10.128.1.0/24",
						"10.128.1.2",
						"10.128.1.1",
						"myPod",
						"10.128.1.3",
						"0a:58:0a:80:01:03",
						namespaceT.Name,
					)
					gwPod := *newPod(namespaceX.Name, "gwPod", "node2", "9.0.0.1")
					gwPod.Annotations = map[string]string{"k8s.ovn.org/routing-namespaces": namespaceT.Name}
					if bfd {
						gwPod.Annotations["k8s.ovn.org/bfd-enabled"] = ""
					}
					gwPod.Spec.HostNetwork = true
					t.baseCmds(fExec)
					fakeOvn.start(ctx,
						&v1.NamespaceList{
							Items: []v1.Namespace{
								namespaceT, namespaceX,
							},
						},
						&v1.PodList{
							Items: []v1.Pod{
								*newPod(t.namespace, t.podName, t.nodeName, t.podIP),
							},
						},
					)
					t.populateLogicalSwitchCache(fakeOvn)
					fakeOvn.controller.WatchNamespaces()
					fakeOvn.controller.WatchPods(&sync.WaitGroup{})
					gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
					fExec.AddFakeCmd(&ovntest.ExpectedCmd{
						Cmd:    nbctlCommand,
						Output: "\n",
					})
					_, err := fakeOvn.fakeClient.KubeClient.CoreV1().Pods(namespaceX.Name).Create(context.TODO(), &gwPod, metav1.CreateOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
					// delete the GW
					for _, c := range nbctlOnDelCommands {
						fExec.AddFakeCmd(&ovntest.ExpectedCmd{
							Cmd:    c.command,
							Output: c.res,
						})
					}

					err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(namespaceX.Name).Delete(context.TODO(), gwPod.Name, *metav1.NewDeleteOptions(0))
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
					return nil
				}

				err := app.Run([]string{app.Name})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			},
			table.Entry("No BFD", false,
				"ovn-nbctl --timeout=15 --may-exist --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.1",
				[]struct {
					command string
					res     string
				}{
					{"ovn-nbctl --timeout=15 --if-exists --policy=src-ip lr-route-del GR_node1 10.128.1.3/32 9.0.0.1", "\n"},
					{"ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=bfd find Logical_Router_Static_Route output_port=rtoe-GR_node1 nexthop=9.0.0.1 bfd!=[]", "\n"},
					{"ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=_uuid find BFD logical_port=rtoe-GR_node1 dst_ip=9.0.0.1", "\n"},
				}),
			table.Entry("BFD", true, "ovn-nbctl --timeout=15 --may-exist --bfd --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.1 rtoe-GR_node1",
				[]struct {
					command string
					res     string
				}{
					{"ovn-nbctl --timeout=15 --if-exists --policy=src-ip lr-route-del GR_node1 10.128.1.3/32 9.0.0.1", "\n"},
					{"ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=bfd find Logical_Router_Static_Route output_port=rtoe-GR_node1 nexthop=9.0.0.1 bfd!=[]", "\n"},
					{"ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=_uuid find BFD logical_port=rtoe-GR_node1 dst_ip=9.0.0.1", "\n"},
				}))
	})
	ginkgo.Context("on using bfd", func() {
		ginkgo.It("should enable bfd only on the namespace gw when set", func() {
			app.Action = func(ctx *cli.Context) error {

				namespaceT := *newNamespace("namespace1")
				namespaceT.Annotations = map[string]string{"k8s.ovn.org/routing-external-gws": "9.0.0.1"}
				namespaceT.Annotations["k8s.ovn.org/bfd-enabled"] = ""
				namespaceX := *newNamespace("namespace2")

				t := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespaceT.Name,
				)
				gwPod := *newPod(namespaceX.Name, "gwPod", "node2", "10.0.0.1")
				gwPod.Annotations = map[string]string{"k8s.ovn.org/routing-namespaces": namespaceT.Name}
				gwPod.Spec.HostNetwork = true
				t.baseCmds(fExec)
				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespaceT,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(t.namespace, t.podName, t.nodeName, t.podIP),
						},
					},
				)
				t.populateLogicalSwitchCache(fakeOvn)
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --may-exist --bfd --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.1 rtoe-GR_node1",
					Output: "\n",
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --may-exist --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 10.0.0.1",
					Output: "\n",
				})
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods(&sync.WaitGroup{})
				_, err := fakeOvn.fakeClient.KubeClient.CoreV1().Pods(namespaceX.Name).Create(context.TODO(), &gwPod, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
		ginkgo.It("should enable bfd only on the gw pod when set", func() {
			app.Action = func(ctx *cli.Context) error {

				namespaceT := *newNamespace("namespace1")
				namespaceT.Annotations = map[string]string{"k8s.ovn.org/routing-external-gws": "9.0.0.1"}
				namespaceX := *newNamespace("namespace2")

				t := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespaceT.Name,
				)
				gwPod := *newPod(namespaceX.Name, "gwPod", "node2", "10.0.0.1")
				gwPod.Annotations = map[string]string{"k8s.ovn.org/routing-namespaces": namespaceT.Name}
				gwPod.Annotations["k8s.ovn.org/bfd-enabled"] = ""

				gwPod.Spec.HostNetwork = true
				t.baseCmds(fExec)
				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespaceT,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(t.namespace, t.podName, t.nodeName, t.podIP),
						},
					},
				)
				t.populateLogicalSwitchCache(fakeOvn)
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --may-exist --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.1",
					Output: "\n",
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --may-exist --bfd --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 10.0.0.1 rtoe-GR_node1",
					Output: "\n",
				})
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods(&sync.WaitGroup{})
				_, err := fakeOvn.fakeClient.KubeClient.CoreV1().Pods(namespaceX.Name).Create(context.TODO(), &gwPod, metav1.CreateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
		ginkgo.It("should disable bfd when removing the annotation from the namespace", func() {
			app.Action = func(ctx *cli.Context) error {

				namespaceT := *newNamespace("namespace1")
				namespaceT.Annotations = map[string]string{"k8s.ovn.org/routing-external-gws": "9.0.0.1"}
				namespaceT.Annotations["k8s.ovn.org/bfd-enabled"] = ""

				t := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespaceT.Name,
				)

				t.baseCmds(fExec)
				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespaceT,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(t.namespace, t.podName, t.nodeName, t.podIP),
						},
					},
				)
				t.populateLogicalSwitchCache(fakeOvn)
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --may-exist --bfd --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.1 rtoe-GR_node1",
					Output: "\n",
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --if-exists --policy=src-ip lr-route-del GR_node1 10.128.1.3/32 9.0.0.1",
					Output: "\n",
				})

				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=bfd find Logical_Router_Static_Route output_port=rtoe-GR_node1 nexthop=9.0.0.1 bfd!=[]",
					Output: "\n",
				})

				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=_uuid find BFD logical_port=rtoe-GR_node1 dst_ip=9.0.0.1",
					Output: "bfduid\n",
				})

				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --if-exists destroy BFD bfduid",
					Output: "bfduid\n",
				})

				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --may-exist --policy=src-ip --ecmp-symmetric-reply lr-route-add GR_node1 10.128.1.3/32 9.0.0.1",
					Output: "\n",
				})
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods(&sync.WaitGroup{})
				namespaceT.Annotations = map[string]string{"k8s.ovn.org/routing-external-gws": "9.0.0.1"}
				_, err := fakeOvn.fakeClient.KubeClient.CoreV1().Namespaces().Update(context.Background(), &namespaceT, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
	})
})
