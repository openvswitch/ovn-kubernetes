package ovn

import (
	"context"
	"fmt"

	"net"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressfirewallapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	t "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/urfave/cli/v2"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func newObjectMeta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		UID:       types.UID(namespace),
		Name:      name,
		Namespace: namespace,
	}

}

func newEgressFirewallObject(name, namespace string, egressRules []egressfirewallapi.EgressFirewallRule) *egressfirewallapi.EgressFirewall {

	return &egressfirewallapi.EgressFirewall{
		ObjectMeta: newObjectMeta(name, namespace),
		Spec: egressfirewallapi.EgressFirewallSpec{
			Egress: egressRules,
		},
	}
}

var _ = ginkgo.Describe("OVN EgressFirewall Operations for local gateway mode", func() {
	var (
		app     *cli.App
		fakeOVN *FakeOVN
		fExec   *ovntest.FakeExec
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each 99999e
		config.PrepareTestConfig()
		config.Gateway.Mode = config.GatewayModeLocal

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fExec = ovntest.NewLooseCompareFakeExec()
		fakeOVN = NewFakeOVN(fExec)

	})

	ginkgo.AfterEach(func() {
		fakeOVN.shutdown()
	})

	ginkgo.Context("on startup", func() {
		ginkgo.It("reconciles an existing egressFirewall with IPv4 CIDR", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find acl priority<=%s priority>=%s direction=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority, t.DirectionFromLPort),
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find logical_router_policy priority<=%s priority>=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority),
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102\" action=allow external-ids:egressFirewall=namespace1",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=" + t.DirectionToLPort + " match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102\" action=allow external-ids:egressFirewall=namespace1 -- add logical_switch " + node1Name + " acls @acl",
				})

				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
				})

				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})

				fakeOVN.controller.WatchNamespaces()
				fakeOVN.controller.WatchEgressFirewall()

				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

		})
		ginkgo.It("reconciles an existing egressFirewall with IPv6 CIDR", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find acl priority<=%s priority>=%s direction=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority, t.DirectionFromLPort),
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find logical_router_policy priority<=%s priority>=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority),
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip6.dst == 2002::1234:abcd:ffff:c0a8:101/64) && (ip4.src == $a10481622940199974102 || ip6.src == $a10481620741176717680)\" action=allow external-ids:egressFirewall=namespace1",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=" + t.DirectionToLPort + " match=\"(ip6.dst == 2002::1234:abcd:ffff:c0a8:101/64) && (ip4.src == $a10481622940199974102 || ip6.src == $a10481620741176717680)\" action=allow external-ids:egressFirewall=namespace1 -- add logical_switch " + node1Name + " acls @acl",
				})

				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "2002::1234:abcd:ffff:c0a8:101/64",
						},
					},
				})

				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					}, &v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})
				config.IPv6Mode = true
				fakeOVN.controller.WatchNamespaces()
				fakeOVN.controller.WatchEgressFirewall()

				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

		})
	})
	ginkgo.Context("during execution", func() {
		ginkgo.It("correctly creates an egressfirewall denying traffic udp traffic on port 100", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find acl priority<=%s priority>=%s direction=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority, t.DirectionFromLPort),
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find logical_router_policy priority<=%s priority>=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority),
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && ((udp && ( udp.dst == 100 )))\" action=drop external-ids:egressFirewall=namespace1",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=" + t.DirectionToLPort + " match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && ((udp && ( udp.dst == 100 )))\" action=drop external-ids:egressFirewall=namespace1 -- add logical_switch " + node1Name + " acls @acl",
				})
				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Deny",
						Ports: []egressfirewallapi.EgressFirewallPort{
							{
								Protocol: "UDP",
								Port:     100,
							},
						},
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
				})
				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})

				fakeOVN.controller.WatchNamespaces()
				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				fakeOVN.controller.WatchEgressFirewall()

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}
			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
		ginkgo.It("correctly deletes an egressfirewall", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find acl priority<=%s priority>=%s direction=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority, t.DirectionFromLPort),
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find logical_router_policy priority<=%s priority>=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority),
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip4.dst == 1.2.3.5/23) && " +
						"ip4.src == $a10481622940199974102 && ((tcp && ( tcp.dst == 100 )))\" action=allow external-ids:egressFirewall=namespace1",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=" + t.DirectionToLPort + " match=\"(ip4.dst == 1.2.3.5/23) && " +
						"ip4.src == $a10481622940199974102 && ((tcp && ( tcp.dst == 100 )))\" action=allow external-ids:egressFirewall=namespace1 -- add logical_switch " + node1Name + " acls @acl",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=" + t.DirectionToLPort + " match=\"(ip4.dst == 1.2.3.5/23) && " +
						"ip4.src == $a10481622940199974102 && ((tcp && ( tcp.dst == 100 )))\" action=allow external-ids:egressFirewall=namespace1 -- add logical_switch " + node2Name + " acls @acl",
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:egressFirewall=namespace1",
					Output: fmt.Sprintf("%s", fakeUUID),
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 remove logical_switch " + node1Name + " acls " + fmt.Sprintf("%s", fakeUUID),
					"ovn-nbctl --timeout=15 remove logical_switch " + node2Name + " acls " + fmt.Sprintf("%s", fakeUUID),
				})
				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Allow",
						Ports: []egressfirewallapi.EgressFirewallPort{
							{
								Protocol: "TCP",
								Port:     100,
							},
						},
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.5/23",
						},
					},
				})

				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node2Name, ""),
							},
						},
					})

				fakeOVN.controller.WatchNamespaces()
				fakeOVN.controller.WatchEgressFirewall()

				err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Delete(context.TODO(), egressFirewall.Name, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
		ginkgo.It("correctly updates an egressfirewall", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find acl priority<=%s priority>=%s direction=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority, t.DirectionFromLPort),
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find logical_router_policy priority<=%s priority>=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority),
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102\" action=allow external-ids:egressFirewall=namespace1",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=" + t.DirectionToLPort + " match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102\" action=allow external-ids:egressFirewall=namespace1 -- add logical_switch " + node1Name + " acls @acl",
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip4.dst == 0.0.0.0/0 || ip6.dst == ::/0) && ip4.src == $a10481622940199974102 && ip4.dst != 10.128.0.0/14\" action=drop external-ids:egressFirewall=namespace1-blockAll",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=10000 direction=" + t.DirectionToLPort + " match=\"(ip4.dst == 0.0.0.0/0 || ip6.dst == ::/0) && ip4.src == $a10481622940199974102 && ip4.dst != 10.128.0.0/14\" action=drop external-ids:egressFirewall=namespace1-blockAll -- add logical_switch " + node1Name + " acls @acl",
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:egressFirewall=namespace1",
					Output: fmt.Sprintf("%s", fakeUUID),
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 remove logical_switch " + node1Name + " acls " + fmt.Sprintf("%s", fakeUUID),
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102\" action=drop external-ids:egressFirewall=namespace1",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=" + t.DirectionToLPort + " match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102\" action=drop external-ids:egressFirewall=namespace1 -- add logical_switch " + node1Name + " acls @acl",
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:egressFirewall=namespace1-blockAll",
					Output: fmt.Sprintf("%s", fakeUUID),
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 remove logical_switch " + node1Name + " acls " + fmt.Sprintf("%s", fakeUUID),
				})

				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
				})
				egressFirewall1 := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Deny",
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
				})

				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})

				fakeOVN.controller.WatchNamespaces()
				fakeOVN.controller.WatchEgressFirewall()

				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				_, err = fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall1.Namespace).Update(context.TODO(), egressFirewall1, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

		})

	})

})

var _ = ginkgo.Describe("OVN EgressFirewall Operations for shared gateway mode", func() {
	var (
		app     *cli.App
		fakeOVN *FakeOVN
		fExec   *ovntest.FakeExec
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each 99999e
		config.PrepareTestConfig()
		config.Gateway.Mode = config.GatewayModeShared

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fExec = ovntest.NewLooseCompareFakeExec()
		fakeOVN = NewFakeOVN(fExec)

	})

	ginkgo.AfterEach(func() {
		fakeOVN.shutdown()
	})

	ginkgo.Context("on startup", func() {
		ginkgo.It("reconciles an existing egressFirewall with IPv4 CIDR", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find acl priority<=%s priority>=%s direction=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority, t.DirectionFromLPort),
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find logical_router_policy priority<=%s priority>=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority),
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=allow external-ids:egressFirewall=namespace1",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=" + t.DirectionToLPort + " match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=allow external-ids:egressFirewall=namespace1 -- add logical_switch join acls @acl",
				})

				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
				})

				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})

				fakeOVN.controller.WatchNamespaces()
				fakeOVN.controller.WatchEgressFirewall()

				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

		})
		ginkgo.It("reconciles an existing egressFirewall with IPv6 CIDR", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find acl priority<=%s priority>=%s direction=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority, t.DirectionFromLPort),
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find logical_router_policy priority<=%s priority>=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority),
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip6.dst == 2002::1234:abcd:ffff:c0a8:101/64) && (ip4.src == $a10481622940199974102 || ip6.src == $a10481620741176717680) && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=allow external-ids:egressFirewall=namespace1",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=" + t.DirectionToLPort + " match=\"(ip6.dst == 2002::1234:abcd:ffff:c0a8:101/64) && (ip4.src == $a10481622940199974102 || ip6.src == $a10481620741176717680) && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=allow external-ids:egressFirewall=namespace1 -- add logical_switch join acls @acl",
				})

				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "2002::1234:abcd:ffff:c0a8:101/64",
						},
					},
				})

				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					}, &v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})
				config.IPv6Mode = true
				fakeOVN.controller.WatchNamespaces()
				fakeOVN.controller.WatchEgressFirewall()

				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

		})
	})
	ginkgo.Context("during execution", func() {
		ginkgo.It("correctly creates an egressfirewall denying traffic udp traffic on port 100", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find acl priority<=%s priority>=%s direction=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority, t.DirectionFromLPort),
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find logical_router_policy priority<=%s priority>=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority),
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && ((udp && ( udp.dst == 100 ))) && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=drop external-ids:egressFirewall=namespace1",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=" + t.DirectionToLPort + " match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && ((udp && ( udp.dst == 100 ))) && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=drop external-ids:egressFirewall=namespace1 -- add logical_switch join acls @acl",
				})
				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Deny",
						Ports: []egressfirewallapi.EgressFirewallPort{
							{
								Protocol: "UDP",
								Port:     100,
							},
						},
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
				})
				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})

				fakeOVN.controller.WatchNamespaces()
				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				fakeOVN.controller.WatchEgressFirewall()

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}
			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
		ginkgo.It("correctly deletes an egressfirewall", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find acl priority<=%s priority>=%s direction=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority, t.DirectionFromLPort),
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find logical_router_policy priority<=%s priority>=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority),
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip4.dst == 1.2.3.5/23) && " +
						"ip4.src == $a10481622940199974102 && ((tcp && ( tcp.dst == 100 ))) && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=allow external-ids:egressFirewall=namespace1",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=" + t.DirectionToLPort + " match=\"(ip4.dst == 1.2.3.5/23) && " +
						"ip4.src == $a10481622940199974102 && ((tcp && ( tcp.dst == 100 ))) && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=allow external-ids:egressFirewall=namespace1 -- add logical_switch join acls @acl",
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:egressFirewall=namespace1",
					Output: fmt.Sprintf("%s", fakeUUID),
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 remove logical_switch join acls " + fmt.Sprintf("%s", fakeUUID),
				})
				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Allow",
						Ports: []egressfirewallapi.EgressFirewallPort{
							{
								Protocol: "TCP",
								Port:     100,
							},
						},
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.5/23",
						},
					},
				})

				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})

				fakeOVN.controller.WatchNamespaces()
				fakeOVN.controller.WatchEgressFirewall()

				err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Delete(context.TODO(), egressFirewall.Name, *metav1.NewDeleteOptions(0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})
		ginkgo.It("correctly updates an egressfirewall", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					node1Name string = "node1"
				)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find acl priority<=%s priority>=%s direction=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority, t.DirectionFromLPort),
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid --format=table find logical_router_policy priority<=%s priority>=%s", t.EgressFirewallStartPriority, t.MinimumReservedEgressFirewallPriority),
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=allow external-ids:egressFirewall=namespace1",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=" + t.DirectionToLPort + " match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=allow external-ids:egressFirewall=namespace1 -- add logical_switch join acls @acl",
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip4.dst == 0.0.0.0/0 || ip6.dst == ::/0) && ip4.src == $a10481622940199974102 && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=drop external-ids:egressFirewall=namespace1-blockAll",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=10000 direction=" + t.DirectionToLPort + " match=\"(ip4.dst == 0.0.0.0/0 || ip6.dst == ::/0) && ip4.src == $a10481622940199974102 && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=drop external-ids:egressFirewall=namespace1-blockAll -- add logical_switch join acls @acl",
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:egressFirewall=namespace1",
					Output: fmt.Sprintf("%s", fakeUUID),
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 remove logical_switch join acls " + fmt.Sprintf("%s", fakeUUID),
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=drop external-ids:egressFirewall=namespace1",
					"ovn-nbctl --timeout=15 --id=@acl create acl priority=9999 direction=" + t.DirectionToLPort + " match=\"(ip4.dst == 1.2.3.4/23) && ip4.src == $a10481622940199974102 && inport == \\\"" + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + "\\\"\" action=drop external-ids:egressFirewall=namespace1 -- add logical_switch join acls @acl",
				})
				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:egressFirewall=namespace1-blockAll",
					Output: fmt.Sprintf("%s", fakeUUID),
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 remove logical_switch join acls " + fmt.Sprintf("%s", fakeUUID),
				})

				namespace1 := *newNamespace("namespace1")
				egressFirewall := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Allow",
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
				})
				egressFirewall1 := newEgressFirewallObject("default", namespace1.Name, []egressfirewallapi.EgressFirewallRule{
					{
						Type: "Deny",
						To: egressfirewallapi.EgressFirewallDestination{
							CIDRSelector: "1.2.3.4/23",
						},
					},
				})

				fakeOVN.start(ctx,
					&egressfirewallapi.EgressFirewallList{
						Items: []egressfirewallapi.EgressFirewall{
							*egressFirewall,
						},
					},
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.NodeList{
						Items: []v1.Node{
							{
								Status: v1.NodeStatus{
									Phase: v1.NodeRunning,
								},
								ObjectMeta: newObjectMeta(node1Name, ""),
							},
						},
					})

				fakeOVN.controller.WatchNamespaces()
				fakeOVN.controller.WatchEgressFirewall()

				_, err := fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Get(context.TODO(), egressFirewall.Name, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				_, err = fakeOVN.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall1.Namespace).Update(context.TODO(), egressFirewall1, metav1.UpdateOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Eventually(fExec.CalledMatchesExpected).Should(gomega.BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

		})

	})

})

var _ = ginkgo.Describe("OVN test basic functions", func() {

	ginkgo.It("computes correct L4Match", func() {
		type testcase struct {
			ports         []egressfirewallapi.EgressFirewallPort
			expectedMatch string
		}
		testcases := []testcase{
			{
				ports: []egressfirewallapi.EgressFirewallPort{
					{
						Protocol: "TCP",
						Port:     100,
					},
				},
				expectedMatch: "((tcp && ( tcp.dst == 100 )))",
			},
			{
				ports: []egressfirewallapi.EgressFirewallPort{
					{
						Protocol: "TCP",
						Port:     100,
					},
					{
						Protocol: "UDP",
					},
				},
				expectedMatch: "((udp) || (tcp && ( tcp.dst == 100 )))",
			},
			{
				ports: []egressfirewallapi.EgressFirewallPort{
					{
						Protocol: "TCP",
						Port:     100,
					},
					{
						Protocol: "SCTP",
						Port:     13,
					},
					{
						Protocol: "TCP",
						Port:     102,
					},
					{
						Protocol: "UDP",
						Port:     400,
					},
				},
				expectedMatch: "((udp && ( udp.dst == 400 )) || (tcp && ( tcp.dst == 100 || tcp.dst == 102 )) || (sctp && ( sctp.dst == 13 )))",
			},
		}
		for _, test := range testcases {
			l4Match := egressGetL4Match(test.ports)
			gomega.Expect(test.expectedMatch).To(gomega.Equal(l4Match))
		}
	})
	ginkgo.It("computes correct match function", func() {
		type testcase struct {
			internalCIDR string
			ipv4source   string
			ipv6source   string
			destinations []matchTarget
			ports        []egressfirewallapi.EgressFirewallPort
			output       string
		}
		testcases := []testcase{
			{
				internalCIDR: "10.128.0.0/14",
				ipv4source:   "testv4",
				ipv6source:   "",
				destinations: []matchTarget{{matchKindV4CIDR, "1.2.3.4/32"}},
				ports:        nil,
				output:       `match="(ip4.dst == 1.2.3.4/32) && ip4.src == $testv4 && inport == \"` + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + `\""`,
			},
			{
				internalCIDR: "10.128.0.0/14",
				ipv4source:   "testv4",
				ipv6source:   "testv6",
				destinations: []matchTarget{{matchKindV4CIDR, "1.2.3.4/32"}},
				ports:        nil,
				output:       `match="(ip4.dst == 1.2.3.4/32) && (ip4.src == $testv4 || ip6.src == $testv6) && inport == \"` + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + `\""`,
			},
			{
				internalCIDR: "10.128.0.0/14",
				ipv4source:   "testv4",
				ipv6source:   "testv6",
				destinations: []matchTarget{{matchKindV4AddressSet, "destv4"}, {matchKindV6AddressSet, "destv6"}},
				ports:        nil,
				output:       `match="(ip4.dst == $destv4 || ip6.dst == $destv6) && (ip4.src == $testv4 || ip6.src == $testv6) && inport == \"` + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + `\""`,
			},
			{
				internalCIDR: "10.128.0.0/14",
				ipv4source:   "testv4",
				ipv6source:   "",
				destinations: []matchTarget{{matchKindV4AddressSet, "destv4"}, {matchKindV6AddressSet, ""}},
				ports:        nil,
				output:       `match="(ip4.dst == $destv4) && ip4.src == $testv4 && inport == \"` + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + `\""`,
			},
			{
				internalCIDR: "10.128.0.0/14",
				ipv4source:   "testv4",
				ipv6source:   "testv6",
				destinations: []matchTarget{{matchKindV6CIDR, "2001::/64"}},
				ports:        nil,
				output:       `match="(ip6.dst == 2001::/64) && (ip4.src == $testv4 || ip6.src == $testv6) && inport == \"` + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + `\""`,
			},
			{
				internalCIDR: "2002:0:0:1234::/64",
				ipv4source:   "",
				ipv6source:   "testv6",
				destinations: []matchTarget{{matchKindV6AddressSet, "destv6"}},
				ports:        nil,
				output:       `match="(ip6.dst == $destv6) && ip6.src == $testv6 && inport == \"` + t.JoinSwitchToGWRouterPrefix + t.OVNClusterRouter + `\""`,
			},
		}

		for _, tc := range testcases {
			_, cidr, _ := net.ParseCIDR(tc.internalCIDR)
			config.Default.ClusterSubnets = []config.CIDRNetworkEntry{{CIDR: cidr}}
			config.Gateway.Mode = config.GatewayModeShared
			matchExpression := generateMatch(tc.ipv4source, tc.ipv6source, tc.destinations, tc.ports)
			gomega.Expect(tc.output).To(gomega.Equal(matchExpression))
		}
	})
	ginkgo.It("correctly parses egressFirewallRules", func() {
		type testcase struct {
			egressFirewallRule egressfirewallapi.EgressFirewallRule
			id                 int
			err                bool
			errOutput          string
			output             egressFirewallRule
		}
		testcases := []testcase{
			{
				egressFirewallRule: egressfirewallapi.EgressFirewallRule{
					Type: egressfirewallapi.EgressFirewallRuleAllow,
					To:   egressfirewallapi.EgressFirewallDestination{CIDRSelector: "1.2.3.4/32"},
				},
				id:  1,
				err: false,
				output: egressFirewallRule{
					id:     1,
					access: egressfirewallapi.EgressFirewallRuleAllow,
					to:     destination{cidrSelector: "1.2.3.4/32"},
				},
			},
			{
				egressFirewallRule: egressfirewallapi.EgressFirewallRule{
					Type: egressfirewallapi.EgressFirewallRuleAllow,
					To:   egressfirewallapi.EgressFirewallDestination{CIDRSelector: "1.2.3./32"},
				},
				id:        1,
				err:       true,
				errOutput: "invalid CIDR address: 1.2.3./32",
				output:    egressFirewallRule{},
			},
			{
				egressFirewallRule: egressfirewallapi.EgressFirewallRule{
					Type: egressfirewallapi.EgressFirewallRuleAllow,
					To:   egressfirewallapi.EgressFirewallDestination{CIDRSelector: "2002::1234:abcd:ffff:c0a8:101/64"},
				},
				id:  2,
				err: false,
				output: egressFirewallRule{
					id:     2,
					access: egressfirewallapi.EgressFirewallRuleAllow,
					to:     destination{cidrSelector: "2002::1234:abcd:ffff:c0a8:101/64"},
				},
			},
		}
		for _, tc := range testcases {
			output, err := newEgressFirewallRule(tc.egressFirewallRule, tc.id)
			if tc.err == true {
				gomega.Expect(err).To(gomega.HaveOccurred())
				gomega.Expect(tc.errOutput).To(gomega.Equal(err.Error()))
			} else {
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(tc.output).To(gomega.Equal(*output))
			}
		}
	})
})

//helper functions to help test egressfirewallDNS

// Create an EgressDNS object without the Sync function
// To make it easier to mock EgressFirewall functionality create an egressFirewall
// without the go routine of the sync function

//GetDNSEntryForTest Gets a dnsEntry from a EgressDNS object for testing
func (e *EgressDNS) GetDNSEntryForTest(dnsName string) (map[string]struct{}, []net.IP, addressset.AddressSet, error) {
	if e.dnsEntries[dnsName] == nil {
		return nil, nil, nil, fmt.Errorf("there is no dnsEntry for dnsName: %s", dnsName)
	}
	return e.dnsEntries[dnsName].namespaces, e.dnsEntries[dnsName].dnsResolves, e.dnsEntries[dnsName].dnsAddressSet, nil
}
