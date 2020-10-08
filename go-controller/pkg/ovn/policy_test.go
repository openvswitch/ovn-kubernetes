package ovn

import (
	"context"
	"fmt"
	"sort"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/urfave/cli/v2"

	v1 "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type networkPolicy struct{}

func newNetworkPolicyMeta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		UID:       types.UID(namespace),
		Name:      name,
		Namespace: namespace,
		Labels: map[string]string{
			"name": name,
		},
	}
}

func newNetworkPolicy(name, namespace string, podSelector metav1.LabelSelector, ingress []knet.NetworkPolicyIngressRule, egress []knet.NetworkPolicyEgressRule) *knet.NetworkPolicy {
	return &knet.NetworkPolicy{
		ObjectMeta: newNetworkPolicyMeta(name, namespace),
		Spec: knet.NetworkPolicySpec{
			PodSelector: podSelector,
			Ingress:     ingress,
			Egress:      egress,
		},
	}
}

func (n networkPolicy) baseCmds(fexec *ovntest.FakeExec, networkPolicy *knet.NetworkPolicy) string {
	readableGroupName := fmt.Sprintf("%s_%s", networkPolicy.Namespace, networkPolicy.Name)
	hashedGroupName := hashedPortGroup(readableGroupName)
	fexec.AddFakeCmdsNoOutputNoError([]string{
		fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=%s", hashedGroupName),
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    fmt.Sprintf("ovn-nbctl --timeout=15 create port_group name=%s external-ids:name=%s", hashedGroupName, readableGroupName),
		Output: readableGroupName,
	})
	return readableGroupName
}

const (
	ingressDenyPG string = "ingressDefaultDeny"
	egressDenyPG  string = "egressDefaultDeny"
)

func (n networkPolicy) addLocalPodCmds(fexec *ovntest.FakeExec, networkPolicy *knet.NetworkPolicy) {
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=ingressDefaultDeny",
		Output: ingressDenyPG,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"outport == @ingressDefaultDeny\" action=drop external-ids:default-deny-policy-type=Ingress",
		Output: fakeUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"outport == @ingressDefaultDeny && arp\" action=allow external-ids:default-deny-policy-type=Ingress",
		Output: fakeUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=egressDefaultDeny",
		Output: egressDenyPG,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"inport == @egressDefaultDeny\" action=drop external-ids:default-deny-policy-type=Egress",
		Output: fakeUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"inport == @egressDefaultDeny && arp\" action=allow external-ids:default-deny-policy-type=Egress",
		Output: fakeUUID,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists remove port_group " + ingressDenyPG + " ports " + fakeUUID + " -- add port_group " + ingressDenyPG + " ports " + fakeUUID,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists remove port_group " + egressDenyPG + " ports " + fakeUUID + " -- add port_group " + egressDenyPG + " ports " + fakeUUID,
	})
	if networkPolicy != nil {
		readableGroupName := fmt.Sprintf("%s_%s", networkPolicy.Namespace, networkPolicy.Name)
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove port_group " + readableGroupName + " ports " + fakeUUID + " -- add port_group " + readableGroupName + " ports " + fakeUUID,
		})
	}
}

func (n networkPolicy) addNamespaceSelectorCmds(fexec *ovntest.FakeExec, networkPolicy *knet.NetworkPolicy, findAgain bool) {
	readableGroupName := n.baseCmds(fexec, networkPolicy)
	for i := range networkPolicy.Spec.Ingress {
		fexec.AddFakeCmdsNoOutputNoError([]string{
			fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:l4Match=\"None\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Ingress_num=%v external-ids:policy_type=Ingress", networkPolicy.Namespace, networkPolicy.Name, i),
			"ovn-nbctl --timeout=15 --id=@acl create acl priority=1001 direction=to-lport match=\"ip4.src == {$a3128014386057836746} && outport == @a14195333570786048679\" action=allow-related external-ids:l4Match=\"None\" external-ids:ipblock_cidr=false external-ids:namespace=namespace1 external-ids:policy=networkpolicy1 external-ids:Ingress_num=0 external-ids:policy_type=Ingress -- add port_group " + readableGroupName + " acls @acl",
		})
		if findAgain {
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.src == {$a3128014386057836746} && outport == @a14195333570786048679\" external-ids:namespace=namespace1 external-ids:policy=networkpolicy1 external-ids:Ingress_num=0 external-ids:policy_type=Ingress",
			})
		}
	}
	for i := range networkPolicy.Spec.Egress {
		fexec.AddFakeCmdsNoOutputNoError([]string{
			fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:l4Match=\"None\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Egress_num=%v external-ids:policy_type=Egress", networkPolicy.Namespace, networkPolicy.Name, i),
			"ovn-nbctl --timeout=15 --id=@acl create acl priority=1001 direction=to-lport match=\"ip4.dst == {$a17928043879887565554} && inport == @a14195333570786048679\" action=allow external-ids:l4Match=\"None\" external-ids:ipblock_cidr=false external-ids:namespace=namespace1 external-ids:policy=networkpolicy1 external-ids:Egress_num=0 external-ids:policy_type=Egress -- add port_group " + readableGroupName + " acls @acl",
		})
		if findAgain {
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.dst == {$a17928043879887565554} && inport == @a14195333570786048679\" external-ids:namespace=namespace1 external-ids:policy=networkpolicy1 external-ids:Egress_num=0 external-ids:policy_type=Egress",
			})
		}
	}
}

func getAddressSetName(namespace, name string, policyType knet.PolicyType, idx int) string {
	direction := strings.ToLower(string(policyType))
	return fmt.Sprintf("%s.%s.%s.%d%s", namespace, name, direction, idx, ipv4AddressSetSuffix)
}

func eventuallyExpectNoAddressSets(fakeOvn *FakeOVN, networkPolicy *knet.NetworkPolicy) {
	for i := range networkPolicy.Spec.Ingress {
		asName := getAddressSetName(networkPolicy.Namespace, networkPolicy.Name, knet.PolicyTypeIngress, i)
		fakeOvn.asf.EventuallyExpectNoAddressSet(asName)
	}
	for i := range networkPolicy.Spec.Egress {
		asName := getAddressSetName(networkPolicy.Namespace, networkPolicy.Name, knet.PolicyTypeEgress, i)
		fakeOvn.asf.EventuallyExpectNoAddressSet(asName)
	}
}

func expectAddressSetsWithIP(fakeOvn *FakeOVN, networkPolicy *knet.NetworkPolicy, ip string) {
	for i := range networkPolicy.Spec.Ingress {
		asName := getAddressSetName(networkPolicy.Namespace, networkPolicy.Name, knet.PolicyTypeIngress, i)
		fakeOvn.asf.ExpectAddressSetWithIPs(asName, []string{ip})
	}
	for i := range networkPolicy.Spec.Egress {
		asName := getAddressSetName(networkPolicy.Namespace, networkPolicy.Name, knet.PolicyTypeEgress, i)
		fakeOvn.asf.ExpectAddressSetWithIPs(asName, []string{ip})
	}
}

func eventuallyExpectEmptyAddressSets(fakeOvn *FakeOVN, networkPolicy *knet.NetworkPolicy) {
	for i := range networkPolicy.Spec.Ingress {
		asName := getAddressSetName(networkPolicy.Namespace, networkPolicy.Name, knet.PolicyTypeIngress, i)
		fakeOvn.asf.EventuallyExpectEmptyAddressSet(asName)
	}
	for i := range networkPolicy.Spec.Egress {
		asName := getAddressSetName(networkPolicy.Namespace, networkPolicy.Name, knet.PolicyTypeEgress, i)
		fakeOvn.asf.EventuallyExpectEmptyAddressSet(asName)
	}
}

func (n networkPolicy) delCmds(fexec *ovntest.FakeExec, pod pod, networkPolicy *knet.NetworkPolicy, withLocal bool) {
	if withLocal {
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove port_group " + ingressDenyPG + " ports " + fakeUUID,
		})
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists remove port_group " + egressDenyPG + " ports " + fakeUUID,
		})
	}
	readableGroupName := fmt.Sprintf("%s_%s", networkPolicy.Namespace, networkPolicy.Name)
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=a14195333570786048679",
		Output: readableGroupName,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		fmt.Sprintf("ovn-nbctl --timeout=15 --if-exists destroy port_group %s", readableGroupName),
	})
}

func (n networkPolicy) delPodCmds(fexec *ovntest.FakeExec, networkPolicy *knet.NetworkPolicy) {
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists remove port_group " + ingressDenyPG + " ports " + fakeUUID,
	})
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists remove port_group " + egressDenyPG + " ports " + fakeUUID,
	})
	readableGroupName := fmt.Sprintf("%s_%s", networkPolicy.Namespace, networkPolicy.Name)
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists remove port_group " + readableGroupName + " ports " + fakeUUID,
	})
}

type multicastPolicy struct{}

func (p multicastPolicy) enableCmds(fExec *ovntest.FakeExec, ns, nsAs string) {
	pg_name := ns
	pg_hash := hashedPortGroup(ns)

	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=" + pg_hash,
	})
	fExec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 create port_group name=" + pg_hash + " external-ids:name=" + pg_name,
		Output: "fake_uuid",
	})

	match := getACLMatch(pg_hash, "ip4.mcast", knet.PolicyTypeEgress)
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL " +
			match + " action=allow external-ids:default-deny-policy-type=Egress",
	})
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --id=@acl create acl priority=1012 direction=from-lport " +
			match + " action=allow external-ids:default-deny-policy-type=Egress " +
			"-- add port_group fake_uuid acls @acl",
	})

	match = "ip4.src == $" + hashedAddressSet(nsAs) + " && ip4.mcast"
	match = getACLMatch(pg_hash, match, knet.PolicyTypeIngress)
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL " +
			match + " action=allow external-ids:default-deny-policy-type=Ingress",
	})
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --id=@acl create acl priority=1012 direction=to-lport " +
			match + " action=allow external-ids:default-deny-policy-type=Ingress " +
			"-- add port_group fake_uuid acls @acl",
	})
}

func (p multicastPolicy) disableCmds(fExec *ovntest.FakeExec, ns, nsAs string) {
	pg_hash := hashedPortGroup(ns)

	match := getACLMatch(pg_hash, "ip4.mcast", knet.PolicyTypeEgress)
	fExec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd: "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL " +
			match + " " + "action=allow external-ids:default-deny-policy-type=Egress",
		Output: "fake_uuid",
	})
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 remove port_group " + pg_hash + " acls fake_uuid",
	})

	match = "ip4.src == $" + hashedAddressSet(nsAs) + " && ip4.mcast"
	match = getACLMatch(pg_hash, match, knet.PolicyTypeIngress)
	fExec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd: "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL " +
			match + " " + "action=allow external-ids:default-deny-policy-type=Ingress",
		Output: "fake_uuid",
	})
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 remove port_group " + pg_hash + " acls fake_uuid",
	})

	fExec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find port_group name=" + pg_hash,
		Output: "fake_uuid",
	})
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 --if-exists destroy port_group fake_uuid",
	})
}

func (p multicastPolicy) addPodCmds(fExec *ovntest.FakeExec, ns string) {
	pg_hash := hashedPortGroup(ns)
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 " +
			"--if-exists remove port_group " + pg_hash + " ports " + fakeUUID + " " +
			"-- add port_group " + pg_hash + " ports " + fakeUUID,
	})
}

func (p multicastPolicy) delPodCmds(fExec *ovntest.FakeExec, ns string) {
	pg_hash := hashedPortGroup(ns)
	fExec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 " +
			"--if-exists remove port_group " + pg_hash + " ports " + fakeUUID,
	})
}

var _ = Describe("OVN NetworkPolicy Operations", func() {
	const (
		namespaceName1    = "namespace1"
		v4AddressSetName1 = namespaceName1 + ipv4AddressSetSuffix
		v6AddressSetName1 = namespaceName1 + ipv6AddressSetSuffix

		namespaceName2    = "namespace2"
		v4AddressSetName2 = namespaceName2 + ipv4AddressSetSuffix
		v6AddressSetName2 = namespaceName2 + ipv6AddressSetSuffix
	)
	var (
		app     *cli.App
		fakeOvn *FakeOVN
		fExec   *ovntest.FakeExec
	)

	BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fExec = ovntest.NewLooseCompareFakeExec()
		fakeOvn = NewFakeOVN(fExec)
	})

	AfterEach(func() {
		fakeOvn.shutdown()
	})

	Context("on startup", func() {

		It("reconciles an existing ingress networkPolicy with a namespace selector", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := networkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)
				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					})

				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, true)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							*networkPolicy,
						},
					},
				)

				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				fakeOvn.asf.ExpectEmptyAddressSet(v4AddressSetName1)
				fakeOvn.asf.ExpectEmptyAddressSet(v4AddressSetName2)
				fakeOvn.asf.ExpectNoAddressSet(v6AddressSetName1)
				fakeOvn.asf.ExpectNoAddressSet(v6AddressSetName2)

				eventuallyExpectEmptyAddressSets(fakeOvn, networkPolicy)

				_, err := fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("reconciles an existing gress networkPolicy with a pod selector in its own namespace", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := networkPolicy{}

				namespace1 := *newNamespace(namespaceName1)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace1.Name,
				)
				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				nPodTest.addPodDenyMcast(fExec)
				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, false)
				npTest.addLocalPodCmds(fExec, networkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							*networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				expectAddressSetsWithIP(fakeOvn, networkPolicy, nPodTest.podIP)
				fakeOvn.asf.ExpectAddressSetWithIPs(v4AddressSetName1, []string{nPodTest.podIP})
				fakeOvn.asf.ExpectNoAddressSet(v6AddressSetName1)

				_, err := fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("reconciles an existing gress networkPolicy with a pod and namespace selector in another namespace", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := networkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)

				nPodTest := newTPod(
					"node2",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace2.Name,
				)
				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				nPodTest.addPodDenyMcast(fExec)
				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, false)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							*networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				fakeOvn.asf.ExpectEmptyAddressSet(v4AddressSetName1)
				expectAddressSetsWithIP(fakeOvn, networkPolicy, nPodTest.podIP)
				fakeOvn.asf.ExpectAddressSetWithIPs(v4AddressSetName2, []string{nPodTest.podIP})

				fakeOvn.asf.ExpectNoAddressSet(v6AddressSetName1)
				fakeOvn.asf.ExpectNoAddressSet(v6AddressSetName2)

				_, err := fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("during execution", func() {

		It("correctly creates a networkpolicy allowing a port to a local pod", func() {
			app.Action = func(ctx *cli.Context) error {
				npTest := networkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace1.Name,
				)
				nPod := newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP)

				const (
					labelName string = "pod-name"
					labelVal  string = "server"
					portNum   int32  = 81
				)
				nPod.Labels[labelName] = labelVal

				tcpProtocol := v1.Protocol(v1.ProtocolTCP)
				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{
						MatchLabels: map[string]string{
							labelName: labelVal,
						},
					},
					[]knet.NetworkPolicyIngressRule{{
						Ports: []knet.NetworkPolicyPort{{
							Port:     &intstr.IntOrString{IntVal: portNum},
							Protocol: &tcpProtocol,
						}},
					}},
					[]knet.NetworkPolicyEgressRule{{
						Ports: []knet.NetworkPolicyPort{{
							Port:     &intstr.IntOrString{IntVal: portNum},
							Protocol: &tcpProtocol,
						}},
					}},
				)

				nPodTest.baseCmds(fExec)
				nPodTest.addPodDenyMcast(fExec)
				npTest.baseCmds(fExec, networkPolicy)
				npTest.addLocalPodCmds(fExec, networkPolicy)

				readableGroupName := fmt.Sprintf("%s_%s", networkPolicy.Namespace, networkPolicy.Name)
				fExec.AddFakeCmdsNoOutputNoError([]string{
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:l4Match=\"tcp && tcp.dst==%d\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Ingress_num=0 external-ids:policy_type=Ingress", portNum, networkPolicy.Namespace, networkPolicy.Name),
					fmt.Sprintf("ovn-nbctl --timeout=15 --id=@acl create acl priority=1001 direction=to-lport match=\"ip4 && tcp && tcp.dst==%d && outport == @a14195333570786048679\" action=allow-related external-ids:l4Match=\"tcp && tcp.dst==%d\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Ingress_num=0 external-ids:policy_type=Ingress -- add port_group %s acls @acl", portNum, portNum, networkPolicy.Namespace, networkPolicy.Name, readableGroupName),
					fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL external-ids:l4Match=\"tcp && tcp.dst==%d\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Egress_num=0 external-ids:policy_type=Egress", portNum, networkPolicy.Namespace, networkPolicy.Name),
					fmt.Sprintf("ovn-nbctl --timeout=15 --id=@acl create acl priority=1001 direction=to-lport match=\"ip4 && tcp && tcp.dst==%d && inport == @a14195333570786048679\" action=allow external-ids:l4Match=\"tcp && tcp.dst==%d\" external-ids:ipblock_cidr=false external-ids:namespace=%s external-ids:policy=%s external-ids:Egress_num=0 external-ids:policy_type=Egress -- add port_group %s acls @acl", portNum, portNum, networkPolicy.Namespace, networkPolicy.Name, readableGroupName),
				})

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{namespace1},
					},
					&v1.PodList{
						Items: []v1.Pod{*nPod},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{*networkPolicy},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				_, err := fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)
				fakeOvn.asf.ExpectAddressSetWithIPs(v4AddressSetName1, []string{nPodTest.podIP})
				fakeOvn.asf.ExpectNoAddressSet(v6AddressSetName1)

				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("reconciles a deleted namespace referenced by a networkpolicy with a local running pod", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := networkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace1.Name,
				)

				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				nPodTest.addPodDenyMcast(fExec)
				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, true)
				npTest.addLocalPodCmds(fExec, networkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							*networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				_, err := fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)
				fakeOvn.asf.ExpectAddressSetWithIPs(v4AddressSetName1, []string{nPodTest.podIP})
				fakeOvn.asf.ExpectNoAddressSet(v6AddressSetName1)

				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.src == {$a3128014386057836746, $a4615334824109672969} && outport == @a14195333570786048679\" external-ids:namespace=namespace1 external-ids:policy=networkpolicy1 external-ids:Ingress_num=0 external-ids:policy_type=Ingress",
					Output: fakeUUID,
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 set acl " + fakeUUID + " match=\"ip4.src == {$a3128014386057836746} && outport == @a14195333570786048679\"",
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.dst == {$a17928043879887565554, $a4615334824109672969} && inport == @a14195333570786048679\" external-ids:namespace=namespace1 external-ids:policy=networkpolicy1 external-ids:Egress_num=0 external-ids:policy_type=Egress",
				})

				err = fakeOvn.fakeClient.CoreV1().Namespaces().Delete(context.TODO(), namespace2.Name, *metav1.NewDeleteOptions(0))
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)
				fakeOvn.asf.EventuallyExpectNoAddressSet(v4AddressSetName2)
				fakeOvn.asf.EventuallyExpectNoAddressSet(v6AddressSetName2)

				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("reconciles a deleted namespace referenced by a networkpolicy", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := networkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)
				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": namespace2.Name,
										},
									},
								},
							},
						},
					})

				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, true)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							*networkPolicy,
						},
					},
				)

				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				_, err := fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				fExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.src == {$a3128014386057836746, $a4615334824109672969} && outport == @a14195333570786048679\" external-ids:namespace=namespace1 external-ids:policy=networkpolicy1 external-ids:Ingress_num=0 external-ids:policy_type=Ingress",
					Output: fakeUUID,
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 set acl " + fakeUUID + " match=\"ip4.src == {$a3128014386057836746} && outport == @a14195333570786048679\"",
				})
				fExec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.dst == {$a17928043879887565554, $a4615334824109672969} && inport == @a14195333570786048679\" external-ids:namespace=namespace1 external-ids:policy=networkpolicy1 external-ids:Egress_num=0 external-ids:policy_type=Egress",
				})

				err = fakeOvn.fakeClient.CoreV1().Namespaces().Delete(context.TODO(), namespace2.Name, *metav1.NewDeleteOptions(0))
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)
				fakeOvn.asf.EventuallyExpectNoAddressSet(v4AddressSetName2)
				fakeOvn.asf.EventuallyExpectNoAddressSet(v6AddressSetName2)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("reconciles a deleted pod referenced by a networkpolicy in its own namespace", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := networkPolicy{}

				namespace1 := *newNamespace(namespaceName1)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace1.Name,
				)
				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				nPodTest.addPodDenyMcast(fExec)
				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, false)
				npTest.addLocalPodCmds(fExec, networkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							*networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				expectAddressSetsWithIP(fakeOvn, networkPolicy, nPodTest.podIP)
				fakeOvn.asf.ExpectAddressSetWithIPs(v4AddressSetName1, []string{nPodTest.podIP})
				fakeOvn.asf.ExpectNoAddressSet(v6AddressSetName1)

				_, err := fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				nPodTest.delCmds(fExec)
				npTest.delPodCmds(fExec, networkPolicy)

				err = fakeOvn.fakeClient.CoreV1().Pods(nPodTest.namespace).Delete(context.TODO(), nPodTest.podName, *metav1.NewDeleteOptions(0))
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				eventuallyExpectEmptyAddressSets(fakeOvn, networkPolicy)
				fakeOvn.asf.EventuallyExpectEmptyAddressSet(v4AddressSetName1)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("reconciles a deleted pod referenced by a networkpolicy in another namespace", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := networkPolicy{}

				namespace1 := *newNamespace(namespaceName1)
				namespace2 := *newNamespace(namespaceName2)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace2.Name,
				)
				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.namespace,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.namespace,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				nPodTest.addPodDenyMcast(fExec)
				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, false)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
							namespace2,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							*networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				fakeOvn.asf.ExpectEmptyAddressSet(v4AddressSetName1)
				expectAddressSetsWithIP(fakeOvn, networkPolicy, nPodTest.podIP)
				fakeOvn.asf.ExpectAddressSetWithIPs(v4AddressSetName2, []string{nPodTest.podIP})
				fakeOvn.asf.ExpectNoAddressSet(v6AddressSetName1)
				fakeOvn.asf.ExpectNoAddressSet(v6AddressSetName2)

				_, err := fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				nPodTest.delCmds(fExec)

				err = fakeOvn.fakeClient.CoreV1().Pods(nPodTest.namespace).Delete(context.TODO(), nPodTest.podName, *metav1.NewDeleteOptions(0))
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				// After deleting the pod all address sets should be empty
				eventuallyExpectEmptyAddressSets(fakeOvn, networkPolicy)
				fakeOvn.asf.EventuallyExpectEmptyAddressSet(v4AddressSetName1)

				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("reconciles a deleted networkpolicy", func() {
			app.Action = func(ctx *cli.Context) error {

				npTest := networkPolicy{}

				namespace1 := *newNamespace(namespaceName1)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace1.Name,
				)
				networkPolicy := newNetworkPolicy("networkpolicy1", namespace1.Name,
					metav1.LabelSelector{},
					[]knet.NetworkPolicyIngressRule{
						{
							From: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					},
					[]knet.NetworkPolicyEgressRule{
						{
							To: []knet.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"name": nPodTest.podName,
										},
									},
								},
							},
						},
					})

				nPodTest.baseCmds(fExec)
				nPodTest.addPodDenyMcast(fExec)
				npTest.addNamespaceSelectorCmds(fExec, networkPolicy, false)
				npTest.addLocalPodCmds(fExec, networkPolicy)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
					&knet.NetworkPolicyList{
						Items: []knet.NetworkPolicy{
							*networkPolicy,
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchNetworkPolicy()

				_, err := fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Get(context.TODO(), networkPolicy.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)
				fakeOvn.asf.ExpectAddressSetWithIPs(v4AddressSetName1, []string{nPodTest.podIP})
				fakeOvn.asf.ExpectNoAddressSet(v6AddressSetName1)

				npTest.delCmds(fExec, nPodTest, networkPolicy, true)

				err = fakeOvn.fakeClient.NetworkingV1().NetworkPolicies(networkPolicy.Namespace).Delete(context.TODO(), networkPolicy.Name, *metav1.NewDeleteOptions(0))
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)
				eventuallyExpectNoAddressSets(fakeOvn, networkPolicy)

				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("tests enabling/disabling multicast in a namespace", func() {
			app.Action = func(ctx *cli.Context) error {
				namespace1 := *newNamespace(namespaceName1)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
				)

				fakeOvn.controller.WatchNamespaces()
				ns, err := fakeOvn.fakeClient.CoreV1().Namespaces().Get(
					context.TODO(), namespace1.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Expect(ns).NotTo(BeNil())

				// Multicast is denied by default.
				_, ok := ns.Annotations[nsMulticastAnnotation]
				Expect(ok).To(BeFalse())

				// Enable multicast in the namespace.
				mcastPolicy := multicastPolicy{}
				mcastPolicy.enableCmds(fExec, namespace1.Name, v4AddressSetName1)
				ns.Annotations[nsMulticastAnnotation] = "true"
				_, err = fakeOvn.fakeClient.CoreV1().Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				// Disable multicast in the namespace.
				mcastPolicy.disableCmds(fExec, namespace1.Name, v4AddressSetName1)
				ns.Annotations[nsMulticastAnnotation] = "false"
				_, err = fakeOvn.fakeClient.CoreV1().Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("tests enabling multicast in a namespace with a pod", func() {
			app.Action = func(ctx *cli.Context) error {
				namespace1 := *newNamespace(namespaceName1)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace1.Name,
				)

				nPodTest.baseCmds(fExec)
				nPodTest.addPodDenyMcast(fExec)
				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
					&v1.PodList{
						Items: []v1.Pod{
							*newPod(nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP),
						},
					},
				)
				nPodTest.populateLogicalSwitchCache(fakeOvn)
				fakeOvn.controller.WatchPods()
				fakeOvn.controller.WatchNamespaces()
				ns, err := fakeOvn.fakeClient.CoreV1().Namespaces().Get(
					context.TODO(), namespace1.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Expect(ns).NotTo(BeNil())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)
				// Enable multicast in the namespace
				mcastPolicy := multicastPolicy{}
				mcastPolicy.enableCmds(fExec, namespace1.Name, v4AddressSetName1)
				// The pod should be added to the multicast allow port group.
				mcastPolicy.addPodCmds(fExec, namespace1.Name)
				ns.Annotations[nsMulticastAnnotation] = "true"
				_, err = fakeOvn.fakeClient.CoreV1().Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)
				fakeOvn.asf.ExpectAddressSetWithIPs(v4AddressSetName1, []string{nPodTest.podIP})
				fakeOvn.asf.ExpectNoAddressSet(v6AddressSetName1)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("tests adding a pod to a multicast enabled namespace", func() {
			app.Action = func(ctx *cli.Context) error {
				namespace1 := *newNamespace(namespaceName1)

				nPodTest := newTPod(
					"node1",
					"10.128.1.0/24",
					"10.128.1.2",
					"10.128.1.1",
					"myPod",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					namespace1.Name,
				)

				fakeOvn.start(ctx,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							namespace1,
						},
					},
				)

				nPodTest.baseCmds(fExec)
				fakeOvn.controller.WatchNamespaces()
				fakeOvn.controller.WatchPods()
				ns, err := fakeOvn.fakeClient.CoreV1().Namespaces().Get(
					context.TODO(), namespace1.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Expect(ns).NotTo(BeNil())

				// Enable multicast in the namespace.
				mcastPolicy := multicastPolicy{}
				mcastPolicy.enableCmds(fExec, namespace1.Name, v4AddressSetName1)
				ns.Annotations[nsMulticastAnnotation] = "true"
				_, err = fakeOvn.fakeClient.CoreV1().Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)

				nPodTest.populateLogicalSwitchCache(fakeOvn)
				nPodTest.addPodDenyMcast(fExec)

				// The pod should be added to the multicast allow group.
				mcastPolicy.addPodCmds(fExec, namespace1.Name)

				_, err = fakeOvn.fakeClient.CoreV1().Pods(nPodTest.namespace).Create(context.TODO(), newPod(
					nPodTest.namespace, nPodTest.podName, nPodTest.nodeName, nPodTest.podIP), metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)
				fakeOvn.asf.ExpectAddressSetWithIPs(v4AddressSetName1, []string{nPodTest.podIP})
				fakeOvn.asf.ExpectNoAddressSet(v6AddressSetName1)

				// Delete the pod from the namespace.
				mcastPolicy.delPodCmds(fExec, namespace1.Name)
				// The pod should be removed from the multicasts default deny
				// group and from the multicast allow group.
				nPodTest.delCmds(fExec)

				err = fakeOvn.fakeClient.CoreV1().Pods(nPodTest.namespace).Delete(context.TODO(),
					nPodTest.podName, *metav1.NewDeleteOptions(0))
				Expect(err).NotTo(HaveOccurred())
				Eventually(fExec.CalledMatchesExpected).Should(BeTrue(), fExec.ErrorDesc)
				fakeOvn.asf.ExpectEmptyAddressSet(v4AddressSetName1)
				fakeOvn.asf.ExpectNoAddressSet(v6AddressSetName1)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
	})
})

func asMatch(addressSets []string) string {
	hashedNames := make([]string, 0, len(addressSets))
	for _, as := range addressSets {
		hashedNames = append(hashedNames, hashedAddressSet(as))
	}
	sort.Strings(hashedNames)
	var match string
	for i, n := range hashedNames {
		if i > 0 {
			match += ", "
		}
		match += fmt.Sprintf("$%s", n)
	}
	return match
}

func addExpectedGressCmds(fExec *ovntest.FakeExec, gp *gressPolicy, pgName string, oldAS, newAS []string) []string {
	const uuid string = "94407fe0-2c15-4a63-baea-ab4af0ea5bb8"

	oldMatch := asMatch(oldAS)
	newMatch := asMatch(newAS)

	gpDirection := string(knet.PolicyTypeIngress)
	fExec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd: fmt.Sprintf("ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find ACL match=\"ip4.src == {%s} && outport == @%s\" external-ids:namespace=%s external-ids:policy=%s external-ids:%s_num=%d external-ids:policy_type=%s",
			oldMatch, pgName, gp.policyNamespace, gp.policyName, gpDirection, gp.idx, gpDirection),
		Output: uuid,
	})
	fExec.AddFakeCmdsNoOutputNoError([]string{
		fmt.Sprintf("ovn-nbctl --timeout=15 set acl %s match=\"ip4.src == {%s} && outport == @%s\"",
			uuid, newMatch, pgName),
	})
	return newAS
}

var _ = Describe("OVN NetworkPolicy Low-Level Operations", func() {
	var (
		fExec     *ovntest.FakeExec
		asFactory *fakeAddressSetFactory
		exec      util.ExecHelper
	)

	BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		var err error
		fExec = ovntest.NewLooseCompareFakeExec()
		exec, err = util.NewExecHelper(fExec)
		Expect(err).NotTo(HaveOccurred())

		asFactory = newFakeAddressSetFactory()
		config.IPv4Mode = true
		config.IPv6Mode = false
	})

	It("computes match strings from address sets correctly", func() {
		const (
			pgUUID string = "pg-uuid"
			pgName string = "pg-name"
		)

		policy := &knet.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				UID:       types.UID("testing"),
				Name:      "policy",
				Namespace: "testing",
			},
		}

		gp := newGressPolicy(exec, knet.PolicyTypeIngress, 0, policy.Namespace, policy.Name)
		err := gp.ensurePeerAddressSet(asFactory)
		Expect(err).NotTo(HaveOccurred())
		asName := getIPv4ASName(gp.peerAddressSet.GetName())

		one := fmt.Sprintf("testing.policy.ingress.1")
		two := fmt.Sprintf("testing.policy.ingress.2")
		three := fmt.Sprintf("testing.policy.ingress.3")
		four := fmt.Sprintf("testing.policy.ingress.4")
		five := fmt.Sprintf("testing.policy.ingress.5")
		six := fmt.Sprintf("testing.policy.ingress.6")

		v4One := one + ipv4AddressSetSuffix
		v4Two := two + ipv4AddressSetSuffix
		v4Three := three + ipv4AddressSetSuffix
		v4Four := four + ipv4AddressSetSuffix
		v4Five := five + ipv4AddressSetSuffix
		v4Six := six + ipv4AddressSetSuffix

		cur := addExpectedGressCmds(fExec, gp, pgName, []string{asName}, []string{asName, v4One})
		gp.addNamespaceAddressSet(one, pgName)
		Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, v4One, v4Two})
		gp.addNamespaceAddressSet(two, pgName)
		Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

		// address sets should be alphabetized
		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, v4One, v4Two, v4Three})
		gp.addNamespaceAddressSet(three, pgName)
		Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

		// re-adding an existing set is a no-op
		gp.addNamespaceAddressSet(one, pgName)
		Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, v4One, v4Two, v4Three, v4Four})
		gp.addNamespaceAddressSet(four, pgName)
		Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

		// now delete a set
		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, v4Two, v4Three, v4Four})
		gp.delNamespaceAddressSet(one, pgName)
		Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

		// deleting again is a no-op
		gp.delNamespaceAddressSet(one, pgName)
		Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

		// add and delete some more...
		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, v4Two, v4Three, v4Four, v4Five})
		gp.addNamespaceAddressSet(five, pgName)
		Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, v4Two, v4Four, v4Five})
		gp.delNamespaceAddressSet(three, pgName)
		Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

		// deleting again is no-op
		gp.delNamespaceAddressSet(one, pgName)
		Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, v4Two, v4Four, v4Five, v4Six})
		gp.addNamespaceAddressSet(six, pgName)
		Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, v4Four, v4Five, v4Six})
		gp.delNamespaceAddressSet(two, pgName)
		Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, v4Four, v4Six})
		gp.delNamespaceAddressSet(five, pgName)
		Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName, v4Four})
		gp.delNamespaceAddressSet(six, pgName)
		Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

		cur = addExpectedGressCmds(fExec, gp, pgName, cur, []string{asName})
		gp.delNamespaceAddressSet(four, pgName)
		Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

		// deleting again is no-op
		gp.delNamespaceAddressSet(four, pgName)
		Expect(fExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)
	})
})
