package node

import (
	"context"
	"net"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilnet "k8s.io/utils/net"

	"github.com/miekg/dns"

	util_mocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/mocks"
	mock "github.com/stretchr/testify/mock"

	egressfirewallapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	nodednsinfo "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/nodednsinfo/v1"
	egressfirewalldns "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/egressfirewall_dns"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func newObjectMeta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		UID:       types.UID(namespace),
		Name:      name,
		Namespace: namespace,
	}

}
func generateRR(dnsName, ip, nextQueryTime string) dns.RR {
	var rr dns.RR
	if utilnet.IsIPv6(net.ParseIP(ip)) {
		rr, _ = dns.NewRR(dnsName + ".        " + nextQueryTime + "     IN      AAAA       " + ip)
	} else {
		rr, _ = dns.NewRR(dnsName + ".        " + nextQueryTime + "     IN      A       " + ip)
	}
	return rr
}

func newEgressFirewallObject(name, namespace string, egressRules []egressfirewallapi.EgressFirewallRule) *egressfirewallapi.EgressFirewall {
	return &egressfirewallapi.EgressFirewall{
		ObjectMeta: newObjectMeta(name, namespace),
		Spec: egressfirewallapi.EgressFirewallSpec{
			Egress: egressRules,
		},
	}
}

var _ = Describe("Node EgressFirewall Operations", func() {
	var app *cli.App
	var fakeNode *FakeOVNNode

	BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		mockDnsOps := new(util_mocks.DNSOps)
		util.SetDNSLibOpsMockInst(mockDnsOps)

	})

	AfterEach(func() {
		fakeNode.shutdown()
	})

	It("EgressFirewallDNS functions will start correctly", func() {
		app.Action = func(ctx *cli.Context) error {
			mockDnsOps := new(util_mocks.DNSOps)
			util.SetDNSLibOpsMockInst(mockDnsOps)
			const (
				nodeName string = "Node1"
				nodeIP   string = "1.2.3.4"
				interval int    = 100000
				ofintval int    = 180
			)

			dnsOpsMockHelper := []ovntest.TestifyMockHelper{
				{"ClientConfigFromFile", []string{"string"}, []interface{}{&dns.ClientConfig{}, nil}, 0, 1},
			}
			for _, item := range dnsOpsMockHelper {
				call := mockDnsOps.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			fexec := ovntest.NewFakeExec()
			fakeNode = NewFakeOVNNode(fexec)
			fakeNode.start(ctx)

			fakeNode.node.watchFactory.InitializeEgressFirewallWatchFactory()
			var err error
			fakeNode.node.egressFirewallDNS, err = egressfirewalldns.NewEgressDNS(nodeName, fakeNode.node.watchFactory, fakeNode.node.Kube, fakeNode.stopChan)
			fakeNode.node.egressFirewallDNS.Run(30)
			Expect(err).NotTo(HaveOccurred())
			fakeNode.node.WatchEgressFirewall()

			time.Sleep(2 * time.Second)
			Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
			return nil

		}
		Expect(1).To(Equal(1))
		err := app.Run([]string{app.Name})
		Expect(err).NotTo(HaveOccurred())
	})
	It("reconciles an existing EgressFirewall", func() {
		app.Action = func(ctx *cli.Context) error {
			mockDnsOps := new(util_mocks.DNSOps)
			util.SetDNSLibOpsMockInst(mockDnsOps)
			const (
				nodeName   string = "Node1"
				dnsName    string = "www.gooogle.com"
				namespace  string = "testingNamespace"
				resolvedIP string = "5.5.5.5"
			)

			dnsOpsMockHelper := []ovntest.TestifyMockHelper{
				{"ClientConfigFromFile", []string{"string"}, []interface{}{&dns.ClientConfig{
					Servers: []string{"1.1.1.1"},
					Port:    "1234",
				}, nil}, 0, 1},
				{"Fqdn", []string{"string"}, []interface{}{dnsName}, 0, 1},
				{"SetQuestion", []string{"*dns.Msg", "string", "uint16"}, []interface{}{&dns.Msg{}}, 0, 1},
				{"Exchange", []string{"*dns.Client", "*dns.Msg", "string"}, []interface{}{&dns.Msg{Answer: []dns.RR{generateRR(dnsName, resolvedIP, "300")}}, 500 * time.Second, nil}, 0, 1},
			}
			for _, item := range dnsOpsMockHelper {
				call := mockDnsOps.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			fexec := ovntest.NewFakeExec()
			egressFirewall := newEgressFirewallObject("default", namespace, []egressfirewallapi.EgressFirewallRule{
				{
					Type: "Allow",
					To: egressfirewallapi.EgressFirewallDestination{
						DNSName: dnsName,
					},
				},
			})
			fakeNode = NewFakeOVNNode(fexec)
			fakeNode.start(ctx, &egressfirewallapi.EgressFirewallList{
				Items: []egressfirewallapi.EgressFirewall{
					*egressFirewall,
				},
			},
			)

			fakeNode.node.watchFactory.InitializeEgressFirewallWatchFactory()
			var err error
			fakeNode.node.egressFirewallDNS, err = egressfirewalldns.NewEgressDNS(nodeName, fakeNode.node.watchFactory, fakeNode.node.Kube, fakeNode.stopChan)
			fakeNode.node.egressFirewallDNS.Run(30 * time.Minute)
			Expect(err).NotTo(HaveOccurred())
			fakeNode.node.WatchEgressFirewall()

			Eventually(func() bool {
				fakeNode.node.egressFirewallDNS.LockEgressDNS()
				defer fakeNode.node.egressFirewallDNS.UnlockEgressDNS()
				ips, namespaces, _ := fakeNode.node.egressFirewallDNS.GetDNSEntry(dnsName)
				return areTwoIPSlicesTheSame(ips, []net.IP{net.ParseIP(resolvedIP)}) && areTwoStringSlicesTheSame(namespaces, []string{namespace})

			}).Should(BeTrue())

			var nodeDNSInfo *nodednsinfo.NodeDNSInfo
			Eventually(func() error {
				nodeDNSInfo, err = fakeNode.node.watchFactory.GetNodeDNSInfo(nodeName)
				return err
			}).Should(BeNil())
			Expect(areTwoStringSlicesTheSame(nodeDNSInfo.Status.DNSEntries[dnsName].IPAddresses, []string{resolvedIP})).To(Equal(true))

			Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
			return nil

		}
		err := app.Run([]string{app.Name})
		Expect(err).NotTo(HaveOccurred())
	})
	It("reconciles an update to a DNS Record", func() {
		app.Action = func(ctx *cli.Context) error {
			mockDnsOps := new(util_mocks.DNSOps)
			util.SetDNSLibOpsMockInst(mockDnsOps)
			const (
				nodeName         string = "Node1"
				dnsName          string = "www.gooogle.com"
				namespace        string = "testingNamespace"
				resolvedIP       string = "5.5.5.5"
				resolvedIPUpdate string = "10.10.10.10"
			)

			dnsOpsMockHelper := []ovntest.TestifyMockHelper{
				{"ClientConfigFromFile", []string{"string"}, []interface{}{&dns.ClientConfig{
					Servers: []string{"1.1.1.1"},
					Port:    "1234",
				}, nil}, 0, 1},
				{"Fqdn", []string{"string"}, []interface{}{dnsName}, 0, 1},
				{"SetQuestion", []string{"*dns.Msg", "string", "uint16"}, []interface{}{&dns.Msg{}}, 0, 1},
				//purposly set ttl very low to force the dnsResolver to query and get another address
				{"Exchange", []string{"*dns.Client", "*dns.Msg", "string"}, []interface{}{&dns.Msg{Answer: []dns.RR{generateRR(dnsName, resolvedIP, "1")}}, 1 * time.Second, nil}, 0, 1},

				{"Fqdn", []string{"string"}, []interface{}{dnsName}, 0, 1},
				{"SetQuestion", []string{"*dns.Msg", "string", "uint16"}, []interface{}{&dns.Msg{}}, 0, 1},
				{"Exchange", []string{"*dns.Client", "*dns.Msg", "string"}, []interface{}{&dns.Msg{Answer: []dns.RR{generateRR(dnsName, resolvedIPUpdate, "300")}}, 1 * time.Second, nil}, 0, 1},
			}
			for _, item := range dnsOpsMockHelper {
				call := mockDnsOps.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			fexec := ovntest.NewFakeExec()
			egressFirewall := newEgressFirewallObject("default", namespace, []egressfirewallapi.EgressFirewallRule{
				{
					Type: "Allow",
					To: egressfirewallapi.EgressFirewallDestination{
						DNSName: dnsName,
					},
				},
			})
			fakeNode = NewFakeOVNNode(fexec)
			fakeNode.start(ctx, &egressfirewallapi.EgressFirewallList{
				Items: []egressfirewallapi.EgressFirewall{
					*egressFirewall,
				},
			},
			)

			fakeNode.node.watchFactory.InitializeEgressFirewallWatchFactory()
			var err error
			fakeNode.node.egressFirewallDNS, err = egressfirewalldns.NewEgressDNS(nodeName, fakeNode.node.watchFactory, fakeNode.node.Kube, fakeNode.stopChan)
			fakeNode.node.egressFirewallDNS.Run(30 * time.Minute)
			Expect(err).NotTo(HaveOccurred())
			fakeNode.node.WatchEgressFirewall()

			Eventually(func() bool {
				fakeNode.node.egressFirewallDNS.LockEgressDNS()
				defer fakeNode.node.egressFirewallDNS.UnlockEgressDNS()
				ips, namespaces, _ := fakeNode.node.egressFirewallDNS.GetDNSEntry(dnsName)
				return areTwoIPSlicesTheSame(ips, []net.IP{net.ParseIP(resolvedIP)}) && areTwoStringSlicesTheSame(namespaces, []string{namespace})

			}).Should(BeTrue())
			fakeNode.node.egressFirewallDNS.LockEgressDNS()
			var nodeDNSInfo *nodednsinfo.NodeDNSInfo
			Eventually(func() error {
				nodeDNSInfo, err = fakeNode.node.watchFactory.GetNodeDNSInfo(nodeName)
				return err
			}).Should(BeNil())
			Expect(areTwoStringSlicesTheSame(nodeDNSInfo.Status.DNSEntries[dnsName].IPAddresses, []string{resolvedIP})).To(Equal(true))
			fakeNode.node.egressFirewallDNS.UnlockEgressDNS()
			//need to wait until the dnsRecord times out
			time.Sleep(2 * time.Second)

			Eventually(func() bool {
				fakeNode.node.egressFirewallDNS.LockEgressDNS()
				defer fakeNode.node.egressFirewallDNS.UnlockEgressDNS()
				ips, namespaces, _ := fakeNode.node.egressFirewallDNS.GetDNSEntry(dnsName)
				return areTwoIPSlicesTheSame(ips, []net.IP{net.ParseIP(resolvedIPUpdate)}) && areTwoStringSlicesTheSame(namespaces, []string{namespace})

			}).Should(BeTrue())
			nodeDNSInfo, err = fakeNode.node.watchFactory.GetNodeDNSInfo(nodeName)
			Expect(err).NotTo(HaveOccurred())
			Expect(areTwoStringSlicesTheSame(nodeDNSInfo.Status.DNSEntries[dnsName].IPAddresses, []string{resolvedIPUpdate})).To(Equal(true))

			Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
			return nil

		}
		err := app.Run([]string{app.Name})
		Expect(err).NotTo(HaveOccurred())
	})
	It("correctly reconciles EgressFirewall deletion", func() {
		app.Action = func(ctx *cli.Context) error {
			mockDnsOps := new(util_mocks.DNSOps)
			util.SetDNSLibOpsMockInst(mockDnsOps)
			const (
				nodeName   string = "Node1"
				dnsName    string = "www.gooogle.com"
				namespace1 string = "testingNamespace1"
				namespace2 string = "testingNamespace2"
				resolvedIP string = "5.5.5.5"
			)

			dnsOpsMockHelper := []ovntest.TestifyMockHelper{
				{"ClientConfigFromFile", []string{"string"}, []interface{}{&dns.ClientConfig{
					Servers: []string{"1.1.1.1"},
					Port:    "1234",
				}, nil}, 0, 1},
				{"Fqdn", []string{"string"}, []interface{}{dnsName}, 0, 1},
				{"SetQuestion", []string{"*dns.Msg", "string", "uint16"}, []interface{}{&dns.Msg{}}, 0, 1},
				{"Exchange", []string{"*dns.Client", "*dns.Msg", "string"}, []interface{}{&dns.Msg{Answer: []dns.RR{generateRR(dnsName, resolvedIP, "300")}}, 500 * time.Second, nil}, 0, 1},
			}
			for _, item := range dnsOpsMockHelper {
				call := mockDnsOps.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			fexec := ovntest.NewFakeExec()
			egressFirewall1 := newEgressFirewallObject("default", namespace1, []egressfirewallapi.EgressFirewallRule{
				{
					Type: "Allow",
					To: egressfirewallapi.EgressFirewallDestination{
						DNSName: dnsName,
					},
				},
			})
			egressFirewall2 := newEgressFirewallObject("default", namespace2, []egressfirewallapi.EgressFirewallRule{
				{
					Type: "Allow",
					To: egressfirewallapi.EgressFirewallDestination{
						DNSName: dnsName,
					},
				},
			})
			fakeNode = NewFakeOVNNode(fexec)
			fakeNode.start(ctx, &egressfirewallapi.EgressFirewallList{
				Items: []egressfirewallapi.EgressFirewall{
					*egressFirewall1,
					*egressFirewall2,
				},
			},
			)

			fakeNode.node.watchFactory.InitializeEgressFirewallWatchFactory()
			var err error
			fakeNode.node.egressFirewallDNS, err = egressfirewalldns.NewEgressDNS(nodeName, fakeNode.node.watchFactory, fakeNode.node.Kube, fakeNode.stopChan)
			fakeNode.node.egressFirewallDNS.Run(30 * time.Minute)
			Expect(err).NotTo(HaveOccurred())
			fakeNode.node.WatchEgressFirewall()

			Eventually(func() bool {
				fakeNode.node.egressFirewallDNS.LockEgressDNS()
				defer fakeNode.node.egressFirewallDNS.UnlockEgressDNS()
				ips, namespaces, _ := fakeNode.node.egressFirewallDNS.GetDNSEntry(dnsName)
				return areTwoIPSlicesTheSame(ips, []net.IP{net.ParseIP(resolvedIP)}) && areTwoStringSlicesTheSame(namespaces, []string{namespace1, namespace2})
			}).Should(BeTrue())
			var nodeDNSInfo *nodednsinfo.NodeDNSInfo
			Eventually(func() error {
				nodeDNSInfo, err = fakeNode.node.watchFactory.GetNodeDNSInfo(nodeName)
				return err
			}).Should(BeNil())
			Expect(areTwoStringSlicesTheSame(nodeDNSInfo.Status.DNSEntries[dnsName].IPAddresses, []string{resolvedIP})).To(Equal(true))

			// delete one egressFirewall and the dnsName entry should still exist with the namespace removed
			err = fakeNode.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall2.Namespace).Delete(context.TODO(), egressFirewall2.Name, *metav1.NewDeleteOptions(0))
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() bool {
				fakeNode.node.egressFirewallDNS.LockEgressDNS()
				defer fakeNode.node.egressFirewallDNS.UnlockEgressDNS()
				ips, namespaces, _ := fakeNode.node.egressFirewallDNS.GetDNSEntry(dnsName)
				return areTwoIPSlicesTheSame(ips, []net.IP{net.ParseIP(resolvedIP)}) && areTwoStringSlicesTheSame(namespaces, []string{namespace1})
			}).Should(BeTrue())

			// delete the last egressFirewall and the dnsName entry should get deleting
			err = fakeNode.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall1.Namespace).Delete(context.TODO(), egressFirewall1.Name, *metav1.NewDeleteOptions(0))
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() bool {
				fakeNode.node.egressFirewallDNS.LockEgressDNS()
				defer fakeNode.node.egressFirewallDNS.UnlockEgressDNS()
				_, _, exists := fakeNode.node.egressFirewallDNS.GetDNSEntry(dnsName)
				return exists
			}).Should(BeFalse())
			nodeDNSInfo, err = fakeNode.node.watchFactory.GetNodeDNSInfo(nodeName)
			//there will be an error becuase the object no longer exists
			Expect(err).To(HaveOccurred())

			Expect(nodeDNSInfo).To(BeNil())

			Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
			return nil

		}
		err := app.Run([]string{app.Name})
		Expect(err).NotTo(HaveOccurred())
	})
	It("reconciles EgressFirewall Updates", func() {
		app.Action = func(ctx *cli.Context) error {
			mockDnsOps := new(util_mocks.DNSOps)
			util.SetDNSLibOpsMockInst(mockDnsOps)
			const (
				nodeName    string = "Node1"
				dnsName1    string = "www.gooogle.com"
				dnsName2    string = "www.github.com"
				namespace   string = "testingNamespace"
				resolvedIP1 string = "5.5.5.5"
				resolvedIP2 string = "6.6.6.6"
			)

			dnsOpsMockHelper := []ovntest.TestifyMockHelper{
				{"ClientConfigFromFile", []string{"string"}, []interface{}{&dns.ClientConfig{
					Servers: []string{"1.1.1.1"},
					Port:    "1234",
				}, nil}, 0, 1},
				// for adding dnsName1
				{"Fqdn", []string{"string"}, []interface{}{dnsName1}, 0, 1},
				{"SetQuestion", []string{"*dns.Msg", "string", "uint16"}, []interface{}{&dns.Msg{}}, 0, 1},
				{"Exchange", []string{"*dns.Client", "*dns.Msg", "string"}, []interface{}{&dns.Msg{Answer: []dns.RR{generateRR(dnsName1, resolvedIP1, "300")}}, 500 * time.Second, nil}, 0, 1},
				// for adding dnsName2
				{"Fqdn", []string{"string"}, []interface{}{dnsName2}, 0, 1},
				{"SetQuestion", []string{"*dns.Msg", "string", "uint16"}, []interface{}{&dns.Msg{}}, 0, 1},
				{"Exchange", []string{"*dns.Client", "*dns.Msg", "string"}, []interface{}{&dns.Msg{Answer: []dns.RR{generateRR(dnsName2, resolvedIP2, "300")}}, 500 * time.Second, nil}, 0, 1},
			}
			for _, item := range dnsOpsMockHelper {
				call := mockDnsOps.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			fexec := ovntest.NewFakeExec()
			egressFirewall := newEgressFirewallObject("default", namespace, []egressfirewallapi.EgressFirewallRule{
				{
					Type: "Allow",
					To: egressfirewallapi.EgressFirewallDestination{
						DNSName: dnsName1,
					},
				},
			})
			fakeNode = NewFakeOVNNode(fexec)
			fakeNode.start(ctx, &egressfirewallapi.EgressFirewallList{
				Items: []egressfirewallapi.EgressFirewall{
					*egressFirewall,
				},
			},
			)

			fakeNode.node.watchFactory.InitializeEgressFirewallWatchFactory()
			var err error
			fakeNode.node.egressFirewallDNS, err = egressfirewalldns.NewEgressDNS(nodeName, fakeNode.node.watchFactory, fakeNode.node.Kube, fakeNode.stopChan)
			fakeNode.node.egressFirewallDNS.Run(30 * time.Minute)
			Expect(err).NotTo(HaveOccurred())
			fakeNode.node.WatchEgressFirewall()

			Eventually(func() bool {
				fakeNode.node.egressFirewallDNS.LockEgressDNS()
				defer fakeNode.node.egressFirewallDNS.UnlockEgressDNS()
				ips, namespaces, _ := fakeNode.node.egressFirewallDNS.GetDNSEntry(dnsName1)
				return areTwoIPSlicesTheSame(ips, []net.IP{net.ParseIP(resolvedIP1)}) && areTwoStringSlicesTheSame(namespaces, []string{namespace})

			}).Should(BeTrue())
			var nodeDNSInfo *nodednsinfo.NodeDNSInfo
			Eventually(func() error {
				nodeDNSInfo, err = fakeNode.node.watchFactory.GetNodeDNSInfo(nodeName)
				return err
			}).Should(BeNil())
			Expect(areTwoStringSlicesTheSame(nodeDNSInfo.Status.DNSEntries[dnsName1].IPAddresses, []string{resolvedIP1})).To(Equal(true))

			//enumerate the cases
			// case 1: no change to the dnsNames
			// case 2: adding a dnsName
			// case 3: removeing a dnsName

			// case 1: changing the egressFirewall so that there is no change to the dnsNames, should not change the nodeDNSInfo or the internal egressDNS struct
			egressFirewall.Spec.Egress[0].Type = "Deny"
			_, err = fakeNode.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Update(context.TODO(), egressFirewall, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() bool {
				fakeNode.node.egressFirewallDNS.LockEgressDNS()
				defer fakeNode.node.egressFirewallDNS.UnlockEgressDNS()
				ips, namespaces, _ := fakeNode.node.egressFirewallDNS.GetDNSEntry(dnsName1)
				return areTwoIPSlicesTheSame(ips, []net.IP{net.ParseIP(resolvedIP1)}) && areTwoStringSlicesTheSame(namespaces, []string{namespace})

			}).Should(BeTrue())

			//case 2: adding a new dnsName
			egressFirewall = newEgressFirewallObject("default", namespace, []egressfirewallapi.EgressFirewallRule{
				{
					Type: "Allow",
					To: egressfirewallapi.EgressFirewallDestination{
						DNSName: dnsName1,
					},
				},
				{
					Type: "Allow",
					To: egressfirewallapi.EgressFirewallDestination{
						DNSName: dnsName2,
					},
				},
			})
			_, err = fakeNode.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Update(context.TODO(), egressFirewall, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() bool {
				fakeNode.node.egressFirewallDNS.LockEgressDNS()
				defer fakeNode.node.egressFirewallDNS.UnlockEgressDNS()
				ips, namespaces, _ := fakeNode.node.egressFirewallDNS.GetDNSEntry(dnsName1)
				return areTwoIPSlicesTheSame(ips, []net.IP{net.ParseIP(resolvedIP1)}) && areTwoStringSlicesTheSame(namespaces, []string{namespace})

			}).Should(BeTrue())
			Eventually(func() bool {
				fakeNode.node.egressFirewallDNS.LockEgressDNS()
				defer fakeNode.node.egressFirewallDNS.UnlockEgressDNS()
				ips, namespaces, _ := fakeNode.node.egressFirewallDNS.GetDNSEntry(dnsName2)
				return areTwoIPSlicesTheSame(ips, []net.IP{net.ParseIP(resolvedIP2)}) && areTwoStringSlicesTheSame(namespaces, []string{namespace})

			}).Should(BeTrue())
			nodeDNSInfo, err = fakeNode.node.watchFactory.GetNodeDNSInfo(nodeName)
			Expect(err).NotTo(HaveOccurred())

			Expect(areTwoStringSlicesTheSame(nodeDNSInfo.Status.DNSEntries[dnsName1].IPAddresses, []string{resolvedIP1})).To(Equal(true))
			Expect(areTwoStringSlicesTheSame(nodeDNSInfo.Status.DNSEntries[dnsName2].IPAddresses, []string{resolvedIP2})).To(Equal(true))

			//case 3: removing a dnsName
			egressFirewall = newEgressFirewallObject("default", namespace, []egressfirewallapi.EgressFirewallRule{
				{
					Type: "Allow",
					To: egressfirewallapi.EgressFirewallDestination{
						DNSName: dnsName1,
					},
				},
			})
			_, err = fakeNode.fakeClient.EgressFirewallClient.K8sV1().EgressFirewalls(egressFirewall.Namespace).Update(context.TODO(), egressFirewall, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() bool {
				fakeNode.node.egressFirewallDNS.LockEgressDNS()
				defer fakeNode.node.egressFirewallDNS.UnlockEgressDNS()
				ips, namespaces, _ := fakeNode.node.egressFirewallDNS.GetDNSEntry(dnsName1)
				return areTwoIPSlicesTheSame(ips, []net.IP{net.ParseIP(resolvedIP1)}) && areTwoStringSlicesTheSame(namespaces, []string{namespace})

			}).Should(BeTrue())
			Eventually(func() bool {
				fakeNode.node.egressFirewallDNS.LockEgressDNS()
				defer fakeNode.node.egressFirewallDNS.UnlockEgressDNS()
				_, _, exists := fakeNode.node.egressFirewallDNS.GetDNSEntry(dnsName2)
				return exists

			}).Should(BeFalse())
			nodeDNSInfo, err = fakeNode.node.watchFactory.GetNodeDNSInfo(nodeName)
			Expect(err).NotTo(HaveOccurred())
			Expect(areTwoStringSlicesTheSame(nodeDNSInfo.Status.DNSEntries[dnsName1].IPAddresses, []string{resolvedIP1})).To(Equal(true))
			_, exists := nodeDNSInfo.Status.DNSEntries[dnsName2]
			Expect(exists).To(BeFalse())

			Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
			return nil

		}
		err := app.Run([]string{app.Name})
		Expect(err).NotTo(HaveOccurred())
	})

})

// there is no order guarenteed make sure the two slices are the same length and same values
func areTwoIPSlicesTheSame(ipResolves, expectedValues []net.IP) bool {
	if len(ipResolves) != len(expectedValues) {
		return false
	}

	maxIndex := len(ipResolves) - 1
	for _, ip := range ipResolves {
		for index, expectedVal := range expectedValues {
			if ip.Equal(expectedVal) {
				break
			}
			if index == maxIndex {
				return false
			}
		}

	}
	return true

}

func areTwoStringSlicesTheSame(testedStrings, expectedValues []string) bool {
	if len(testedStrings) != len(expectedValues) {
		return false
	}

	maxIndex := len(testedStrings) - 1
	for _, testString := range testedStrings {
		for index, expectedVal := range expectedValues {
			if testString == expectedVal {
				break
			}
			if index == maxIndex {
				return false
			}
		}

	}
	return true
}
