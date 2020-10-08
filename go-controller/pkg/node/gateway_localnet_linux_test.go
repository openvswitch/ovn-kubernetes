package node

import (
	"fmt"
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/urfave/cli/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func getFakeLocalAddrs() map[string]net.IPNet {
	localAddrSet := make(map[string]net.IPNet)
	for _, network := range []string{"127.0.0.1/32", "10.10.10.1/24"} {
		ip, ipNet, err := net.ParseCIDR(network)
		Expect(err).NotTo(HaveOccurred())
		localAddrSet[ip.String()] = *ipNet
	}
	return localAddrSet
}

func initFakeNodePortWatcher(fakeOvnNode *FakeOVNNode, iptV4, iptV6 util.IPTablesHelper) *localPortWatcherData {
	initIPTable := map[string]util.FakeTable{
		"filter": {},
		"nat":    {},
	}

	f4 := iptV4.(*util.FakeIPTables)
	err := f4.MatchState(initIPTable)
	Expect(err).NotTo(HaveOccurred())

	f6 := iptV6.(*util.FakeIPTables)
	err = f6.MatchState(initIPTable)
	Expect(err).NotTo(HaveOccurred())

	fNPW := localPortWatcherData{
		exec:         fakeOvnNode.exec,
		recorder:     fakeOvnNode.recorder,
		gatewayIPv4:  v4localnetGatewayIP,
		localAddrSet: getFakeLocalAddrs(),
	}
	return &fNPW
}

func newServiceMeta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		UID:       types.UID(namespace),
		Name:      name,
		Namespace: namespace,
		Labels: map[string]string{
			"name": name,
		},
	}
}

func newService(name, namespace, ip string, ports []v1.ServicePort, serviceType v1.ServiceType, externalIPs []string) *v1.Service {
	return &v1.Service{
		ObjectMeta: newServiceMeta(name, namespace),
		Spec: v1.ServiceSpec{
			ClusterIP:   ip,
			Ports:       ports,
			Type:        serviceType,
			ExternalIPs: externalIPs,
		},
	}
}

var _ = Describe("Node Operations", func() {

	var (
		app         *cli.App
		fakeOvnNode *FakeOVNNode
		fExec       *ovntest.FakeExec
	)

	BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fExec = ovntest.NewFakeExec()
		fakeOvnNode = NewFakeOVNNode(fExec)
	})

	Context("on startup", func() {

		It("inits physical routing rules", func() {
			app.Action = func(ctx *cli.Context) error {

				iptV4, iptV6 := util.SetFakeIPTablesHelpers()
				fNPW := initFakeNodePortWatcher(fakeOvnNode, iptV4, iptV6)

				fakeOvnNode.fakeExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip rule",
					Output: "0:	from all lookup local\n32766:	from all lookup main\n32767:	from all lookup default\n",
				})
				fakeOvnNode.fakeExec.AddFakeCmdsNoOutputNoError([]string{
					"ip rule add from all table " + localnetGatewayExternalIDTable,
				})
				fakeOvnNode.fakeExec.AddFakeCmdsNoOutputNoError([]string{
					"ip route list table " + localnetGatewayExternalIDTable,
				})

				fakeOvnNode.start(ctx)
				fakeOvnNode.node.watchLocalPorts(fNPW)

				expectedTables := map[string]util.FakeTable{
					"filter": {
						"FORWARD": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OVN-KUBE-NODEPORT":   []string{},
						"OVN-KUBE-EXTERNALIP": []string{},
					},
					"nat": {
						"PREROUTING": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OUTPUT": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OVN-KUBE-NODEPORT":   []string{},
						"OVN-KUBE-EXTERNALIP": []string{},
					},
				}
				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				expectedTables = map[string]util.FakeTable{
					"filter": {},
					"nat":    {},
				}
				f6 := iptV6.(*util.FakeIPTables)
				err = f6.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				fakeOvnNode.shutdown()
				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("removes stale physical routing rules while keeping remaining intact", func() {
			app.Action = func(ctx *cli.Context) error {

				externalIP := "1.1.1.1"
				externalIPPort := int32(8032)

				iptV4, iptV6 := util.SetFakeIPTablesHelpers()
				fNPW := initFakeNodePortWatcher(fakeOvnNode, iptV4, iptV6)

				// Create some fake routing and iptable rules
				fakeOvnNode.fakeExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd: "ip rule",
					Output: "0:	from all lookup local\n32766:	from all lookup main\n32767:	from all lookup default\n",
				})
				fakeOvnNode.fakeExec.AddFakeCmdsNoOutputNoError([]string{
					"ip rule add from all table " + localnetGatewayExternalIDTable,
				})
				fakeOvnNode.fakeExec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ip route list table " + localnetGatewayExternalIDTable,
					Output: fmt.Sprintf("%s via %s dev %s\n9.9.9.9 via %s dev %s\n", externalIP, v4localnetGatewayIP, localnetGatewayNextHopPort, v4localnetGatewayIP, localnetGatewayNextHopPort),
				})
				fakeOvnNode.fakeExec.AddFakeCmdsNoOutputNoError([]string{
					fmt.Sprintf("ip route del 9.9.9.9 via %s dev %s table %s", v4localnetGatewayIP, localnetGatewayNextHopPort, localnetGatewayExternalIDTable),
				})
				fakeOvnNode.fakeExec.AddFakeCmdsNoOutputNoError([]string{
					fmt.Sprintf("ip route replace %s via %s dev %s table %s", externalIP, v4localnetGatewayIP, localnetGatewayNextHopPort, localnetGatewayExternalIDTable),
				})

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							Port:     externalIPPort,
							Protocol: v1.ProtocolTCP,
						},
					},
					v1.ServiceTypeClusterIP,
					[]string{externalIP},
				)

				fakeRules := getExternalIPTRules(service.Spec.Ports[0], externalIP, service.Spec.ClusterIP)
				addIptRules(fakeRules)
				fakeRules = getExternalIPTRules(
					v1.ServicePort{
						Port:     27000,
						Protocol: v1.ProtocolUDP,
						Name:     "This is going to dissapear I hope",
					},
					"10.10.10.10",
					"172.32.0.12",
				)
				addIptRules(fakeRules)

				expectedTables := map[string]util.FakeTable{
					"filter": {
						"OVN-KUBE-EXTERNALIP": []string{
							fmt.Sprintf("-p UDP -d 10.10.10.10 --dport 27000 -j ACCEPT"),
							fmt.Sprintf("-p %s -d %s --dport %v -j ACCEPT", service.Spec.Ports[0].Protocol, externalIP, service.Spec.Ports[0].Port),
						},
					},
					"nat": {
						"OVN-KUBE-EXTERNALIP": []string{
							fmt.Sprintf("-p UDP -d 10.10.10.10 --dport 27000 -j DNAT --to-destination 172.32.0.12:27000"),
							fmt.Sprintf("-p %s -d %s --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, externalIP, service.Spec.Ports[0].Port, service.Spec.ClusterIP, service.Spec.Ports[0].Port),
						},
					},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				fakeOvnNode.start(ctx,
					&v1.ServiceList{
						Items: []v1.Service{
							service,
						},
					},
				)
				fakeOvnNode.node.watchLocalPorts(fNPW)
				Expect(fakeOvnNode.fakeExec.CalledMatchesExpected()).To(BeTrue(), fExec.ErrorDesc)

				expectedTables = map[string]util.FakeTable{
					"filter": {
						"FORWARD": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OVN-KUBE-NODEPORT": []string{},
						"OVN-KUBE-EXTERNALIP": []string{
							fmt.Sprintf("-p %s -d %s --dport %v -j ACCEPT", service.Spec.Ports[0].Protocol, externalIP, service.Spec.Ports[0].Port),
						},
					},
					"nat": {
						"PREROUTING": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OUTPUT": []string{
							"-j OVN-KUBE-EXTERNALIP",
							"-j OVN-KUBE-NODEPORT",
						},
						"OVN-KUBE-NODEPORT": []string{},
						"OVN-KUBE-EXTERNALIP": []string{
							fmt.Sprintf("-p %s -d %s --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, externalIP, service.Spec.Ports[0].Port, service.Spec.ClusterIP, service.Spec.Ports[0].Port),
						},
					},
				}

				f4 = iptV4.(*util.FakeIPTables)
				err = f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				fakeOvnNode.shutdown()
				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("on add", func() {

		It("inits physical routing rules with ExternalIP outside any local network", func() {
			app.Action = func(ctx *cli.Context) error {

				externalIP := "1.1.1.1"

				iptV4, iptV6 := util.SetFakeIPTablesHelpers()
				fNPW := initFakeNodePortWatcher(fakeOvnNode, iptV4, iptV6)

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							Port:     8032,
							Protocol: v1.ProtocolTCP,
						},
					},
					v1.ServiceTypeClusterIP,
					[]string{externalIP},
				)

				fakeOvnNode.fakeExec.AddFakeCmdsNoOutputNoError([]string{
					fmt.Sprintf("ip route replace %s via %s dev %s table %s", externalIP, v4localnetGatewayIP, localnetGatewayNextHopPort, localnetGatewayExternalIDTable),
				})

				fNPW.addService(&service)

				expectedTables := map[string]util.FakeTable{
					"filter": {},
					"nat":    {},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				f6 := iptV6.(*util.FakeIPTables)
				err = f6.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("does nothing when ExternalIP on shared network", func() {
			app.Action = func(ctx *cli.Context) error {

				externalIP := "10.10.10.2"

				iptV4, iptV6 := util.SetFakeIPTablesHelpers()
				fNPW := initFakeNodePortWatcher(fakeOvnNode, iptV4, iptV6)

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							Port:     8032,
							Protocol: v1.ProtocolTCP,
						},
					},
					v1.ServiceTypeClusterIP,
					[]string{externalIP},
				)

				fNPW.addService(&service)

				expectedTables := map[string]util.FakeTable{
					"filter": {},
					"nat":    {},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				f6 := iptV6.(*util.FakeIPTables)
				err = f6.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("inits iptables rules when ExternalIP attached to network interface", func() {
			app.Action = func(ctx *cli.Context) error {

				externalIP := "10.10.10.1"

				iptV4, iptV6 := util.SetFakeIPTablesHelpers()
				fNPW := initFakeNodePortWatcher(fakeOvnNode, iptV4, iptV6)

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							Port:     8032,
							Protocol: v1.ProtocolTCP,
						},
					},
					v1.ServiceTypeClusterIP,
					[]string{externalIP},
				)

				fNPW.addService(&service)

				expectedTables := map[string]util.FakeTable{
					"filter": {
						"OVN-KUBE-EXTERNALIP": []string{
							fmt.Sprintf("-p %s -d %s --dport %v -j ACCEPT", service.Spec.Ports[0].Protocol, externalIP, service.Spec.Ports[0].Port),
						},
					},
					"nat": {
						"OVN-KUBE-EXTERNALIP": []string{
							fmt.Sprintf("-p %s -d %s --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, externalIP, service.Spec.Ports[0].Port, service.Spec.ClusterIP, service.Spec.Ports[0].Port),
						},
					},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("inits iptables rules with NodePort", func() {
			app.Action = func(ctx *cli.Context) error {

				nodePort := int32(31111)

				iptV4, iptV6 := util.SetFakeIPTablesHelpers()
				fNPW := initFakeNodePortWatcher(fakeOvnNode, iptV4, iptV6)

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							NodePort: nodePort,
							Protocol: v1.ProtocolTCP,
						},
					},
					v1.ServiceTypeNodePort,
					nil,
				)

				fNPW.addService(&service)

				expectedTables := map[string]util.FakeTable{
					"filter": {
						"OVN-KUBE-NODEPORT": []string{
							fmt.Sprintf("-p %s --dport %v -j ACCEPT", service.Spec.Ports[0].Protocol, service.Spec.Ports[0].NodePort),
						},
					},
					"nat": {
						"OVN-KUBE-NODEPORT": []string{
							fmt.Sprintf("-p %s --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, service.Spec.Ports[0].NodePort, service.Spec.ClusterIP, service.Spec.Ports[0].Port),
						},
					},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("emits event when ExternalIP attached to network interface with headless service", func() {
			app.Action = func(ctx *cli.Context) error {

				externalIP := "10.10.10.1"
				externalIPPort := int32(8032)

				iptV4, iptV6 := util.SetFakeIPTablesHelpers()
				fNPW := initFakeNodePortWatcher(fakeOvnNode, iptV4, iptV6)

				service := *newService("service1", "namespace1", "None",
					[]v1.ServicePort{
						{
							Port:     externalIPPort,
							Protocol: v1.ProtocolTCP,
						},
					},
					v1.ServiceTypeClusterIP,
					[]string{externalIP},
				)

				fNPW.addService(&service)

				// Check that event was emitted
				recordedEvent := <-fakeOvnNode.recorder.Events
				Expect(recordedEvent).To(ContainSubstring("UnsupportedServiceDefinition"))

				expectedTables := map[string]util.FakeTable{
					"filter": {},
					"nat":    {},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				f6 := iptV6.(*util.FakeIPTables)
				err = f6.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("on delete", func() {

		It("deletes physical routing rules with ExternalIP outside any local network", func() {
			app.Action = func(ctx *cli.Context) error {

				externalIP := "1.1.1.1"

				iptV4, iptV6 := util.SetFakeIPTablesHelpers()
				fNPW := initFakeNodePortWatcher(fakeOvnNode, iptV4, iptV6)

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							Port:     8032,
							Protocol: v1.ProtocolTCP,
						},
					},
					v1.ServiceTypeClusterIP,
					[]string{externalIP},
				)

				fakeOvnNode.fakeExec.AddFakeCmdsNoOutputNoError([]string{
					fmt.Sprintf("ip route del %s via %s dev %s table %s", externalIP, v4localnetGatewayIP, localnetGatewayNextHopPort, localnetGatewayExternalIDTable),
				})

				fNPW.deleteService(&service)

				expectedTables := map[string]util.FakeTable{
					"filter": {},
					"nat":    {},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				f6 := iptV6.(*util.FakeIPTables)
				err = f6.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("does nothing when ExternalIP on shared network", func() {
			app.Action = func(ctx *cli.Context) error {

				externalIP := "10.10.10.2"

				iptV4, iptV6 := util.SetFakeIPTablesHelpers()
				fNPW := initFakeNodePortWatcher(fakeOvnNode, iptV4, iptV6)

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							Port:     8032,
							Protocol: v1.ProtocolTCP,
						},
					},
					v1.ServiceTypeClusterIP,
					[]string{externalIP},
				)

				fNPW.deleteService(&service)

				expectedTables := map[string]util.FakeTable{
					"filter": {},
					"nat":    {},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				f6 := iptV6.(*util.FakeIPTables)
				err = f6.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("deletes iptables rules with ExternalIP attached to network interface", func() {
			app.Action = func(ctx *cli.Context) error {

				externalIP := "10.10.10.1"

				iptV4, iptV6 := util.SetFakeIPTablesHelpers()
				fNPW := initFakeNodePortWatcher(fakeOvnNode, iptV4, iptV6)

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							Port:     8032,
							Protocol: v1.ProtocolTCP,
						},
					},
					v1.ServiceTypeClusterIP,
					[]string{externalIP},
				)

				fNPW.deleteService(&service)

				expectedTables := map[string]util.FakeTable{
					"filter": {},
					"nat":    {},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				f6 := iptV6.(*util.FakeIPTables)
				err = f6.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("deletes iptables rules for NodePort", func() {
			app.Action = func(ctx *cli.Context) error {

				nodePort := int32(31111)

				iptV4, iptV6 := util.SetFakeIPTablesHelpers()
				fNPW := initFakeNodePortWatcher(fakeOvnNode, iptV4, iptV6)

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							NodePort: nodePort,
							Protocol: v1.ProtocolTCP,
						},
					},
					v1.ServiceTypeNodePort,
					nil,
				)

				fNPW.deleteService(&service)

				expectedTables := map[string]util.FakeTable{
					"filter": {},
					"nat":    {},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				f6 := iptV6.(*util.FakeIPTables)
				err = f6.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("on add and delete", func() {

		It("manages iptables rules with ExternalIP attached to network interface", func() {
			app.Action = func(ctx *cli.Context) error {

				externalIP := "10.10.10.1"
				externalIPPort := int32(8034)

				iptV4, iptV6 := util.SetFakeIPTablesHelpers()
				fNPW := initFakeNodePortWatcher(fakeOvnNode, iptV4, iptV6)

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							Port:     externalIPPort,
							Protocol: v1.ProtocolTCP,
						},
					},
					v1.ServiceTypeClusterIP,
					[]string{externalIP},
				)

				fNPW.addService(&service)

				expectedTables := map[string]util.FakeTable{
					"filter": {
						"OVN-KUBE-EXTERNALIP": []string{
							fmt.Sprintf("-p %s -d %s --dport %v -j ACCEPT", service.Spec.Ports[0].Protocol, externalIP, service.Spec.Ports[0].Port),
						},
					},
					"nat": {
						"OVN-KUBE-EXTERNALIP": []string{
							fmt.Sprintf("-p %s -d %s --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, externalIP, service.Spec.Ports[0].Port, service.Spec.ClusterIP, service.Spec.Ports[0].Port),
						},
					},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				fNPW.deleteService(&service)

				expectedTables = map[string]util.FakeTable{
					"filter": {
						"OVN-KUBE-EXTERNALIP": []string{},
					},
					"nat": {
						"OVN-KUBE-EXTERNALIP": []string{},
					},
				}

				f4 = iptV4.(*util.FakeIPTables)
				err = f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("manages iptables rules for NodePort", func() {
			app.Action = func(ctx *cli.Context) error {

				nodePort := int32(38034)

				iptV4, iptV6 := util.SetFakeIPTablesHelpers()
				fNPW := initFakeNodePortWatcher(fakeOvnNode, iptV4, iptV6)

				service := *newService("service1", "namespace1", "10.129.0.2",
					[]v1.ServicePort{
						{
							NodePort: nodePort,
							Protocol: v1.ProtocolTCP,
						},
					},
					v1.ServiceTypeNodePort,
					nil,
				)

				fNPW.addService(&service)

				expectedTables := map[string]util.FakeTable{
					"filter": {
						"OVN-KUBE-NODEPORT": []string{
							fmt.Sprintf("-p %s --dport %v -j ACCEPT", service.Spec.Ports[0].Protocol, nodePort),
						},
					},
					"nat": {
						"OVN-KUBE-NODEPORT": []string{
							fmt.Sprintf("-p %s --dport %v -j DNAT --to-destination %s:%v", service.Spec.Ports[0].Protocol, nodePort, service.Spec.ClusterIP, service.Spec.Ports[0].Port),
						},
					},
				}

				f4 := iptV4.(*util.FakeIPTables)
				err := f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				fNPW.deleteService(&service)

				expectedTables = map[string]util.FakeTable{
					"filter": {
						"OVN-KUBE-NODEPORT": []string{},
					},
					"nat": {
						"OVN-KUBE-NODEPORT": []string{},
					},
				}

				f4 = iptV4.(*util.FakeIPTables)
				err = f4.MatchState(expectedTables)
				Expect(err).NotTo(HaveOccurred())

				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

	})
})
