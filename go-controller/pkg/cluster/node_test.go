package cluster

import (
	"fmt"

	"github.com/urfave/cli"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Node Operations", func() {
	var app *cli.App

	BeforeEach(func() {
		// Restore global default values before each testcase
		config.RestoreDefaultConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags
	})

	It("sets correct OVN external IDs", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				nodeName string = "1.2.5.6"
				interval int    = 100000
			)

			fexec := ovntest.NewFakeExec()
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: fmt.Sprintf("ovs-vsctl --timeout=15 set Open_vSwitch . "+
					"external_ids:ovn-encap-type=geneve "+
					"external_ids:ovn-encap-ip=%s "+
					"external_ids:ovn-remote-probe-interval=%d "+
					"external_ids:hostname=\"%s\"",
					nodeName, interval, nodeName),
			})

			err := util.SetExec(fexec)
			Expect(err).NotTo(HaveOccurred())

			_, err = config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			err = setupOVNNode(nodeName)
			Expect(err).NotTo(HaveOccurred())

			Expect(fexec.CalledMatchesExpected()).To(BeTrue())
			return nil
		}

		err := app.Run([]string{app.Name})
		Expect(err).NotTo(HaveOccurred())
	})
	It("test validateOVNConfigEndpoint()", func() {

		type testcase struct {
			name           string
			subsets        []kapi.EndpointSubset
			expectedResult bool
		}

		testcases := []testcase{
			{
				name: "valid endpoint",
				subsets: []kapi.EndpointSubset{
					{
						Addresses: []kapi.EndpointAddress{
							{IP: "10.1.2.3"},
						},
						Ports: []kapi.EndpointPort{
							{
								Name: "north",
								Port: 1234,
							},
							{
								Name: "south",
								Port: 4321,
							},
						},
					},
				},
				expectedResult: true,
			},
			{
				name: "valid endpoint, multiple IPs",
				subsets: []kapi.EndpointSubset{
					{
						Addresses: []kapi.EndpointAddress{
							{IP: "10.1.2.3"}, {IP: "11.1.2.3"},
						},
						Ports: []kapi.EndpointPort{
							{
								Name: "north",
								Port: 1234,
							},
							{
								Name: "south",
								Port: 4321,
							},
						},
					},
				},
				expectedResult: true,
			},
			{
				name: "invalid endpoint two few ports",
				subsets: []kapi.EndpointSubset{
					{
						Addresses: []kapi.EndpointAddress{
							{IP: "10.1.2.3"},
						},
						Ports: []kapi.EndpointPort{
							{
								Name: "north",
								Port: 1234,
							},
						},
					},
				},
				expectedResult: false,
			},
			{
				name: "invalid endpoint too many ports",
				subsets: []kapi.EndpointSubset{
					{
						Addresses: []kapi.EndpointAddress{
							{IP: "10.1.2.3"},
						},
						Ports: []kapi.EndpointPort{
							{
								Name: "north",
								Port: 1234,
							},
							{
								Name: "south",
								Port: 4321,
							},
							{
								Name: "east",
								Port: 7654,
							},
						},
					},
				},
				expectedResult: false,
			},
			{
				name:           "invalid endpoint no subsets",
				subsets:        []kapi.EndpointSubset{},
				expectedResult: false,
			},
		}

		for _, tc := range testcases {
			test := kapi.Endpoints{
				Subsets: tc.subsets,
			}
			Expect(validateOVNConfigEndpoint(&test)).To(Equal(tc.expectedResult), " test case \"%s\" returned %t instead of %t", tc.name, !tc.expectedResult, tc.expectedResult)
		}
	})
	It("test watchConfigEndpoints single IP", func() {
		app.Action = func(ctx *cli.Context) error {

			const (
				masterAddress string = "10.1.2.3"
				nbPort        int32  = 1234
				sbPort        int32  = 4321
			)

			fexec := ovntest.NewFakeExec()
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: fmt.Sprintf("ovs-vsctl --timeout=15 set Open_vSwitch . "+
					"external_ids:ovn-nb=\"tcp:%s:%d\"",
					masterAddress, nbPort),
			})

			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: fmt.Sprintf("ovs-vsctl --timeout=15 set Open_vSwitch . "+
					"external_ids:ovn-remote=\"tcp:%s:%d\"",
					masterAddress, sbPort),
			})

			err := util.SetExec(fexec)
			Expect(err).NotTo(HaveOccurred())

			fakeClient := fake.NewSimpleClientset(&kapi.EndpointsList{
				Items: []kapi.Endpoints{{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ovn-kubernetes", Name: "ovnkube-db"},
					Subsets: []kapi.EndpointSubset{
						{
							Addresses: []kapi.EndpointAddress{
								{IP: masterAddress},
							},
							Ports: []kapi.EndpointPort{
								{
									Name: "north",
									Port: nbPort,
								},
								{
									Name: "south",
									Port: sbPort,
								},
							},
						},
					},
				}},
			})
			_, err = config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			stopChan := make(chan struct{})
			f, err := factory.NewWatchFactory(fakeClient, stopChan)
			Expect(err).NotTo(HaveOccurred())
			defer f.Shutdown()

			cluster := NewClusterController(fakeClient, f)
			Expect(cluster).NotTo(BeNil())

			Expect(config.OvnNorth.Address).To(Equal("tcp:1.1.1.1:6641"), "config.OvnNorth.Address does not equal cli arg")
			Expect(config.OvnSouth.Address).To(Equal("tcp:1.1.1.1:6642"), "config.OvnSouth.Address does not equal cli arg")

			err = cluster.watchConfigEndpoints()
			Expect(err).NotTo(HaveOccurred())

			// Kubernetes endpoints should eventually propogate to OvnNorth/OvnSouth
			Eventually(func() string {
				return config.OvnNorth.Address
			}).Should(Equal(fmt.Sprintf("tcp:%s:%d", masterAddress, nbPort)), "Northbound DB Port did not get set by watchConfigEndpoints")
			Eventually(func() string {
				return config.OvnSouth.Address
			}).Should(Equal(fmt.Sprintf("tcp:%s:%d", masterAddress, sbPort)), "Southbound DBPort did not get set by watchConfigEndpoints")

			return nil
		}
		err := app.Run([]string{app.Name, "-nb-address=tcp://1.1.1.1:6641", "-sb-address=tcp://1.1.1.1:6642"})
		Expect(err).NotTo(HaveOccurred())

	})
	It("test watchConfigEndpoints multiple IPs", func() {
		app.Action = func(ctx *cli.Context) error {

			const (
				masterAddress1 string = "10.1.2.3"
				masterAddress2 string = "11.1.2.3"
				nbPort         int32  = 1234
				sbPort         int32  = 4321
			)

			fexec := ovntest.NewFakeExec()
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: fmt.Sprintf("ovs-vsctl --timeout=15 set Open_vSwitch . "+
					"external_ids:ovn-nb=\"tcp:%s:%d,tcp:%s:%d\"",
					masterAddress1, nbPort, masterAddress2, nbPort),
			})

			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: fmt.Sprintf("ovs-vsctl --timeout=15 set Open_vSwitch . "+
					"external_ids:ovn-remote=\"tcp:%s:%d,tcp:%s:%d\"",
					masterAddress1, sbPort, masterAddress2, sbPort),
			})

			err := util.SetExec(fexec)
			Expect(err).NotTo(HaveOccurred())

			fakeClient := fake.NewSimpleClientset(&kapi.EndpointsList{
				Items: []kapi.Endpoints{{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ovn-kubernetes", Name: "ovnkube-db"},
					Subsets: []kapi.EndpointSubset{
						{
							Addresses: []kapi.EndpointAddress{
								{IP: masterAddress1}, {IP: masterAddress2},
							},
							Ports: []kapi.EndpointPort{
								{
									Name: "north",
									Port: nbPort,
								},
								{
									Name: "south",
									Port: sbPort,
								},
							},
						},
					},
				}},
			})
			_, err = config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			stopChan := make(chan struct{})
			f, err := factory.NewWatchFactory(fakeClient, stopChan)
			Expect(err).NotTo(HaveOccurred())
			defer f.Shutdown()

			cluster := NewClusterController(fakeClient, f)
			Expect(cluster).NotTo(BeNil())

			Expect(config.OvnNorth.Address).To(Equal("tcp:1.1.1.1:6641"), "config.OvnNorth.Address does not equal cli arg")
			Expect(config.OvnSouth.Address).To(Equal("tcp:1.1.1.1:6642"), "config.OvnSouth.Address does not equal cli arg")

			err = cluster.watchConfigEndpoints()
			Expect(err).NotTo(HaveOccurred())

			// Kubernetes endpoints should eventually propogate to OvnNorth/OvnSouth
			Eventually(func() string {
				return config.OvnNorth.Address
			}).Should(Equal(fmt.Sprintf("tcp:%s:%d,tcp:%s:%d", masterAddress1, nbPort, masterAddress2, nbPort)), "Northbound DB Port did not get set by watchConfigEndpoints")
			Eventually(func() string {
				return config.OvnSouth.Address
			}).Should(Equal(fmt.Sprintf("tcp:%s:%d,tcp:%s:%d", masterAddress1, sbPort, masterAddress2, sbPort)), "Southbound DBPort did not get set by watchConfigEndpoints")

			return nil
		}
		err := app.Run([]string{app.Name, "-nb-address=tcp://1.1.1.1:6641", "-sb-address=tcp://1.1.1.1:6642"})
		Expect(err).NotTo(HaveOccurred())

	})
})
