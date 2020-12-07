package node

import (
	"fmt"

	"github.com/urfave/cli/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("Node Operations", func() {
	var app *cli.App

	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags
	})

	ginkgo.It("sets correct OVN external IDs", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				nodeIP   string = "1.2.5.6"
				nodeName string = "cannot.be.resolv.ed"
				interval int    = 100000
				ofintval int    = 180
			)
			node := kapi.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName,
				},
				Status: kapi.NodeStatus{
					Addresses: []kapi.NodeAddress{
						{
							Type:    kapi.NodeExternalIP,
							Address: nodeIP,
						},
					},
				},
			}

			fexec := ovntest.NewFakeExec()
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: fmt.Sprintf("ovs-vsctl --timeout=15 set Open_vSwitch . "+
					"external_ids:ovn-encap-type=geneve "+
					"external_ids:ovn-encap-ip=%s "+
					"external_ids:ovn-remote-probe-interval=%d "+
					"external_ids:ovn-openflow-probe-interval=%d "+
					"external_ids:hostname=\"%s\" "+
					"external_ids:ovn-monitor-all=true",
					nodeIP, interval, ofintval, nodeName),
			})

			err := util.SetExec(fexec)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			_, err = config.InitConfig(ctx, fexec, nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			err = setupOVNNode(&node)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)
			return nil
		}

		err := app.Run([]string{app.Name})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})
	ginkgo.It("sets non-default OVN encap port", func() {
		app.Action = func(ctx *cli.Context) error {
			const (
				nodeIP      string = "1.2.5.6"
				nodeName    string = "cannot.be.resolv.ed"
				encapPort   uint   = 666
				interval    int    = 100000
				ofintval    int    = 180
				chassisUUID string = "1a3dfc82-2749-4931-9190-c30e7c0ecea3"
				encapUUID   string = "e4437094-0094-4223-9f14-995d98d5fff8"
			)
			node := kapi.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName,
				},
				Status: kapi.NodeStatus{
					Addresses: []kapi.NodeAddress{
						{
							Type:    kapi.NodeExternalIP,
							Address: nodeIP,
						},
					},
				},
			}

			fexec := ovntest.NewFakeExec()
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: fmt.Sprintf("ovs-vsctl --timeout=15 set Open_vSwitch . "+
					"external_ids:ovn-encap-type=geneve "+
					"external_ids:ovn-encap-ip=%s "+
					"external_ids:ovn-remote-probe-interval=%d "+
					"external_ids:ovn-openflow-probe-interval=%d "+
					"external_ids:hostname=\"%s\" "+
					"external_ids:ovn-monitor-all=true",
					nodeIP, interval, ofintval, nodeName),
			})
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: fmt.Sprintf("ovs-vsctl --timeout=15 " +
					"--if-exists get Open_vSwitch . external_ids:system-id"),
				Output: chassisUUID,
			})
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: fmt.Sprintf("ovn-sbctl --timeout=15 --data=bare --no-heading --columns=_uuid find "+
					"Encap chassis_name=%s", chassisUUID),
				Output: encapUUID,
			})
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd: fmt.Sprintf("ovn-sbctl --timeout=15 set encap "+
					"%s options:dst_port=%d", encapUUID, encapPort),
			})

			err := util.SetExec(fexec)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			_, err = config.InitConfig(ctx, fexec, nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			config.Default.EncapPort = encapPort

			err = setupOVNNode(&node)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)
			return nil
		}

		err := app.Run([]string{app.Name})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})
})
