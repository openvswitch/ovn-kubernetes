package ovn

import (
	"fmt"
	"net"

	"github.com/urfave/cli/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type testAddressSetName struct {
	namespace string
	suffix1   string
	suffix2   string
}

func (asn *testAddressSetName) makeName() string {
	return fmt.Sprintf("%s.%s.%s", asn.namespace, asn.suffix1, asn.suffix2)
}

var _ = Describe("OVN Address Set operations", func() {
	var (
		app       *cli.App
		fexec     *ovntest.FakeExec
		asFactory AddressSetFactory
	)

	BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fexec = ovntest.NewFakeExec()
		exec, err := util.NewExecHelper(fexec)
		Expect(err).NotTo(HaveOccurred())

		asFactory = NewOvnAddressSetFactory(exec)
	})

	Context("when iterating address sets", func() {
		It("calls the iterator function for each address set with the given prefix", func() {
			app.Action = func(ctx *cli.Context) error {
				_, err := config.InitConfig(ctx, fexec, nil)
				Expect(err).NotTo(HaveOccurred())

				namespaces := []testAddressSetName{
					{
						namespace: "ns1",
						suffix1:   "foo",
						suffix2:   "bar",
					},
					{
						namespace: "ns2",
						suffix1:   "test",
						suffix2:   "test2",
					},
					{
						namespace: "ns3",
					},
				}

				var namespacesRes string
				for _, n := range namespaces {
					name := n.makeName()
					namespacesRes += fmt.Sprintf("%s,name=%s\n", hashedAddressSet(name), name)
				}
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=external_ids find address_set",
					Output: namespacesRes,
				})

				err = asFactory.ForEachAddressSet(func(addrSetName, namespaceName, nameSuffix string) {
					found := false
					for _, n := range namespaces {
						name := n.makeName()
						if addrSetName == name {
							found = true
							Expect(namespaceName).To(Equal(n.namespace))
							if n.suffix1 != "" {
								Expect(nameSuffix).To(Equal(n.suffix1))
							} else {
								Expect(nameSuffix).To(Equal(""))
							}
						}
					}
					Expect(found).To(BeTrue())
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("when creating an address set object", func() {
		It("re-uses an existing address set and replaces IPs", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					addr1 string = "1.2.3.4"
					addr2 string = "5.6.7.8"
				)

				_, err := config.InitConfig(ctx, fexec, nil)
				Expect(err).NotTo(HaveOccurred())

				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=a16990491322166530807",
					Output: fakeUUID,
				})
				fexec.AddFakeCmdsNoOutputNoError([]string{
					`ovn-nbctl --timeout=15 set address_set ` + fakeUUID + ` addresses="` + addr1 + `" "` + addr2 + `"`,
				})

				_, err = asFactory.NewAddressSet("foobar", []net.IP{net.ParseIP(addr1), net.ParseIP(addr2)})
				Expect(err).NotTo(HaveOccurred())
				Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("clears an existing address set of IPs", func() {
			app.Action = func(ctx *cli.Context) error {
				_, err := config.InitConfig(ctx, fexec, nil)
				Expect(err).NotTo(HaveOccurred())

				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=a16990491322166530807",
					Output: fakeUUID,
				})
				fexec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 clear address_set " + fakeUUID + " addresses",
				})

				_, err = asFactory.NewAddressSet("foobar", nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("creates a new address set and sets IPs", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					addr1 string = "1.2.3.4"
					addr2 string = "5.6.7.8"
				)

				_, err := config.InitConfig(ctx, fexec, nil)
				Expect(err).NotTo(HaveOccurred())

				fexec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=a16990491322166530807",
				})
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    `ovn-nbctl --timeout=15 create address_set name=a16990491322166530807 external-ids:name=foobar_v4 addresses="` + addr1 + `" "` + addr2 + `"`,
					Output: fakeUUID,
				})

				_, err = asFactory.NewAddressSet("foobar", []net.IP{net.ParseIP(addr1), net.ParseIP(addr2)})
				Expect(err).NotTo(HaveOccurred())
				Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	It("destroys an address set", func() {
		app.Action = func(ctx *cli.Context) error {
			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())

			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=a16990491322166530807",
				Output: fakeUUID,
			})
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 clear address_set " + fakeUUID + " addresses",
				"ovn-nbctl --timeout=15 --if-exists destroy address_set " + fakeUUID,
			})

			as, err := asFactory.NewAddressSet("foobar", nil)
			Expect(err).NotTo(HaveOccurred())

			err = as.Destroy()
			Expect(err).NotTo(HaveOccurred())
			Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
			return nil
		}

		err := app.Run([]string{app.Name})
		Expect(err).NotTo(HaveOccurred())
	})

	Context("when manipulating IPs in an address set object", func() {
		It("adds an IP to an empty address set", func() {
			app.Action = func(ctx *cli.Context) error {
				const addr1 string = "1.2.3.4"

				_, err := config.InitConfig(ctx, fexec, nil)
				Expect(err).NotTo(HaveOccurred())

				fexec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=a16990491322166530807",
				})
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 create address_set name=a16990491322166530807 external-ids:name=foobar_v4",
					Output: fakeUUID,
				})
				fexec.AddFakeCmdsNoOutputNoError([]string{
					`ovn-nbctl --timeout=15 add address_set ` + fakeUUID + ` addresses "` + addr1 + `"`,
				})

				as, err := asFactory.NewAddressSet("foobar", nil)
				Expect(err).NotTo(HaveOccurred())

				// Re-adding is a no-op
				err = as.AddIPs([]net.IP{net.ParseIP(addr1)})
				Expect(err).NotTo(HaveOccurred())

				Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("deletes an IP from an address set", func() {
			app.Action = func(ctx *cli.Context) error {
				const addr1 string = "1.2.3.4"

				_, err := config.InitConfig(ctx, fexec, nil)
				Expect(err).NotTo(HaveOccurred())

				fexec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=a16990491322166530807",
				})
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    `ovn-nbctl --timeout=15 create address_set name=a16990491322166530807 external-ids:name=foobar_v4 addresses="` + addr1 + `"`,
					Output: fakeUUID,
				})
				fexec.AddFakeCmdsNoOutputNoError([]string{
					`ovn-nbctl --timeout=15 remove address_set ` + fakeUUID + ` addresses "` + addr1 + `"`,
				})

				as, err := asFactory.NewAddressSet("foobar", []net.IP{net.ParseIP(addr1)})
				Expect(err).NotTo(HaveOccurred())

				err = as.DeleteIPs([]net.IP{net.ParseIP(addr1)})
				Expect(err).NotTo(HaveOccurred())

				// Deleting a non-existent address is a no-op
				err = as.DeleteIPs([]net.IP{net.ParseIP(addr1)})
				Expect(err).NotTo(HaveOccurred())

				Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("Dual stack : when creating an address set object", func() {
		It("re-uses an existing dual stack address set and replaces IPs", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					addr1 string = "1.2.3.4"
					addr2 string = "5.6.7.8"
					addr3 string = "2001:db8::1"
					addr4 string = "2001:db8::2"
				)

				_, err := config.InitConfig(ctx, fexec, nil)
				Expect(err).NotTo(HaveOccurred())
				config.IPv6Mode = true

				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=a16990491322166530807",
					Output: fakeUUID,
				})
				fexec.AddFakeCmdsNoOutputNoError([]string{
					`ovn-nbctl --timeout=15 set address_set ` + fakeUUID + ` addresses="` + addr1 + `" "` + addr2 + `"`,
				})

				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=a16990493521189787229",
					Output: fakeUUIDv6,
				})
				fexec.AddFakeCmdsNoOutputNoError([]string{
					`ovn-nbctl --timeout=15 set address_set ` + fakeUUIDv6 + ` addresses="` + addr3 + `" "` + addr4 + `"`,
				})

				_, err = asFactory.NewAddressSet("foobar", []net.IP{net.ParseIP(addr1), net.ParseIP(addr2),
					net.ParseIP(addr3), net.ParseIP(addr4)})
				Expect(err).NotTo(HaveOccurred())
				Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("clears an existing address set of dual stack IPs", func() {
			app.Action = func(ctx *cli.Context) error {
				_, err := config.InitConfig(ctx, fexec, nil)
				Expect(err).NotTo(HaveOccurred())
				config.IPv6Mode = true

				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=a16990491322166530807",
					Output: fakeUUID,
				})
				fexec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 clear address_set " + fakeUUID + " addresses",
				})

				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=a16990493521189787229",
					Output: fakeUUIDv6,
				})
				fexec.AddFakeCmdsNoOutputNoError([]string{
					`ovn-nbctl --timeout=15 clear address_set ` + fakeUUIDv6 + " addresses",
				})

				_, err = asFactory.NewAddressSet("foobar", nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("creates a new address set and sets dual stack IPs", func() {
			app.Action = func(ctx *cli.Context) error {
				const (
					addr1 string = "1.2.3.4"
					addr2 string = "5.6.7.8"
					addr3 string = "2001:db8::1"
					addr4 string = "2001:db8::2"
				)

				_, err := config.InitConfig(ctx, fexec, nil)
				Expect(err).NotTo(HaveOccurred())
				config.IPv6Mode = true

				fexec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=a16990491322166530807",
				})
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    `ovn-nbctl --timeout=15 create address_set name=a16990491322166530807 external-ids:name=foobar_v4 addresses="` + addr1 + `" "` + addr2 + `"`,
					Output: fakeUUID,
				})

				fexec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=a16990493521189787229",
				})
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    `ovn-nbctl --timeout=15 create address_set name=a16990493521189787229 external-ids:name=foobar_v6 addresses="` + addr3 + `" "` + addr4 + `"`,
					Output: fakeUUIDv6,
				})

				_, err = asFactory.NewAddressSet("foobar", []net.IP{net.ParseIP(addr1), net.ParseIP(addr2),
					net.ParseIP(addr3), net.ParseIP(addr4)})
				Expect(err).NotTo(HaveOccurred())
				Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	It("destroys an dual stack address set", func() {
		app.Action = func(ctx *cli.Context) error {
			_, err := config.InitConfig(ctx, fexec, nil)
			Expect(err).NotTo(HaveOccurred())
			config.IPv6Mode = true

			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=a16990491322166530807",
				Output: fakeUUID,
			})
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 clear address_set " + fakeUUID + " addresses",
			})

			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=a16990493521189787229",
				Output: fakeUUIDv6,
			})
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 clear address_set " + fakeUUIDv6 + " addresses",
			})
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --timeout=15 --if-exists destroy address_set " + fakeUUID,
				"ovn-nbctl --timeout=15 --if-exists destroy address_set " + fakeUUIDv6,
			})

			as, err := asFactory.NewAddressSet("foobar", nil)
			Expect(err).NotTo(HaveOccurred())

			err = as.Destroy()
			Expect(err).NotTo(HaveOccurred())
			Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
			return nil
		}

		err := app.Run([]string{app.Name})
		Expect(err).NotTo(HaveOccurred())
	})

	Context("Dual Stack : when manipulating IPs in an address set object", func() {
		It("adds  IP to an empty dual stack address set", func() {
			app.Action = func(ctx *cli.Context) error {
				const addr1 string = "1.2.3.4"
				const addr2 string = "2001:db8::1"

				_, err := config.InitConfig(ctx, fexec, nil)
				Expect(err).NotTo(HaveOccurred())
				config.IPv6Mode = true

				fexec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=a16990491322166530807",
				})
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 create address_set name=a16990491322166530807 external-ids:name=foobar_v4",
					Output: fakeUUID,
				})
				fexec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=a16990493521189787229",
				})
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    "ovn-nbctl --timeout=15 create address_set name=a16990493521189787229 external-ids:name=foobar_v6",
					Output: fakeUUIDv6,
				})
				fexec.AddFakeCmdsNoOutputNoError([]string{
					`ovn-nbctl --timeout=15 add address_set ` + fakeUUID + ` addresses "` + addr1 + `"`,
				})

				fexec.AddFakeCmdsNoOutputNoError([]string{
					`ovn-nbctl --timeout=15 add address_set ` + fakeUUIDv6 + ` addresses "` + addr2 + `"`,
				})

				as, err := asFactory.NewAddressSet("foobar", nil)
				Expect(err).NotTo(HaveOccurred())

				err = as.AddIPs([]net.IP{net.ParseIP(addr1), net.ParseIP(addr2)})
				Expect(err).NotTo(HaveOccurred())

				// Re-adding is a no-op
				err = as.AddIPs([]net.IP{net.ParseIP(addr1)})
				Expect(err).NotTo(HaveOccurred())

				Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})

		It("deletes an IP from an dual stack address set", func() {
			app.Action = func(ctx *cli.Context) error {
				const addr1 string = "1.2.3.4"
				const addr2 string = "2001:db8::1"

				_, err := config.InitConfig(ctx, fexec, nil)
				Expect(err).NotTo(HaveOccurred())
				config.IPv6Mode = true

				fexec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=a16990491322166530807",
				})
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    `ovn-nbctl --timeout=15 create address_set name=a16990491322166530807 external-ids:name=foobar_v4 addresses="` + addr1 + `"`,
					Output: fakeUUID,
				})
				fexec.AddFakeCmdsNoOutputNoError([]string{
					"ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find address_set name=a16990493521189787229",
				})
				fexec.AddFakeCmd(&ovntest.ExpectedCmd{
					Cmd:    `ovn-nbctl --timeout=15 create address_set name=a16990493521189787229 external-ids:name=foobar_v6 addresses="` + addr2 + `"`,
					Output: fakeUUIDv6,
				})

				fexec.AddFakeCmdsNoOutputNoError([]string{
					`ovn-nbctl --timeout=15 remove address_set ` + fakeUUID + ` addresses "` + addr1 + `"`,
				})
				fexec.AddFakeCmdsNoOutputNoError([]string{
					`ovn-nbctl --timeout=15 remove address_set ` + fakeUUIDv6 + ` addresses "` + addr2 + `"`,
				})

				as, err := asFactory.NewAddressSet("foobar", []net.IP{net.ParseIP(addr1), net.ParseIP(addr2)})
				Expect(err).NotTo(HaveOccurred())

				err = as.DeleteIPs([]net.IP{net.ParseIP(addr1), net.ParseIP(addr2)})
				Expect(err).NotTo(HaveOccurred())

				// Deleting a non-existent address is a no-op
				err = as.DeleteIPs([]net.IP{net.ParseIP(addr1)})
				Expect(err).NotTo(HaveOccurred())

				Expect(fexec.CalledMatchesExpected()).To(BeTrue(), fexec.ErrorDesc)
				return nil
			}

			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
