package cni

import (
	"fmt"

	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("CNI OVS tests", func() {
	var fexec *ovntest.FakeExec

	ginkgo.BeforeEach(func() {
		fexec = ovntest.NewFakeExec()
		setExec(fexec)
	})

	ginkgo.It("returns non-empty elements from ovsFind", func() {
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd: "ovs-vsctl --timeout=30 --no-heading --format=csv --data=bare --columns=_uuid find Interface external-ids:iface-id=foobar",
			Output: `75419b50-ec6e-4989-b769-164488f53375
4609184a-cb69-46ed-880f-807b6a4e99f5
d9af11aa-37c3-4ea9-8ba3-a74843cc0f47
`,
		})

		uuids, err := ovsFind("Interface", "_uuid", "external-ids:iface-id=foobar")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(len(uuids)).To(gomega.Equal(3), fmt.Sprintf("got %v", uuids))
		gomega.Expect(uuids[0]).To(gomega.Equal("75419b50-ec6e-4989-b769-164488f53375"))
		gomega.Expect(uuids[1]).To(gomega.Equal("4609184a-cb69-46ed-880f-807b6a4e99f5"))
		gomega.Expect(uuids[2]).To(gomega.Equal("d9af11aa-37c3-4ea9-8ba3-a74843cc0f47"))
	})

	ginkgo.It("returns nil if no element is returned from ovsFind", func() {
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovs-vsctl --timeout=30 --no-heading --format=csv --data=bare --columns=_uuid find Interface external-ids:iface-id=foobar",
			Output: "",
		})

		uuids, err := ovsFind("Interface", "_uuid", "external-ids:iface-id=foobar")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(uuids).To(gomega.BeNil())
	})

	ginkgo.It("returns empty values if the elements themselves are empty from ovsFind", func() {
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd: "ovs-vsctl --timeout=30 --no-heading --format=csv --data=bare --columns=_uuid find Interface external-ids:iface-id=foobar",
			Output: `

`,
		})

		uuids, err := ovsFind("Interface", "_uuid", "external-ids:iface-id=foobar")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(len(uuids)).To(gomega.Equal(2), fmt.Sprintf("got %v", uuids))
		gomega.Expect(uuids[0]).To(gomega.Equal(""))
		gomega.Expect(uuids[1]).To(gomega.Equal(""))
	})

	ginkgo.It("returns quoted empty values if the elements themselves are empty from ovsFind", func() {
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd: "ovs-vsctl --timeout=30 --no-heading --format=csv --data=bare --columns=_uuid find Interface external-ids:iface-id=foobar",
			Output: `""
""
`,
		})

		uuids, err := ovsFind("Interface", "_uuid", "external-ids:iface-id=foobar")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(len(uuids)).To(gomega.Equal(2), fmt.Sprintf("got %v", uuids))
		gomega.Expect(uuids[0]).To(gomega.Equal(`""`))
		gomega.Expect(uuids[1]).To(gomega.Equal(`""`))
	})
})
