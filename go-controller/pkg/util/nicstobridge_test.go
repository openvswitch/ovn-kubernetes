package util

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	netlink_mocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/vishvananda/netlink"
	"github.com/vishvananda/netlink"

	mock_k8s_io_utils_exec "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/k8s.io/utils/exec"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/mocks"
	"github.com/stretchr/testify/mock"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestGetNicName(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}
	tests := []struct {
		desc                string
		errMatch            error
		outputExp           string
		inpBrName           string
		onRetArgsExecIface  []onCallReturnArgs
		onRetArgsKexecIface []onCallReturnArgs
	}{
		{
			desc:      "empty string as inputBrName",
			errMatch:  fmt.Errorf("failed to get list of ports on bridge"),
			outputExp: "",
			inpBrName: "",
			onRetArgsExecIface: []onCallReturnArgs{
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), fmt.Errorf("test error")}},
			},
			onRetArgsKexecIface: []onCallReturnArgs{
				{"Command", []string{"string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
			},
		},
		{
			desc:      "test code path when `ovs-vsctl get Port port Interfaces` returns error",
			errMatch:  fmt.Errorf("failed to get port"),
			outputExp: "",
			inpBrName: "testPortName",
			onRetArgsExecIface: []onCallReturnArgs{
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("port1\nport2")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), fmt.Errorf("mock error")}},
			},
			onRetArgsKexecIface: []onCallReturnArgs{
				{"Command", []string{"string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
				{"Command", []string{"string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
			},
		},
		{
			desc:      "test code path when `ovs-vsctl get Interface ifaceId Type` returns error",
			errMatch:  fmt.Errorf("failed to get Interface"),
			outputExp: "",
			inpBrName: "testPortName",
			onRetArgsExecIface: []onCallReturnArgs{
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("port1")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("[080841d8-4e12-4003-b0ac-36fefd63bae1]")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), fmt.Errorf("mock error")}},
			},
			onRetArgsKexecIface: []onCallReturnArgs{
				{"Command", []string{"string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
				{"Command", []string{"string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
				{"Command", []string{"string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
			},
		},
		{
			desc:      "test code path when `ovs-vsctl get Interface ifaceId Type` returns `system`",
			outputExp: "port1",
			inpBrName: "testPortName",
			onRetArgsExecIface: []onCallReturnArgs{
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("port1")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("[080841d8-4e12-4003-b0ac-36fefd63bae1]")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("system")), bytes.NewBuffer([]byte("")), nil}},
			},
			onRetArgsKexecIface: []onCallReturnArgs{
				{"Command", []string{"string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
				{"Command", []string{"string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
				{"Command", []string{"string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
			},
		},
		{
			desc:      "test code path when `ovs-vsctl br-get-external-id` returns error",
			errMatch:  fmt.Errorf("failed to get the bridge-uplink for the bridge"),
			outputExp: "",
			inpBrName: "testPortName",
			onRetArgsExecIface: []onCallReturnArgs{
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("port1")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("[080841d8-4e12-4003-b0ac-36fefd63bae1]")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("internal")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), fmt.Errorf("mock error")}},
			},
			onRetArgsKexecIface: []onCallReturnArgs{
				{"Command", []string{"string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
				{"Command", []string{"string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
				{"Command", []string{"string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
				{"Command", []string{"string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
			},
		},
		{
			desc:      "test code path when input bridge name has prefix `br` and stdout is empty",
			outputExp: "Name",
			inpBrName: "brName",
			onRetArgsExecIface: []onCallReturnArgs{
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("port1")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("[080841d8-4e12-4003-b0ac-36fefd63bae1]")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("internal")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), nil}},
			},
			onRetArgsKexecIface: []onCallReturnArgs{
				{"Command", []string{"string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
				{"Command", []string{"string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
				{"Command", []string{"string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
				{"Command", []string{"string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
			},
		},
		{
			desc:      "test code path when input bridge name has NO prefix `br`",
			outputExp: "someoutput",
			inpBrName: "testName",
			onRetArgsExecIface: []onCallReturnArgs{
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("port1")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("[080841d8-4e12-4003-b0ac-36fefd63bae1]")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("internal")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("someoutput")), bytes.NewBuffer([]byte("")), nil}},
			},
			onRetArgsKexecIface: []onCallReturnArgs{
				{"Command", []string{"string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
				{"Command", []string{"string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
				{"Command", []string{"string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
				{"Command", []string{"string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			for _, item := range tc.onRetArgsExecIface {
				call := mockExecRunner.On(item.onCallMethodName)
				for _, arg := range item.onCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.retArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			for _, item := range tc.onRetArgsKexecIface {
				call := mockKexecIface.On(item.onCallMethodName)
				for _, arg := range item.onCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.retArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			res, err := GetNicName(runner, tc.inpBrName)

			t.Log(res, err)

			if tc.errMatch != nil {
				assert.Contains(t, err.Error(), tc.errMatch.Error())
			} else {
				assert.Equal(t, res, tc.outputExp)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestSaveIPAddress(t *testing.T) {
	mockNetLinkOps := new(mocks.NetLinkOps)
	mockLink := new(netlink_mocks.Link)
	// below is defined in net_linux.go
	netLinkOps = mockNetLinkOps
	tests := []struct {
		desc                     string
		inpOldLink               netlink.Link
		inpNewLink               netlink.Link
		inpAddrs                 []netlink.Addr
		errExp                   bool
		onRetArgsNetLinkLibOpers []onCallReturnArgs
		onRetArgsLinkIfaceOpers  []onCallReturnArgs
	}{
		{
			desc:       "empty address list, LinkSetup(newLink) succeeds",
			inpOldLink: mockLink,
			inpNewLink: mockLink,
			inpAddrs:   []netlink.Addr{},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
			},
		},
		{
			desc:       "deleting address from old link errors out",
			errExp:     true,
			inpOldLink: mockLink,
			inpNewLink: mockLink,
			inpAddrs:   []netlink.Addr{{IPNet: ovntest.MustParseIPNet("192.168.1.15/24")}},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				{"AddrDel", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{fmt.Errorf("mock error")}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:       "adding address to new link errors out",
			errExp:     true,
			inpOldLink: mockLink,
			inpNewLink: mockLink,
			inpAddrs:   []netlink.Addr{{IPNet: ovntest.MustParseIPNet("192.168.1.15/24")}},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				{"AddrDel", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"AddrAdd", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{fmt.Errorf("mock error")}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:       "saving IP address to new link succeeds",
			inpOldLink: mockLink,
			inpNewLink: mockLink,
			inpAddrs:   []netlink.Addr{{IPNet: ovntest.MustParseIPNet("192.168.1.15/24")}},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				{"AddrDel", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"AddrAdd", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			for _, item := range tc.onRetArgsNetLinkLibOpers {
				call := mockNetLinkOps.On(item.onCallMethodName)
				for _, arg := range item.onCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.retArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			for _, item := range tc.onRetArgsLinkIfaceOpers {
				call := mockLink.On(item.onCallMethodName)
				for _, arg := range item.onCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.retArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			err := saveIPAddress(tc.inpNewLink, tc.inpOldLink, tc.inpAddrs)
			t.Log(err)
			if tc.errExp {
				assert.Error(t, err)
			} else {
				assert.Nil(t, err)
			}
			mockNetLinkOps.AssertExpectations(t)
			mockLink.AssertExpectations(t)
		})
	}
}

func TestDelAddRoute(t *testing.T) {
	mockNetLinkOps := new(mocks.NetLinkOps)
	mockLink := new(netlink_mocks.Link)
	// below is defined in net_linux.go
	netLinkOps = mockNetLinkOps

	tests := []struct {
		desc                     string
		errExp                   bool
		inpOldLink               netlink.Link
		inpNewLink               netlink.Link
		inpRoute                 netlink.Route
		onRetArgsNetLinkLibOpers []onCallReturnArgs
		onRetArgsLinkIfaceOpers  []onCallReturnArgs
	}{
		{
			desc:       "test path where RouteDel() fails",
			errExp:     true,
			inpOldLink: mockLink,
			inpNewLink: mockLink,
			inpRoute:   netlink.Route{Dst: ovntest.MustParseIPNet("192.168.1.0/24")},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				{"RouteDel", []string{"*netlink.Route"}, []interface{}{fmt.Errorf("mock error")}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:       "test path where RouteAdd() fails",
			errExp:     true,
			inpOldLink: mockLink,
			inpNewLink: mockLink,
			inpRoute:   netlink.Route{Dst: ovntest.MustParseIPNet("192.168.1.0/24")},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				{"RouteDel", []string{"*netlink.Route"}, []interface{}{nil}},
				{"RouteAdd", []string{"*netlink.Route"}, []interface{}{fmt.Errorf("mock error")}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Index: 1}}},
			},
		},
		{
			desc:       "test success path",
			inpOldLink: mockLink,
			inpNewLink: mockLink,
			inpRoute:   netlink.Route{Dst: ovntest.MustParseIPNet("192.168.1.0/24")},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				{"RouteDel", []string{"*netlink.Route"}, []interface{}{nil}},
				{"RouteAdd", []string{"*netlink.Route"}, []interface{}{nil}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Index: 1}}},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			for _, item := range tc.onRetArgsNetLinkLibOpers {
				call := mockNetLinkOps.On(item.onCallMethodName)
				for _, arg := range item.onCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.retArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			for _, item := range tc.onRetArgsLinkIfaceOpers {
				call := mockLink.On(item.onCallMethodName)
				for _, arg := range item.onCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.retArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			err := delAddRoute(tc.inpOldLink, tc.inpNewLink, tc.inpRoute)
			t.Log(err)
			if tc.errExp {
				assert.Error(t, err)
			} else {
				assert.Nil(t, err)
			}
			mockNetLinkOps.AssertExpectations(t)
			mockLink.AssertExpectations(t)
		})
	}
}

func TestSaveRoute(t *testing.T) {
	mockNetLinkOps := new(mocks.NetLinkOps)
	mockLink := new(netlink_mocks.Link)
	// below is defined in net_linux.go
	netLinkOps = mockNetLinkOps

	tests := []struct {
		desc                     string
		errExp                   bool
		inpOldLink               netlink.Link
		inpNewLink               netlink.Link
		inpRoutes                []netlink.Route
		onRetArgsNetLinkLibOpers []onCallReturnArgs
		onRetArgsLinkIfaceOpers  []onCallReturnArgs
	}{
		{
			desc: "providing empty routes should return no error",
		},
		{
			desc:       "test error path for GCE special case",
			errExp:     true,
			inpNewLink: mockLink,
			inpOldLink: mockLink,
			inpRoutes: []netlink.Route{
				{Dst: ovntest.MustParseIPNet("192.168.1.0/24"), Gw: ovntest.MustParseIP("10.10.10.1")},
				{Gw: ovntest.MustParseIP("10.10.10.1"), LinkIndex: 1},
			},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				{"RouteDel", []string{"*netlink.Route"}, []interface{}{fmt.Errorf("mock error")}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:       "test error path for when adding default gateway",
			errExp:     true,
			inpNewLink: mockLink,
			inpOldLink: mockLink,
			inpRoutes: []netlink.Route{
				{Gw: ovntest.MustParseIP("10.10.10.1"), LinkIndex: 1},
			},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				{"RouteDel", []string{"*netlink.Route"}, []interface{}{fmt.Errorf("mock error")}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:       "test success path",
			inpNewLink: mockLink,
			inpOldLink: mockLink,
			inpRoutes: []netlink.Route{
				{Gw: ovntest.MustParseIP("10.10.10.1"), LinkIndex: 1},
			},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				{"RouteDel", []string{"*netlink.Route"}, []interface{}{nil}},
				{"RouteAdd", []string{"*netlink.Route"}, []interface{}{nil}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			for _, item := range tc.onRetArgsNetLinkLibOpers {
				call := mockNetLinkOps.On(item.onCallMethodName)
				for _, arg := range item.onCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.retArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			for _, item := range tc.onRetArgsLinkIfaceOpers {
				call := mockLink.On(item.onCallMethodName)
				for _, arg := range item.onCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.retArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			err := saveRoute(tc.inpOldLink, tc.inpNewLink, tc.inpRoutes)
			t.Log(err)
			if tc.errExp {
				assert.Error(t, err)
			} else {
				assert.Nil(t, err)
			}
			mockNetLinkOps.AssertExpectations(t)
			mockLink.AssertExpectations(t)
		})
	}
}

func TestNicToBridge(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	mockNetLinkOps := new(mocks.NetLinkOps)
	mockLink := new(netlink_mocks.Link)
	// below is defined in net_linux.go
	netLinkOps = mockNetLinkOps
	tests := []struct {
		desc                     string
		inpIface                 string
		outBridge                string
		errExp                   bool
		onRetArgsExecUtilsIface  *onCallReturnArgsRepetitive
		onRetArgsKexecIface      *onCallReturnArgsRepetitive
		onRetArgsNetLinkLibOpers []onCallReturnArgs
		onRetArgsLinkIfaceOpers  []onCallReturnArgs
	}{
		{
			desc:     "invalid interface name fails to return a link",
			inpIface: "",
			errExp:   true,
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				{"LinkByName", []string{"string"}, []interface{}{nil, fmt.Errorf("mock error")}},
			},
		},
		{
			desc:                    "RunOVSVsctl fails to create OVS bridge",
			inpIface:                "eth0",
			errExp:                  true,
			onRetArgsExecUtilsIface: &onCallReturnArgsRepetitive{"RunCmd", 31, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), fmt.Errorf("RunOVSVsctl error")}},
			onRetArgsKexecIface:     &onCallReturnArgsRepetitive{"Command", 32, []string{}, []interface{}{mockCmd}},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:                    "IP address retrieval for link fails",
			inpIface:                "eth0",
			errExp:                  true,
			onRetArgsExecUtilsIface: &onCallReturnArgsRepetitive{"RunCmd", 31, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgsRepetitive{"Command", 32, []string{}, []interface{}{mockCmd}},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{nil, fmt.Errorf("mock error")}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:                    "Route retrieval for link fails",
			inpIface:                "eth0",
			errExp:                  true,
			onRetArgsExecUtilsIface: &onCallReturnArgsRepetitive{"RunCmd", 31, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgsRepetitive{"Command", 32, []string{}, []interface{}{mockCmd}},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Addr{{IPNet: ovntest.MustParseIPNet("192.168.1.15/24")}}, nil}},
				{"RouteList", []string{"*mocks.Link", "int"}, []interface{}{nil, fmt.Errorf("mock error")}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:                    "Retrieving link by bridge name fails",
			errExp:                  true,
			onRetArgsExecUtilsIface: &onCallReturnArgsRepetitive{"RunCmd", 31, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgsRepetitive{"Command", 32, []string{}, []interface{}{mockCmd}},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Addr{{IPNet: ovntest.MustParseIPNet("192.168.1.15/24")}}, nil}},
				{"RouteList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Route{{Dst: ovntest.MustParseIPNet("10.168.1.0/24")}}, nil}},
				{"LinkByName", []string{"string"}, []interface{}{nil, fmt.Errorf("mock error")}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:                    "Saving IP address to bridge fails",
			errExp:                  true,
			onRetArgsExecUtilsIface: &onCallReturnArgsRepetitive{"RunCmd", 31, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgsRepetitive{"Command", 32, []string{}, []interface{}{mockCmd}},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Addr{}, nil}},
				{"RouteList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Route{}, nil}},
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{fmt.Errorf("mock error")}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:                    "Saving routes to bridge fails",
			errExp:                  true,
			onRetArgsExecUtilsIface: &onCallReturnArgsRepetitive{"RunCmd", 31, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgsRepetitive{"Command", 32, []string{}, []interface{}{mockCmd}},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Addr{}, nil}},
				{"RouteList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Route{{Gw: ovntest.MustParseIP("10.10.10.1"), LinkIndex: 1}}, nil}},
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
				{"RouteDel", []string{"*netlink.Route"}, []interface{}{fmt.Errorf("mock error")}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:                    "IP address and Routes of interface to OVS bridge succeeds",
			onRetArgsExecUtilsIface: &onCallReturnArgsRepetitive{"RunCmd", 31, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgsRepetitive{"Command", 32, []string{}, []interface{}{mockCmd}},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Addr{}, nil}},
				{"RouteList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Route{{Gw: ovntest.MustParseIP("10.10.10.1"), LinkIndex: 1}}, nil}},
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
				{"RouteDel", []string{"*netlink.Route"}, []interface{}{nil}},
				{"RouteAdd", []string{"*netlink.Route"}, []interface{}{nil}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			if tc.onRetArgsExecUtilsIface != nil {
				call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
				for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				// append the repetitive arg types of `string` at the end
				for i := 0; i < tc.onRetArgsExecUtilsIface.onCallMethodsArgsStrTypeAppendCount; i++ {
					call.Arguments = append(call.Arguments, mock.AnythingOfType("string"))
				}
				for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			if tc.onRetArgsKexecIface != nil {
				ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
				for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
					ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
				}
				// append the repetitive arg types of `string` at the end
				for i := 0; i < tc.onRetArgsKexecIface.onCallMethodsArgsStrTypeAppendCount; i++ {
					ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType("string"))
				}
				for _, ret := range tc.onRetArgsKexecIface.retArgList {
					ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
				}
				ifaceCall.Once()
			}

			for _, item := range tc.onRetArgsNetLinkLibOpers {
				call := mockNetLinkOps.On(item.onCallMethodName)
				for _, arg := range item.onCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.retArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			for _, item := range tc.onRetArgsLinkIfaceOpers {
				call := mockLink.On(item.onCallMethodName)
				for _, arg := range item.onCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.retArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			res, err := NicToBridge(runner, tc.inpIface)
			t.Log(res, err)
			if tc.errExp {
				assert.Error(t, err)
				assert.Equal(t, len(res), 0)
			} else {
				assert.Nil(t, err)
				assert.Greater(t, len(res), 0)
			}
			mockKexecIface.AssertExpectations(t)
			mockExecRunner.AssertExpectations(t)
			mockNetLinkOps.AssertExpectations(t)
			mockLink.AssertExpectations(t)
		})
	}
}

func TestBridgeToNic(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	mockNetLinkOps := new(mocks.NetLinkOps)
	mockLink := new(netlink_mocks.Link)
	// below is defined in net_linux.go
	netLinkOps = mockNetLinkOps
	tests := []struct {
		desc                     string
		inpBridge                string
		errExp                   bool
		onRetArgsExecUtilsIface  []onCallReturnArgsRepetitive
		onRetArgsKexecIface      []onCallReturnArgsRepetitive
		onRetArgsNetLinkLibOpers []onCallReturnArgs
		onRetArgsLinkIfaceOpers  []onCallReturnArgs
	}{
		{
			desc:      "invalid bridge name fails to return a link",
			inpBridge: "brinvalid",
			errExp:    true,
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `bridgeLink, err := netlink.LinkByName(bridge)` code path
				{"LinkByName", []string{"string"}, []interface{}{nil, fmt.Errorf("mock error")}},
			},
		},
		{
			desc:      "IP address retrieval for link fails",
			inpBridge: "breth0",
			errExp:    true,
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `bridgeLink, err := netlink.LinkByName(bridge)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below row entry is for mocking the `addrs, err := netlink.AddrList(bridgeLink, syscall.AF_INET)` code path
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{nil, fmt.Errorf("mock error")}},
			},
		},
		{
			desc:      "Route retrieval for link fails",
			inpBridge: "breth0",
			errExp:    true,
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `bridgeLink, err := netlink.LinkByName(bridge)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below row entry is for mocking the `addrs, err := netlink.AddrList(bridgeLink, syscall.AF_INET)` code path
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Addr{{IPNet: ovntest.MustParseIPNet("192.168.1.15/24")}}, nil}},
				// Below row entry is for mocking the `routes, err := netlink.RouteList(bridgeLink, syscall.AF_INET)` code path
				{"RouteList", []string{"*mocks.Link", "int"}, []interface{}{nil, fmt.Errorf("mock error")}},
			},
		},
		{
			desc:      "Nic Name retrieval using bridge name fails",
			inpBridge: "breth0",
			errExp:    true,
			// Below two entries are for mocking the `nicName, err := GetNicName(bridge)` code path
			onRetArgsExecUtilsIface: []onCallReturnArgsRepetitive{
				//Below entry is for mocking the `nicName, err := GetNicName(bridge)` code path
				{"RunCmd", 4, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("eth0")), bytes.NewBuffer([]byte("")), fmt.Errorf("mock error")}},
			},
			onRetArgsKexecIface: []onCallReturnArgsRepetitive{
				//Below entry is for mocking the `nicName, err := GetNicName(bridge)` code path
				{"Command", 5, []string{}, []interface{}{mockCmd}},
			},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `bridgeLink, err := netlink.LinkByName(bridge)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below row entry is for mocking the `addrs, err := netlink.AddrList(bridgeLink, syscall.AF_INET)` code path
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Addr{{IPNet: ovntest.MustParseIPNet("192.168.1.15/24")}}, nil}},
				// Below row entry is for mocking the `routes, err := netlink.RouteList(bridgeLink, syscall.AF_INET)` code path
				{"RouteList", []string{"*mocks.Link", "int"}, []interface{}{nil, nil}},
			},
		},
		{
			desc:      "retrieving interface link using nic name fails",
			inpBridge: "breth0",
			errExp:    true,
			// Below two entries are for mocking the `nicName, err := GetNicName(bridge)` code path
			//onRetArgsExecUtilsIface: &onCallReturnArgsRepetitive{"RunCmd", 4, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("eth0")), bytes.NewBuffer([]byte("")), nil}},
			//onRetArgsKexecIface:     &onCallReturnArgsRepetitive{"Command", 5, []string{}, []interface{}{mockCmd}},
			onRetArgsExecUtilsIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"RunCmd", 4, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("eth0")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("[080841d8-4e12-4003-b0ac-36fefd63bae1]")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("system")), bytes.NewBuffer([]byte("")), nil}},
			},
			onRetArgsKexecIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"Command", 5, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
			},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `bridgeLink, err := netlink.LinkByName(bridge)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below row entry is for mocking the `addrs, err := netlink.AddrList(bridgeLink, syscall.AF_INET)` code path
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Addr{{IPNet: ovntest.MustParseIPNet("192.168.1.15/24")}}, nil}},
				// Below row entry is for mocking the `routes, err := netlink.RouteList(bridgeLink, syscall.AF_INET)` code path
				{"RouteList", []string{"*mocks.Link", "int"}, []interface{}{nil, nil}},
				// Below row entry is for mocking the `ifaceLink, err := netlink.LinkByName(nicName)` code path
				{"LinkByName", []string{"string"}, []interface{}{nil, fmt.Errorf("mock error")}},
			},
		},
		{
			desc:      "saving IP address to iface fails",
			inpBridge: "breth0",
			errExp:    true,
			// Below two entries are for mocking the `nicName, err := GetNicName(bridge)` code path
			onRetArgsExecUtilsIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"RunCmd", 4, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("eth0")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("[080841d8-4e12-4003-b0ac-36fefd63bae1]")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("system")), bytes.NewBuffer([]byte("")), nil}}},
			onRetArgsKexecIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"Command", 5, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
			},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `bridgeLink, err := netlink.LinkByName(bridge)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below row entry is for mocking the `addrs, err := netlink.AddrList(bridgeLink, syscall.AF_INET)` code path
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Addr{{IPNet: ovntest.MustParseIPNet("192.168.1.15/24")}}, nil}},
				// Below row entry is for mocking the `routes, err := netlink.RouteList(bridgeLink, syscall.AF_INET)` code path
				{"RouteList", []string{"*mocks.Link", "int"}, []interface{}{nil, nil}},
				// Below row entry is for mocking the `ifaceLink, err := netlink.LinkByName(nicName)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below three rows are to invoke the save ip adddress function
				{"AddrDel", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"AddrAdd", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{fmt.Errorf("mock error")}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `if err = saveIPAddress(bridgeLink, ifaceLink, addrs); err != nil` code path
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:      "saving routes to iface fails",
			inpBridge: "breth0",
			errExp:    true,
			// Below two entries are for mocking the `nicName, err := GetNicName(bridge)` code path
			onRetArgsExecUtilsIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"RunCmd", 4, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("eth0")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("[080841d8-4e12-4003-b0ac-36fefd63bae1]")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("system")), bytes.NewBuffer([]byte("")), nil}},
			},
			onRetArgsKexecIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"Command", 5, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
			},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `bridgeLink, err := netlink.LinkByName(bridge)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below row entry is for mocking the `addrs, err := netlink.AddrList(bridgeLink, syscall.AF_INET)` code path
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Addr{{IPNet: ovntest.MustParseIPNet("192.168.1.15/24")}}, nil}},
				// Below row entry is for mocking the `routes, err := netlink.RouteList(bridgeLink, syscall.AF_INET)` code path
				{"RouteList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Route{{Gw: ovntest.MustParseIP("10.10.10.1"), LinkIndex: 1}}, nil}},
				// Below row entry is for mocking the `ifaceLink, err := netlink.LinkByName(nicName)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below three row entries are for mocking the `if err = saveIPAddress(bridgeLink, ifaceLink, addrs); err != nil` code path
				{"AddrDel", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"AddrAdd", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
				// Below two row entries are for mocking the `if err = saveRoute(bridgeLink, ifaceLink, routes); err != nil` code path
				{"RouteDel", []string{"*netlink.Route"}, []interface{}{nil}},
				{"RouteAdd", []string{"*netlink.Route"}, []interface{}{fmt.Errorf("mock error")}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `if err = saveIPAddress(bridgeLink, ifaceLink, addrs); err != nil` code path
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
				// Below two row entries are for mocking the `if err = saveRoute(bridgeLink, ifaceLink, routes); err != nil` code path.
				//The delAddRoute function is indirectly invoked and needs mocking of Attrs() function.
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:      "list-ifaces (via RunOVSVsctl) for given bridge errors out",
			inpBridge: "breth0",
			errExp:    true,
			// Below two entries are for mocking the `nicName, err := GetNicName(bridge)` code path
			onRetArgsExecUtilsIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"RunCmd", 4, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("eth0")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("[080841d8-4e12-4003-b0ac-36fefd63bae1]")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("system")), bytes.NewBuffer([]byte("")), nil}},
				//Below row is for mocking the `stdout, stderr, err := RunOVSVsctl("list-ifaces", bridge)` code path
				{"RunCmd", 3, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), fmt.Errorf("mock error")}},
			},
			onRetArgsKexecIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"Command", 5, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `stdout, stderr, err := RunOVSVsctl("list-ifaces", bridge)` code path
				{"Command", 4, []string{}, []interface{}{mockCmd}},
			},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `bridgeLink, err := netlink.LinkByName(bridge)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below row entry is for mocking the `addrs, err := netlink.AddrList(bridgeLink, syscall.AF_INET)` code path
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Addr{{IPNet: ovntest.MustParseIPNet("192.168.1.15/24")}}, nil}},
				// Below row entry is for mocking the `routes, err := netlink.RouteList(bridgeLink, syscall.AF_INET)` code path
				{"RouteList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Route{{Gw: ovntest.MustParseIP("10.10.10.1"), LinkIndex: 1}}, nil}},
				// Below row entry is for mocking the `ifaceLink, err := netlink.LinkByName(nicName)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below three row entries are for mocking the `if err = saveIPAddress(bridgeLink, ifaceLink, addrs); err != nil` code path
				{"AddrDel", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"AddrAdd", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
				// Below two row entries are for mocking the `if err = saveRoute(bridgeLink, ifaceLink, routes); err != nil` code path
				{"RouteDel", []string{"*netlink.Route"}, []interface{}{nil}},
				{"RouteAdd", []string{"*netlink.Route"}, []interface{}{nil}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `if err = saveIPAddress(bridgeLink, ifaceLink, addrs); err != nil` code path
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
				// Below entry is for mocking the `if err = saveRoute(bridgeLink, ifaceLink, routes); err != nil` code path.
				//The delAddRoute function is indirectly invoked and needs mocking of Attrs() function.
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:      "determining iface type fails",
			inpBridge: "breth0",
			errExp:    true,
			onRetArgsExecUtilsIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"RunCmd", 4, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("eth0")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("[080841d8-4e12-4003-b0ac-36fefd63bae1]")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("system")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err := RunOVSVsctl("list-ifaces", bridge)` code path
				{"RunCmd", 3, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("9d2bc35689fa975")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("get", "interface", iface, "type")` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), fmt.Errorf("mock error")}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("--", "--if-exists", "del-br", bridge)` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), fmt.Errorf("mock error")}},
			},
			onRetArgsKexecIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"Command", 5, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `stdout, stderr, err := RunOVSVsctl("list-ifaces", bridge)` code path
				{"Command", 4, []string{}, []interface{}{mockCmd}},
				// Below rows are for mocking the three RunOVSVsctl executed inside the for loop that processes the interface list returned
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("--", "--if-exists", "del-br", bridge)` code path
				{"Command", 6, []string{}, []interface{}{mockCmd}},
			},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `bridgeLink, err := netlink.LinkByName(bridge)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below row entry is for mocking the `addrs, err := netlink.AddrList(bridgeLink, syscall.AF_INET)` code path
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Addr{{IPNet: ovntest.MustParseIPNet("192.168.1.15/24")}}, nil}},
				// Below row entry is for mocking the `routes, err := netlink.RouteList(bridgeLink, syscall.AF_INET)` code path
				{"RouteList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Route{{Gw: ovntest.MustParseIP("10.10.10.1"), LinkIndex: 1}}, nil}},
				// Below row entry is for mocking the `ifaceLink, err := netlink.LinkByName(nicName)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below three row entries are for mocking the `if err = saveIPAddress(bridgeLink, ifaceLink, addrs); err != nil` code path
				{"AddrDel", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"AddrAdd", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
				// Below two row entries are for mocking the `if err = saveRoute(bridgeLink, ifaceLink, routes); err != nil` code path
				{"RouteDel", []string{"*netlink.Route"}, []interface{}{nil}},
				{"RouteAdd", []string{"*netlink.Route"}, []interface{}{nil}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `if err = saveIPAddress(bridgeLink, ifaceLink, addrs); err != nil` code path
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
				// Below two row entries are for mocking the `if err = saveRoute(bridgeLink, ifaceLink, routes); err != nil` code path.
				//The delAddRoute function is indirectly invoked and needs mocking of Attrs() function.
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:      "test code path where the interface type IS NOT patch",
			inpBridge: "breth0",
			errExp:    true,
			onRetArgsExecUtilsIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"RunCmd", 4, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("eth0")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("[080841d8-4e12-4003-b0ac-36fefd63bae1]")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("system")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err := RunOVSVsctl("list-ifaces", bridge)` code path
				{"RunCmd", 3, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("9d2bc35689fa975")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("get", "interface", iface, "type")` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("internal")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("--", "--if-exists", "del-br", bridge)` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), fmt.Errorf("mock error")}},
			},
			onRetArgsKexecIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"Command", 5, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `stdout, stderr, err := RunOVSVsctl("list-ifaces", bridge)` code path
				{"Command", 4, []string{}, []interface{}{mockCmd}},
				// Below rows are for mocking the three RunOVSVsctl executed inside the for loop that processes the interface list returned
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("--", "--if-exists", "del-br", bridge)` code path
				{"Command", 6, []string{}, []interface{}{mockCmd}},
			},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `bridgeLink, err := netlink.LinkByName(bridge)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below row entry is for mocking the `addrs, err := netlink.AddrList(bridgeLink, syscall.AF_INET)` code path
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Addr{{IPNet: ovntest.MustParseIPNet("192.168.1.15/24")}}, nil}},
				// Below row entry is for mocking the `routes, err := netlink.RouteList(bridgeLink, syscall.AF_INET)` code path
				{"RouteList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Route{{Gw: ovntest.MustParseIP("10.10.10.1"), LinkIndex: 1}}, nil}},
				// Below row entry is for mocking the `ifaceLink, err := netlink.LinkByName(nicName)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below three row entries are for mocking the `if err = saveIPAddress(bridgeLink, ifaceLink, addrs); err != nil` code path
				{"AddrDel", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"AddrAdd", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
				// Below two row entries are for mocking the `if err = saveRoute(bridgeLink, ifaceLink, routes); err != nil` code path
				{"RouteDel", []string{"*netlink.Route"}, []interface{}{nil}},
				{"RouteAdd", []string{"*netlink.Route"}, []interface{}{nil}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `if err = saveIPAddress(bridgeLink, ifaceLink, addrs); err != nil` code path
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
				// Below two row entries are for mocking the `if err = saveRoute(bridgeLink, ifaceLink, routes); err != nil` code path.
				//The delAddRoute function is indirectly invoked and needs mocking of Attrs() function.
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:      "fails to get peer port for patch interface",
			inpBridge: "breth0",
			errExp:    true,
			onRetArgsExecUtilsIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"RunCmd", 4, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("eth0")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("[080841d8-4e12-4003-b0ac-36fefd63bae1]")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("system")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err := RunOVSVsctl("list-ifaces", bridge)` code path
				{"RunCmd", 3, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("ovn-3e22f4-0")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("get", "interface", iface, "type")` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("patch")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("get", "interface", iface, "options:peer")` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), fmt.Errorf("mock error")}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("--", "--if-exists", "del-br", bridge)` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), fmt.Errorf("mock error")}},
			},
			onRetArgsKexecIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"Command", 5, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `stdout, stderr, err := RunOVSVsctl("list-ifaces", bridge)` code path
				{"Command", 4, []string{}, []interface{}{mockCmd}},
				// Below rows are for mocking the three RunOVSVsctl executed inside the for loop that processes the interface list returned
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("get", "interface", iface, "options:peer")` code path
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("--", "--if-exists", "del-br", bridge)` code path
				{"Command", 6, []string{}, []interface{}{mockCmd}},
			},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `bridgeLink, err := netlink.LinkByName(bridge)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below row entry is for mocking the `addrs, err := netlink.AddrList(bridgeLink, syscall.AF_INET)` code path
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Addr{{IPNet: ovntest.MustParseIPNet("192.168.1.15/24")}}, nil}},
				// Below row entry is for mocking the `routes, err := netlink.RouteList(bridgeLink, syscall.AF_INET)` code path
				{"RouteList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Route{{Gw: ovntest.MustParseIP("10.10.10.1"), LinkIndex: 1}}, nil}},
				// Below row entry is for mocking the `ifaceLink, err := netlink.LinkByName(nicName)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below three row entries are for mocking the `if err = saveIPAddress(bridgeLink, ifaceLink, addrs); err != nil` code path
				{"AddrDel", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"AddrAdd", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
				// Below two row entries are for mocking the `if err = saveRoute(bridgeLink, ifaceLink, routes); err != nil` code path
				{"RouteDel", []string{"*netlink.Route"}, []interface{}{nil}},
				{"RouteAdd", []string{"*netlink.Route"}, []interface{}{nil}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `if err = saveIPAddress(bridgeLink, ifaceLink, addrs); err != nil` code path
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
				// Below two row entries are for mocking the `if err = saveRoute(bridgeLink, ifaceLink, routes); err != nil` code path.
				//The delAddRoute function is indirectly invoked and needs mocking of Attrs() function.
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:      "failed to delete peer patch port on br-int",
			inpBridge: "breth0",
			errExp:    true,
			onRetArgsExecUtilsIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"RunCmd", 4, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("eth0")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("[080841d8-4e12-4003-b0ac-36fefd63bae1]")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("system")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err := RunOVSVsctl("list-ifaces", bridge)` code path
				{"RunCmd", 3, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("ovn-3e22f4-0")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("get", "interface", iface, "type")` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("patch")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("get", "interface", iface, "options:peer")` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `_, stderr, err = RunOVSVsctl("--if-exists", "del-port", "br-int", peer)` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), fmt.Errorf("mock error")}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("--", "--if-exists", "del-br", bridge)` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), fmt.Errorf("mock error")}},
			},
			onRetArgsKexecIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"Command", 5, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `stdout, stderr, err := RunOVSVsctl("list-ifaces", bridge)` code path
				{"Command", 4, []string{}, []interface{}{mockCmd}},
				// Below rows are for mocking the three RunOVSVsctl executed inside the for loop that processes the interface list returned
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("get", "interface", iface, "options:peer")` code path
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `_, stderr, err = RunOVSVsctl("--if-exists", "del-port", "br-int", peer)` code path
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("--", "--if-exists", "del-br", bridge)` code path
				{"Command", 6, []string{}, []interface{}{mockCmd}},
			},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `bridgeLink, err := netlink.LinkByName(bridge)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below row entry is for mocking the `addrs, err := netlink.AddrList(bridgeLink, syscall.AF_INET)` code path
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Addr{{IPNet: ovntest.MustParseIPNet("192.168.1.15/24")}}, nil}},
				// Below row entry is for mocking the `routes, err := netlink.RouteList(bridgeLink, syscall.AF_INET)` code path
				{"RouteList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Route{{Gw: ovntest.MustParseIP("10.10.10.1"), LinkIndex: 1}}, nil}},
				// Below row entry is for mocking the `ifaceLink, err := netlink.LinkByName(nicName)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below three row entries are for mocking the `if err = saveIPAddress(bridgeLink, ifaceLink, addrs); err != nil` code path
				{"AddrDel", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"AddrAdd", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
				// Below two row entries are for mocking the `if err = saveRoute(bridgeLink, ifaceLink, routes); err != nil` code path
				{"RouteDel", []string{"*netlink.Route"}, []interface{}{nil}},
				{"RouteAdd", []string{"*netlink.Route"}, []interface{}{nil}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `if err = saveIPAddress(bridgeLink, ifaceLink, addrs); err != nil` code path
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
				// Below two row entries are for mocking the `if err = saveRoute(bridgeLink, ifaceLink, routes); err != nil` code path.
				//The delAddRoute function is indirectly invoked and needs mocking of Attrs() function.
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:      "deleting the bridge fails",
			inpBridge: "breth0",
			errExp:    true,
			onRetArgsExecUtilsIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"RunCmd", 4, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("eth0")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("[080841d8-4e12-4003-b0ac-36fefd63bae1]")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("system")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err := RunOVSVsctl("list-ifaces", bridge)` code path
				{"RunCmd", 3, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("ovn-3e22f4-0")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("get", "interface", iface, "type")` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("patch")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("get", "interface", iface, "options:peer")` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `_, stderr, err = RunOVSVsctl("--if-exists", "del-port", "br-int", peer)` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("--", "--if-exists", "del-br", bridge)` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), fmt.Errorf("mock error")}},
			},
			onRetArgsKexecIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"Command", 5, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `stdout, stderr, err := RunOVSVsctl("list-ifaces", bridge)` code path
				{"Command", 4, []string{}, []interface{}{mockCmd}},
				// Below rows are for mocking the three RunOVSVsctl executed inside the for loop that processes the interface list returned
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("get", "interface", iface, "options:peer")` code path
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `_, stderr, err = RunOVSVsctl("--if-exists", "del-port", "br-int", peer)` code path
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("--", "--if-exists", "del-br", bridge)` code path
				{"Command", 6, []string{}, []interface{}{mockCmd}},
			},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `bridgeLink, err := netlink.LinkByName(bridge)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below row entry is for mocking the `addrs, err := netlink.AddrList(bridgeLink, syscall.AF_INET)` code path
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Addr{{IPNet: ovntest.MustParseIPNet("192.168.1.15/24")}}, nil}},
				// Below row entry is for mocking the `routes, err := netlink.RouteList(bridgeLink, syscall.AF_INET)` code path
				{"RouteList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Route{{Gw: ovntest.MustParseIP("10.10.10.1"), LinkIndex: 1}}, nil}},
				// Below row entry is for mocking the `ifaceLink, err := netlink.LinkByName(nicName)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below three row entries are for mocking the `if err = saveIPAddress(bridgeLink, ifaceLink, addrs); err != nil` code path
				{"AddrDel", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"AddrAdd", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
				// Below two row entries are for mocking the `if err = saveRoute(bridgeLink, ifaceLink, routes); err != nil` code path
				{"RouteDel", []string{"*netlink.Route"}, []interface{}{nil}},
				{"RouteAdd", []string{"*netlink.Route"}, []interface{}{nil}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `if err = saveIPAddress(bridgeLink, ifaceLink, addrs); err != nil` code path
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
				// Below two row entries are for mocking the `if err = saveRoute(bridgeLink, ifaceLink, routes); err != nil` code path.
				//The delAddRoute function is indirectly invoked and needs mocking of Attrs() function.
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:      "delete bridge successfully",
			inpBridge: "breth0",
			onRetArgsExecUtilsIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"RunCmd", 4, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("eth0")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("[080841d8-4e12-4003-b0ac-36fefd63bae1]")), bytes.NewBuffer([]byte("")), nil}},
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("system")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err := RunOVSVsctl("list-ifaces", bridge)` code path
				{"RunCmd", 3, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("ovn-3e22f4-0")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("get", "interface", iface, "type")` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("patch")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("get", "interface", iface, "options:peer")` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `_, stderr, err = RunOVSVsctl("--if-exists", "del-port", "br-int", peer)` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), nil}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("--", "--if-exists", "del-br", bridge)` code path
				{"RunCmd", 5, []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), nil}},
			},
			onRetArgsKexecIface: []onCallReturnArgsRepetitive{
				//Below three entries are for mocking the `nicName, err := GetNicName(bridge)` code path
				{"Command", 5, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `stdout, stderr, err := RunOVSVsctl("list-ifaces", bridge)` code path
				{"Command", 4, []string{}, []interface{}{mockCmd}},
				// Below rows are for mocking the three RunOVSVsctl executed inside the for loop that processes the interface list returned
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("get", "interface", iface, "options:peer")` code path
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `_, stderr, err = RunOVSVsctl("--if-exists", "del-port", "br-int", peer)` code path
				{"Command", 6, []string{}, []interface{}{mockCmd}},
				// Below row is for mocking the `stdout, stderr, err = RunOVSVsctl("--", "--if-exists", "del-br", bridge)` code path
				{"Command", 6, []string{}, []interface{}{mockCmd}},
			},
			onRetArgsNetLinkLibOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `bridgeLink, err := netlink.LinkByName(bridge)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below row entry is for mocking the `addrs, err := netlink.AddrList(bridgeLink, syscall.AF_INET)` code path
				{"AddrList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Addr{{IPNet: ovntest.MustParseIPNet("192.168.1.15/24")}}, nil}},
				// Below row entry is for mocking the `routes, err := netlink.RouteList(bridgeLink, syscall.AF_INET)` code path
				{"RouteList", []string{"*mocks.Link", "int"}, []interface{}{[]netlink.Route{{Gw: ovntest.MustParseIP("10.10.10.1"), LinkIndex: 1}}, nil}},
				// Below row entry is for mocking the `ifaceLink, err := netlink.LinkByName(nicName)` code path
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				// Below three row entries are for mocking the `if err = saveIPAddress(bridgeLink, ifaceLink, addrs); err != nil` code path
				{"AddrDel", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"AddrAdd", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
				// Below two row entries are for mocking the `if err = saveRoute(bridgeLink, ifaceLink, routes); err != nil` code path
				{"RouteDel", []string{"*netlink.Route"}, []interface{}{nil}},
				{"RouteAdd", []string{"*netlink.Route"}, []interface{}{nil}},
			},
			onRetArgsLinkIfaceOpers: []onCallReturnArgs{
				// Below row entry is for mocking the `if err = saveIPAddress(bridgeLink, ifaceLink, addrs); err != nil` code path
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
				// Below two row entries are for mocking the `if err = saveRoute(bridgeLink, ifaceLink, routes); err != nil` code path.
				//The delAddRoute function is indirectly invoked and needs mocking of Attrs() function.
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			for _, item := range tc.onRetArgsExecUtilsIface {
				call := mockExecRunner.On(item.onCallMethodName)
				for _, arg := range item.onCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				// append the repetitive arg types of `string` at the end
				for i := 0; i < item.onCallMethodsArgsStrTypeAppendCount; i++ {
					call.Arguments = append(call.Arguments, mock.AnythingOfType("string"))
				}
				for _, ret := range item.retArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			for _, item := range tc.onRetArgsKexecIface {
				ifaceCall := mockKexecIface.On(item.onCallMethodName)
				for _, arg := range item.onCallMethodArgType {
					ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
				}
				// append the repetitive arg types of `string` at the end
				for i := 0; i < item.onCallMethodsArgsStrTypeAppendCount; i++ {
					ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType("string"))
				}
				for _, ret := range item.retArgList {
					ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
				}
				ifaceCall.Once()
			}

			for _, item := range tc.onRetArgsNetLinkLibOpers {
				call := mockNetLinkOps.On(item.onCallMethodName)
				for _, arg := range item.onCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.retArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			for _, item := range tc.onRetArgsLinkIfaceOpers {
				call := mockLink.On(item.onCallMethodName)
				for _, arg := range item.onCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.retArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			err := BridgeToNic(runner, tc.inpBridge)
			t.Log(err)
			if tc.errExp {
				assert.Error(t, err)
			} else {
				assert.Nil(t, err)
			}
			mockKexecIface.AssertExpectations(t)
			mockExecRunner.AssertExpectations(t)
			mockNetLinkOps.AssertExpectations(t)
			mockLink.AssertExpectations(t)
		})
	}
}

func TestRunningPlatform(t *testing.T) {
	// Below is defined in nicstobridge.go file
	appFs := afero.NewMemMapFs()
	appFs.MkdirAll("/etc", 0755)
	tests := []struct {
		desc            string
		fileContent     []byte
		filePermissions os.FileMode
		expOut          string
		expErr          error
	}{
		{
			desc:   "ReadFile returns error",
			expErr: fmt.Errorf("failed to parse file"),
		},
		{
			desc:            "failed to find platform name",
			expErr:          fmt.Errorf("failed to find the platform name"),
			fileContent:     []byte("NAME="),
			filePermissions: 0755,
		},
		{
			desc:            "platform name returned is RHEL",
			expOut:          "RHEL",
			fileContent:     []byte("NAME=\"CentOS Linux\""),
			filePermissions: 0755,
		},
		{
			desc:            "platform name returned is Ubuntu",
			expOut:          "Ubuntu",
			fileContent:     []byte("NAME=\"Debian\""),
			filePermissions: 0755,
		},
		{
			desc:            "platform name returned is Photon",
			expOut:          "Photon",
			fileContent:     []byte("NAME=\"VMware\""),
			filePermissions: 0755,
		},
		{
			desc:            "unknown platform",
			expErr:          fmt.Errorf("unknown platform"),
			fileContent:     []byte("NAME=\"blah\""),
			filePermissions: 0755,
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			if tc.fileContent != nil && tc.filePermissions != 0 {
				afero.WriteFile(appFs, "/etc/os-release", tc.fileContent, tc.filePermissions)
				defer appFs.Remove("/etc/os-release")
			}
			res, err := runningPlatform(appFs)
			t.Log(res, err)
			if tc.expErr != nil {
				assert.Contains(t, err.Error(), tc.expErr.Error())
			} else {
				assert.Equal(t, res, tc.expOut)
			}
		})
	}
}
