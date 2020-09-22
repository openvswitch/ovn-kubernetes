package cni

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"

	"github.com/Mellanox/sriovnet"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni/mocks"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni/types"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	cni_type_mocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/containernetworking/cni/pkg/types"
	cni_ns_mocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/containernetworking/plugins/pkg/ns"
	netlink_mocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/vishvananda/netlink"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	util_mocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/vishvananda/netlink"
)

func TestRenameLink(t *testing.T) {
	mockNetLinkOps := new(util_mocks.NetLinkOps)
	mockLink := new(netlink_mocks.Link)
	// below sets the `netLinkOps` in util/net_linux.go to a mock instance for purpose of unit tests execution
	util.SetNetLinkOpMockInst(mockNetLinkOps)

	tests := []struct {
		desc                 string
		inpCurrName          string
		inpNewName           string
		errExp               bool
		netLinkOpsMockHelper []ovntest.TestifyMockHelper
	}{
		{
			desc:        "test code path when LinkByName() errors out",
			inpCurrName: "testCurrName",
			inpNewName:  "testNewName",
			errExp:      true,
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				{"LinkByName", []string{"string", "string"}, []interface{}{nil, fmt.Errorf("mock error")}},
			},
		},
		{
			desc:        "test code path when LinkSetDown() errors out",
			inpCurrName: "testCurrName",
			inpNewName:  "testNewName",
			errExp:      true,
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				{"LinkByName", []string{"string", "string"}, []interface{}{mockLink, nil}},
				{"LinkSetDown", []string{"*mocks.Link"}, []interface{}{fmt.Errorf("mock error")}},
			},
		},
		{
			desc:        "test code path when LinkSetName() errors out",
			inpCurrName: "testCurrName",
			inpNewName:  "testNewName",
			errExp:      true,
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				{"LinkByName", []string{"string", "string"}, []interface{}{mockLink, nil}},
				{"LinkSetDown", []string{"*mocks.Link"}, []interface{}{nil}},
				{"LinkSetName", []string{"*mocks.Link", "string"}, []interface{}{fmt.Errorf("mock error")}},
			},
		},
		{
			desc:        "test code path when LinkSetUp() errors out",
			inpCurrName: "testCurrName",
			inpNewName:  "testNewName",
			errExp:      true,
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				{"LinkByName", []string{"string", "string"}, []interface{}{mockLink, nil}},
				{"LinkSetDown", []string{"*mocks.Link"}, []interface{}{nil}},
				{"LinkSetName", []string{"*mocks.Link", "string"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{fmt.Errorf("mock error")}},
			},
		},
		{
			desc:        "test success code path",
			inpCurrName: "testCurrName",
			inpNewName:  "testNewName",
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				{"LinkByName", []string{"string", "string"}, []interface{}{mockLink, nil}},
				{"LinkSetDown", []string{"*mocks.Link"}, []interface{}{nil}},
				{"LinkSetName", []string{"*mocks.Link", "string"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			for _, item := range tc.netLinkOpsMockHelper {
				call := mockNetLinkOps.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			err := renameLink(tc.inpCurrName, tc.inpNewName)
			t.Log(err)
			if tc.errExp {
				assert.Error(t, err)
			} else {
				assert.Nil(t, err)
			}
			mockNetLinkOps.AssertExpectations(t)
		})
	}
}

func TestMoveIfToNetns(t *testing.T) {
	mockNetLinkOps := new(util_mocks.NetLinkOps)
	mockNetNS := new(cni_ns_mocks.NetNS)
	mockLink := new(netlink_mocks.Link)
	// below sets the `netLinkOps` in util/net_linux.go to a mock instance for purpose of unit tests execution
	util.SetNetLinkOpMockInst(mockNetLinkOps)

	tests := []struct {
		desc                 string
		inpIfaceName         string
		inpNetNs             ns.NetNS
		errMatch             error
		netLinkOpsMockHelper []ovntest.TestifyMockHelper
		netNsOpsMockHelper   []ovntest.TestifyMockHelper
	}{
		{
			desc:         "test code path when LinkByName() returns error",
			inpIfaceName: "testIfaceName",
			inpNetNs:     nil,
			errMatch:     fmt.Errorf("failed to lookup vf device"),
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				{"LinkByName", []string{"string"}, []interface{}{nil, fmt.Errorf("mock error")}},
			},
		},
		{
			desc:         "test code path when LinkSetNsFd() returns error",
			inpIfaceName: "testIfaceName",
			inpNetNs:     mockNetNS,
			errMatch:     fmt.Errorf("failed to move device"),
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				{"LinkSetNsFd", []string{"*mocks.Link", "int"}, []interface{}{fmt.Errorf("mock error")}},
			},
			netNsOpsMockHelper: []ovntest.TestifyMockHelper{
				{"Fd", []string{}, []interface{}{uintptr(123456)}},
			},
		},
		{
			desc:         "test success path",
			inpIfaceName: "testIfaceName",
			inpNetNs:     mockNetNS,
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				{"LinkSetNsFd", []string{"*mocks.Link", "int"}, []interface{}{nil}},
			},
			netNsOpsMockHelper: []ovntest.TestifyMockHelper{
				{"Fd", []string{}, []interface{}{uintptr(123456)}},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			for _, item := range tc.netLinkOpsMockHelper {
				call := mockNetLinkOps.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			for _, item := range tc.netNsOpsMockHelper {
				call := mockNetNS.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			err := moveIfToNetns(tc.inpIfaceName, tc.inpNetNs)
			t.Log(err)
			if tc.errMatch != nil {
				assert.Contains(t, err.Error(), tc.errMatch.Error())
			} else {
				assert.Nil(t, err)
			}
			mockNetLinkOps.AssertExpectations(t)
			mockNetNS.AssertExpectations(t)
		})
	}
}

func TestSetupNetwork(t *testing.T) {
	mockNetLinkOps := new(util_mocks.NetLinkOps)
	mockLink := new(netlink_mocks.Link)
	mockCNIPlugin := new(mocks.CNIPluginLibOps)
	// below sets the `netLinkOps` in util/net_linux.go to a mock instance for purpose of unit tests execution
	util.SetNetLinkOpMockInst(mockNetLinkOps)
	// below `cniPluginLibOps` is defined in helper_linux.go
	cniPluginLibOps = mockCNIPlugin

	tests := []struct {
		desc                 string
		inpLink              netlink.Link
		inpPodIfaceInfo      *PodInterfaceInfo
		errMatch             error
		netLinkOpsMockHelper []ovntest.TestifyMockHelper
		linkMockHelper       []ovntest.TestifyMockHelper
		cniPluginMockHelper  []ovntest.TestifyMockHelper
	}{
		{
			desc:    "test code path when LinkSetHardwareAddr returns error",
			inpLink: mockLink,
			inpPodIfaceInfo: &PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{
					MAC: ovntest.MustParseMAC("11:22:33:44:55:66"),
				},
			},
			errMatch: fmt.Errorf("failed to add mac address"),
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				{"LinkSetDown", []string{"*mocks.Link"}, []interface{}{nil}},
				{"LinkSetHardwareAddr", []string{"*mocks.Link", "net.HardwareAddr"}, []interface{}{fmt.Errorf("mock error")}},
			},
			linkMockHelper: []ovntest.TestifyMockHelper{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:    "test code path when AddrAdd returns error",
			inpLink: mockLink,
			inpPodIfaceInfo: &PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{
					IPs: ovntest.MustParseIPNets("192.168.0.5/24"),
					MAC: ovntest.MustParseMAC("0A:58:FD:98:00:01"),
				},
			},
			errMatch: fmt.Errorf("failed to add IP addr"),
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				{"LinkSetDown", []string{"*mocks.Link"}, []interface{}{nil}},
				{"LinkSetHardwareAddr", []string{"*mocks.Link", "net.HardwareAddr"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
				{"AddrAdd", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{fmt.Errorf("mock error")}},
			},
			linkMockHelper: []ovntest.TestifyMockHelper{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:    "test code path when AddRoute for gateway returns error",
			inpLink: mockLink,
			inpPodIfaceInfo: &PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{
					IPs:      ovntest.MustParseIPNets("192.168.0.5/24"),
					MAC:      ovntest.MustParseMAC("0A:58:FD:98:00:01"),
					Gateways: ovntest.MustParseIPs("192.168.0.1"),
				},
			},
			errMatch: fmt.Errorf("failed to add gateway route"),
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				{"LinkSetDown", []string{"*mocks.Link"}, []interface{}{nil}},
				{"LinkSetHardwareAddr", []string{"*mocks.Link", "net.HardwareAddr"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
				{"AddrAdd", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
			},
			cniPluginMockHelper: []ovntest.TestifyMockHelper{
				{"AddRoute", []string{"*net.IPNet", "net.IP", "*mocks.Link"}, []interface{}{fmt.Errorf("mock error")}},
			},
		},
		{
			desc:    "test code path when AddRoute for pod returns error",
			inpLink: mockLink,
			inpPodIfaceInfo: &PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{
					IPs:      ovntest.MustParseIPNets("192.168.0.5/24"),
					MAC:      ovntest.MustParseMAC("0A:58:FD:98:00:01"),
					Gateways: ovntest.MustParseIPs("192.168.0.1"),
					Routes: []util.PodRoute{
						{
							Dest:    ovntest.MustParseIPNet("192.168.1.0/24"),
							NextHop: net.ParseIP("192.168.1.1"),
						},
					},
				},
			},
			errMatch: fmt.Errorf("failed to add pod route"),
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				{"LinkSetDown", []string{"*mocks.Link"}, []interface{}{nil}},
				{"LinkSetHardwareAddr", []string{"*mocks.Link", "net.HardwareAddr"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
				{"AddrAdd", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
			},
			cniPluginMockHelper: []ovntest.TestifyMockHelper{
				{"AddRoute", []string{"*net.IPNet", "net.IP", "*mocks.Link"}, []interface{}{nil}},
				{"AddRoute", []string{"*net.IPNet", "net.IP", "*mocks.Link"}, []interface{}{fmt.Errorf("mock error")}},
			},
		},
		{
			desc:    "test success path",
			inpLink: mockLink,
			inpPodIfaceInfo: &PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{
					IPs:      ovntest.MustParseIPNets("192.168.0.5/24"),
					MAC:      ovntest.MustParseMAC("0A:58:FD:98:00:01"),
					Gateways: ovntest.MustParseIPs("192.168.0.1"),
					Routes: []util.PodRoute{
						{
							Dest:    ovntest.MustParseIPNet("192.168.1.0/24"),
							NextHop: net.ParseIP("192.168.1.1"),
						},
					},
				},
			},
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				{"LinkSetDown", []string{"*mocks.Link"}, []interface{}{nil}},
				{"LinkSetHardwareAddr", []string{"*mocks.Link", "net.HardwareAddr"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
				{"AddrAdd", []string{"*mocks.Link", "*netlink.Addr"}, []interface{}{nil}},
			},
			cniPluginMockHelper: []ovntest.TestifyMockHelper{
				{"AddRoute", []string{"*net.IPNet", "net.IP", "*mocks.Link"}, []interface{}{nil}},
				{"AddRoute", []string{"*net.IPNet", "net.IP", "*mocks.Link"}, []interface{}{nil}},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			for _, item := range tc.netLinkOpsMockHelper {
				call := mockNetLinkOps.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			for _, item := range tc.linkMockHelper {
				call := mockLink.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			for _, item := range tc.cniPluginMockHelper {
				call := mockCNIPlugin.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			err := setupNetwork(tc.inpLink, tc.inpPodIfaceInfo)
			t.Log(err)
			if tc.errMatch != nil {
				assert.Contains(t, err.Error(), tc.errMatch.Error())
			} else {
				assert.Nil(t, err)
			}
			mockNetLinkOps.AssertExpectations(t)
			mockLink.AssertExpectations(t)
			mockCNIPlugin.AssertExpectations(t)
		})
	}
}

func TestSetupInterface(t *testing.T) {
	mockNetLinkOps := new(util_mocks.NetLinkOps)
	mockCNIPlugin := new(mocks.CNIPluginLibOps)
	mockNS := new(cni_ns_mocks.NetNS)
	// below sets the `netLinkOps` in util/net_linux.go to a mock instance for purpose of unit tests execution
	util.SetNetLinkOpMockInst(mockNetLinkOps)
	// `cniPluginLibOps` is defined in helper_linux.go
	cniPluginLibOps = mockCNIPlugin

	/* Need the below to test the Do() function that requires root and needs to be figured out
	testOSNameSpace, err := ns.GetCurrentNS()
	if err != nil {
		t.Log(err)
		t.Fatal("failed to get NameSpace for test")
	}*/

	tests := []struct {
		desc                 string
		inpNetNS             ns.NetNS
		inpContID            string
		inpIfaceName         string
		inpPodIfaceInfo      *PodInterfaceInfo
		errExp               bool
		errMatch             error
		cniPluginMockHelper  []ovntest.TestifyMockHelper
		nsMockHelper         []ovntest.TestifyMockHelper
		netLinkOpsMockHelper []ovntest.TestifyMockHelper
	}{
		{
			desc:         "test code path when Do() returns error",
			inpNetNS:     mockNS,
			inpContID:    "35b82dbe2c39768d9874861aee38cf569766d4855b525ae02bff2bfbda73392a",
			inpIfaceName: "eth0",
			inpPodIfaceInfo: &PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{},
				MTU:           1500,
			},
			errExp: true,
			nsMockHelper: []ovntest.TestifyMockHelper{
				{"Do", []string{"func(ns.NetNS) error"}, []interface{}{fmt.Errorf("mock error")}},
			},
		},
		/* TODO: Running the below requires root, need to figure this out
		// `sudo -E /usr/local/go/bin/go test -v -run TestSetupInterface` would be the command, but mocking SetupVeth() mock is a challenge
		{
			desc:         "test code path when SetupVeth() returns error",
			inpNetNS:     testOSNameSpace,
			inpContID:    "test",
			inpIfaceName: "eth0",
			inpPodIfaceInfo: &PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{},
				MTU:           1500,
			},
			errExp: true,
			cniPluginMockHelper: []ovntest.TestifyMockHelper{
				{"SetupVeth",[]string{"string", "int", "*ns.NetNS"}, []interface{}{nil, nil, fmt.Errorf("mock error")}},
			},
		},*/
		{
			desc:         "test code path when renameLink() returns error",
			inpNetNS:     mockNS,
			inpContID:    "35b82dbe2c39768d9874861aee38cf569766d4855b525ae02bff2bfbda73392a",
			inpIfaceName: "eth0",
			inpPodIfaceInfo: &PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{},
				MTU:           1500,
			},
			errMatch: fmt.Errorf("failed to rename"),
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				{"LinkByName", []string{"string", "string"}, []interface{}{nil, fmt.Errorf("mock error")}},
			},
			nsMockHelper: []ovntest.TestifyMockHelper{
				{"Do", []string{"func(ns.NetNS) error"}, []interface{}{nil}},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			for _, item := range tc.netLinkOpsMockHelper {
				call := mockNetLinkOps.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			for _, item := range tc.cniPluginMockHelper {
				call := mockCNIPlugin.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			for _, item := range tc.nsMockHelper {
				call := mockNS.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			hostIface, contIface, err := setupInterface(tc.inpNetNS, tc.inpContID, tc.inpIfaceName, tc.inpPodIfaceInfo)
			t.Log(hostIface, contIface, err)
			if tc.errExp {
				assert.NotNil(t, err)
			} else if tc.errMatch != nil {
				assert.Contains(t, err.Error(), tc.errMatch.Error())
			} else {
				assert.Nil(t, err)
			}
			mockNetLinkOps.AssertExpectations(t)
			mockCNIPlugin.AssertExpectations(t)
			mockNS.AssertExpectations(t)
		})
	}
}

func TestSetupSriovInterface(t *testing.T) {
	mockNetLinkOps := new(util_mocks.NetLinkOps)
	mockCNIPlugin := new(mocks.CNIPluginLibOps)
	mockSriovNetLibOps := new(mocks.SriovNetLibOps)
	mockNS := new(cni_ns_mocks.NetNS)
	mockLink := new(netlink_mocks.Link)
	// below sets the `netLinkOps` in util/net_linux.go to a mock instance for purpose of unit tests execution
	util.SetNetLinkOpMockInst(mockNetLinkOps)
	// `cniPluginLibOps` is defined in helper_linux.go
	cniPluginLibOps = mockCNIPlugin
	// `sriovLibOps` is defined in helper_linux.go
	sriovLibOps = mockSriovNetLibOps

	res, err := sriovnet.GetUplinkRepresentor("0000:01:00.0")
	t.Log(res, err)
	/* Need the below to test the Do() function that requires root and needs to be figured out
	testOSNameSpace, err := ns.GetCurrentNS()
	if err != nil {
		t.Log(err)
		t.Fatal("failed to get NameSpace for test")
	}*/

	tests := []struct {
		desc                 string
		inpNetNS             ns.NetNS
		inpContID            string
		inpIfaceName         string
		inpPodIfaceInfo      *PodInterfaceInfo
		inpPCIAddrs          string
		errExp               bool
		errMatch             error
		cniPluginMockHelper  []ovntest.TestifyMockHelper
		nsMockHelper         []ovntest.TestifyMockHelper
		netLinkOpsMockHelper []ovntest.TestifyMockHelper
		sriovOpsMockHelper   []ovntest.TestifyMockHelper
		linkMockHelper       []ovntest.TestifyMockHelper
	}{
		{
			desc:         "test code path when GetNetDevicesFromPci() returns error",
			inpNetNS:     mockNS,
			inpContID:    "35b82dbe2c39768d9874861aee38cf569766d4855b525ae02bff2bfbda73392a",
			inpIfaceName: "eth0",
			inpPodIfaceInfo: &PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{},
				MTU:           1500,
			},
			inpPCIAddrs: "0000:03:00.1",
			errExp:      true,
			sriovOpsMockHelper: []ovntest.TestifyMockHelper{
				{"GetNetDevicesFromPci", []string{"string"}, []interface{}{nil, fmt.Errorf("mock error")}},
			},
		},
		{
			desc:         "test code path when netdevice per pci address does not equal one",
			inpNetNS:     mockNS,
			inpContID:    "35b82dbe2c39768d9874861aee38cf569766d4855b525ae02bff2bfbda73392a",
			inpIfaceName: "eth0",
			inpPodIfaceInfo: &PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{},
				MTU:           1500,
			},
			inpPCIAddrs: "0000:03:00.1",
			errMatch:    fmt.Errorf("failed to get one netdevice interface per"),
			sriovOpsMockHelper: []ovntest.TestifyMockHelper{
				// e.g; `ls -l /sys/bus/pci/devices/0000:01:00.0/net/` is the equivalent command line to get devices info
				{"GetNetDevicesFromPci", []string{"string"}, []interface{}{[]string{"en01", "eno2"}, nil}},
			},
		},
		{
			desc:         "test code path when GetUplinkRepresentor() returns error",
			inpNetNS:     mockNS,
			inpContID:    "35b82dbe2c39768d9874861aee38cf569766d4855b525ae02bff2bfbda73392a",
			inpIfaceName: "eth0",
			inpPodIfaceInfo: &PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{},
				MTU:           1500,
			},
			inpPCIAddrs: "0000:03:00.1",
			errExp:      true,
			sriovOpsMockHelper: []ovntest.TestifyMockHelper{
				{"GetNetDevicesFromPci", []string{"string"}, []interface{}{[]string{"en01"}, nil}},
				{"GetVfIndexByPciAddress", []string{"string"}, []interface{}{0, nil}},
				{"GetUplinkRepresentor", []string{"string"}, []interface{}{"", fmt.Errorf("mock error")}},
			},
		},
		{
			desc:         "test code path when GetVfIndexByPciAddress() returns error",
			inpNetNS:     mockNS,
			inpContID:    "35b82dbe2c39768d9874861aee38cf569766d4855b525ae02bff2bfbda73392a",
			inpIfaceName: "eth0",
			inpPodIfaceInfo: &PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{},
				MTU:           1500,
			},
			inpPCIAddrs: "0000:03:00.1",
			errExp:      true,
			sriovOpsMockHelper: []ovntest.TestifyMockHelper{
				{"GetNetDevicesFromPci", []string{"string"}, []interface{}{[]string{"en01"}, nil}},
				{"GetVfIndexByPciAddress", []string{"string"}, []interface{}{-1, fmt.Errorf("mock error")}},
			},
		},
		{
			desc:         "test code path when GetVfRepresentor() returns error",
			inpNetNS:     mockNS,
			inpContID:    "35b82dbe2c39768d9874861aee38cf569766d4855b525ae02bff2bfbda73392a",
			inpIfaceName: "eth0",
			inpPodIfaceInfo: &PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{},
				MTU:           1500,
			},
			inpPCIAddrs: "0000:03:00.1",
			errExp:      true,
			sriovOpsMockHelper: []ovntest.TestifyMockHelper{
				{"GetNetDevicesFromPci", []string{"string"}, []interface{}{[]string{"en01"}, nil}},
				{"GetUplinkRepresentor", []string{"string"}, []interface{}{"testlinkrepresentor", nil}},
				{"GetVfIndexByPciAddress", []string{"string"}, []interface{}{0, nil}},
				{"GetVfRepresentor", []string{"string", "int"}, []interface{}{"", fmt.Errorf("mock error")}},
			},
		},
		{
			desc:         "test code path when renaming host VF representor errors out",
			inpNetNS:     mockNS,
			inpContID:    "35b82dbe2c39768d9874861aee38cf569766d4855b525ae02bff2bfbda73392a",
			inpIfaceName: "eth0",
			inpPodIfaceInfo: &PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{},
				MTU:           1500,
			},
			inpPCIAddrs: "0000:03:00.1",
			errMatch:    fmt.Errorf("failed to rename"),
			sriovOpsMockHelper: []ovntest.TestifyMockHelper{
				{"GetNetDevicesFromPci", []string{"string"}, []interface{}{[]string{"en01"}, nil}},
				{"GetUplinkRepresentor", []string{"string"}, []interface{}{"testlinkrepresentor", nil}},
				{"GetVfIndexByPciAddress", []string{"string"}, []interface{}{0, nil}},
				{"GetVfRepresentor", []string{"string", "int"}, []interface{}{"VFRepresentor", nil}},
			},
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				// The below is mocked for the renameLink() method that internally invokes LinkByName
				{"LinkByName", []string{"string", "string"}, []interface{}{nil, fmt.Errorf("mock error")}},
			},
		},
		{
			desc:         "test code path when retrieving LinkByName() for host interface errors out",
			inpNetNS:     mockNS,
			inpContID:    "35b82dbe2c39768d9874861aee38cf569766d4855b525ae02bff2bfbda73392a",
			inpIfaceName: "eth0",
			inpPodIfaceInfo: &PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{},
				MTU:           1500,
			},
			inpPCIAddrs: "0000:03:00.1",
			errExp:      true,
			sriovOpsMockHelper: []ovntest.TestifyMockHelper{
				{"GetNetDevicesFromPci", []string{"string"}, []interface{}{[]string{"en01"}, nil}},
				{"GetUplinkRepresentor", []string{"string"}, []interface{}{"testlinkrepresentor", nil}},
				{"GetVfIndexByPciAddress", []string{"string"}, []interface{}{0, nil}},
				{"GetVfRepresentor", []string{"string", "int"}, []interface{}{"VFRepresentor", nil}},
			},
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				// The below 4 calls are mocked for the renameLink() method that internally invokes the below 4 calls
				{"LinkByName", []string{"string", "string"}, []interface{}{mockLink, nil}},
				{"LinkSetDown", []string{"*mocks.Link"}, []interface{}{nil}},
				{"LinkSetName", []string{"*mocks.Link", "string"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
				// The below mock call is needed for the LinkByName() invocation right after the renameLink() method
				{"LinkByName", []string{"string", "string"}, []interface{}{nil, fmt.Errorf("mock error")}},
			},
		},
		{
			desc:         "test code path when LinkSetMTU() fails",
			inpNetNS:     mockNS,
			inpContID:    "35b82dbe2c39768d9874861aee38cf569766d4855b525ae02bff2bfbda73392a",
			inpIfaceName: "eth0",
			inpPodIfaceInfo: &PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{},
				MTU:           1500,
			},
			inpPCIAddrs: "0000:03:00.1",
			errMatch:    fmt.Errorf("failed to set MTU on"),
			sriovOpsMockHelper: []ovntest.TestifyMockHelper{
				{"GetNetDevicesFromPci", []string{"string"}, []interface{}{[]string{"en01"}, nil}},
				{"GetUplinkRepresentor", []string{"string"}, []interface{}{"testlinkrepresentor", nil}},
				{"GetVfIndexByPciAddress", []string{"string"}, []interface{}{0, nil}},
				{"GetVfRepresentor", []string{"string", "int"}, []interface{}{"VFRepresentor", nil}},
			},
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				// The below 4 calls are mocked for the renameLink() method that internally invokes the below 4 calls
				{"LinkByName", []string{"string", "string"}, []interface{}{mockLink, nil}},
				{"LinkSetDown", []string{"*mocks.Link"}, []interface{}{nil}},
				{"LinkSetName", []string{"*mocks.Link", "string"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
				// The below mock call is needed for the LinkByName() invocation right after the renameLink() method
				{"LinkByName", []string{"string", "string"}, []interface{}{mockLink, nil}},
				// The below mock call is self-explanatory and is for the LinkSetMTU() method
				{"LinkSetMTU", []string{"*mocks.Link", "int"}, []interface{}{fmt.Errorf("mock error")}},
			},
			linkMockHelper: []ovntest.TestifyMockHelper{
				// The below mock call is to retrieve the MAC address of host interface right before LinkSetMTU() method
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:         "test code path when moveIfToNetns() returns error",
			inpNetNS:     mockNS,
			inpContID:    "35b82dbe2c39768d9874861aee38cf569766d4855b525ae02bff2bfbda73392a",
			inpIfaceName: "eth0",
			inpPodIfaceInfo: &PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{},
				MTU:           1500,
			},
			inpPCIAddrs: "0000:03:00.1",
			errExp:      true,
			sriovOpsMockHelper: []ovntest.TestifyMockHelper{
				{"GetNetDevicesFromPci", []string{"string"}, []interface{}{[]string{"en01"}, nil}},
				{"GetUplinkRepresentor", []string{"string"}, []interface{}{"testlinkrepresentor", nil}},
				{"GetVfIndexByPciAddress", []string{"string"}, []interface{}{0, nil}},
				{"GetVfRepresentor", []string{"string", "int"}, []interface{}{"VFRepresentor", nil}},
			},
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				// The below 4 calls are mocked for the renameLink() method that internally invokes the below 4 calls
				{"LinkByName", []string{"string", "string"}, []interface{}{mockLink, nil}},
				{"LinkSetDown", []string{"*mocks.Link"}, []interface{}{nil}},
				{"LinkSetName", []string{"*mocks.Link", "string"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
				// The below mock call is needed for the LinkByName() invocation right after the renameLink() method
				{"LinkByName", []string{"string", "string"}, []interface{}{mockLink, nil}},
				// The below mock call is self-explanatory and is for the LinkSetMTU() method
				{"LinkSetMTU", []string{"*mocks.Link", "int"}, []interface{}{nil}},
				// The below mock call is needed for the moveIfToNetns() call that internally invokes the LinkbyName()
				{"LinkByName", []string{"string"}, []interface{}{nil, fmt.Errorf("mock error")}},
			},
			linkMockHelper: []ovntest.TestifyMockHelper{
				// The below mock call is to retrieve the MAC address of host interface right before LinkSetMTU() method
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
		},
		{
			desc:         "test code path when Do() returns error",
			inpNetNS:     mockNS,
			inpContID:    "35b82dbe2c39768d9874861aee38cf569766d4855b525ae02bff2bfbda73392a",
			inpIfaceName: "eth0",
			inpPodIfaceInfo: &PodInterfaceInfo{
				PodAnnotation: util.PodAnnotation{},
				MTU:           1500,
			},
			inpPCIAddrs: "0000:03:00.1",
			errExp:      true,
			sriovOpsMockHelper: []ovntest.TestifyMockHelper{
				{"GetNetDevicesFromPci", []string{"string"}, []interface{}{[]string{"en01"}, nil}},
				{"GetUplinkRepresentor", []string{"string"}, []interface{}{"testlinkrepresentor", nil}},
				{"GetVfIndexByPciAddress", []string{"string"}, []interface{}{0, nil}},
				{"GetVfRepresentor", []string{"string", "int"}, []interface{}{"VFRepresentor", nil}},
			},
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				// The below 4 calls are mocked for the renameLink() method that internally invokes the below 4 calls
				{"LinkByName", []string{"string", "string"}, []interface{}{mockLink, nil}},
				{"LinkSetDown", []string{"*mocks.Link"}, []interface{}{nil}},
				{"LinkSetName", []string{"*mocks.Link", "string"}, []interface{}{nil}},
				{"LinkSetUp", []string{"*mocks.Link"}, []interface{}{nil}},
				// The below mock call is needed for the LinkByName() invocation right after the renameLink() method
				{"LinkByName", []string{"string", "string"}, []interface{}{mockLink, nil}},
				// The below mock call is self-explanatory and is for the LinkSetMTU() method
				{"LinkSetMTU", []string{"*mocks.Link", "int"}, []interface{}{nil}},
				// The below two mock calls are needed for the moveIfToNetns() call that internally invokes them
				{"LinkByName", []string{"string"}, []interface{}{mockLink, nil}},
				{"LinkSetNsFd", []string{"*mocks.Link", "int"}, []interface{}{nil}},
			},
			linkMockHelper: []ovntest.TestifyMockHelper{
				{"Attrs", []string{}, []interface{}{&netlink.LinkAttrs{Name: "testIfaceName"}}},
			},
			nsMockHelper: []ovntest.TestifyMockHelper{
				// The below mock call is needed when moveIfToNetns() is called
				{"Fd", []string{}, []interface{}{uintptr(123456)}},
				// The below mock call is for the netns.Do() invocation
				{"Do", []string{"func(ns.NetNS) error"}, []interface{}{fmt.Errorf("mock error")}},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			for _, item := range tc.netLinkOpsMockHelper {
				call := mockNetLinkOps.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			for _, item := range tc.cniPluginMockHelper {
				call := mockCNIPlugin.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			for _, item := range tc.nsMockHelper {
				call := mockNS.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			for _, item := range tc.sriovOpsMockHelper {
				call := mockSriovNetLibOps.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			for _, item := range tc.linkMockHelper {
				call := mockLink.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			hostIface, contIface, err := setupSriovInterface(tc.inpNetNS, tc.inpContID, tc.inpIfaceName, tc.inpPodIfaceInfo, tc.inpPCIAddrs)
			t.Log(hostIface, contIface, err)
			if tc.errExp {
				assert.NotNil(t, err)
			} else if tc.errMatch != nil {
				assert.Contains(t, err.Error(), tc.errMatch.Error())
			} else {
				assert.Nil(t, err)
			}
			mockNetLinkOps.AssertExpectations(t)
			mockCNIPlugin.AssertExpectations(t)
			mockNS.AssertExpectations(t)
			mockSriovNetLibOps.AssertExpectations(t)
			mockLink.AssertExpectations(t)
		})
	}
}

func TestPodRequest_deletePodConntrack(t *testing.T) {
	mockTypeResult := new(cni_type_mocks.Result)
	mockNetLinkOps := new(util_mocks.NetLinkOps)
	// below sets the `netLinkOps` in util/net_linux.go to a mock instance for purpose of unit tests execution
	util.SetNetLinkOpMockInst(mockNetLinkOps)
	tests := []struct {
		desc                 string
		inpPodRequest        PodRequest
		inpPrevResult        *current.Result
		resultMockHelper     []ovntest.TestifyMockHelper
		netLinkOpsMockHelper []ovntest.TestifyMockHelper
	}{
		{
			desc: "test code path when CNIConf.PrevResult == nil",
			inpPodRequest: PodRequest{
				CNIConf: &types.NetConf{
					NetConf: cnitypes.NetConf{
						PrevResult: nil,
					},
				},
			},
		},
		{
			desc: "test code path NewResultFromResult returns error",
			inpPodRequest: PodRequest{
				CNIConf: &types.NetConf{
					NetConf: cnitypes.NetConf{
						PrevResult: mockTypeResult,
					},
				},
			},
			resultMockHelper: []ovntest.TestifyMockHelper{
				{"Version", []string{}, []interface{}{"0.0.0"}},
			},
		},
		{
			desc: "test code path when ip.Interface != nil and path when Sandbox is empty value",
			inpPodRequest: PodRequest{
				CNIConf: &types.NetConf{
					NetConf: cnitypes.NetConf{
						PrevResult: mockTypeResult,
					},
				},
			},
			inpPrevResult: &current.Result{
				CNIVersion: "0.4.0",
				Interfaces: []*current.Interface{{Name: "eth0"}},
				IPs:        []*current.IPConfig{{Version: "4", Interface: &[]int{0}[0], Address: *ovntest.MustParseIPNet("192.168.1.15/24"), Gateway: ovntest.MustParseIP("192.168.1.1")}},
			},
		},
		{
			desc: "test code path when DeleteConntrack returns error",
			inpPodRequest: PodRequest{
				CNIConf: &types.NetConf{
					NetConf: cnitypes.NetConf{
						PrevResult: mockTypeResult,
					},
				},
			},
			inpPrevResult: &current.Result{
				CNIVersion: "0.4.0",
				Interfaces: []*current.Interface{{Name: "eth0", Sandbox: "blah"}},
				IPs:        []*current.IPConfig{{Version: "4", Interface: &[]int{0}[0], Address: *ovntest.MustParseIPNet("192.168.1.15/24"), Gateway: ovntest.MustParseIP("192.168.1.1")}},
			},
			netLinkOpsMockHelper: []ovntest.TestifyMockHelper{
				{"ConntrackDeleteFilter", []string{"netlink.ConntrackTableType", "netlink.InetFamily", "*netlink.ConntrackFilter"}, []interface{}{uint(1), fmt.Errorf("mock error")}},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			for _, item := range tc.resultMockHelper {
				call := mockTypeResult.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			for _, item := range tc.netLinkOpsMockHelper {
				call := mockNetLinkOps.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			if tc.inpPrevResult != nil {
				res, err := json.Marshal(tc.inpPrevResult)
				if err != nil {
					t.Log(err)
					t.Fatal("json marshal error, test input invalid for inpPrevResult")
				} else {
					tc.inpPodRequest.CNIConf.PrevResult, err = current.NewResult(res)
					if err != nil {
						t.Fatal("NewResult failed")
					}
				}
			}
			tc.inpPodRequest.deletePodConntrack()
			mockTypeResult.AssertExpectations(t)
		})
	}
}

func TestPodRequest_PlatformSpecificCleanup(t *testing.T) {
	// Skipping the test for now as this test passes when individually run but fails as part of suite run
	t.SkipNow()
	tests := []struct {
		desc          string
		inpPodRequest PodRequest
		errExp        bool
	}{
		{
			desc: "tests entire function coverage",
			inpPodRequest: PodRequest{
				SandboxID: "35b82dbe2c39768d9874861aee38cf569766d4855b525ae02bff2bfbda73392a",
				CNIConf: &types.NetConf{
					NetConf: cnitypes.NetConf{},
				},
			},
		},
		// TODO: Below test causes nil pointer exception when `pr.CNIConf.PrevResult == nil` is encountered in deletePodConntrack() method as pr.CNIConf is nil.
		// The code may need to be updated to check that pr.CNIConf is not nil?
		//{
		//	desc: "tests code path when CNIConf is not provided",
		//	inpPodRequest: PodRequest{
		//		SandboxID: "35b82dbe2c39768d9874861aee38cf569766d4855b525ae02bff2bfbda73392a",
		//	},
		//},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			err := tc.inpPodRequest.PlatformSpecificCleanup()
			if tc.errExp {
				assert.Error(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}
