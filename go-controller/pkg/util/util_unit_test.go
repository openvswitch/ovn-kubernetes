package util

import (
	"bytes"
	"fmt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"net"
	"testing"

	mock_k8s_io_utils_exec "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/k8s.io/utils/exec"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGetLegacyK8sMgmtIntfName(t *testing.T) {
	tests := []struct {
		desc        string
		inpNodeName string
		expRetStr   string
	}{
		{
			desc:        "node name less than 11 characters",
			inpNodeName: "lesseleven",
			expRetStr:   "k8s-lesseleven",
		},
		{
			desc:        "node name more than 11 characters",
			inpNodeName: "morethaneleven",
			expRetStr:   "k8s-morethanele",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			ret := GetLegacyK8sMgmtIntfName(tc.inpNodeName)
			if tc.expRetStr != ret {
				t.Fail()
			}
		})
	}
}

func TestGetNodeChassisID(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		errExpected             bool
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "ovs-vsctl command returns error",
			errExpected:             true,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), fmt.Errorf("test error")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "ovs-vsctl command returns empty chassisID along with error",
			errExpected:             true,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), fmt.Errorf("test error")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "ovs-vsctl command returns empty chassisID with NO error",
			errExpected:             true,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "ovs-vsctl command returns valid chassisID",
			errExpected:             false,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("4e98c281-f12b-4601-ab5a-a3d759fcb493")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()

			ret, e := GetNodeChassisID(runner)
			if tc.errExpected {
				assert.Error(t, e)
			} else {
				assert.Greater(t, len(ret), 0)
			}
			mockExecRunner.AssertExpectations(t)
			mockCmd.AssertExpectations(t)
		})
	}
}

func TestUpdateNodeSwitchExcludeIPs(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		inpNodeName             string
		inpSubnetStr            string
		errExpected             bool
		setCfgHybridOvlyEnabled bool
		onRetArgsExecUtilsIface []onCallReturnArgs
		onRetArgsKexecIface     []onCallReturnArgs
	}{
		{
			desc:         "IPv4 CIDR, ovn-nbctl fails to list logical switch ports",
			errExpected:  true,
			inpNodeName:  "ovn-control-plane",
			inpSubnetStr: "192.168.1.0/24",
			onRetArgsExecUtilsIface: []onCallReturnArgs{
				{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), fmt.Errorf("RunOVNNbctl error")}},
			},
			onRetArgsKexecIface: []onCallReturnArgs{
				{"Command", []string{"string", "string", "string", "string"}, []interface{}{mockCmd}},
			},
		},
		{
			desc:         "IPv6 CIDR, never excludes",
			errExpected:  false,
			inpNodeName:  "ovn-control-plane",
			inpSubnetStr: "fd04:3e42:4a4e:3381::/64",
		},
		{
			desc:                    "IPv4 CIDR, config.HybridOverlayEnable=true, sets haveMangementPort=true, ovn-nbctl command excludeIPs list empty",
			errExpected:             false,
			inpNodeName:             "ovn-control-plane",
			inpSubnetStr:            "192.168.1.0/24",
			setCfgHybridOvlyEnabled: true,
			onRetArgsExecUtilsIface: []onCallReturnArgs{
				{
					"RunCmd",
					[]string{"*mocks.Cmd", "string", "[]string", "string", "string", "string"},
					[]interface{}{
						// below is output from command --> ovn-nbctl lsp-list ovn-control-plane
						bytes.NewBuffer([]byte("7dc3d98a-660a-477b-a6bc-d42904ed59e7 (k8s-ovn-control-plane)\nd23162b4-87b1-4ff8-b5a5-5cb731d822ed (kube-system_coredns-6955765f44-l9jxq)\n1e8cd861-c584-4e38-8c50-7a71a6ae26bb (local-path-storage_local-path-provisioner-85445b74d4-w5ghw)\n8f1b3173-aa43-4014-adcb-36eae52f7502 (stor-ovn-control-plane)")),
						bytes.NewBuffer([]byte("")),
						nil,
					},
				},
				{
					"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), nil},
				},
			},
			onRetArgsKexecIface: []onCallReturnArgs{
				{"Command", []string{"string", "string", "string", "string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
				{"Command", []string{"string", "string", "string", "string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
			},
		},
		{
			desc:                    "IPv4 CIDR, config.HybridOverlayEnable=true, sets haveHybridOverlayPort=false, ovn-nbctl command excludeIPs list populated",
			errExpected:             false,
			inpNodeName:             "ovn-control-plane",
			inpSubnetStr:            "192.168.1.0/24",
			setCfgHybridOvlyEnabled: true,
			onRetArgsExecUtilsIface: []onCallReturnArgs{
				{
					"RunCmd",
					[]string{"*mocks.Cmd", "string", "[]string", "string", "string", "string"},
					[]interface{}{
						// below is output from command --> ovn-nbctl lsp-list ovn-control-plane
						bytes.NewBuffer([]byte("7dc3d98a-660a-477b-a6bc-d42904ed59e7 (int-ovn-control-plane)\nd23162b4-87b1-4ff8-b5a5-5cb731d822ed (kube-system_coredns-6955765f44-l9jxq)\n1e8cd861-c584-4e38-8c50-7a71a6ae26bb (local-path-storage_local-path-provisioner-85445b74d4-w5ghw)\n8f1b3173-aa43-4014-adcb-36eae52f7502 (stor-ovn-control-plane)")),
						bytes.NewBuffer([]byte("")),
						nil,
					},
				},
				{
					"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), nil},
				},
			},
			onRetArgsKexecIface: []onCallReturnArgs{
				{"Command", []string{"string", "string", "string", "string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
				{"Command", []string{"string", "string", "string", "string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
			},
		},
		{
			desc:         "IPv4 CIDR, haveMangementPort=false, ovn-nbctl command with excludeIPs list populated, returns error ",
			errExpected:  false,
			inpNodeName:  "ovn-control-plane",
			inpSubnetStr: "192.168.1.0/24",
			onRetArgsExecUtilsIface: []onCallReturnArgs{
				{
					"RunCmd",
					[]string{"*mocks.Cmd", "string", "[]string", "string", "string", "string"},
					[]interface{}{
						// below is output from command --> ovn-nbctl lsp-list ovn-control-plane
						bytes.NewBuffer([]byte("d23162b4-87b1-4ff8-b5a5-5cb731d822ed (kube-system_coredns-6955765f44-l9jxq)\n1e8cd861-c584-4e38-8c50-7a71a6ae26bb (local-path-storage_local-path-provisioner-85445b74d4-w5ghw)\n8f1b3173-aa43-4014-adcb-36eae52f7502 (stor-ovn-control-plane)")),
						bytes.NewBuffer([]byte("")),
						nil,
					},
				},
				{
					"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("")), bytes.NewBuffer([]byte("")), fmt.Errorf("test error")},
				},
			},
			onRetArgsKexecIface: []onCallReturnArgs{
				{"Command", []string{"string", "string", "string", "string"}, []interface{}{mockCmd}},
				{"Command", []string{"string", "string", "string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
			},
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			if tc.onRetArgsExecUtilsIface != nil {
				for _, item := range tc.onRetArgsExecUtilsIface {
					call := mockExecRunner.On(item.onCallMethodName)
					for _, arg := range item.onCallMethodArgType {
						call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
					}
					for _, elem := range item.retArgList {
						call.ReturnArguments = append(call.ReturnArguments, elem)
					}
					call.Once()
				}
			}

			if tc.onRetArgsKexecIface != nil {
				for _, item := range tc.onRetArgsKexecIface {
					ifaceCall := mockKexecIface.On(item.onCallMethodName)
					for _, arg := range item.onCallMethodArgType {
						ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
					}
					for _, elem := range item.retArgList {
						ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, elem)
					}
					ifaceCall.Once()
				}
			}

			_, ipnet, err := net.ParseCIDR(tc.inpSubnetStr)
			if err != nil {
				t.Fail()
			}
			var e error
			if tc.setCfgHybridOvlyEnabled {
				config.HybridOverlay.Enabled = true
				e = UpdateNodeSwitchExcludeIPs(runner, tc.inpNodeName, ipnet)
				config.HybridOverlay.Enabled = false
			} else {
				e = UpdateNodeSwitchExcludeIPs(runner, tc.inpNodeName, ipnet)
			}

			if tc.errExpected {
				assert.Error(t, e)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}
