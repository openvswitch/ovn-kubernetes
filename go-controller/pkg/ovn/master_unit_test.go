package ovn

import (
	"fmt"
	"testing"

	goovn "github.com/ebay/go-ovn"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	goovn_mock "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/github.com/ebay/go-ovn"
	"github.com/stretchr/testify/assert"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

const (
	lsName    = "TestLSName"
	portName  = "TestPortName"
	portType  = "TestRouterType"
	addresses = "10.1.1.1:80"
	//lspUUID   = "e72eb0bb-a1ce-45d5-b8a0-3200aed7e5e9"
	//lspName   = "TestLSPName"
)

var (
	options    = map[string]string{"router-port": "stor-node1"}
	optionsMap = map[string]string{"router-port": "stor-node1"}
	//execError  = errors.New("transaction Failed due to an error")
	//otherError = errors.New("other error")
)

func TestAddNodeLogicalSwitchPort(t *testing.T) {
	mockGoOvnNBClient := new(goovn_mock.Client)

	// TODO: Replace fakeExec with Mock OvnNBClient
	// once LSPSetPortType() merges upstream in go-ovn

	gomega.RegisterFailHandler(Fail)
	fexec := ovntest.NewFakeExec()
	err := util.SetExec(fexec)
	fexec.AddFakeCmdsNoOutputNoError([]string{
		"ovn-nbctl --timeout=15 lsp-set-type TestPortName TestRouterType",
		"ovn-nbctl --timeout=15 lsp-set-type TestPortName TestRouterType",
	})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	tests := []struct {
		desc                      string
		inpLsName                 string
		inpPortName               string
		inpPortType               string
		inpAddresses              string
		inpOptions                map[string]string
		errExp                    bool
		errMatch                  error
		onRetArgMockGoOvnNBClient []ovntest.TestifyMockHelper
	}{
		{
			desc:         "test error when ovnNBClient.LSPGet() fails",
			inpLsName:    lsName,
			inpPortName:  portName,
			inpPortType:  portType,
			inpAddresses: addresses,
			inpOptions:   options,
			errExp:       true,
			errMatch:     fmt.Errorf("unable to get the lsp: %s the nbdb: %v", portName, otherError),
			onRetArgMockGoOvnNBClient: []ovntest.TestifyMockHelper{
				{
					OnCallMethodName: "LSPGet", OnCallMethodArgType: []string{"string"}, RetArgList: []interface{}{nil, goovn.ErrorOption},
				},
			},
		},
		{
			desc:         "test error when no lsp exists and ovnNBClient.LSPAdd() fails",
			inpLsName:    lsName,
			inpPortName:  portName,
			inpPortType:  portType,
			inpAddresses: addresses,
			inpOptions:   options,
			errMatch:     fmt.Errorf("failed to add logical port %s to switch %s error: %v", portName, lsName, otherError),
			onRetArgMockGoOvnNBClient: []ovntest.TestifyMockHelper{
				{
					OnCallMethodName: "LSPGet", OnCallMethodArgType: []string{"string"}, RetArgList: []interface{}{nil, nil},
				},
				{
					OnCallMethodName: "LSPAdd", OnCallMethodArgType: []string{"string", "string"}, RetArgList: []interface{}{nil, otherError},
				},
			},
		},
		{
			desc:         "test error when ovnNBClient.LSPSetAddress() fails",
			inpLsName:    lsName,
			inpPortName:  portName,
			inpPortType:  portType,
			inpAddresses: addresses,
			errMatch:     fmt.Errorf("failed to set address %s to port %s error: %v", addresses, portName, otherError),
			onRetArgMockGoOvnNBClient: []ovntest.TestifyMockHelper{
				{
					OnCallMethodName: "LSPGet", OnCallMethodArgType: []string{"string"}, RetArgList: []interface{}{&goovn.LogicalSwitchPort{UUID: lspUUID, Name: lspName}, nil},
				},
				{
					OnCallMethodName: "LSPSetAddress", OnCallMethodArgType: []string{"string", "string"}, RetArgList: []interface{}{nil, otherError},
				},
			},
		},
		{
			desc:         "test error when lsp exists and ovnNBClient.LSPSetOptions() fails",
			inpLsName:    lsName,
			inpPortName:  portName,
			inpPortType:  portType,
			inpAddresses: addresses,
			inpOptions:   options,
			errMatch:     fmt.Errorf("failed to set options  %v to port %s error: %v", optionsMap, portName, otherError),
			onRetArgMockGoOvnNBClient: []ovntest.TestifyMockHelper{
				{
					OnCallMethodName: "LSPGet", OnCallMethodArgType: []string{"string"}, RetArgList: []interface{}{&goovn.LogicalSwitchPort{UUID: lspUUID, Name: lspName}, nil},
				},
				{
					OnCallMethodName: "LSPSetAddress", OnCallMethodArgType: []string{"string", "string"}, RetArgList: []interface{}{&goovn.OvnCommand{}, nil},
				},
				{
					OnCallMethodName: "LSPSetOptions", OnCallMethodArgType: []string{"string", "map[string]string"}, RetArgList: []interface{}{nil, otherError},
				},
			},
		},
		{
			desc:         "test error ovnNBClient.Execute fails",
			inpLsName:    lsName,
			inpPortName:  portName,
			inpPortType:  portType,
			inpAddresses: addresses,
			inpOptions:   options,
			errMatch:     fmt.Errorf("failed to add Logical Switch Portname %s  %v", portName, execError),
			onRetArgMockGoOvnNBClient: []ovntest.TestifyMockHelper{
				{
					OnCallMethodName: "LSPGet", OnCallMethodArgType: []string{"string"}, RetArgList: []interface{}{&goovn.LogicalSwitchPort{UUID: lspUUID, Name: lspName}, nil},
				},
				{
					OnCallMethodName: "LSPSetAddress", OnCallMethodArgType: []string{"string", "string"}, RetArgList: []interface{}{&goovn.OvnCommand{}, nil},
				},
				{
					OnCallMethodName: "LSPSetOptions", OnCallMethodArgType: []string{"string", "map[string]string"}, RetArgList: []interface{}{&goovn.OvnCommand{}, nil},
				},
				{
					OnCallMethodName: "Execute", OnCallMethodArgType: []string{"*goovn.OvnCommand", "*goovn.OvnCommand"}, RetArgList: []interface{}{execError},
				},
			},
		},
		{
			desc:         "test error when LSPGet fails after ovnNBClient.Execute passes",
			inpLsName:    lsName,
			inpPortName:  portName,
			inpPortType:  portType,
			inpAddresses: addresses,
			inpOptions:   options,
			errMatch:     otherError,
			onRetArgMockGoOvnNBClient: []ovntest.TestifyMockHelper{
				{
					OnCallMethodName: "LSPGet", OnCallMethodArgType: []string{"string"}, RetArgList: []interface{}{&goovn.LogicalSwitchPort{UUID: lspUUID, Name: lspName}, nil},
				},
				{
					OnCallMethodName: "LSPSetAddress", OnCallMethodArgType: []string{"string", "string"}, RetArgList: []interface{}{&goovn.OvnCommand{}, nil},
				},
				{
					OnCallMethodName: "LSPSetOptions", OnCallMethodArgType: []string{"string", "map[string]string"}, RetArgList: []interface{}{&goovn.OvnCommand{}, nil},
				},
				{
					OnCallMethodName: "Execute", OnCallMethodArgType: []string{"*goovn.OvnCommand", "*goovn.OvnCommand"}, RetArgList: []interface{}{nil},
				},
				{
					OnCallMethodName: "LSPGet", OnCallMethodArgType: []string{"string"}, RetArgList: []interface{}{nil, otherError},
				},
			},
		},
		{
			desc:         "positive test case",
			inpLsName:    lsName,
			inpPortName:  portName,
			inpPortType:  portType,
			inpAddresses: addresses,
			inpOptions:   options,
			errMatch:     nil,
			onRetArgMockGoOvnNBClient: []ovntest.TestifyMockHelper{
				{
					OnCallMethodName: "LSPGet", OnCallMethodArgType: []string{"string"}, RetArgList: []interface{}{&goovn.LogicalSwitchPort{UUID: lspUUID, Name: lspName}, nil},
				},
				{
					OnCallMethodName: "LSPSetAddress", OnCallMethodArgType: []string{"string", "string"}, RetArgList: []interface{}{&goovn.OvnCommand{}, nil},
				},
				{
					OnCallMethodName: "LSPSetOptions", OnCallMethodArgType: []string{"string", "map[string]string"}, RetArgList: []interface{}{&goovn.OvnCommand{}, nil},
				},
				{
					OnCallMethodName: "Execute", OnCallMethodArgType: []string{"*goovn.OvnCommand", "*goovn.OvnCommand"}, RetArgList: []interface{}{nil},
				},
				{
					OnCallMethodName: "LSPGet", OnCallMethodArgType: []string{"string"}, RetArgList: []interface{}{&goovn.LogicalSwitchPort{UUID: lspUUID, Name: lspName}, nil},
				},
			},
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			ovntest.ProcessMockFnList(&mockGoOvnNBClient.Mock, tc.onRetArgMockGoOvnNBClient)
			_, err := addNodeLogicalSwitchPort(mockGoOvnNBClient, tc.inpLsName, tc.inpPortName, tc.inpPortType, tc.inpAddresses, tc.inpOptions)
			if tc.errExp {
				assert.Error(t, err)
			} else if tc.errMatch != nil {
				assert.Contains(t, err.Error(), tc.errMatch.Error())
			} else {
				assert.Nil(t, err)
			}
			mockGoOvnNBClient.AssertExpectations(t)
		})
	}
}
