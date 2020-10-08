package util

import (
	"bytes"
	"fmt"
	"net"
	"testing"

	goovn "github.com/ebay/go-ovn"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	goovn_mocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/ebay/go-ovn"
	mock_k8s_io_utils_exec "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/k8s.io/utils/exec"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNextIP(t *testing.T) {
	tests := []struct {
		desc      string
		input     string
		expOutput string
	}{
		// Note: test was not successful when providing input of 0.0.0.0
		{
			desc:      "test increment of fourth octet",
			input:     "255.255.255.254",
			expOutput: "255.255.255.255",
		},
		{
			desc:      "test increment of third octet",
			input:     "255.255.254.255",
			expOutput: "255.255.255.0",
		},
		{
			desc:      "test increment of second octet",
			input:     "255.254.255.255",
			expOutput: "255.255.0.0",
		},
		{
			desc:      "test increment of first octet",
			input:     "254.255.255.255",
			expOutput: "255.0.0.0",
		},
		{
			desc:      "IPv6: test increment of eight hextet",
			input:     "2001:db8::ffff",
			expOutput: "2001:db8::1:0",
		},
		{
			desc:      "IPv6: test increment of first hextet",
			input:     "fffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
			expOutput: "ffff::",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res := NextIP(ovntest.MustParseIP(tc.input))
			t.Log(res.String())
			assert.Equal(t, tc.expOutput, res.String())
		})
	}
}

func TestGetPortAddresses(t *testing.T) {
	mockOvnNBClient := new(goovn_mocks.Client)
	tests := []struct {
		desc                 string
		inpPort              string
		errAssert            bool
		errMatch             error
		onRetArgsOvnNBClient *onCallReturnArgs
	}{
		{
			desc:                 "test path where LSPGet() returns goovn.ErrorSchema/goovn.ErrorNotFound",
			inpPort:              "TEST_PORT",
			onRetArgsOvnNBClient: &onCallReturnArgs{"LSPGet", []string{"string"}, []interface{}{nil, goovn.ErrorSchema}},
		},
		{
			desc:                 "test path where LSPGet() returns an error other than goovn.ErrorSchema/goovn.ErrorNotFound",
			inpPort:              "TEST_PORT",
			errAssert:            true,
			onRetArgsOvnNBClient: &onCallReturnArgs{"LSPGet", []string{"string"}, []interface{}{nil, goovn.ErrorOption}},
		},
		{
			desc:                 "test path where LSPGet() returns nil",
			inpPort:              "TEST_PORT",
			onRetArgsOvnNBClient: &onCallReturnArgs{"LSPGet", []string{"string"}, []interface{}{nil, nil}},
		},
		{
			desc:                 "test path where lsp.DynamicAddresses is a zero length string and len(addresses)==0",
			inpPort:              "TEST_PORT",
			onRetArgsOvnNBClient: &onCallReturnArgs{"LSPGet", []string{"string"}, []interface{}{&goovn.LogicalSwitchPort{DynamicAddresses: ""}, nil}},
		},
		{
			desc:                 "test path where lsp.DynamicAddresses is non-zero length string and value of first address in addresses list is set to dynamic",
			inpPort:              "TEST_PORT",
			onRetArgsOvnNBClient: &onCallReturnArgs{"LSPGet", []string{"string"}, []interface{}{&goovn.LogicalSwitchPort{DynamicAddresses: "06:c6:d4:fb:fb:ba 10.244.2.2"}, nil}},
		},
		{
			desc:                 "test code path where addresses list count is less than 2",
			inpPort:              "TEST_PORT",
			errMatch:             fmt.Errorf("error while obtaining addresses for"),
			onRetArgsOvnNBClient: &onCallReturnArgs{"LSPGet", []string{"string"}, []interface{}{&goovn.LogicalSwitchPort{DynamicAddresses: "06:c6:d4:fb:fb:ba"}, nil}},
		},
		{
			desc:                 "test the code path where ParseMAC fails",
			inpPort:              "TEST_PORT",
			errMatch:             fmt.Errorf("failed to parse logical switch port"),
			onRetArgsOvnNBClient: &onCallReturnArgs{"LSPGet", []string{"string"}, []interface{}{&goovn.LogicalSwitchPort{Addresses: []string{"192.168.1.3 0a:00:00:00:00:01"}}, nil}},
		},
		{
			desc:                 "test code path where IP address parsing fails",
			inpPort:              "TEST_PORT",
			errMatch:             fmt.Errorf("failed to parse logical switch port"),
			onRetArgsOvnNBClient: &onCallReturnArgs{"LSPGet", []string{"string"}, []interface{}{&goovn.LogicalSwitchPort{Addresses: []string{"192.168.1.3 0a:00:00:00:00:01"}}, nil}},
		},
		{
			desc:                 "test success path where MAC, IPs are returned",
			inpPort:              "TEST_PORT",
			onRetArgsOvnNBClient: &onCallReturnArgs{"LSPGet", []string{"string"}, []interface{}{&goovn.LogicalSwitchPort{Addresses: []string{"0a:00:00:00:00:01 192.168.1.3"}}, nil}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockOvnNBClient.On(tc.onRetArgsOvnNBClient.onCallMethodName)
			for _, arg := range tc.onRetArgsOvnNBClient.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsOvnNBClient.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			hwAddr, ipList, err := GetPortAddresses(tc.inpPort, mockOvnNBClient)
			t.Log(hwAddr.String(), ipList, err)
			if tc.errAssert {
				assert.Error(t, err)
			} else if tc.errMatch != nil {
				assert.Contains(t, err.Error(), tc.errMatch.Error())
			}
		})
	}
}

func TestGetOVSPortMACAddress(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		input                   string
		errExpected             bool
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		// NOTE: May need a test to validate (e.g; zero length string ) portName parameter that is passed to function
		{
			desc:                    "tests code path when RunOVSVsctl returns error",
			input:                   "TEST_PORT",
			errExpected:             true,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string", "string"}, []interface{}{nil, nil, fmt.Errorf("executable file not found in $PATH")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "tests code path when MAC address returned is []",
			input:                   "TEST_PORT",
			errExpected:             true,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("[]")), nil, nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "tests code path when Valid MAC address is returned",
			input:                   "TEST_PORT",
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("00:00:a9:fe:21:01")), nil, nil}},
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

			res, err := GetOVSPortMACAddress(runner, tc.input)
			t.Log(res, err)
			if tc.errExpected {
				assert.Error(t, err)
			}
			mockKexecIface.AssertExpectations(t)
			mockExecRunner.AssertExpectations(t)
		})
	}
}

func TestIPFamilyName(t *testing.T) {
	tests := []struct {
		desc   string
		input  bool
		expOut string
	}{
		{
			desc:   "verify bool value `true` maps to IPv6",
			input:  true,
			expOut: "IPv6",
		},
		{
			desc:   "verify bool value `false` maps to IPv4",
			input:  false,
			expOut: "IPv4",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res := IPFamilyName(tc.input)
			t.Log(res)
			assert.Equal(t, res, tc.expOut)
		})
	}
}

func TestMatchIPFamily(t *testing.T) {
	tests := []struct {
		desc      string
		inpIsIPv6 bool // true matches with IPv6 and false with IPv4
		inpIPs    []string
		expected  string
	}{
		{
			desc:      "negative: attempt to get IPv6 from an empty IP list",
			inpIsIPv6: true,
			inpIPs:    []string{},
			expected:  "",
		},
		{
			desc:      "negative: attempt to get IPv4 from an empty IP list",
			inpIsIPv6: false,
			inpIPs:    []string{},
			expected:  "",
		},
		{
			desc:      "negative: attempt to get IPv4 from IPv6-only list",
			inpIsIPv6: false,
			inpIPs:    []string{"fd01::1"},
			expected:  "",
		},
		{
			desc:      "positive: retrieve IPv6 valid address",
			inpIsIPv6: true,
			inpIPs:    []string{"192.168.1.0", "fd01::1"},
			expected:  "fd01::1",
		},
		{
			desc:      "positive: retrieve IPv4 valid address",
			inpIsIPv6: false,
			inpIPs:    []string{"192.168.1.0", "fd01::1"},
			expected:  "192.168.1.0",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res, err := MatchIPFamily(tc.inpIsIPv6, ovntest.MustParseIPs(tc.inpIPs...))
			t.Log(res, err)
			if tc.expected == "" {
				assert.Error(t, err)
			} else {
				assert.Equal(t, res, ovntest.MustParseIP(tc.expected))
			}
		})
	}
}

func TestMatchIPNetFamily(t *testing.T) {
	tests := []struct {
		desc       string
		inpIsIPv6  bool // true matches with IPv6 and false with IPv4
		inpSubnets []string
		expected   string
	}{
		{
			desc:       "negative: attempt to get IPv6 from an empty IP list",
			inpIsIPv6:  true,
			inpSubnets: []string{},
			expected:   "",
		},
		{
			desc:       "negative: attempt to get IPv4 from an empty IP list",
			inpIsIPv6:  false,
			inpSubnets: []string{},
			expected:   "",
		},
		{
			desc:       "negative: attempt to get IPv4 from IPv6-only list",
			inpIsIPv6:  false,
			inpSubnets: []string{"fd01::1/64"},
			expected:   "",
		},
		{
			desc:       "positive: retrieve IPv6 valid address",
			inpIsIPv6:  true,
			inpSubnets: []string{"192.168.1.0/24", "fd01::1/64"},
			expected:   "fd01::1/64",
		},
		{
			desc:       "positive: retrieve IPv4 valid address",
			inpIsIPv6:  false,
			inpSubnets: []string{"192.168.1.0/24", "fd01::1/64"},
			expected:   "192.168.1.0/24",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res, err := MatchIPNetFamily(tc.inpIsIPv6, ovntest.MustParseIPNets(tc.inpSubnets...))
			t.Log(res, err)
			if tc.expected == "" {
				assert.Error(t, err)
			} else {
				assert.Equal(t, res, ovntest.MustParseIPNet(tc.expected))
			}
		})
	}
}

func TestJoinHostPortInt32(t *testing.T) {
	tests := []struct {
		desc    string
		inpHost string
		inpPort int32
		outExp  string
	}{
		{
			desc:    "empty string for host name and a negative port number",
			inpPort: -25,
			outExp:  ":-25",
		},
		{
			desc:    "valid non-zero length string for host name",
			inpHost: "hostname",
			inpPort: 22,
			outExp:  "hostname:22",
		},
		{
			desc:    "valid IPv4 address as host name",
			inpHost: "192.168.1.15",
			inpPort: 22,
			outExp:  "192.168.1.15:22",
		},
		{
			desc:    "valid IPv6 address as host name",
			inpHost: "fd01::1234",
			inpPort: 22,
			outExp:  "[fd01::1234]:22",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res := JoinHostPortInt32(tc.inpHost, tc.inpPort)
			t.Log(res)
			assert.Equal(t, res, tc.outExp)
		})
	}
}

func TestIPAddrToHWAddr(t *testing.T) {
	tests := []struct {
		desc   string
		inpIP  net.IP
		outExp net.HardwareAddr
	}{
		{
			desc:   "test IPv4 instance of net.IP",
			inpIP:  ovntest.MustParseIP("192.168.1.5"),
			outExp: ovntest.MustParseMAC("0a:58:c0:a8:01:05"),
		},
		{
			desc:  "test IPv6 instance of net.IP",
			inpIP: ovntest.MustParseIP("fd01::1234"),
			// 0a:58:ee:33:fc:1a generated from util.IPAddrToHWAddr(net.ParseIP(""fd01::1234")).String()
			outExp: ovntest.MustParseMAC("0a:58:11:37:a6:26"),
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res := IPAddrToHWAddr(tc.inpIP)
			t.Log(res)
			assert.Equal(t, res, tc.outExp)
		})
	}
}

func TestJoinIPs(t *testing.T) {
	tests := []struct {
		desc         string
		inpIPList    []net.IP
		inpSeparator string
		outExp       string
	}{
		{
			desc:         "an empty net.IPNet list with ',' separator",
			inpSeparator: ",",
			outExp:       "",
		},
		{
			desc:         "single item in net.IPNet list with `;` separator",
			inpIPList:    ovntest.MustParseIPs("192.168.1.5"),
			inpSeparator: ";",
			outExp:       "192.168.1.5",
		},
		{
			desc:         "two items in net.IPNet list with `;` separator",
			inpIPList:    ovntest.MustParseIPs("192.168.1.5", "192.168.1.6"),
			inpSeparator: ";",
			outExp:       "192.168.1.5;192.168.1.6",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res := JoinIPs(tc.inpIPList, tc.inpSeparator)
			t.Log(res)
			assert.Equal(t, res, tc.outExp)
		})
	}
}

func TestJoinIPNets(t *testing.T) {
	tests := []struct {
		desc         string
		inpIPNetList []*net.IPNet
		inpSeparator string
		outExp       string
	}{
		{
			desc:         "an empty net.IPNet list with ',' separator",
			inpSeparator: ",",
			outExp:       "",
		},
		{
			desc:         "single item in net.IPNet list with `;` separator",
			inpIPNetList: ovntest.MustParseIPNets("192.168.1.5/24"),
			inpSeparator: ";",
			outExp:       "192.168.1.5/24",
		},
		{
			desc:         "two items in net.IPNet list with `;` separator",
			inpIPNetList: ovntest.MustParseIPNets("192.168.1.5/24", "192.168.1.6/24"),
			inpSeparator: ";",
			outExp:       "192.168.1.5/24;192.168.1.6/24",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res := JoinIPNets(tc.inpIPNetList, tc.inpSeparator)
			t.Log(res)
			assert.Equal(t, res, tc.outExp)
		})
	}
}

func TestJoinIPNetIPs(t *testing.T) {
	tests := []struct {
		desc         string
		inpIPNetList []*net.IPNet
		inpSeparator string
		outExp       string
	}{
		{
			desc:         "an empty net.IPNet list with ',' separator",
			inpSeparator: ",",
			outExp:       "",
		},
		{
			desc:         "single item in net.IPNet list with `;` separator",
			inpIPNetList: ovntest.MustParseIPNets("192.168.1.5/24"),
			inpSeparator: ";",
			outExp:       "192.168.1.5",
		},
		{
			desc:         "two items in net.IPNet list with `;` separator",
			inpIPNetList: ovntest.MustParseIPNets("192.168.1.5/24", "192.168.1.6/24"),
			inpSeparator: ";",
			outExp:       "192.168.1.5;192.168.1.6",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res := JoinIPNetIPs(tc.inpIPNetList, tc.inpSeparator)
			t.Log(res)
			assert.Equal(t, res, tc.outExp)
		})
	}
}
