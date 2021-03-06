package util

import (
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	annotatorMock "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube/mocks"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestL3GatewayConfig_MarshalJSON(t *testing.T) {
	vlanid := uint(1024)
	tests := []struct {
		desc       string
		inpL3GwCfg *L3GatewayConfig
		expOutput  []byte
	}{
		{
			desc:       "test empty config i.e gateway mode disabled by default",
			inpL3GwCfg: &L3GatewayConfig{},
			expOutput:  []byte(`{"mode":""}`),
		},
		{
			desc: "test gateway mode set to local and verify that node-port-enable is set to false by default",
			inpL3GwCfg: &L3GatewayConfig{
				Mode: config.GatewayModeLocal,
			},
			expOutput: []byte(`{"mode":"local","node-port-enable":"false"}`),
		},
		{
			desc: "test VLANID not nil",
			inpL3GwCfg: &L3GatewayConfig{
				Mode:   config.GatewayModeShared,
				VLANID: &vlanid,
			},
			expOutput: []byte(`{"mode":"shared","node-port-enable":"false","vlan-id":"1024"}`),
		},
		{
			desc: "test single IP address and single next hop path",
			inpL3GwCfg: &L3GatewayConfig{
				Mode:        config.GatewayModeLocal,
				VLANID:      &vlanid,
				IPAddresses: []*net.IPNet{ovntest.MustParseIPNet("192.168.1.10/24")},
				NextHops:    []net.IP{ovntest.MustParseIP("192.168.1.1")},
			},
			expOutput: []byte(`{"mode":"local","ip-addresses":["192.168.1.10/24"],"ip-address":"192.168.1.10/24","next-hops":["192.168.1.1"],"next-hop":"192.168.1.1","node-port-enable":"false","vlan-id":"1024"}`),
		},
		{
			desc: "test multiple IP address and multiple next hop paths",
			inpL3GwCfg: &L3GatewayConfig{
				Mode:        config.GatewayModeLocal,
				VLANID:      &vlanid,
				InterfaceID: "INTERFACE-ID",
				MACAddress:  ovntest.MustParseMAC("11:22:33:44:55:66"),
				IPAddresses: []*net.IPNet{
					ovntest.MustParseIPNet("192.168.1.10/24"),
					ovntest.MustParseIPNet("fd01::1234/64"),
				},
				NextHops: []net.IP{
					ovntest.MustParseIP("192.168.1.1"),
					ovntest.MustParseIP("fd01::1"),
				},
			},
			expOutput: []byte(`{"mode":"local","interface-id":"INTERFACE-ID","mac-address":"11:22:33:44:55:66","ip-addresses":["192.168.1.10/24","fd01::1234/64"],"next-hops":["192.168.1.1","fd01::1"],"node-port-enable":"false","vlan-id":"1024"}`),
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res, e := tc.inpL3GwCfg.MarshalJSON()
			t.Log(string(res), e)
			assert.True(t, reflect.DeepEqual(res, tc.expOutput))
		})
	}
}

func TestL3GatewayConfig_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		desc       string
		expOut     L3GatewayConfig
		inputParam []byte
		errAssert  bool
		errMatch   error
	}{
		{
			desc:       "error: test bad input causing json Unmarshal error",
			errAssert:  true,
			inputParam: []byte(`{`),
		},
		{
			desc:       "success: test gateway mode disabled path",
			inputParam: []byte(`{"mode":""}`),
			expOut: L3GatewayConfig{
				Mode:           "",
				NodePortEnable: false,
			},
		},
		{
			desc:       "error: test unsupported gateway mode",
			inputParam: []byte(`{"mode":"blah"}`),
			errMatch:   fmt.Errorf("bad 'mode' value"),
		},
		{
			desc:       "error: test bad VLANID input",
			inputParam: []byte(`{"mode":"shared","vlan-id":"A"}`),
			errMatch:   fmt.Errorf("bad 'vlan-id' value"),
		},
		{desc: "error: test VLANID is supported only in shared gateway mode",
			inputParam: []byte(`{"mode":"local","vlan-id":"223"}`),
			errMatch:   fmt.Errorf("vlan-id is supported only in shared gateway mode"),
		},
		{
			desc:       "success: test valid VLANID input",
			inputParam: []byte(`{"mode":"shared","vlan-id":"223"}`),
			expOut: L3GatewayConfig{
				Mode:           "shared",
				NodePortEnable: false,
				VLANID:         &[]uint{223}[0],
			},
		},
		{
			desc:       "test bad MAC address value",
			inputParam: []byte(`{"mode":"local","mac-address":"BADMAC"}`),
			errMatch:   fmt.Errorf("bad 'mac-address' value"),
		},
		{
			desc:       "test bad 'IP address' value",
			inputParam: []byte(`{"mode":"local","mac-address":"11:22:33:44:55:66","ip-address":"192.168.1/24"}`),
			errMatch:   fmt.Errorf("bad 'ip-address' value"),
		},
		{
			desc:       "test bad 'IP addresses' value",
			inputParam: []byte(`{"mode":"local","mac-address":"11:22:33:44:55:66","ip-addresses":["192.168.1/24","fd01::1234/64"]}`),
			errMatch:   fmt.Errorf("bad 'ip-addresses' value"),
		},
		{
			desc:       "test valid 'IP addresses' value",
			inputParam: []byte(`{"mode":"local","mac-address":"11:22:33:44:55:66","ip-addresses":["192.168.1.5/24","fd01::1234/64"]}`),
			expOut: L3GatewayConfig{
				Mode:           "local",
				MACAddress:     ovntest.MustParseMAC("11:22:33:44:55:66"),
				NodePortEnable: false,
				IPAddresses:    ovntest.MustParseIPNets("192.168.1.5/24", "fd01::1234/64"),
				NextHops:       []net.IP{nil},
			},
		},
		{
			desc:       "test bad 'next-hop' value",
			inputParam: []byte(`{"mode":"local","mac-address":"11:22:33:44:55:66","ip-address":"192.168.1.5/24","next-hop":"192.168.11"}`),
			errMatch:   fmt.Errorf("bad 'next-hop' value"),
		},
		{
			desc:       "test bad 'next-hops' value",
			inputParam: []byte(`{"mode":"local","mac-address":"11:22:33:44:55:66","ip-address":"192.168.1.5/24", "next-hops":["192.168.1.","fd01::1"]}`),
			errMatch:   fmt.Errorf("bad 'next-hops' value"),
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			l3GwCfg := L3GatewayConfig{}
			e := l3GwCfg.UnmarshalJSON(tc.inputParam)
			if tc.errAssert {
				t.Log(e)
				assert.Error(t, e)
			} else if tc.errMatch != nil {
				assert.Contains(t, e.Error(), tc.errMatch.Error())
			} else {
				t.Log(l3GwCfg)
				assert.Equal(t, l3GwCfg, tc.expOut)
			}
		})
	}
}

func TestSetL3GatewayConfig(t *testing.T) {
	mockAnnotator := new(annotatorMock.Annotator)

	tests := []struct {
		desc                   string
		inpNodeAnnotator       kube.Annotator
		inputL3GwCfg           L3GatewayConfig
		errExpected            bool
		onRetArgsAnnotatorList []ovntest.TestifyMockHelper
	}{
		{
			desc:             "success: empty L3GatewayConfig applied should pass",
			inpNodeAnnotator: mockAnnotator,
			inputL3GwCfg:     L3GatewayConfig{},
			onRetArgsAnnotatorList: []ovntest.TestifyMockHelper{
				{OnCallMethodName: "Set", OnCallMethodArgType: []string{"string", "interface{}"}, RetArgList: []interface{}{nil}},
			},
		},
		{
			desc:             "test error path when setting gateway annotation",
			inpNodeAnnotator: mockAnnotator,
			inputL3GwCfg:     L3GatewayConfig{},
			onRetArgsAnnotatorList: []ovntest.TestifyMockHelper{
				{OnCallMethodName: "Set", OnCallMethodArgType: []string{"string", "interface{}"}, RetArgList: []interface{}{fmt.Errorf("mock error")}},
			},
		},
		{
			desc:             "success: apply empty Chassis id",
			inpNodeAnnotator: mockAnnotator,
			inputL3GwCfg: L3GatewayConfig{
				ChassisID: " ",
			},
			onRetArgsAnnotatorList: []ovntest.TestifyMockHelper{
				{OnCallMethodName: "Set", OnCallMethodArgType: []string{"string", "interface{}"}, RetArgList: []interface{}{nil}},
				{OnCallMethodName: "Set", OnCallMethodArgType: []string{"string", "interface{}"}, RetArgList: []interface{}{nil}},
			},
		},
		{
			desc:             "test error path when applying Chassis ID",
			inpNodeAnnotator: mockAnnotator,
			inputL3GwCfg: L3GatewayConfig{
				ChassisID: "testid",
			},
			onRetArgsAnnotatorList: []ovntest.TestifyMockHelper{
				{OnCallMethodName: "Set", OnCallMethodArgType: []string{"string", "interface{}"}, RetArgList: []interface{}{nil}},
				{OnCallMethodName: "Set", OnCallMethodArgType: []string{"string", "interface{}"}, RetArgList: []interface{}{fmt.Errorf("mock error")}},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			for _, item := range tc.onRetArgsAnnotatorList {
				call := mockAnnotator.On(item.OnCallMethodName)
				for range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.Anything)
				}

				for _, e := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, e)
				}
				call.Once()
			}
			e := SetL3GatewayConfig(tc.inpNodeAnnotator, &tc.inputL3GwCfg)
			if tc.errExpected {
				t.Log(e)
				assert.Error(t, e)
			}
			mockAnnotator.AssertExpectations(t)
		})
	}
}

func TestParseNodeL3GatewayAnnotation(t *testing.T) {
	tests := []struct {
		desc      string
		inpNode   *v1.Node
		errAssert bool
		errMatch  error
	}{
		{
			desc:      "error: annotation not found for node",
			inpNode:   &v1.Node{},
			errAssert: true,
			errMatch:  fmt.Errorf("%s annotation not found for node", ovnNodeL3GatewayConfig),
		},
		{
			desc: "error: fail to unmarshal l3 gateway config annotations",
			inpNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"k8s.ovn.org/l3-gateway-config": `{"default":{"mode":"local","mac_address":"}}`},
				},
			},
			errAssert: true,
			errMatch:  fmt.Errorf("failed to unmarshal l3 gateway config annotation"),
		},
		{
			desc: "error: annotation for network not found",
			inpNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"k8s.ovn.org/l3-gateway-config": `{"nondefault":{"mode":"local","mac-address":"7e:57:f8:f0:3c:49", "ip-address":"169.254.33.2/24", "next-hop":"169.254.33.1"}}`},
				},
			},
			errAssert: true,
			errMatch:  fmt.Errorf("%s annotation not found", ovnNodeL3GatewayConfig),
		},
		{
			desc: "error: nod chassis ID annotation not found",
			inpNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"k8s.ovn.org/l3-gateway-config": `{"default":{"mode":"local","mac-address":"7e:57:f8:f0:3c:49", "ip-address":"169.254.33.2/24", "next-hop":"169.254.33.1"}}`},
				},
			},
			errAssert: true,
			errMatch:  fmt.Errorf("%s annotation not found", ovnNodeChassisID),
		},
		{
			desc: "success: parse completed",
			inpNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"k8s.ovn.org/l3-gateway-config": `{"default":{"mode":"local","mac-address":"7e:57:f8:f0:3c:49", "ip-address":"169.254.33.2/24", "next-hop":"169.254.33.1"}}`,
						"k8s.ovn.org/node-chassis-id":   "79fdcfc4-6fe6-4cd3-8242-c0f85a4668ec",
					},
				},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			cfg, e := ParseNodeL3GatewayAnnotation(tc.inpNode)
			if tc.errAssert {
				t.Log(e)
				assert.Error(t, e)
			} else if tc.errMatch != nil {
				assert.Contains(t, e.Error(), tc.errMatch.Error())
			} else {
				assert.NotNil(t, cfg)
			}
		})
	}
}

func TestParseNodeManagementPortMACAddress(t *testing.T) {
	tests := []struct {
		desc        string
		inpNode     v1.Node
		errExpected bool
		expOutput   bool
	}{
		{
			desc:      "mac address annotation not found for node, however, does not return error",
			inpNode:   v1.Node{},
			expOutput: false,
		},
		{
			desc: "success: parse mac address",
			inpNode: v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"k8s.ovn.org/node-mgmt-port-mac-address": "96:8f:e8:25:a2:e5"},
				},
			},
			expOutput: true,
		},
		{
			desc: "error: parse mac address error",
			inpNode: v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"k8s.ovn.org/node-mgmt-port-mac-address": "96:8f:e8:25:a2:"},
				},
			},
			errExpected: true,
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			cfg, e := ParseNodeManagementPortMACAddress(&tc.inpNode)
			if tc.errExpected {
				t.Log(e)
				assert.Error(t, e)
				assert.Nil(t, cfg)
			}
			if tc.expOutput {
				assert.NotNil(t, cfg)
			}
		})
	}
}
