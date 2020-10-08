package util

import (
	"fmt"
	"net"
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

func TestMarshalPodAnnotation(t *testing.T) {
	tests := []struct {
		desc           string
		inpPodAnnot    PodAnnotation
		errAssert      bool  // used when an error string CANNOT be matched or sub-matched
		errMatch       error //used when an error string CAN be matched or sub-matched
		expectedOutput map[string]string
	}{
		{
			desc:           "PodAnnotation instance with no fields set",
			inpPodAnnot:    PodAnnotation{},
			expectedOutput: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":null,"mac_address":""}}`},
		},
		{
			desc: "single IP assigned to pod with MAC, Gateway, Routes NOT SPECIFIED",
			inpPodAnnot: PodAnnotation{
				IPs: []*net.IPNet{ovntest.MustParseIPNet("192.168.0.5/24")},
			},
			expectedOutput: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["192.168.0.5/24"],"mac_address":"","ip_address":"192.168.0.5/24"}}`},
		},
		{
			desc: "multiple IPs assigned to pod with MAC, Gateway, Routes NOT SPECIFIED",
			inpPodAnnot: PodAnnotation{
				IPs: []*net.IPNet{
					ovntest.MustParseIPNet("192.168.0.5/24"),
					ovntest.MustParseIPNet("fd01::1234/64"),
				},
			},
			expectedOutput: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["192.168.0.5/24","fd01::1234/64"],"mac_address":""}}`},
		},
		{
			desc: "test code path when podInfo.Gateways count is equal to ONE",
			inpPodAnnot: PodAnnotation{
				IPs: []*net.IPNet{ovntest.MustParseIPNet("192.168.0.5/24")},
				Gateways: []net.IP{
					net.ParseIP("192.168.0.1"),
				},
			},
			expectedOutput: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["192.168.0.5/24"],"mac_address":"","gateway_ips":["192.168.0.1"],"ip_address":"192.168.0.5/24","gateway_ip":"192.168.0.1"}}`},
		},
		{
			desc:     "verify error thrown when number of gateways greater than one for a single-stack network",
			errMatch: fmt.Errorf("bad podNetwork data: single-stack network can only have a single gateway"),
			inpPodAnnot: PodAnnotation{
				IPs: []*net.IPNet{ovntest.MustParseIPNet("192.168.0.5/24")},
				Gateways: []net.IP{
					net.ParseIP("192.168.1.0"),
					net.ParseIP("fd01::1"),
				},
			},
		},
		{
			desc:      "verify error thrown when destination IP not specified as part of Route",
			errAssert: true,
			inpPodAnnot: PodAnnotation{
				Routes: []PodRoute{
					{
						Dest:    ovntest.MustParseIPNet("0.0.0.0/0"),
						NextHop: net.ParseIP("192.168.1.1"),
					},
				},
			},
		},
		{
			desc: "test code path when destination IP is specified as part of Route",
			inpPodAnnot: PodAnnotation{
				Routes: []PodRoute{
					{
						Dest:    ovntest.MustParseIPNet("192.168.1.0/24"),
						NextHop: net.ParseIP("192.168.1.1"),
					},
				},
			},
			expectedOutput: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":null,"mac_address":"","routes":[{"dest":"192.168.1.0/24","nextHop":"192.168.1.1"}]}}`},
		},
		{
			desc: "next hop not set for route",
			inpPodAnnot: PodAnnotation{
				Routes: []PodRoute{
					{
						Dest: ovntest.MustParseIPNet("192.168.1.0/24"),
					},
				},
			},
			expectedOutput: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":null,"mac_address":"","routes":[{"dest":"192.168.1.0/24","nextHop":""}]}}`},
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res := map[string]string{}
			e := MarshalPodAnnotation(&res, &tc.inpPodAnnot, types.DefaultNetworkName)
			t.Log(res, e)
			if tc.errAssert {
				assert.Error(t, e)
			} else if tc.errMatch != nil {
				assert.Contains(t, e.Error(), tc.errMatch.Error())
			} else {
				assert.True(t, reflect.DeepEqual(res, tc.expectedOutput))
			}
		})
	}
}

func TestUnmarshalPodAnnotation(t *testing.T) {
	tests := []struct {
		desc        string
		inpAnnotMap map[string]string
		errAssert   bool
		errMatch    error
	}{
		{
			desc:        "verify `OVN pod annotation not found` error thrown",
			inpAnnotMap: nil,
			errMatch:    fmt.Errorf("could not find OVN pod annotation in"),
		},
		{
			desc:        "verify json unmarshal error",
			inpAnnotMap: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":null,"mac_address":"}}`}, //removed a quote to force json unmarshal error
			errMatch:    fmt.Errorf("failed to unmarshal ovn pod annotation"),
		},
		{
			desc:        "verify MAC error parse error",
			inpAnnotMap: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":null,"mac_address":""}}`},
			errMatch:    fmt.Errorf("failed to parse pod MAC"),
		},
		{
			desc:        "verify error thrown when neither ip_addresses nor ip_address is set",
			inpAnnotMap: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":null,"mac_address":"0a:58:fd:98:00:01"}}`},
			errMatch:    fmt.Errorf("bad annotation data (neither ip_address nor ip_addresses is set)"),
		},
		{
			desc:        "test path when ip_addresses is empty and ip_address is set",
			inpAnnotMap: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":null,"mac_address":"0a:58:fd:98:00:01", "ip_address":"192.168.0.11/24"}}`},
		},
		{
			desc:        "verify error thrown when ip_address and ip_addresses are conflicted",
			inpAnnotMap: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["192.168.0.5/24"],"mac_address":"0a:58:fd:98:00:01","ip_address":"192.168.0.11/24"}}`},
			errMatch:    fmt.Errorf("bad annotation data (ip_address and ip_addresses conflict)"),
		},
		{
			desc:        "verify error thrown when failed to parse pod IP",
			inpAnnotMap: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["192.168.0./24"],"mac_address":"0a:58:fd:98:00:01","ip_address":"192.168.0./24"}}`},
			errMatch:    fmt.Errorf("failed to parse pod IP"),
		},
		{
			desc:        "verify error thrown when gateway_ip and gateway_ips are conflicted",
			inpAnnotMap: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["192.168.0.5/24"],"gateway_ips":["192.168.0.1"], "gateway_ip":"192.168.1.1","mac_address":"0a:58:fd:98:00:01","ip_address":"192.168.0.5/24"}}`},
			errMatch:    fmt.Errorf("bad annotation data (gateway_ip and gateway_ips conflict)"),
		},
		{
			desc:        "test path when gateway_ips list is empty but gateway_ip is present",
			inpAnnotMap: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["192.168.0.5/24"],"gateway_ips":[], "gateway_ip":"192.168.0.1","mac_address":"0a:58:fd:98:00:01","ip_address":"192.168.0.5/24"}}`},
		},
		{
			desc:        "verify error thrown when failed to parse pod gateway",
			inpAnnotMap: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["192.168.0.5/24"],"gateway_ips":["192.168.0."], "gateway_ip":"192.168.0.","mac_address":"0a:58:fd:98:00:01","ip_address":"192.168.0.5/24"}}`},
			errMatch:    fmt.Errorf("failed to parse pod gateway"),
		},
		{
			desc:        "verify error thrown when failed to parse pod route destination",
			inpAnnotMap: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["192.168.0.5/24"],"mac_address":"0a:58:fd:98:00:01","gateway_ips":["192.168.0.1"],"routes":[{"dest":"192.168.1./24"}],"ip_address":"192.168.0.5/24","gateway_ip":"192.168.0.1"}}`},
			errMatch:    fmt.Errorf("failed to parse pod route dest"),
		},
		{
			desc:        "verify error thrown when default Route not specified as gateway",
			inpAnnotMap: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["192.168.0.5/24"],"mac_address":"0a:58:fd:98:00:01","gateway_ips":["192.168.0.1"],"routes":[{"dest":"0.0.0.0/0"}],"ip_address":"192.168.0.5/24","gateway_ip":"192.168.0.1"}}`},
			errAssert:   true,
		},
		{
			desc:        "verify error thrown when failed to parse pod route next hop",
			inpAnnotMap: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["192.168.0.5/24"],"mac_address":"0a:58:fd:98:00:01","gateway_ips":["192.168.0.1"],"routes":[{"dest":"192.168.1.0/24","nextHop":"192.168.1."}],"ip_address":"192.168.0.5/24","gateway_ip":"192.168.0.1"}}`},
			errMatch:    fmt.Errorf("failed to parse pod route next hop"),
		},
		{
			desc:        "verify error thrown where pod route has next hop of different family",
			inpAnnotMap: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["192.168.0.5/24"],"mac_address":"0a:58:fd:98:00:01","gateway_ips":["192.168.0.1"],"routes":[{"dest":"fd01::1234/64","nextHop":"192.168.1.1"}],"ip_address":"192.168.0.5/24","gateway_ip":"192.168.0.1"}}`},
			errAssert:   true,
		},
		{
			desc:        "verify successful unmarshal of pod annotation",
			inpAnnotMap: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["192.168.0.5/24"],"mac_address":"0a:58:fd:98:00:01","gateway_ips":["192.168.0.1"],"routes":[{"dest":"192.168.1.0/24","nextHop":"192.168.1.1"}],"ip_address":"192.168.0.5/24","gateway_ip":"192.168.0.1"}}`},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res, e := UnmarshalPodAnnotation(tc.inpAnnotMap, types.DefaultNetworkName)
			t.Log(res, e)
			if tc.errAssert {
				assert.Error(t, e)
			} else if tc.errMatch != nil {
				assert.Contains(t, e.Error(), tc.errMatch.Error())
			} else {
				t.Log(res)
				assert.NotNil(t, res)
			}
		})
	}
}

func TestGetAllPodIPs(t *testing.T) {
	tests := []struct {
		desc      string
		inpPod    *v1.Pod
		errAssert bool
		errMatch  error
		outExp    []net.IP
	}{
		// TODO: The function body may need to check that pod input is non-nil to avoid panic ?
		/*{
			desc:	"test when pod input is nil",
			inpPod: nil,
			errExp: true,
		},*/
		{
			desc: "test when pod annotation is non-nil",
			inpPod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["192.168.0.1/24"],"mac_address":"0a:58:fd:98:00:01"}}`},
				},
			},
			outExp: []net.IP{ovntest.MustParseIP("192.168.0.1")},
		},
		{
			desc:     "test when pod.status.PodIP is empty",
			inpPod:   &v1.Pod{},
			errMatch: fmt.Errorf("no pod IPs found on pod"),
		},
		{
			desc: "test when pod.status.PodIP is non-empty",
			inpPod: &v1.Pod{
				Status: v1.PodStatus{
					PodIP: "192.168.1.15",
				},
			},
			outExp: []net.IP{ovntest.MustParseIP("192.168.1.15")},
		},
		{
			desc: "test when pod.status.PodIPs is non-empty",
			inpPod: &v1.Pod{
				Status: v1.PodStatus{
					PodIPs: []v1.PodIP{
						{"192.168.1.15"},
					},
				},
			},
			outExp: []net.IP{ovntest.MustParseIP("192.168.1.15")},
		},
		{
			desc: "test path when an entry in pod.status.PodIPs is malformed",
			inpPod: &v1.Pod{
				Status: v1.PodStatus{
					PodIPs: []v1.PodIP{
						{"192.168.1."},
					},
				},
			},
			outExp: []net.IP{},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res, e := GetAllPodIPs(tc.inpPod)
			t.Log(res, e)
			if tc.errAssert {
				assert.Error(t, e)
			} else if tc.errMatch != nil {
				assert.Contains(t, e.Error(), tc.errMatch.Error())
			} else {
				assert.Equal(t, tc.outExp, res)
			}
		})
	}
}
