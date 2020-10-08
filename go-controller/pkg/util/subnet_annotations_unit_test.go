package util

import (
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCreateSubnetAnnotation(t *testing.T) {
	// TODO: test has to be enhanced to compare outputs in a future iteration
	tests := []struct {
		desc              string
		inpAnnotName      string
		inpDefaultSubnets []string
		expectedErr       bool
	}{
		{
			desc:              "non-zero length annotation name and subnet list size of ONE provided as input",
			inpAnnotName:      ovnNodeSubnets,
			inpDefaultSubnets: []string{"192.168.1.12/24"},
		},
		{
			desc:              "empty annotation name provided as input",
			inpAnnotName:      "",
			inpDefaultSubnets: []string{"192.168.1.12/24"},
		},
		{
			desc:              "non-zero length annotation name and subnet list size greater than ONE provided as input",
			inpAnnotName:      ovnNodeSubnets,
			inpDefaultSubnets: []string{"192.168.1.12/24", "fd02:0:0:2::2895/64"},
		},
		{
			desc:              "subnet list of size 0 provided as input",
			inpAnnotName:      ovnNodeSubnets,
			inpDefaultSubnets: []string{},
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			var defSubList []*net.IPNet
			for _, item := range tc.inpDefaultSubnets {
				_, ipnet, err := net.ParseCIDR(item)
				if err != nil {
					t.Fail()
				}
				defSubList = append(defSubList, ipnet)
			}
			mapRes, e := createSubnetAnnotation(tc.inpAnnotName, defSubList)
			if tc.expectedErr {
				assert.Error(t, e)
			}
			t.Log(mapRes[tc.inpAnnotName], e)
		})
	}
}

func TestSetSubnetAnnotation(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(&v1.NodeList{})
	k := &kube.Kube{KClient: fakeClient}
	testAnnotator := kube.NewNodeAnnotator(k, &v1.Node{})
	tests := []struct {
		desc             string
		inpNodeAnnotator kube.Annotator
		inpAnnotName     string
		inpDefSubnetIps  []*net.IPNet
		errExp           bool
	}{
		{
			desc:             "tests function coverage, success path",
			inpNodeAnnotator: testAnnotator,
			inpAnnotName:     ovnNodeSubnets,
			inpDefSubnetIps:  ovntest.MustParseIPNets("192.168.1.12/24"),
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			err := setSubnetAnnotation(tc.inpNodeAnnotator, tc.inpAnnotName, tc.inpDefSubnetIps)
			t.Log(err)
			if tc.errExp {
				assert.NotNil(t, err)
			}
		})
	}
}

func TestParseSubnetAnnotation(t *testing.T) {
	tests := []struct {
		desc        string
		inpNode     v1.Node
		annName     string
		errExpected bool
	}{
		{
			desc:        "incorrect annotation",
			annName:     "blah",
			errExpected: true,
			inpNode: v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testNode",
					Annotations: map[string]string{
						"k8s.ovn.org/node-subnets": "{\"default\":\"10.244.0.0/24\"}",
					},
				},
			},
		},
		{
			desc:    "correct annotation with one subnet",
			annName: ovnNodeSubnets,
			inpNode: v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testNode",
					Annotations: map[string]string{
						"k8s.ovn.org/node-subnets": "{\"default\":\"10.244.0.0/24\"}",
					},
				},
			},
		},
		{
			desc:    "parse as dual-stack",
			annName: ovnNodeSubnets,
			inpNode: v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testNode",
					Annotations: map[string]string{
						"k8s.ovn.org/node-subnets": "{\"default\": [\"10.244.0.0/24\", \"fd02:0:0:2::2895/64\"]}",
					},
				},
			},
		},
		{
			desc:        "error:cannot parse as single or dual stack",
			annName:     ovnNodeSubnets,
			errExpected: true,
			inpNode: v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testNode",
					Annotations: map[string]string{
						"k8s.ovn.org/node-subnets": "{\"default\": [\"10.244.0.0/24\", \"\"fd02:0:0:2::2895/64\"]}", //added the extra \" in front of fd02: to cause json.Unmarshal error
					},
				},
			},
		},
		{
			desc:        "error:annotation has no default network",
			annName:     ovnNodeSubnets,
			errExpected: true,
			inpNode: v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testNode",
					Annotations: map[string]string{
						"k8s.ovn.org/node-subnets": "{}",
					},
				},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			ipList, e := parseSubnetAnnotation(tc.inpNode.Annotations, tc.annName)
			if tc.errExpected {
				t.Log(e)
				assert.Error(t, e)
			} else {
				t.Log(ipList)
				assert.Greater(t, len(ipList), 0)
			}
		})
	}
}

func TestCreateNodeHostSubnetAnnotation(t *testing.T) {
	tests := []struct {
		desc            string
		inpDefSubnetIps []*net.IPNet
		outExp          map[string]string
		errExp          bool
	}{
		{
			desc:            "success path, valid default subnets",
			inpDefSubnetIps: ovntest.MustParseIPNets("192.168.1.12/24"),
			outExp: map[string]string{
				"k8s.ovn.org/node-subnets": "{\"default\":[\"192.168.1.12/24\"]}",
			},
		},
		{
			desc:   "success path, inpDefSubnetIps is nil",
			outExp: map[string]string{},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res := map[string]string{}
			err := UpdateNodeHostSubnetAnnotation(res, tc.inpDefSubnetIps, types.DefaultNetworkName)
			t.Log(res, err)
			if tc.errExp {
				assert.NotNil(t, err)
			} else {
				assert.True(t, reflect.DeepEqual(res, tc.outExp))
			}
		})
	}
}

func TestSetNodeHostSubnetAnnotation(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(&v1.NodeList{})
	k := &kube.Kube{KClient: fakeClient}
	testAnnotator := kube.NewNodeAnnotator(k, &v1.Node{})

	tests := []struct {
		desc             string
		inpNodeAnnotator kube.Annotator
		inpDefSubnetIps  []*net.IPNet
		errExp           bool
	}{
		{
			desc:             "tests function coverage, success path",
			inpNodeAnnotator: testAnnotator,
			inpDefSubnetIps:  ovntest.MustParseIPNets("192.168.1.12/24"),
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			err := SetNodeHostSubnetAnnotation(tc.inpNodeAnnotator, tc.inpDefSubnetIps)
			t.Log(err)
			if tc.errExp {
				assert.NotNil(t, err)
			}
		})
	}
}

func TestDeleteNodeHostSubnetAnnotation(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(&v1.NodeList{})
	k := &kube.Kube{KClient: fakeClient}
	testAnnotator := kube.NewNodeAnnotator(k, &v1.Node{})

	tests := []struct {
		desc             string
		inpNodeAnnotator kube.Annotator
	}{
		{
			desc:             "function code coverage",
			inpNodeAnnotator: testAnnotator,
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			DeleteNodeHostSubnetAnnotation(tc.inpNodeAnnotator, types.DefaultNetworkName)
		})
	}
}

func TestParseNodeHostSubnetAnnotation(t *testing.T) {
	tests := []struct {
		desc    string
		inpNode v1.Node
		errExp  bool
	}{
		{
			desc: "tests function coverage, success path",
			inpNode: v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testNode",
					Annotations: map[string]string{
						"k8s.ovn.org/node-subnets": "{\"default\":\"10.244.0.0/24\"}",
					},
				},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res, err := ParseNodeHostSubnetAnnotation(&tc.inpNode, types.DefaultNetworkName)
			t.Log(res, err)
			if tc.errExp {
				assert.NotNil(t, err)
			} else {
				assert.NotNil(t, res)
			}
		})
	}
}

func TestCreateNodeLocalNatAnnotation(t *testing.T) {
	tests := []struct {
		desc      string
		inpIPList []net.IP
		expOutput map[string]interface{}
	}{
		{
			desc:      "empty IP List",
			inpIPList: ovntest.MustParseIPs(),
			expOutput: map[string]interface{}{
				"k8s.ovn.org/node-local-nat-ip": `{"default":[]}`,
			},
		},
		{
			desc:      "valid IP list",
			inpIPList: ovntest.MustParseIPs("192.168.1.25", "10.168.12.5"),
			expOutput: map[string]interface{}{
				"k8s.ovn.org/node-local-nat-ip": `{"default":["192.168.1.25","10.168.12.5"]}`,
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res, err := CreateNodeLocalNatAnnotation(tc.inpIPList)
			t.Log(res, err)
			assert.Equal(t, tc.expOutput, res)
		})
	}
}

func TestSetNodeLocalNatAnnotation(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(&v1.NodeList{})
	k := &kube.Kube{KClient: fakeClient}
	testAnnotator := kube.NewNodeAnnotator(k, &v1.Node{})
	tests := []struct {
		desc             string
		inpNodeAnnotator kube.Annotator
		inpLocalNatIPs   []net.IP
		errExp           bool
	}{
		// Note: error path unit test not applicable as CreateNodeLocalNatAnnotation returns error only when there is json.Marshal error
		{
			desc:             "test function success path",
			inpNodeAnnotator: testAnnotator,
			inpLocalNatIPs:   ovntest.MustParseIPs("192.168.1.3"),
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			err := SetNodeLocalNatAnnotation(tc.inpNodeAnnotator, tc.inpLocalNatIPs)
			t.Log(err)
			if tc.errExp {
				assert.Error(t, err)
			}
		})
	}
}

func TestParseNodeLocalNatIPAnnotation(t *testing.T) {
	tests := []struct {
		desc      string
		inpNode   v1.Node
		expOutput []net.IP
		expErr    bool
	}{
		{
			desc:      "k8s.ovn.org/node-local-nat-ip annotation missing on the node",
			inpNode:   v1.Node{},
			expOutput: nil,
			expErr:    true,
		},
		{
			desc: "annotation not parseable as value not in list format",
			inpNode: v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testNode",
					Annotations: map[string]string{
						"k8s.ovn.org/node-local-nat-ip": `{"default":"10.244.0.0"}`,
					},
				},
			},
		},
		{
			desc: "key `default` is NOT in node annotation i.e default network missing",
			inpNode: v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testNode",
					Annotations: map[string]string{
						"k8s.ovn.org/node-local-nat-ip": `{"blah":["10.244.0.0"]}`,
					},
				},
			},
		},
		{
			desc: "annotation with invalid value for default network",
			inpNode: v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testNode",
					Annotations: map[string]string{
						"k8s.ovn.org/node-local-nat-ip": `{"default":["10.244.0.0/24"]}`,
					},
				},
			},
		},
		{
			desc: "correct annotation with valid values",
			inpNode: v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testNode",
					Annotations: map[string]string{
						"k8s.ovn.org/node-local-nat-ip": `{"default":["10.244.0.0"]}`,
					},
				},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			res, err := ParseNodeLocalNatIPAnnotation(&tc.inpNode)
			t.Log(res, err)
		})
	}
}
