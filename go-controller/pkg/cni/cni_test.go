package cni

import (
	"fmt"
	Kube "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	clientgo_mock "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/k8s.io/client-go/kubernetes"
	mock_core_v1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/k8s.io/client-go/kubernetes/typed/core/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"testing"
)

func TestValidateBandwidthIsReasonable(t *testing.T) {
	tests := []struct {
		desc        string
		value       string
		expectedErr bool
		errorMatch  error
	}{
		{
			desc:        "Test code path when value is unreasonably small",
			value:       "0.5k",
			expectedErr: true,
			errorMatch:  fmt.Errorf("resource is unreasonably small (< 1kbit)"),
		},
		{
			desc:        "Test code path when value is unreasonably large",
			value:       "2P",
			expectedErr: true,
			errorMatch:  fmt.Errorf("resource is unreasonably small (< 1kbit)"),
		},
		{
			desc:        "Positive test code path when value is in the correct range",
			value:       "1.2k",
			expectedErr: false,
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			value, err := resource.ParseQuantity(tc.value)
			if err != nil {
				return
			}
			e := validateBandwidthIsReasonable(&value)

			if tc.expectedErr {
				assert.Error(t, e)
			} else {
				assert.Nil(t, e)
			}
		})
	}
}

func TestExtractPodBandwidthResources(t *testing.T) {
	tests := []struct {
		desc         string
		egressValue  string
		ingressValue string
		expectedErr  bool
	}{
		{
			desc:         "Test code path when ingress bandwidth is unreasonably small",
			egressValue:  "2k",
			ingressValue: "0.5k",
			expectedErr:  true,
		},
		{
			desc:         "Test code path when egress bandwidth is unreasonably small",
			egressValue:  "0.5k",
			ingressValue: "2k",
			expectedErr:  true,
		},
		{
			desc:         "Test code path when egress bandwidth is unreasonably large",
			egressValue:  "2P",
			ingressValue: "2k",
			expectedErr:  true,
		},
		{
			desc:         "Test code path when ingress bandwidth is unreasonably large",
			egressValue:  "2k",
			ingressValue: "2P",
			expectedErr:  true,
		},
		{
			desc:         "Positive test code path",
			egressValue:  "2k",
			ingressValue: "2k",
			expectedErr:  false,
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			podAnnotations := make(map[string]string)
			podAnnotations["kubernetes.io/egress-bandwidth"] = tc.egressValue
			podAnnotations["kubernetes.io/ingress-bandwidth"] = tc.ingressValue

			_, _, e := extractPodBandwidthResources(podAnnotations)
			if tc.expectedErr {
				assert.Error(t, e)
			} else {
				assert.Nil(t, e)
			}
		})
	}
}

func TestPodRequest_CmdAdd(t *testing.T) {
	mockIface := new(clientgo_mock.Interface)
	mockCoreIface := new(mock_core_v1.CoreV1Interface)
	mockPodIface := new(mock_core_v1.PodInterface)
	k := &Kube.Kube{KClient: mockIface}

	tests := []struct {
		desc                   string
		podRequest             PodRequest
		expectedErr            bool
		errorMatch             error
		onRetMockInterfaceArgs *ovntest.TestifyMockHelper
		onRetMockCoreArgs      *ovntest.TestifyMockHelper
		onRetMockPodArgs       *ovntest.TestifyMockHelper
	}{
		// {
		// 	desc:        "Negative test code path",
		// 	podRequest:  PodRequest{},
		// 	expectedErr: true,
		// 	errorMatch:  fmt.Errorf("required CNI variable missing"),
		// },
		{
			desc: "Positive test code path",
			podRequest: PodRequest{
				PodNamespace: "some-namespace",
				PodName:      "some-podname",
			},
			expectedErr:            false,
			onRetMockInterfaceArgs: &ovntest.TestifyMockHelper{"CoreV1", []string{}, []interface{}{mockCoreIface}},
			onRetMockCoreArgs:      &ovntest.TestifyMockHelper{"Pods", []string{"string"}, []interface{}{mockPodIface}},
			onRetMockPodArgs:       &ovntest.TestifyMockHelper{"Get", []string{"*context.emptyCtx", "string", "v1.GetOptions"}, []interface{}{&v1.Pod{}, nil}},
			errorMatch:             fmt.Errorf("required CNI variable missing"),
		},
	}
	for i, tc := range tests {

		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			if tc.onRetMockInterfaceArgs != nil {
				mockiFaceCall := mockIface.On(tc.onRetMockInterfaceArgs.OnCallMethodName)
				for _, arg := range tc.onRetMockInterfaceArgs.OnCallMethodArgType {
					mockiFaceCall.Arguments = append(mockiFaceCall.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range tc.onRetMockInterfaceArgs.RetArgList {
					mockiFaceCall.ReturnArguments = append(mockiFaceCall.ReturnArguments, ret)
				}
				mockiFaceCall.Once()
			}

			if tc.onRetMockCoreArgs != nil {
				mockCoreCall := mockCoreIface.On(tc.onRetMockCoreArgs.OnCallMethodName)
				for _, arg := range tc.onRetMockCoreArgs.OnCallMethodArgType {
					mockCoreCall.Arguments = append(mockCoreCall.Arguments, mock.AnythingOfType(arg))
				}
				for _, elem := range tc.onRetMockCoreArgs.RetArgList {
					mockCoreCall.ReturnArguments = append(mockCoreCall.ReturnArguments, elem)
				}
				mockCoreCall.Once()
			}

			if tc.onRetMockPodArgs != nil {
				mockPodCall := mockPodIface.On(tc.onRetMockPodArgs.OnCallMethodName)
				for _, arg := range tc.onRetMockPodArgs.OnCallMethodArgType {
					mockPodCall.Arguments = append(mockPodCall.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range tc.onRetMockPodArgs.RetArgList {
					mockPodCall.ReturnArguments = append(mockPodCall.ReturnArguments, ret)
				}
				mockPodCall.Once()
			}
			_, e := tc.podRequest.cmdAdd(k.KClient)

			if tc.expectedErr {
				assert.Error(t, e)
			} else {
				assert.Nil(t, e)
			}

			mockIface.AssertExpectations(t)
			mockCoreIface.AssertExpectations(t)
			mockPodIface.AssertExpectations(t)

		})
	}
}

func TestHandleCNIRequest(t *testing.T) {
	mockInterface := new(clientgo_mock.Interface)
	tests := []struct {
		desc        string
		podRequest  *PodRequest
		expectedErr bool
		errorMatch  error
		onRetArgs   *ovntest.TestifyMockHelper
	}{
		{
			desc: "Negative test test code path",
			podRequest: &PodRequest{
				Command: "ADD",
			},
			expectedErr: true,
			errorMatch:  fmt.Errorf("required CNI variable missing"),
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			if tc.onRetArgs != nil {
				call := mockInterface.On(tc.onRetArgs.OnCallMethodName)
				for _, arg := range tc.onRetArgs.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, elem := range tc.onRetArgs.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, elem)
				}
				call.Once()
			}
			_, e := HandleCNIRequest(tc.podRequest, mockInterface)

			if tc.expectedErr {
				assert.Error(t, e)
			} else {
				assert.Nil(t, e)
			}
			mockInterface.AssertExpectations(t)
		})
	}
}

func TestPodRequest_GetCNIResult(t *testing.T) {
	tests := []struct {
		desc        string
		req         PodRequest
		expectedErr bool
		errorMatch  error
	}{
		{
			desc: "Positive test test code path",
			req: PodRequest{
				PodNamespace: "Podnamespace",
				PodName:      "PodName",
			},
			expectedErr: true,
			errorMatch:  fmt.Errorf("required CNI variable missing"),
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			PodInterfaceInfo := &PodInterfaceInfo{}
			_, e := tc.req.getCNIResult(PodInterfaceInfo)
			if tc.expectedErr {
				assert.Error(t, e)
			} else {
				assert.Nil(t, e)
			}
		})
	}
}
