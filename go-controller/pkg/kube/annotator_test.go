package kube

import (
	"fmt"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	mock_clientgo_iface "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/k8s.io/client-go/kubernetes"
	mock_core_v1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/k8s.io/client-go/kubernetes/typed/core/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	v1 "k8s.io/api/core/v1"
	"testing"
)

func supportfailfnImpl(obj interface{}, key string, val interface{}) {
	// Do nothing as it does not return anything
}

func TestNewNodeAnnotator(t *testing.T) {
	node := &v1.Node{}
	//Kube defined in kube.go
	k := &Kube{}
	tests := []struct {
		desc string
	}{
		{
			desc: "Positive test code path, returns a new node annotator",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			e := NewNodeAnnotator(k, node)

			assert.NotNil(t, e)
		})
	}
}

func TestNodeAnnotator_Set(t *testing.T) {
	nodeAnnotator := nodeAnnotator{}
	nodeAnnotator.changes = make(map[string]*action)
	tests := []struct {
		desc string
		val  interface{}
	}{
		{
			desc: "Positive test code path",
			val:  "annotations",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			e := nodeAnnotator.Set("key", tc.val)

			assert.Nil(t, e)
		})
	}
}

func TestNodeAnnotator_SetWithFailureHandler(t *testing.T) {
	nodeAnnotator := nodeAnnotator{}
	nodeAnnotator.changes = make(map[string]*action)
	tests := []struct {
		desc string
		val  interface{}
	}{
		{
			desc: "Test code path when annotations is Nil",
			val:  nil,
		},
		{
			desc: "Test code path; annotations is not of type string",
			val:  map[string]string{},
		},
		{
			desc: "Test code path; annotations is string",
			val:  "annotations",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			e := nodeAnnotator.SetWithFailureHandler("key", tc.val, nil)

			assert.Nil(t, e)
		})
	}
}

func TestNodeAnnotator_Delete(t *testing.T) {
	nodeAnnotator := nodeAnnotator{}
	nodeAnnotator.changes = make(map[string]*action)
	tests := []struct {
		desc string
		key  string
	}{
		{
			desc: "Positive test code path",
			key:  "key",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			nodeAnnotator.Delete(tc.key)

		})
	}
}

func TestNodeAnnotator_Run(t *testing.T) {
	mockIface := new(mock_clientgo_iface.Interface)
	mockCoreIface := new(mock_core_v1.CoreV1Interface)
	mockNodeIface := new(mock_core_v1.NodeInterface)
	nodeAnnotator := nodeAnnotator{}
	nodeAnnotator.kube = &Kube{KClient: mockIface}
	nodeAnnotator.changes = make(map[string]*action)
	nodeAnnotator.node = &v1.Node{}
	nodeAnnotator.node.Annotations = make(map[string]string)
	nodeAnnotator.node.Annotations["key"] = ""
	tests := []struct {
		desc                   string
		expectedErr            error
		onRetMockInterfaceArgs *ovntest.TestifyMockHelper
		onRetMockCoreArgs      *ovntest.TestifyMockHelper
		onRetMockNodeArgs      *ovntest.TestifyMockHelper
		act                    *action
	}{
		{
			desc:        "Test code path when length of annotations is zero",
			expectedErr: nil,
		},
		{
			desc:                   "Positive test code path",
			expectedErr:            nil,
			onRetMockInterfaceArgs: &ovntest.TestifyMockHelper{"CoreV1", []string{}, []interface{}{mockCoreIface}},
			onRetMockCoreArgs:      &ovntest.TestifyMockHelper{"Nodes", []string{"string"}, []interface{}{mockNodeIface}},
			onRetMockNodeArgs:      &ovntest.TestifyMockHelper{"Patch", []string{"*context.emptyCtx", "string", "types.PatchType", "[]uint8", "v1.PatchOptions"}, []interface{}{nil, nil}},
			act:                    &action{key: "key", origVal: "val"},
		},
		{
			desc:                   "Test code path when origVal is nil",
			expectedErr:            nil,
			onRetMockInterfaceArgs: &ovntest.TestifyMockHelper{"CoreV1", []string{}, []interface{}{mockCoreIface}},
			onRetMockCoreArgs:      &ovntest.TestifyMockHelper{"Nodes", []string{"string"}, []interface{}{mockNodeIface}},
			onRetMockNodeArgs:      &ovntest.TestifyMockHelper{"Patch", []string{"*context.emptyCtx", "string", "types.PatchType", "[]uint8", "v1.PatchOptions"}, []interface{}{nil, nil}},
			act:                    &action{key: "key"},
		},
		{
			desc:                   "Negative test code path",
			expectedErr:            fmt.Errorf("mock Error: Failed to run SetAnnotationsOnNode"),
			onRetMockInterfaceArgs: &ovntest.TestifyMockHelper{"CoreV1", []string{}, []interface{}{mockCoreIface}},
			onRetMockCoreArgs:      &ovntest.TestifyMockHelper{"Nodes", []string{"string"}, []interface{}{mockNodeIface}},
			onRetMockNodeArgs:      &ovntest.TestifyMockHelper{"Patch", []string{"*context.emptyCtx", "string", "types.PatchType", "[]uint8", "v1.PatchOptions"}, []interface{}{nil, fmt.Errorf("mock Error: Failed to run SetAnnotationsOnNode")}},
		},
		{
			desc:                   "Negative test code path",
			expectedErr:            fmt.Errorf("mock Error: Failed to run SetAnnotationsOnNode"),
			onRetMockInterfaceArgs: &ovntest.TestifyMockHelper{"CoreV1", []string{}, []interface{}{mockCoreIface}},
			onRetMockCoreArgs:      &ovntest.TestifyMockHelper{"Nodes", []string{"string"}, []interface{}{mockNodeIface}},
			onRetMockNodeArgs:      &ovntest.TestifyMockHelper{"Patch", []string{"*context.emptyCtx", "string", "types.PatchType", "[]uint8", "v1.PatchOptions"}, []interface{}{nil, fmt.Errorf("mock Error: Failed to run SetAnnotationsOnNode")}},
			act:                    &action{key: "key", origVal: "val", failFn: supportfailfnImpl},
		},
	}
	for i, tc := range tests {

		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			if tc.act != nil {
				nodeAnnotator.changes[""] = tc.act
			}

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

			if tc.onRetMockNodeArgs != nil {
				mockPodCall := mockNodeIface.On(tc.onRetMockNodeArgs.OnCallMethodName)
				for _, arg := range tc.onRetMockNodeArgs.OnCallMethodArgType {
					mockPodCall.Arguments = append(mockPodCall.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range tc.onRetMockNodeArgs.RetArgList {
					mockPodCall.ReturnArguments = append(mockPodCall.ReturnArguments, ret)
				}
				mockPodCall.Once()
			}

			e := nodeAnnotator.Run()

			if tc.expectedErr != nil {
				assert.Error(t, e)
			} else {
				assert.Nil(t, e)
			}

			mockIface.AssertExpectations(t)
			mockCoreIface.AssertExpectations(t)
			mockNodeIface.AssertExpectations(t)

		})
	}
}

func TestNewPodAnnotator(t *testing.T) {
	pod := &v1.Pod{}
	//Kube defined in kube.go
	k := &Kube{}
	tests := []struct {
		desc string
	}{
		{
			desc: "Positive test code path, returns a new pod annotator",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			e := NewPodAnnotator(k, pod)

			assert.NotNil(t, e)
		})
	}
}

func TestPodAnnotator_Set(t *testing.T) {
	podAnnotator := podAnnotator{}
	podAnnotator.changes = make(map[string]*action)
	tests := []struct {
		desc string
		val  interface{}
	}{
		{
			desc: "Positive test code path",
			val:  "annotations",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			e := podAnnotator.Set("key", tc.val)

			assert.Nil(t, e)
		})
	}
}

func TestPodAnnotator_SetWithFailureHandler(t *testing.T) {
	podAnnotator := podAnnotator{}
	podAnnotator.changes = make(map[string]*action)
	tests := []struct {
		desc string
		val  interface{}
	}{
		{
			desc: "Test code path when annotations is Nil",
			val:  nil,
		},
		{
			desc: "Test code path when annotations is not Nil",
			val:  map[string]string{},
		},
		{
			desc: "Test code path when annotations is string",
			val:  "annotations",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			e := podAnnotator.SetWithFailureHandler("key", tc.val, nil)

			assert.Nil(t, e)
		})
	}
}

func TestPodAnnotator_Delete(t *testing.T) {
	podAnnotator := podAnnotator{}
	podAnnotator.changes = make(map[string]*action)
	tests := []struct {
		desc string
		key  string
	}{
		{
			desc: "Positive test code path",
			key:  "key",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			podAnnotator.Delete(tc.key)

		})
	}
}

func TestPodAnnotator_Run(t *testing.T) {
	mockIface := new(mock_clientgo_iface.Interface)
	mockCoreIface := new(mock_core_v1.CoreV1Interface)
	mockPodIface := new(mock_core_v1.PodInterface)
	podAnnotator := podAnnotator{}
	podAnnotator.kube = &Kube{KClient: mockIface}
	podAnnotator.changes = make(map[string]*action)
	podAnnotator.pod = &v1.Pod{}
	podAnnotator.pod.Annotations = make(map[string]string)
	podAnnotator.pod.Annotations["key"] = ""
	tests := []struct {
		desc                   string
		errorMatch             error
		onRetMockInterfaceArgs *ovntest.TestifyMockHelper
		onRetMockCoreArgs      *ovntest.TestifyMockHelper
		onRetMockPodArgs       *ovntest.TestifyMockHelper
		act                    *action
	}{
		{
			desc:       "Test code path when length of annotations is zero",
			errorMatch: nil,
		},
		{
			desc:                   "Positive test code path",
			errorMatch:             nil,
			onRetMockInterfaceArgs: &ovntest.TestifyMockHelper{"CoreV1", []string{}, []interface{}{mockCoreIface}},
			onRetMockCoreArgs:      &ovntest.TestifyMockHelper{"Pods", []string{"string"}, []interface{}{mockPodIface}},
			onRetMockPodArgs:       &ovntest.TestifyMockHelper{"Patch", []string{"*context.emptyCtx", "string", "types.PatchType", "[]uint8", "v1.PatchOptions"}, []interface{}{nil, nil}},
			act:                    &action{key: "key", origVal: "val"},
		},
		{
			desc:                   "Test code path when origVal is nil",
			errorMatch:             nil,
			onRetMockInterfaceArgs: &ovntest.TestifyMockHelper{"CoreV1", []string{}, []interface{}{mockCoreIface}},
			onRetMockCoreArgs:      &ovntest.TestifyMockHelper{"Pods", []string{"string"}, []interface{}{mockPodIface}},
			onRetMockPodArgs:       &ovntest.TestifyMockHelper{"Patch", []string{"*context.emptyCtx", "string", "types.PatchType", "[]uint8", "v1.PatchOptions"}, []interface{}{nil, nil}},
			act:                    &action{key: "key"},
		},
		{
			desc:                   "Negative test code path",
			errorMatch:             fmt.Errorf("mock Error: Failed to run SetAnnotationsOnPod"),
			onRetMockInterfaceArgs: &ovntest.TestifyMockHelper{"CoreV1", []string{}, []interface{}{mockCoreIface}},
			onRetMockCoreArgs:      &ovntest.TestifyMockHelper{"Pods", []string{"string"}, []interface{}{mockPodIface}},
			onRetMockPodArgs:       &ovntest.TestifyMockHelper{"Patch", []string{"*context.emptyCtx", "string", "types.PatchType", "[]uint8", "v1.PatchOptions"}, []interface{}{nil, fmt.Errorf("mock Error: Failed to run SetAnnotationsOnPod")}},
			act:                    &action{key: "key", origVal: "val"},
		},
		{
			desc:                   "Negative test code path and failFn not nil",
			errorMatch:             fmt.Errorf("mock Error: Failed to run SetAnnotationsOnPod"),
			onRetMockInterfaceArgs: &ovntest.TestifyMockHelper{"CoreV1", []string{}, []interface{}{mockCoreIface}},
			onRetMockCoreArgs:      &ovntest.TestifyMockHelper{"Pods", []string{"string"}, []interface{}{mockPodIface}},
			onRetMockPodArgs:       &ovntest.TestifyMockHelper{"Patch", []string{"*context.emptyCtx", "string", "types.PatchType", "[]uint8", "v1.PatchOptions"}, []interface{}{nil, fmt.Errorf("mock Error: Failed to run SetAnnotationsOnPod")}},
			act:                    &action{key: "key", origVal: "val", failFn: supportfailfnImpl},
		},
	}
	for i, tc := range tests {

		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			if tc.act != nil {
				podAnnotator.changes[""] = tc.act
			}

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

			e := podAnnotator.Run()

			if tc.errorMatch != nil {
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

func TestNewNamespaceAnnotator(t *testing.T) {
	namespace := &v1.Namespace{}
	//Kube defined in kube.go
	k := &Kube{}
	tests := []struct {
		desc string
	}{
		{
			desc: "Positive test code path, returns a new Namespace annotator",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			e := NewNamespaceAnnotator(k, namespace)

			assert.NotNil(t, e)
		})
	}
}

func TestNamespaceAnnotator_Set(t *testing.T) {
	namespaceAnnotator := namespaceAnnotator{}
	namespaceAnnotator.changes = make(map[string]*action)
	tests := []struct {
		desc string
		val  interface{}
	}{
		{
			desc: "Positive test code path",
			val:  "annotations",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			e := namespaceAnnotator.Set("key", tc.val)

			assert.Nil(t, e)
		})
	}
}

func TestNamespaceAnnotator_SetWithFailureHandler(t *testing.T) {
	namespaceAnnotator := namespaceAnnotator{}
	namespaceAnnotator.changes = make(map[string]*action)
	tests := []struct {
		desc string
		val  interface{}
	}{
		{
			desc: "Test code path when annotations is Nil",
			val:  nil,
		},
		{
			desc: "Test code path when annotations is not Nil",
			val:  map[string]string{"k8s.ovn.org/node-mgmt-port-mac-address": "96:8f:e8:25:a2:e5"},
		},
		{
			desc: "Test code path when annotations is string",
			val:  "annotations",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			e := namespaceAnnotator.SetWithFailureHandler("key", tc.val, nil)

			assert.Nil(t, e)
		})
	}
}

func TestNameespaceAnnotator_Delete(t *testing.T) {
	namespaceAnnotator := namespaceAnnotator{}
	namespaceAnnotator.changes = make(map[string]*action)
	tests := []struct {
		desc string
		key  string
	}{
		{
			desc: "Positive test code path",
			key:  "key",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			namespaceAnnotator.Delete(tc.key)

		})
	}
}

func TestNamespaceAnnotator_Run(t *testing.T) {
	mockIface := new(mock_clientgo_iface.Interface)
	mockCoreIface := new(mock_core_v1.CoreV1Interface)
	mockNameSpaceIface := new(mock_core_v1.NamespaceInterface)
	namespaceAnnotator := namespaceAnnotator{}
	namespaceAnnotator.kube = &Kube{KClient: mockIface}
	namespaceAnnotator.changes = make(map[string]*action)
	namespaceAnnotator.namespace = &v1.Namespace{}
	namespaceAnnotator.namespace.Annotations = make(map[string]string)
	namespaceAnnotator.namespace.Annotations["key"] = ""
	tests := []struct {
		desc                   string
		errorMatch             error
		onRetMockInterfaceArgs *ovntest.TestifyMockHelper
		onRetMockCoreArgs      *ovntest.TestifyMockHelper
		onRetMockNamespaceArgs *ovntest.TestifyMockHelper
		act                    *action
	}{
		{
			desc:       "Test code path when length of annotations is zero",
			errorMatch: nil,
		},
		{
			desc:                   "Positive test code path",
			errorMatch:             nil,
			onRetMockInterfaceArgs: &ovntest.TestifyMockHelper{"CoreV1", []string{}, []interface{}{mockCoreIface}},
			onRetMockCoreArgs:      &ovntest.TestifyMockHelper{"Namespaces", []string{"string"}, []interface{}{mockNameSpaceIface}},
			onRetMockNamespaceArgs: &ovntest.TestifyMockHelper{"Patch", []string{"*context.emptyCtx", "string", "types.PatchType", "[]uint8", "v1.PatchOptions"}, []interface{}{nil, nil}},
			act:                    &action{key: "key", origVal: "val"},
		},
		{
			desc:                   "Test code path when origVal is nil",
			errorMatch:             nil,
			onRetMockInterfaceArgs: &ovntest.TestifyMockHelper{"CoreV1", []string{}, []interface{}{mockCoreIface}},
			onRetMockCoreArgs:      &ovntest.TestifyMockHelper{"Namespaces", []string{"string"}, []interface{}{mockNameSpaceIface}},
			onRetMockNamespaceArgs: &ovntest.TestifyMockHelper{"Patch", []string{"*context.emptyCtx", "string", "types.PatchType", "[]uint8", "v1.PatchOptions"}, []interface{}{nil, nil}},
			act:                    &action{key: "key"},
		},
		{
			desc:                   "Negative test code path for setannotationsonNamespace",
			errorMatch:             fmt.Errorf("mock Error: Failed to run SetAnnotationsOnNamespacces"),
			onRetMockInterfaceArgs: &ovntest.TestifyMockHelper{"CoreV1", []string{}, []interface{}{mockCoreIface}},
			onRetMockCoreArgs:      &ovntest.TestifyMockHelper{"Namespaces", []string{"string"}, []interface{}{mockNameSpaceIface}},
			onRetMockNamespaceArgs: &ovntest.TestifyMockHelper{"Patch", []string{"*context.emptyCtx", "string", "types.PatchType", "[]uint8", "v1.PatchOptions"}, []interface{}{nil, fmt.Errorf("mock Error: Failed to run SetAnnotationsOnNamespacces")}},
			act:                    &action{key: "key", origVal: "val"},
		},
		{
			desc:                   "Negative test code path for setannotationsonNamespace and failFn not nil",
			errorMatch:             fmt.Errorf("mock Error: Failed to run SetAnnotationsOnNamespacces"),
			onRetMockInterfaceArgs: &ovntest.TestifyMockHelper{"CoreV1", []string{}, []interface{}{mockCoreIface}},
			onRetMockCoreArgs:      &ovntest.TestifyMockHelper{"Namespaces", []string{"string"}, []interface{}{mockNameSpaceIface}},
			onRetMockNamespaceArgs: &ovntest.TestifyMockHelper{"Patch", []string{"*context.emptyCtx", "string", "types.PatchType", "[]uint8", "v1.PatchOptions"}, []interface{}{nil, fmt.Errorf("mock Error: Failed to run SetAnnotationsOnNamespacces")}},
			act:                    &action{key: "key", origVal: "val", failFn: supportfailfnImpl},
		},
	}
	for i, tc := range tests {

		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			if tc.act != nil {
				namespaceAnnotator.changes[""] = tc.act
			}

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

			if tc.onRetMockNamespaceArgs != nil {
				mockPodCall := mockNameSpaceIface.On(tc.onRetMockNamespaceArgs.OnCallMethodName)
				for _, arg := range tc.onRetMockNamespaceArgs.OnCallMethodArgType {
					mockPodCall.Arguments = append(mockPodCall.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range tc.onRetMockNamespaceArgs.RetArgList {
					mockPodCall.ReturnArguments = append(mockPodCall.ReturnArguments, ret)
				}
				mockPodCall.Once()
			}

			e := namespaceAnnotator.Run()

			if tc.errorMatch != nil {
				assert.Error(t, e)
			} else {
				assert.Nil(t, e)
			}

			mockIface.AssertExpectations(t)
			mockCoreIface.AssertExpectations(t)
			mockNameSpaceIface.AssertExpectations(t)

		})
	}
}
