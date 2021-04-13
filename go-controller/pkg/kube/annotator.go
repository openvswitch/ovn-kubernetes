package kube

import (
	"encoding/json"
	"fmt"
	"reflect"

	kapi "k8s.io/api/core/v1"
)

// Annotator represents the exported methods for handling node annotations
type Annotator interface {
	Set(key string, value interface{}) error
	Delete(key string)
	Run() error
}

type action struct {
	key     string
	val     string
	origVal interface{}
}

type nodeAnnotator struct {
	kube Interface
	node *kapi.Node

	changes map[string]*action
}

// NewNodeAnnotator returns a new annotator for Node objects
func NewNodeAnnotator(kube Interface, node *kapi.Node) Annotator {
	return &nodeAnnotator{
		kube:    kube,
		node:    node,
		changes: make(map[string]*action),
	}
}

func (na *nodeAnnotator) Set(key string, val interface{}) error {
	act := &action{
		key:     key,
		origVal: val,
	}
	if val != nil {
		// Annotations must be either a valid string value or nil; coerce
		// any non-empty values to string
		if reflect.TypeOf(val).Kind() == reflect.String {
			act.val = val.(string)
		} else {
			bytes, err := json.Marshal(val)
			if err != nil {
				return fmt.Errorf("failed to marshal %q value %v to string: %v", key, val, err)
			}
			act.val = string(bytes)
		}
	}
	na.changes[key] = act
	return nil
}

func (na *nodeAnnotator) Delete(key string) {
	na.changes[key] = &action{key: key}
}

func (na *nodeAnnotator) Run() error {
	annotations := make(map[string]interface{})
	for k, act := range na.changes {
		// Ignore annotations that already exist with the same value
		if existing, ok := na.node.Annotations[k]; existing != act.val || !ok {
			if act.origVal != nil {
				// Annotation should be updated to new value
				annotations[k] = act.val
			} else {
				// Annotation should be deleted
				annotations[k] = nil
			}
		}
	}
	if len(annotations) == 0 {
		return nil
	}

	return na.kube.SetAnnotationsOnNode(na.node, annotations)
}

// NewPodAnnotator returns a new annotator for Pod objects
func NewPodAnnotator(kube Interface, pod *kapi.Pod) Annotator {
	return &podAnnotator{
		kube:    kube,
		pod:     pod,
		changes: make(map[string]*action),
	}
}

type podAnnotator struct {
	kube Interface
	pod  *kapi.Pod

	changes map[string]*action
}

func (pa *podAnnotator) Set(key string, val interface{}) error {
	act := &action{
		key:     key,
		origVal: val,
	}
	if val != nil {
		// Annotations must be either a valid string value or nil; coerce
		// any non-empty values to string
		if reflect.TypeOf(val).Kind() == reflect.String {
			act.val = val.(string)
		} else {
			bytes, err := json.Marshal(val)
			if err != nil {
				return fmt.Errorf("failed to marshal %q value %v to string: %v", key, val, err)
			}
			act.val = string(bytes)
		}
	}
	pa.changes[key] = act
	return nil
}

func (pa *podAnnotator) Delete(key string) {
	pa.changes[key] = &action{key: key}
}

func (pa *podAnnotator) Run() error {
	annotations := make(map[string]string)
	for k, act := range pa.changes {
		// Ignore annotations that already exist with the same value
		if existing, ok := pa.pod.Annotations[k]; existing != act.val || !ok {
			if act.origVal != nil {
				// Annotation should be updated to new value
				annotations[k] = act.val
			} else {
				// Annotation should be deleted
				annotations[k] = ""
			}
		}
	}
	if len(annotations) == 0 {
		return nil
	}

	return pa.kube.SetAnnotationsOnPod(pa.pod.Namespace, pa.pod.Name, annotations)
}

// NewNamespaceAnnotator returns a new annotator for Namespace objects
func NewNamespaceAnnotator(kube Interface, namespace *kapi.Namespace) Annotator {
	return &namespaceAnnotator{
		kube:      kube,
		namespace: namespace,
		changes:   make(map[string]*action),
	}
}

type namespaceAnnotator struct {
	kube      Interface
	namespace *kapi.Namespace

	changes map[string]*action
}

func (na *namespaceAnnotator) Set(key string, val interface{}) error {
	act := &action{
		key:     key,
		origVal: val,
	}
	if val != nil {
		// Annotations must be either a valid string value or nil; coerce
		// any non-empty values to string
		if reflect.TypeOf(val).Kind() == reflect.String {
			act.val = val.(string)
		} else {
			bytes, err := json.Marshal(val)
			if err != nil {
				return fmt.Errorf("failed to marshal %q value %v to string: %v", key, val, err)
			}
			act.val = string(bytes)
		}
	}
	na.changes[key] = act
	return nil
}

func (na *namespaceAnnotator) Delete(key string) {
	na.changes[key] = &action{key: key}
}

func (na *namespaceAnnotator) Run() error {
	annotations := make(map[string]string)
	for k, act := range na.changes {
		// Ignore annotations that already exist with the same value
		if existing, ok := na.namespace.Annotations[k]; existing != act.val || !ok {
			if act.origVal != nil {
				// Annotation should be updated to new value
				annotations[k] = act.val
			} else {
				// Annotation should be deleted
				annotations[k] = ""
			}
		}
	}
	if len(annotations) == 0 {
		return nil
	}

	return na.kube.SetAnnotationsOnNamespace(na.namespace, annotations)
}
