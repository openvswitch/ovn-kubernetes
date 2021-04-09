package main

import (
	"context"
	"fmt"

	egressfirewallv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	egressfirewallclientset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned"

	v1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

var (
	egressFirewallResource = metav1.GroupVersionResource{
		Version:  egressfirewallv1.SchemeGroupVersion.Version,
		Group:    egressfirewallv1.SchemeGroupVersion.Group,
		Resource: "egressfirewalls",
	}
)

func validateEgressFirewall(req *v1.AdmissionRequest) error {
	if req.Resource != egressFirewallResource {
		return fmt.Errorf("expect resource to be %s", egressFirewallResource)
	}
	raw := req.Object.Raw
	eFW := egressfirewallv1.EgressFirewall{}
	if _, _, err := universalDeserializer.Decode(raw, nil, &eFW); err != nil {
		return fmt.Errorf("could not deserialize EgressFirewall object: %v", err)
	}

	// It only makes sense to run this inside a cluster
	restconfig, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("could not retrive config file from cluster: %v", err)
	}
	egressfirewallClientset, err := egressfirewallclientset.NewForConfig(restconfig)
	if err != nil {
		return fmt.Errorf("could not create a viable clientset from cluster provided configuration:  %v", err)
	}

	egressfirewalls, err := egressfirewallClientset.K8sV1().EgressFirewalls(eFW.Namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("could not retrive egressfirewalls from cluster: %v", err)
	}
	if len(egressfirewalls.Items) != 0 {
		return fmt.Errorf("there is already an egressfirewall policy in namespace %s named %s", eFW.Namespace, egressfirewalls.Items[0].Name)
	}
	return nil
}
