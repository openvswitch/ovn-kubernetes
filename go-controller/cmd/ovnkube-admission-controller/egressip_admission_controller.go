package main

import (
	"fmt"
	"net"

	egressipv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	v1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

var (
	egressIPResource = metav1.GroupVersionResource{
		Version:  egressipv1.SchemeGroupVersion.Version,
		Group:    egressipv1.SchemeGroupVersion.Group,
		Resource: "egressips",
	}
)

func validateEgressIP(req *v1.AdmissionRequest) error {
	if req.Resource != egressIPResource {
		return fmt.Errorf("expect resource to be %s", egressIPResource)
	}
	raw := req.Object.Raw
	eIP := egressipv1.EgressIP{}
	if _, _, err := universalDeserializer.Decode(raw, nil, &eIP); err != nil {
		return fmt.Errorf("could not deserialize EgressIP object: %v", err)
	}
	egressIPSet := sets.String{}
	// Validate that we have a set of unique and properly defined IPs
	for _, ip := range eIP.Spec.EgressIPs {
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			if egressIPSet.Has(parsedIP.String()) {
				return fmt.Errorf("EgressIP: %s has duplicate egress IPs defined: %s", eIP.Name, parsedIP.String())
			}
			egressIPSet.Insert(parsedIP.String())
		} else {
			return fmt.Errorf("EgressIP: %s has an invalid IP address defined: %s", eIP.Name, ip)
		}
	}
	return nil
}
