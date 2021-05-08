package services

import (
	"testing"

	v1 "k8s.io/api/core/v1"
)

func Test_serviceTracker_updateService(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		proto     v1.Protocol
		vip       string
	}{
		// Create a new service
		{
			name:      "svc1",
			namespace: "ns1",
			proto:     v1.ProtocolTCP,
			vip:       "10.0.0.0:80",
		},
		// Update the service endpoint
		{
			name:      "svc1",
			namespace: "ns1",
			proto:     v1.ProtocolTCP,
			vip:       "10.0.0.0:80",
		},
		// Add a new VIP to the service
		{
			name:      "svc1",
			namespace: "ns1",
			proto:     v1.ProtocolTCP,
			vip:       "10.0.0.0:890",
		},
		// Create another service
		{
			name:      "svc2",
			namespace: "ns1",
			proto:     v1.ProtocolUDP,
			vip:       "10.0.0.0:80",
		},
	}

	st := newServiceTracker()
	for _, tt := range tests {
		st.updateService(tt.name, tt.namespace, tt.vip, tt.proto, "")
		if !st.hasService(tt.name, tt.namespace) {
			t.Fatalf("Error: service %s %s not updated", tt.name, tt.namespace)
		}
		if !st.hasServiceVIP(tt.name, tt.namespace, tt.vip, tt.proto) {
			t.Fatalf("Error: service %s %s vip %s-%v not updated", tt.name, tt.namespace, tt.vip, tt.proto)
		}
	}

	// Delete a non existent service
	st.deleteService("svc-fake", "ns1")
	if st.hasService("svc-fake", "ns1") {
		t.Fatalf("Service ns1 svc-fake should not exist")
	}
	// Delete service svc2
	st.deleteService("svc2", "ns1")
	if st.hasService("svc2", "ns1") {
		t.Fatalf("Service ns1 svc2 should not exist")
	}
	// Delete a non existent VIP (is a noop)
	st.deleteServiceVIP("svc3", "ns1", "10.0.0.0:890", v1.ProtocolTCP)
	// Delete vip 10.0.0.0:890-TCP on service svc1
	st.deleteServiceVIP("svc1", "ns1", "10.0.0.0:890", v1.ProtocolTCP)
	if st.hasServiceVIP("svc1", "ns1", "10.0.0.0:890", v1.ProtocolTCP) {
		t.Fatalf("Service ns1 svc2 should not exist")
	}
}
