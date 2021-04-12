package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +resource:path=nodednsinfo
// +kubebuilder:resource:path=nodednsinfos,scope=Cluster
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:printcolumn:name="nodeDNSInfo Status",type=string,JSONPath=".status.status"
// NodeDNSInfo describes the current state of DNS name resolution for DNS names mentioned in
// EgressFirewalls for a specific node. Each node maintains it's own NodeDNSInfo object so
// that the master can generate the required ovn rules so  EgressFirewalls referencing
// DNS names can be applied cluster wide.
type NodeDNSInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior of EgressFirewallDNS
	Spec NodeDNSInfoSpec `json:"spec,omitempty"`

	// Observed status of EgressFirewallDNS
	// +optional
	Status NodeDNSInfoStatus `json:"status,omitempty"`
}

type NodeDNSInfoSpec struct {
}

// The list of IP addresses that the node resolves a DNS name to
type DNSEntry struct {
	IPAddresses []string `json:"ipAddresses,omitempty"`
}

type NodeDNSInfoStatus struct {
	//a map indexed by DNS name to its corresponding resolved ip addresses
	DNSEntries map[string]DNSEntry `json:"egressdnsEntries,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=nodednsinfo
// NodeDNSInfoList is the list of NodeDNSInfos
type NodeDNSInfoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []NodeDNSInfo `json:"items"`
}
