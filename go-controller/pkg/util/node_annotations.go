package util

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	kapi "k8s.io/api/core/v1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
)

// This handles the annotations used by the node to pass information about its local
// network configuration to the master:
//
//   annotations:
//     k8s.ovn.org/l3-gateway-config: |
//       {
//         "default": {
//           "mode": "local",
//           "interface-id": "br-local_ip-10-0-129-64.us-east-2.compute.internal",
//           "mac-address": "f2:20:a0:3c:26:4c",
//           "ip-addresses": ["169.254.33.2/24"],
//           "next-hops": ["169.254.33.1"],
//           "node-port-enable": "true",
//           "vlan-id": "0"
//
//           # backward-compat
//           "ip-address": "169.254.33.2/24",
//           "next-hop": "169.254.33.1",
//         }
//       }
//     k8s.ovn.org/node-chassis-id: b1f96182-2bdd-42b6-88f9-9a1fc1c85ece
//     k8s.ovn.org/node-mgmt-port-mac-address: fa:f1:27:f5:54:69
//
// The "ip_address" and "next_hop" fields are deprecated and will eventually go away.
// (And they are not output when "ip_addresses" or "next_hops" contains multiple
// values.)

const (
	// ovnNodeL3GatewayConfig is the constant string representing the l3 gateway annotation key
	ovnNodeL3GatewayConfig = "k8s.ovn.org/l3-gateway-config"

	// ovnNodeManagementPortMacAddress is the constant string representing the annotation key
	ovnNodeManagementPortMacAddress = "k8s.ovn.org/node-mgmt-port-mac-address"

	// ovnNodeChassisID is the systemID of the node needed for creating L3 gateway
	ovnNodeChassisID = "k8s.ovn.org/node-chassis-id"

	// ovnNodeCIDR is the CIDR form representation of primary network interface's attached IP address (i.e: 192.168.126.31/24 or 0:0:0:0:0:feff:c0a8:8e0c/64)
	ovnNodeIfAddr = "k8s.ovn.org/node-primary-ifaddr"

	// OvnNodeEgressLabel is a user assigned node label indicating to ovn-kubernetes that the node is to be used for egress IP assignment
	ovnNodeEgressLabel = "k8s.ovn.org/egress-assignable"
)

type L3GatewayConfig struct {
	Mode           config.GatewayMode
	ChassisID      string
	InterfaceID    string
	MACAddress     net.HardwareAddr
	IPAddresses    []*net.IPNet
	NextHops       []net.IP
	NodePortEnable bool
	VLANID         *uint
}

type l3GatewayConfigJSON struct {
	Mode           config.GatewayMode `json:"mode"`
	InterfaceID    string             `json:"interface-id,omitempty"`
	MACAddress     string             `json:"mac-address,omitempty"`
	IPAddresses    []string           `json:"ip-addresses,omitempty"`
	IPAddress      string             `json:"ip-address,omitempty"`
	NextHops       []string           `json:"next-hops,omitempty"`
	NextHop        string             `json:"next-hop,omitempty"`
	NodePortEnable string             `json:"node-port-enable,omitempty"`
	VLANID         string             `json:"vlan-id,omitempty"`
}

func (cfg *L3GatewayConfig) MarshalJSON() ([]byte, error) {
	cfgjson := l3GatewayConfigJSON{
		Mode: cfg.Mode,
	}
	if cfg.Mode == config.GatewayModeDisabled {
		return json.Marshal(&cfgjson)
	}

	cfgjson.InterfaceID = cfg.InterfaceID
	cfgjson.MACAddress = cfg.MACAddress.String()
	cfgjson.NodePortEnable = fmt.Sprintf("%t", cfg.NodePortEnable)
	if cfg.VLANID != nil {
		cfgjson.VLANID = fmt.Sprintf("%d", *cfg.VLANID)
	}

	cfgjson.IPAddresses = make([]string, len(cfg.IPAddresses))
	for i, ip := range cfg.IPAddresses {
		cfgjson.IPAddresses[i] = ip.String()
	}
	if len(cfgjson.IPAddresses) == 1 {
		cfgjson.IPAddress = cfgjson.IPAddresses[0]
	}
	cfgjson.NextHops = make([]string, len(cfg.NextHops))
	for i, nh := range cfg.NextHops {
		cfgjson.NextHops[i] = nh.String()
	}
	if len(cfgjson.NextHops) == 1 {
		cfgjson.NextHop = cfgjson.NextHops[0]
	}

	return json.Marshal(&cfgjson)
}

func (cfg *L3GatewayConfig) UnmarshalJSON(bytes []byte) error {
	cfgjson := l3GatewayConfigJSON{}
	if err := json.Unmarshal(bytes, &cfgjson); err != nil {
		return err
	}

	cfg.Mode = cfgjson.Mode
	if cfg.Mode == config.GatewayModeDisabled {
		return nil
	} else if cfg.Mode != config.GatewayModeShared && cfg.Mode != config.GatewayModeLocal {
		return fmt.Errorf("bad 'mode' value %q", cfgjson.Mode)
	}

	cfg.InterfaceID = cfgjson.InterfaceID
	cfg.NodePortEnable = cfgjson.NodePortEnable == "true"
	if cfgjson.VLANID != "" {
		vlanID64, err := strconv.ParseUint(cfgjson.VLANID, 10, 0)
		if err != nil {
			return fmt.Errorf("bad 'vlan-id' value %q: %v", cfgjson.VLANID, err)
		}
		if cfg.Mode != config.GatewayModeShared && uint(vlanID64) != 0 {
			return fmt.Errorf("vlan-id is supported only in shared gateway mode")
		}
		vlanID := uint(vlanID64)
		cfg.VLANID = &vlanID
	}

	var err error
	cfg.MACAddress, err = net.ParseMAC(cfgjson.MACAddress)
	if err != nil {
		return fmt.Errorf("bad 'mac-address' value %q: %v", cfgjson.MACAddress, err)
	}

	if len(cfgjson.IPAddresses) == 0 {
		cfg.IPAddresses = make([]*net.IPNet, 1)
		ip, ipnet, err := net.ParseCIDR(cfgjson.IPAddress)
		if err != nil {
			return fmt.Errorf("bad 'ip-address' value %q: %v", cfgjson.IPAddress, err)
		}
		cfg.IPAddresses[0] = &net.IPNet{IP: ip, Mask: ipnet.Mask}
	} else {
		cfg.IPAddresses = make([]*net.IPNet, len(cfgjson.IPAddresses))
		for i, ipStr := range cfgjson.IPAddresses {
			ip, ipnet, err := net.ParseCIDR(ipStr)
			if err != nil {
				return fmt.Errorf("bad 'ip-addresses' value %q: %v", ipStr, err)
			}
			cfg.IPAddresses[i] = &net.IPNet{IP: ip, Mask: ipnet.Mask}
		}
	}

	if len(cfgjson.NextHops) == 0 {
		cfg.NextHops = make([]net.IP, 1)
		cfg.NextHops[0] = net.ParseIP(cfgjson.NextHop)
		if cfg.NextHops[0] == nil {
			return fmt.Errorf("bad 'next-hop' value %q", cfgjson.NextHop)
		}
	} else {
		cfg.NextHops = make([]net.IP, len(cfgjson.NextHops))
		for i, nextHopStr := range cfgjson.NextHops {
			cfg.NextHops[i] = net.ParseIP(nextHopStr)
			if cfg.NextHops[i] == nil {
				return fmt.Errorf("bad 'next-hops' value %q", nextHopStr)
			}
		}
	}

	return nil
}

func SetL3GatewayConfig(nodeAnnotator kube.Annotator, cfg *L3GatewayConfig) error {
	gatewayAnnotation := map[string]*L3GatewayConfig{types.DefaultNetworkName: cfg}
	if err := nodeAnnotator.Set(ovnNodeL3GatewayConfig, gatewayAnnotation); err != nil {
		return err
	}
	if cfg.ChassisID != "" {
		if err := nodeAnnotator.Set(ovnNodeChassisID, cfg.ChassisID); err != nil {
			return err
		}
	}
	return nil
}

// ParseNodeL3GatewayAnnotation returns the parsed l3-gateway-config annotation
func ParseNodeL3GatewayAnnotation(node *kapi.Node) (*L3GatewayConfig, error) {
	l3GatewayAnnotation, ok := node.Annotations[ovnNodeL3GatewayConfig]
	if !ok {
		return nil, newAnnotationNotSetError("%s annotation not found node %q", ovnNodeL3GatewayConfig, node.Name)
	}

	var cfgs map[string]*L3GatewayConfig
	if err := json.Unmarshal([]byte(l3GatewayAnnotation), &cfgs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal l3 gateway config annotation %s for node %q: %v", l3GatewayAnnotation, node.Name, err)
	}

	cfg, ok := cfgs[types.DefaultNetworkName]
	if !ok {
		return nil, fmt.Errorf("%s annotation for %s network not found", ovnNodeL3GatewayConfig, types.DefaultNetworkName)
	}

	if cfg.Mode != config.GatewayModeDisabled {
		cfg.ChassisID, ok = node.Annotations[ovnNodeChassisID]
		if !ok {
			return nil, fmt.Errorf("%s annotation not found", ovnNodeChassisID)
		}
	}

	return cfg, nil
}

func SetNodeManagementPortMACAddress(nodeAnnotator kube.Annotator, macAddress net.HardwareAddr) error {
	return nodeAnnotator.Set(ovnNodeManagementPortMacAddress, macAddress.String())
}

func ParseNodeManagementPortMACAddress(node *kapi.Node) (net.HardwareAddr, error) {
	macAddress, ok := node.Annotations[ovnNodeManagementPortMacAddress]
	if !ok {
		return nil, newAnnotationNotSetError("macAddress annotation not found node %q ", node.Name)
	}

	return net.ParseMAC(macAddress)
}

type primaryIfAddrAnnotation struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

// SetNodePrimaryIfAddr sets the IPv4 / IPv6 values of the node's primary network interface
func SetNodePrimaryIfAddr(nodeAnnotator kube.Annotator, nodeIPNetv4, nodeIPNetv6 *net.IPNet) (err error) {
	primaryIfAddrAnnotation := primaryIfAddrAnnotation{}
	if nodeIPNetv4 != nil {
		primaryIfAddrAnnotation.IPv4 = nodeIPNetv4.String()
	}
	if nodeIPNetv6 != nil {
		primaryIfAddrAnnotation.IPv6 = nodeIPNetv6.String()
	}
	return nodeAnnotator.Set(ovnNodeIfAddr, primaryIfAddrAnnotation)
}

// ParseNodePrimaryIfAddr returns the IPv4 / IPv6 values for the node's primary network interface
func ParseNodePrimaryIfAddr(node *kapi.Node) (string, string, error) {
	nodeIfAddrAnnotation, ok := node.Annotations[ovnNodeIfAddr]
	if !ok {
		return "", "", newAnnotationNotSetError("%s annotation not found for node %q", ovnNodeIfAddr, node.Name)
	}
	nodeIfAddr := primaryIfAddrAnnotation{}
	if err := json.Unmarshal([]byte(nodeIfAddrAnnotation), &nodeIfAddr); err != nil {
		return "", "", fmt.Errorf("failed to unmarshal annotation: %s for node %q, err: %v", ovnNodeIfAddr, node.Name, err)
	}
	if nodeIfAddr.IPv4 == "" && nodeIfAddr.IPv6 == "" {
		return "", "", fmt.Errorf("node: %q does not have any IP information set", node.Name)
	}
	return nodeIfAddr.IPv4, nodeIfAddr.IPv6, nil
}

// GetNodeEgressLabel returns label annotation needed for marking nodes as egress assignable
func GetNodeEgressLabel() string {
	return ovnNodeEgressLabel
}
