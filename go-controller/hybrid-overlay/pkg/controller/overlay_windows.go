package controller

import (
	"encoding/json"
	"fmt"
	"k8s.io/apimachinery/pkg/util/sets"
	"net"

	"github.com/Microsoft/hcsshim/hcn"
	"k8s.io/klog"

	ps "github.com/bhendo/go-powershell"
	psBackend "github.com/bhendo/go-powershell/backend"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
)

// Datastore for NetworkInfo.
type NetworkInfo struct {
	ID           string
	Name         string
	Subnets      []SubnetInfo
	VSID         uint32
	AutomaticDNS bool
	IsPersistent bool
	VXLANPort    uint16
}

// Datastore for SubnetInfo.
type SubnetInfo struct {
	AddressPrefix  *net.IPNet
	GatewayAddress net.IP
	VSID           uint32
}

// GetHostComputeSubnetConfig converts SubnetInfo into an HCN format.
func (subnet *SubnetInfo) GetHostComputeSubnetConfig() (*hcn.Subnet, error) {
	ipAddr := subnet.AddressPrefix.String()
	gwAddr := ""
	destPrefix := ""
	if subnet.GatewayAddress != nil {
		gwAddr = subnet.GatewayAddress.String()
		destPrefix = "0.0.0.0/0"
	}

	vsidJSON, err := json.Marshal(&hcn.VsidPolicySetting{
		IsolationId: subnet.VSID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal VSID policy: %v", err)
	}

	subnetPolicyJson, err := json.Marshal(hcn.SubnetPolicy{
		Type:     "VSID",
		Settings: vsidJSON,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subnet policy: %v", err)
	}

	return &hcn.Subnet{
		IpAddressPrefix: ipAddr,
		Routes: []hcn.Route{{
			NextHop:           gwAddr,
			DestinationPrefix: destPrefix,
		}},
		Policies: []json.RawMessage{
			subnetPolicyJson,
		},
	}, nil
}

// GetHostComputeNetworkConfig converts NetworkInfo to HCN format.
func (info *NetworkInfo) GetHostComputeNetworkConfig() (*hcn.HostComputeNetwork, error) {
	subnets := []hcn.Subnet{}
	for _, subnet := range info.Subnets {
		subnetConfig, err := subnet.GetHostComputeSubnetConfig()
		if err != nil {
			return nil, err
		}

		subnets = append(subnets, *subnetConfig)
	}

	dnsJSON, err := json.Marshal(&hcn.AutomaticDNSNetworkPolicySetting{
		Enable: info.AutomaticDNS,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal automatic DNS policy: %v", err)
	}

	var ipams []hcn.Ipam
	if len(subnets) > 0 {
		ipams = append(ipams, hcn.Ipam{
			Type:    "Static",
			Subnets: subnets,
		})
	}

	var flags hcn.NetworkFlags
	if !info.IsPersistent {
		flags = hcn.EnableNonPersistent
	}

	policies := []hcn.NetworkPolicy{{
		Type:     hcn.AutomaticDNS,
		Settings: dnsJSON,
	}}

	// Only configure the VXLAN UDP port if the port is not
	// the default port.
	// Note: the calling code is responsible for making sure non-default
	// ports are only passed to this function if the underlying platform
	// supports it.
	if info.VXLANPort != config.DefaultVXLANPort {
		vxlanPortJSON, err := json.Marshal(&hcn.VxlanPortPolicySetting{
			Port: info.VXLANPort,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal the VXLAN port policy: %v", err)
		}

		policies = append(policies, hcn.NetworkPolicy{
			Type:     hcn.VxlanPort,
			Settings: vxlanPortJSON,
		})
	}

	return &hcn.HostComputeNetwork{
		SchemaVersion: hcn.SchemaVersion{
			Major: 2,
			Minor: 0,
		},
		Name:     info.Name,
		Type:     hcn.NetworkType("Overlay"),
		Ipams:    ipams,
		Flags:    flags,
		Policies: policies,
	}, nil
}

func AddHostRoutePolicy(network *hcn.HostComputeNetwork) error {
	return network.AddPolicy(hcn.PolicyNetworkRequest{
		Policies: []hcn.NetworkPolicy{{
			Type:     hcn.HostRoute,
			Settings: []byte("{}"),
		}},
	})
}

// CreateNetworkPolicySetting builds a NetAdapterNameNetworkPolicySetting.
func CreateNetworkPolicySetting(networkAdapterName string) (*hcn.NetworkPolicy, error) {
	policyJSON, err := json.Marshal(hcn.NetAdapterNameNetworkPolicySetting{
		NetworkAdapterName: networkAdapterName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed ot marshal network adapter policy: %v", err)
	}

	return &hcn.NetworkPolicy{
		Type:     hcn.NetAdapterName,
		Settings: policyJSON,
	}, nil
}

// AddRemoteSubnetPolicy adds a remote subnet policy
func AddRemoteSubnetPolicy(network *hcn.HostComputeNetwork, settings *hcn.RemoteSubnetRoutePolicySetting) error {
	json, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to marshall remote subnet route policy settings: %v", err)
	}

	network.AddPolicy(hcn.PolicyNetworkRequest{
		Policies: []hcn.NetworkPolicy{{
			Type:     hcn.RemoteSubnetRoute,
			Settings: json,
		}},
	})
	return nil
}

func removeOneRemoteSubnetPolicy(network *hcn.HostComputeNetwork, settings []byte) error {
	network.RemovePolicy(hcn.PolicyNetworkRequest{
		Policies: []hcn.NetworkPolicy{{
			Type:     hcn.RemoteSubnetRoute,
			Settings: settings,
		}},
	})
	return nil
}

// RemoveRemoteSubnetPolicy removes a remote subnet policy
func RemoveRemoteSubnetPolicy(network *hcn.HostComputeNetwork, destinationPrefix string) error {
	for _, policy := range network.Policies {
		if policy.Type != hcn.RemoteSubnetRoute {
			continue
		}

		existingPolicySettings := hcn.RemoteSubnetRoutePolicySetting{}
		if err := json.Unmarshal(policy.Settings, &existingPolicySettings); err != nil {
			return fmt.Errorf("failed to unmarshal remote subnet route policy settings: %v", err)
		}

		if existingPolicySettings.DestinationPrefix == destinationPrefix {
			if err := removeOneRemoteSubnetPolicy(network, policy.Settings); err != nil {
				return fmt.Errorf("failed to remove remote subnet policy %v: %v",
					existingPolicySettings.DestinationPrefix, err)
			}
		}
	}

	return nil
}

func ClearRemoteSubnetPolicies(network *hcn.HostComputeNetwork) error {
	for _, policy := range network.Policies {
		if policy.Type != hcn.RemoteSubnetRoute {
			continue
		}

		existingPolicySettings := hcn.RemoteSubnetRoutePolicySetting{}
		if err := json.Unmarshal(policy.Settings, &existingPolicySettings); err != nil {
			return fmt.Errorf("failed to unmarshal remote subnet route policy settings: %v", err)
		}

		if err := removeOneRemoteSubnetPolicy(network, policy.Settings); err != nil {
			// We don't return the error in this case, we take a best effort
			// approach to clear the remote subnets.
			klog.Errorf("Failed to remove remote subnet policy %v: %v",
				existingPolicySettings.DestinationPrefix, err)
		}
	}

	return nil
}

func GetGatewayAddress(subnet *hcn.Subnet) string {
	for _, route := range subnet.Routes {
		if route.DestinationPrefix == "0.0.0.0/0" || route.DestinationPrefix == "::/0" {
			return route.NextHop
		}
	}
	return ""
}

func GetExistingNetwork(networkName string, expectedAddressPrefix []string, expectedGW []string) *hcn.HostComputeNetwork {
	existingNetwork, err := hcn.GetNetworkByName(networkName)
	if err != nil || existingNetwork.Type != hcn.Overlay {
		return nil
	}

	existingSubnets := sets.String{}
	existingGatewayAddresses := sets.String{}
	for _, existingIpams := range existingNetwork.Ipams {
		for _, existingSubnet := range existingIpams.Subnets {
			gatewayAddress := GetGatewayAddress(&existingSubnet)
			existingSubnets.Insert(existingSubnet.IpAddressPrefix)
			existingGatewayAddresses.Insert(gatewayAddress)
		}
	}
	if existingSubnets.Len() != len(expectedAddressPrefix) {
		return nil
	}
	for index := range expectedAddressPrefix {
		if !existingSubnets.Has(expectedAddressPrefix[index]) && !existingGatewayAddresses.Has(expectedGW[index]) {
			return nil
		}
	}
	return existingNetwork
}

func DuplicatePersistentIPRoutes() error {
	shell, err := ps.New(&psBackend.Local{})
	if err != nil {
		return err
	}
	defer shell.Exit()

	script := `
	# Find physical adapters whose interfaces are bound to a vswitch (i.e. the MAC addresses match)
	$boundAdapters = (Get-NetAdapter -Physical | where { (Get-NetAdapter -Name "*vEthernet*").MacAddress -eq $_.MacAddress })

	# Forward all the persistent routes associated with the physical interface to the associated vNIC
	foreach ($boundAdapter in $boundAdapters) {
		$associatedVNic = Get-NetAdapter -Name "*vEthernet*" | where { $_.MacAddress -eq $boundAdapter.MacAddress }
		$routes = Get-NetRoute -PolicyStore PersistentStore -InterfaceIndex $boundAdapter.IfIndex -ErrorAction SilentlyContinue
		foreach ($route in $routes) {
			netsh.exe int ipv4 add route interface=$($associatedVNic.ifIndex) prefix=$($route.DestinationPrefix) nexthop=$($route.NextHop) metric=$($route.RouteMetric) store=persistent
		}
	}
	`

	if _, stderr, err := shell.Execute(script + "\r\n\r\n"); err != nil {
		return fmt.Errorf("falied to refresh the network persistent routes, %v: %v", stderr, err)
	}

	return nil
}
