package types

const (
	DefaultNetworkName = "default"
	K8sPrefix          = "k8s-"
	// K8sMgmtIntfName name to be used as an OVS internal port on the node
	K8sMgmtIntfName = "ovn-k8s-mp0"

	// PhysicalNetworkName is the name that maps to an OVS bridge that provides
	// access to physical/external network
	PhysicalNetworkName = "physnet"

	// LocalNetworkName is the name that maps to an OVS bridge that provides
	// access to local service
	LocalNetworkName = "locnet"

	// types.OVNClusterRouter is the name of the distributed router
	OVNClusterRouter = "ovn_cluster_router"
	OVNJoinSwitch    = "join"

	JoinSwitchPrefix             = "join_"
	ExternalSwitchPrefix         = "ext_"
	GWRouterPrefix               = "GR_"
	RouterToSwitchPrefix         = "rtos-"
	InterPrefix                  = "inter-"
	SwitchToRouterPrefix         = "stor-"
	JoinSwitchToGWRouterPrefix   = "jtor-"
	GWRouterToJoinSwitchPrefix   = "rtoj-"
	DistRouterToJoinSwitchPrefix = "dtoj-"
	JoinSwitchToDistRouterPrefix = "jtod-"
	EXTSwitchToGWRouterPrefix    = "etor-"
	GWRouterToExtSwitchPrefix    = "rtoe-"

	NodeLocalSwitch = "node_local_switch"

	// priority of logical router policies on the OVNClusterRouter
	EgressFirewallStartPriority           = "10000"
	MinimumReservedEgressFirewallPriority = "2000"
	MGMTPortPolicyPriority                = "1005"
	NodeSubnetPolicyPriority              = "1004"
	InterNodePolicyPriority               = "1003"
	HybridOverlayReroutePriority          = "501"
	DefaultNoRereoutePriority             = "101"
	EgressIPReroutePriority               = "100"

	V6NodeLocalNATSubnet           = "fd99::/64"
	V6NodeLocalNATSubnetPrefix     = 64
	V6NodeLocalNATSubnetNextHop    = "fd99::1"
	V6NodeLocalDistributedGWPortIP = "fd99::2"

	V4NodeLocalNATSubnet           = "169.254.0.0/20"
	V4NodeLocalNATSubnetPrefix     = 20
	V4NodeLocalNATSubnetNextHop    = "169.254.0.1"
	V4NodeLocalDistributedGWPortIP = "169.254.0.2"

	// OpenFlow and Networking constants
	RouteAdvertisementICMPType    = 134
	NeighborAdvertisementICMPType = 136

	OvnACLLoggingMeter = "acl-logging"
)
