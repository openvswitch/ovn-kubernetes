package ovn

import (
	"context"
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	kapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	goovn "github.com/ebay/go-ovn"
	hocontroller "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/controller"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/ipallocator"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

const (
	// OvnServiceIdledAt is a constant string representing the Service annotation key
	// whose value indicates the time stamp in RFC3339 format when a Service was idled
	OvnServiceIdledAt              = "k8s.ovn.org/idled-at"
	OvnNodeAnnotationRetryInterval = 100 * time.Millisecond
	OvnNodeAnnotationRetryTimeout  = 1 * time.Second
	OvnSingleJoinSwitchTopoVersion = 1
	OvnNamespacedDenyPGTopoVersion = 2
	OvnCurrentTopologyVersion      = OvnNamespacedDenyPGTopoVersion
)

type ovnkubeMasterLeaderMetrics struct{}

func (ovnkubeMasterLeaderMetrics) On(string) {
	metrics.MetricMasterLeader.Set(1)
}

func (ovnkubeMasterLeaderMetrics) Off(string) {
	metrics.MetricMasterLeader.Set(0)
}

type ovnkubeMasterLeaderMetricsProvider struct{}

func (_ ovnkubeMasterLeaderMetricsProvider) NewLeaderMetric() leaderelection.SwitchMetric {
	return ovnkubeMasterLeaderMetrics{}
}

// Start waits until this process is the leader before starting master functions
func (mc *OvnMHController) Start() error {
	// Set up leader election process first
	rl, err := resourcelock.New(
		resourcelock.ConfigMapsResourceLock,
		config.Kubernetes.OVNConfigNamespace,
		"ovn-kubernetes-master",
		mc.client.CoreV1(),
		nil,
		resourcelock.ResourceLockConfig{Identity: mc.nodeName},
	)
	if err != nil {
		return err
	}

	lec := leaderelection.LeaderElectionConfig{
		Lock:          rl,
		LeaseDuration: time.Duration(config.MasterHA.ElectionLeaseDuration) * time.Second,
		RenewDeadline: time.Duration(config.MasterHA.ElectionRenewDeadline) * time.Second,
		RetryPeriod:   time.Duration(config.MasterHA.ElectionRetryPeriod) * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				klog.Infof("Won leader election; in active mode")
				// run the cluster controller to init the master
				start := time.Now()
				defer func() {
					end := time.Since(start)
					metrics.MetricMasterReadyDuration.Set(end.Seconds())
				}()

				// run the End-to-end timestamp metric updater only on the
				// active master node.
				metrics.StartE2ETimeStampMetricUpdater(mc.stopChan, mc.ovnNBClient)
				mc.watchCRD()

				// Default Network controller may already be created as result of watchCRD().
				if mc.ovnController == nil {
					if err := mc.setDefaultOvnController(nil); err != nil {
						panic(err.Error())
					}
				}
				if err := mc.ovnController.StartClusterMaster(mc.nodeName); err != nil {
					panic(err.Error())
				}
				if err := mc.ovnController.Run(); err != nil {
					panic(err.Error())
				}
			},
			OnStoppedLeading: func() {
				//This node was leader and it lost the election.
				// Whenever the node transitions from leader to follower,
				// we need to handle the transition properly like clearing
				// the cache. It is better to exit for now.
				// kube will restart and this will become a follower.
				klog.Infof("No longer leader; exiting")
				os.Exit(1)
			},
			OnNewLeader: func(newLeaderName string) {
				if newLeaderName != mc.nodeName {
					klog.Infof("Lost the election to %s; in standby mode", newLeaderName)
				}
			},
		},
	}

	leaderelection.SetProvider(ovnkubeMasterLeaderMetricsProvider{})
	leaderElector, err := leaderelection.NewLeaderElector(lec)
	if err != nil {
		return err
	}

	go leaderElector.Run(context.Background())

	return nil
}

// cleanup obsolete *gressDefaultDeny port groups
func (oc *Controller) upgradeToNamespacedDenyPGOVNTopology(existingNodeList *kapi.NodeList) error {
	deletePortGroup("ingressDefaultDeny")
	deletePortGroup("egressDefaultDeny")
	return nil
}

// delete obsoleted logical OVN entities that are specific for Multiple join switches OVN topology. Also cleanup
// OVN entities for deleted nodes (similar to syncNodes() but for obsoleted Multiple join switches OVN topology)
func (oc *Controller) upgradeToSingleSwitchOVNTopology(existingNodeList *kapi.NodeList) error {
	existingNodes := make(map[string]bool)
	for _, node := range existingNodeList.Items {
		existingNodes[node.Name] = true

		// delete the obsoleted node-join-subnets annotation
		err := oc.mc.kube.SetAnnotationsOnNode(&node, map[string]interface{}{"k8s.ovn.org/node-join-subnets": nil})
		if err != nil {
			klog.Errorf("Failed to remove node-join-subnets annotation for node %s", node.Name)
		}
	}

	nodeSwitches, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading", "--format=csv",
		"--columns=name", "find", "logical_switch")
	if err != nil {
		return fmt.Errorf("failed to get all logical switches for upgrade: stderr: %q, error: %v",
			stderr, err)
	}

	logicalNodes := make(map[string]bool)
	for _, switchName := range strings.Split(nodeSwitches, "\n") {
		// We are interested only in the join_* switches
		if !strings.HasPrefix(switchName, "join_") {
			continue
		}
		nodeName := strings.TrimPrefix(switchName, "join_")
		logicalNodes[nodeName] = true
	}

	for nodeName := range logicalNodes {
		// if the node was deleted when ovn-master was down, delete its per-node switch
		upgradeOnly := true
		if _, ok := existingNodes[nodeName]; !ok {
			_ = oc.deleteNodeLogicalNetwork(nodeName)
			upgradeOnly = false
		}

		// for all nodes include the ones that were deleted, delete its gateway entities.
		// See comments above the multiJoinSwitchGatewayCleanup() function for details.
		err = multiJoinSwitchGatewayCleanup(nodeName, upgradeOnly)
		if err != nil {
			return err
		}
	}
	return nil
}

func (oc *Controller) upgradeOVNTopology(existingNodes *kapi.NodeList) error {
	// Find out the current OVN topology version. If "k8s-ovn-topo-version" key in external_ids column does not exist,
	// it is prior to OVN topology versioning and therefore set version number to OvnCurrentTopologyVersion
	ver := 0
	ovnClusterRouter := util.GetNetworkPrefix(oc.netconf.Name) + types.OVNClusterRouter
	stdout, stderr, err := util.RunOVNNbctl("--data=bare", "--no-headings", "--columns=name", "find", "logical_router",
		fmt.Sprintf("name=%s", ovnClusterRouter))
	if err != nil {
		return fmt.Errorf("failed in retrieving %s to determine the current version of OVN logical topology: "+
			"stderr: %q, error: %v", ovnClusterRouter, stderr, err)
	}
	if len(stdout) == 0 {
		// no OVNClusterRouter exists, DB is empty, nothing to upgrade
		return nil
	}

	stdout, stderr, err = util.RunOVNNbctl("--if-exists", "get", "logical_router", ovnClusterRouter,
		"external_ids:k8s-ovn-topo-version")
	if err != nil {
		return fmt.Errorf("failed to determine the current version of OVN logical topology: stderr: %q, error: %v",
			stderr, err)
	} else if len(stdout) == 0 {
		klog.Infof("No version string found. The OVN topology is before versioning is introduced. Upgrade needed")
	} else {
		v, err := strconv.Atoi(stdout)
		if err != nil {
			return fmt.Errorf("invalid OVN topology version string for the cluster: %s", stdout)
		} else {
			ver = v
		}
	}

	// If current DB version is greater than OvnSingleJoinSwitchTopoVersion, no need to upgrade to single switch topology
	if ver < OvnSingleJoinSwitchTopoVersion {
		klog.Infof("Upgrading to Single Switch OVN Topology")
		err = oc.upgradeToSingleSwitchOVNTopology(existingNodes)
	}
	if err == nil && ver < OvnNamespacedDenyPGTopoVersion {
		klog.Infof("Upgrading to Namespace Deny PortGroup OVN Topology")
		err = oc.upgradeToNamespacedDenyPGOVNTopology(existingNodes)
	}
	return err
}

// enableOVNLogicalDataPathGroups sets an OVN flag to enable logical datapath
// groups on OVN 20.12 and later. The option is ignored if OVN doesn't
// understand it. Logical datapath groups reduce the size of the southbound
// database in large clusters. ovn-controllers should be upgraded to a version
// that supports them before the option is turned on by the master.
func (oc *Controller) enableOVNLogicalDatapathGroups() error {
	options, err := oc.mc.ovnNBClient.NBGlobalGetOptions()
	if err != nil {
		klog.Errorf("Failed to get NB global options: %v", err)
		return err
	}
	options["use_logical_dp_groups"] = "true"
	cmd, err := oc.mc.ovnNBClient.NBGlobalSetOptions(options)
	if err != nil {
		klog.Errorf("Failed to set NB global option to enable logical datapath groups: %v", err)
		return err
	}
	if err := cmd.Execute(); err != nil {
		klog.Errorf("Failed to enable logical datapath groups: %v", err)
		return err
	}

	return nil
}

// StartClusterMaster runs a subnet IPAM and a controller that watches arrival/departure
// of nodes in the cluster
// On an addition to the cluster (node create), a new subnet is created for it that will translate
// to creation of a logical switch (done by the node, but could be created here at the master process too)
// Upon deletion of a node, the switch will be deleted
//
// TODO: Verify that the cluster was not already called with a different global subnet
//  If true, then either quit or perform a complete reconfiguration of the cluster (recreate switches/routers with new subnet values)
func (oc *Controller) StartClusterMaster(masterNodeName string) error {
	klog.Infof("Starting cluster master for network %s", oc.netconf.Name)
	// The gateway router need to be connected to the distributed router via a per-node join switch.
	// We need a subnet allocator that allocates subnet for this per-node join switch.
	if !oc.netconf.NotDefault {

		if config.IPv4Mode {
			// initialize the subnet required for DNAT and SNAT ip for the shared gateway mode
			_, nodeLocalNatSubnetCIDR, _ := net.ParseCIDR(types.V4NodeLocalNATSubnet)
			oc.nodeLocalNatIPv4Allocator, _ = ipallocator.NewCIDRRange(nodeLocalNatSubnetCIDR)
			// set aside the first two IPs for the nextHop on the host and for distributed gateway port
			_ = oc.nodeLocalNatIPv4Allocator.Allocate(net.ParseIP(types.V4NodeLocalNATSubnetNextHop))
			_ = oc.nodeLocalNatIPv4Allocator.Allocate(net.ParseIP(types.V4NodeLocalDistributedGWPortIP))
		}
		if config.IPv6Mode {
			// initialize the subnet required for DNAT and SNAT ip for the shared gateway mode
			_, nodeLocalNatSubnetCIDR, _ := net.ParseCIDR(types.V6NodeLocalNATSubnet)
			oc.nodeLocalNatIPv6Allocator, _ = ipallocator.NewCIDRRange(nodeLocalNatSubnetCIDR)
			// set aside the first two IPs for the nextHop on the host and for distributed gateway port
			_ = oc.nodeLocalNatIPv6Allocator.Allocate(net.ParseIP(types.V6NodeLocalNATSubnetNextHop))
			_ = oc.nodeLocalNatIPv6Allocator.Allocate(net.ParseIP(types.V6NodeLocalDistributedGWPortIP))
		}
	}

	// Enable logical datapath groups for OVN 20.12 and later
	if err := oc.enableOVNLogicalDatapathGroups(); err != nil {
		return err
	}

	existingNodes, err := oc.mc.kube.GetNodes()
	if err != nil {
		klog.Errorf("Error in fetching nodes: %v", err)
		return err
	}
	klog.V(5).Infof("Existing number of nodes: %d", len(existingNodes.Items))
	err = oc.upgradeOVNTopology(existingNodes)
	if err != nil {
		klog.Errorf("Failed to upgrade OVN topology to version %d: %v", OvnCurrentTopologyVersion, err)
		return err
	}

	for _, ipnet := range oc.clusterSubnets {
		err := oc.masterSubnetAllocator.AddNetworkRange(ipnet.CIDR, ipnet.HostSubnetLength)
		if err != nil {
			return fmt.Errorf("failed to add network %s to networkAllocator for network %s", ipnet.CIDR.String(), oc.netconf.Name)
		}
		klog.V(5).Infof("Added network range %s to the allocator", ipnet.CIDR)
	}

	if !oc.netconf.NotDefault {
		if _, _, err := util.RunOVNNbctl("--columns=_uuid", "list", "port_group"); err != nil {
			klog.Fatal("OVN version too old; does not support port groups")
		}

		if oc.multicastSupport {
			if _, _, err := util.RunOVNSbctl("--columns=_uuid", "list", "IGMP_Group"); err != nil {
				klog.Warningf("Multicast support enabled, however version of OVN in use does not support IGMP Group. " +
					"Disabling Multicast Support")
				oc.multicastSupport = false
			}
		}
		if uuid, _, err := util.RunOVNNbctl("--data=bare", "--columns=_uuid", "find", "meter", "name="+types.OvnACLLoggingMeter); err == nil && uuid == "" {
			dropRate := strconv.Itoa(config.Logging.ACLLoggingRateLimit)
			if _, _, err := util.RunOVNNbctl("meter-add", types.OvnACLLoggingMeter, "drop", dropRate, "pktps"); err != nil {
				klog.Warningf("ACL logging support enabled, however acl-logging meter could not be created. Disabling ACL logging support")
				oc.aclLoggingEnabled = false
			}
		}
	} else {
		oc.multicastSupport = false
	}

	err = oc.SetupMaster(masterNodeName)
	if err != nil {
		klog.Errorf("Failed to setup master (%v)", err)
		return err
	}

	// default network only
	if !oc.netconf.NotDefault && config.HybridOverlay.Enabled {
		oc.hoMaster, err = hocontroller.NewMaster(
			oc.mc.kube,
			oc.mc.watchFactory.NodeInformer(),
			oc.mc.watchFactory.NamespaceInformer(),
			oc.mc.watchFactory.PodInformer(),
			oc.mc.ovnNBClient,
			oc.mc.ovnSBClient,
			informer.NewDefaultEventHandler,
		)
		if err != nil {
			return fmt.Errorf("failed to set up hybrid overlay master: %v", err)
		}
	}

	return nil
}

// SetupMaster creates the central router and load-balancers for the network
func (oc *Controller) SetupMaster(masterNodeName string) error {
	netPrefix := util.GetNetworkPrefix(oc.netconf.Name)
	clusterRouterName := netPrefix + types.OVNClusterRouter
	// Create a single common distributed router for the cluster.
	cmdArgs := []string{"--", "--may-exist", "lr-add", clusterRouterName,
		"--", "set", "logical_router", clusterRouterName, "external_ids:k8s-cluster-router=yes",
		fmt.Sprintf("external_ids:k8s-ovn-topo-version=%d", OvnCurrentTopologyVersion)}
	if oc.netconf.NotDefault {
		cmdArgs = append(cmdArgs, "external_ids:network_name="+oc.netconf.Name)
	}
	stdout, stderr, err := util.RunOVNNbctl(cmdArgs...)
	if err != nil {
		klog.Errorf("Failed to create a single common distributed router for network %s, "+
			"stdout: %q, stderr: %q, error: %v", oc.netconf.Name, stdout, stderr, err)
		return err
	}

	if oc.netconf.NotDefault {
		return nil
	}

	if err := addDistributedGWPort(); err != nil {
		return err
	}

	// Determine SCTP support
	oc.SCTPSupport, err = util.DetectSCTPSupport()
	if err != nil {
		return err
	}
	if !oc.SCTPSupport {
		klog.Warningf("SCTP unsupported by this version of OVN. Kubernetes service creation with SCTP will not work ")
	} else {
		klog.Info("SCTP support detected in OVN")
	}

	// Create a cluster-wide port group that all logical switch ports are part of
	oc.clusterPortGroupUUID, err = createPortGroup(clusterPortGroupName, clusterPortGroupName)
	if err != nil {
		klog.Errorf("Failed to create cluster port group: %v", err)
		return err
	}

	// Create a cluster-wide port group with all node-to-cluster router
	// logical switch ports.  Currently the only user is multicast but it might
	// be used for other features in the future.
	oc.clusterRtrPortGroupUUID, err = createPortGroup(clusterRtrPortGroupName, clusterRtrPortGroupName)
	if err != nil {
		klog.Errorf("Failed to create cluster port group: %v", err)
		return err
	}

	// If supported, enable IGMP relay on the router to forward multicast
	// traffic between nodes.
	if oc.multicastSupport {
		stdout, stderr, err = util.RunOVNNbctl("--", "set", "logical_router",
			clusterRouterName, "options:mcast_relay=\"true\"")
		if err != nil {
			klog.Errorf("Failed to enable IGMP relay on the cluster router, "+
				"stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
			return err
		}

		// Drop IP multicast globally. Multicast is allowed only if explicitly
		// enabled in a namespace.
		if err := oc.createDefaultDenyMulticastPolicy(); err != nil {
			klog.Errorf("Failed to create default deny multicast policy, error: %v", err)
			return err
		}

		// Allow IP multicast from node switch to cluster router and from
		// cluster router to node switch.
		if err := oc.createDefaultAllowMulticastPolicy(); err != nil {
			klog.Errorf("Failed to create default deny multicast policy, error: %v", err)
			return err
		}
	}

	// Create load balancers

	// If we enable idling we have to set the option before creating the loadbalancers
	if config.Kubernetes.OVNEmptyLbEvents {
		_, _, err := util.RunOVNNbctl("set", "nb_global", ".", "options:controller_event=true")
		if err != nil {
			klog.Error("Unable to enable controller events. Unidling not possible")
			return err
		}
	}

	// Create 3 load-balancers for east-west traffic for UDP, TCP, SCTP
	oc.TCPLoadBalancerUUID, stderr, err = util.RunOVNNbctl("--data=bare", "--no-heading", "--columns=_uuid", "find", "load_balancer", "external_ids:k8s-cluster-lb-tcp=yes")
	if err != nil {
		klog.Errorf("Failed to get tcp load balancer, stderr: %q, error: %v", stderr, err)
		return err
	}

	if oc.TCPLoadBalancerUUID == "" {
		oc.TCPLoadBalancerUUID, stderr, err = util.RunOVNNbctl("--", "create", "load_balancer", "external_ids:k8s-cluster-lb-tcp=yes", "protocol=tcp")
		if err != nil {
			klog.Errorf("Failed to create tcp load balancer, stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
			return err
		}
	}

	oc.UDPLoadBalancerUUID, stderr, err = util.RunOVNNbctl("--data=bare", "--no-heading", "--columns=_uuid", "find", "load_balancer", "external_ids:k8s-cluster-lb-udp=yes")
	if err != nil {
		klog.Errorf("Failed to get udp load balancer, stderr: %q, error: %v", stderr, err)
		return err
	}
	if oc.UDPLoadBalancerUUID == "" {
		oc.UDPLoadBalancerUUID, stderr, err = util.RunOVNNbctl("--", "create", "load_balancer", "external_ids:k8s-cluster-lb-udp=yes", "protocol=udp")
		if err != nil {
			klog.Errorf("Failed to create udp load balancer, stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
			return err
		}
	}

	oc.SCTPLoadBalancerUUID, stderr, err = util.RunOVNNbctl("--data=bare", "--no-heading", "--columns=_uuid", "find", "load_balancer", "external_ids:k8s-cluster-lb-sctp=yes")
	if err != nil {
		klog.Errorf("Failed to get sctp load balancer, stderr: %q, error: %v", stderr, err)
		return err
	}
	if oc.SCTPLoadBalancerUUID == "" && oc.SCTPSupport {
		oc.SCTPLoadBalancerUUID, stderr, err = util.RunOVNNbctl("--", "create", "load_balancer", "external_ids:k8s-cluster-lb-sctp=yes", "protocol=sctp")
		if err != nil {
			klog.Errorf("Failed to create sctp load balancer, stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
			return err
		}
	}

	// Initialize the OVNJoinSwitch switch IP manager
	// The OVNJoinSwitch will be allocated IP addresses in the range 100.64.0.0/16 or fd98::/64.
	oc.joinSwIPManager, err = initJoinLogicalSwitchIPManager()
	if err != nil {
		return err
	}

	// Allocate IPs for logical router port "GwRouterToJoinSwitchPrefix + OVNClusterRouter". This should always
	// allocate the first IPs in the join switch subnets
	gwLRPIfAddrs, err := oc.joinSwIPManager.ensureJoinLRPIPs(clusterRouterName)
	if err != nil {
		return fmt.Errorf("failed to allocate join switch IP address connected to %s: %v", clusterRouterName, err)
	}

	// Create OVNJoinSwitch that will be used to connect gateway routers to the distributed router.
	joinSwitchName := netPrefix + types.OVNJoinSwitch
	cmdArgs = []string{"--may-exist", "ls-add", joinSwitchName}
	if oc.netconf.NotDefault {
		cmdArgs = append(cmdArgs, "--", "set", "logical_switch", joinSwitchName, "external_ids:network_name="+oc.netconf.Name)
	}
	_, stderr, err = util.RunOVNNbctl(cmdArgs...)
	if err != nil {
		klog.Errorf("Failed to create logical switch %s, stderr: %q, error: %v", types.OVNJoinSwitch, stderr, err)
		return err
	}

	// Connect the distributed router to OVNJoinSwitch.
	drSwitchPort := types.JoinSwitchToGWRouterPrefix + types.OVNClusterRouter
	drRouterPort := types.GWRouterToJoinSwitchPrefix + types.OVNClusterRouter
	gwLRPMAC := util.IPAddrToHWAddr(gwLRPIfAddrs[0].IP)
	args := []string{
		"--", "--if-exists", "lrp-del", drRouterPort,
		"--", "lrp-add", clusterRouterName, drRouterPort, gwLRPMAC.String(),
	}
	for _, gwLRPIfAddr := range gwLRPIfAddrs {
		args = append(args, gwLRPIfAddr.String())
	}
	_, stderr, err = util.RunOVNNbctl(args...)
	if err != nil {
		klog.Errorf("Failed to add logical router port %s, stderr: %q, error: %v", drRouterPort, stderr, err)
		return err
	}

	// Connect the switch OVNJoinSwitch to the router.
	_, stderr, err = util.RunOVNNbctl("--may-exist", "lsp-add", joinSwitchName,
		drSwitchPort, "--", "set", "logical_switch_port", drSwitchPort, "type=router",
		"options:router-port="+drRouterPort, "addresses=router")
	if err != nil {
		klog.Errorf("Failed to add router-type logical switch port %s to %s, stderr: %q, error: %v",
			drSwitchPort, joinSwitchName, stderr, err)
		return err
	}
	return nil
}

// deleteMaster delete the central router and switch for the network
func (oc *Controller) deleteMaster() {
	if !oc.netconf.NotDefault {
		// delete a logical switch called "join" that will be used to connect gateway routers to the distributed router.
		// The "join" switch will be allocated IP addresses in the range 100.64.0.0/16.
		stdout, stderr, err := util.RunOVNNbctl("--if-exist", "ls-del", "join")
		if err != nil {
			klog.Errorf("Failed to delete logical switch called \"join"+"\", stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
		}
	}

	netPrefix := util.GetNetworkPrefix(oc.netconf.Name)
	clusterRouter := netPrefix + types.OVNClusterRouter

	// delete the single common distributed router for the cluster.
	stdout, stderr, err := util.RunOVNNbctl("--if-exist", "lr-del", clusterRouter)
	if err != nil {
		klog.Errorf("Failed to delete a distributed %s router for the cluster, "+
			"stdout: %q, stderr: %q, error: %v", clusterRouter, stdout, stderr, err)
	}
}

func addNodeLogicalSwitchPort(logicalSwitch, portName, portType, addresses, options string) (string, error) {
	stdout, stderr, err := util.RunOVNNbctl("--", "--may-exist", "lsp-add", logicalSwitch, portName,
		"--", "lsp-set-type", portName, portType,
		"--", "lsp-set-options", portName, options,
		"--", "lsp-set-addresses", portName, addresses)
	if err != nil {
		klog.Errorf("Failed to add logical port %s to switch %s, stdout: %q, stderr: %q, error: %v", portName, logicalSwitch, stdout, stderr, err)
		return "", err
	}

	// UUID must be retrieved separately from the lsp-add transaction since
	// (as of OVN 2.12) a bogus UUID is returned if they are part of the same
	// transaction.
	uuid, stderr, err := util.RunOVNNbctl("get", "logical_switch_port", portName, "_uuid")
	if err != nil {
		klog.Errorf("Error getting UUID for logical port %s "+
			"stdout: %q, stderr: %q (%v)", portName, uuid, stderr, err)
		return "", err
	}
	if uuid == "" {
		return uuid, fmt.Errorf("invalid logical port %s uuid", portName)
	}
	return uuid, nil
}

func (oc *Controller) syncNodeManagementPort(node *kapi.Node, hostSubnets []*net.IPNet) error {
	// management port is not needed for non-default network
	if oc.netconf.NotDefault {
		return nil
	}

	macAddress, err := util.ParseNodeManagementPortMACAddress(node)
	if err != nil {
		return err
	}

	if hostSubnets == nil {
		hostSubnets, err = util.ParseNodeHostSubnetAnnotation(node, oc.netconf.Name)
		if err != nil {
			return err
		}
	}

	var v4Subnet *net.IPNet
	addresses := macAddress.String()
	for _, hostSubnet := range hostSubnets {
		mgmtIfAddr := util.GetNodeManagementIfAddr(hostSubnet)
		addresses += " " + mgmtIfAddr.IP.String()

		if err := addAllowACLFromNode(node.Name, mgmtIfAddr.IP, oc.mc.ovnNBClient); err != nil {
			return err
		}

		if !utilnet.IsIPv6CIDR(hostSubnet) {
			v4Subnet = hostSubnet
		}

		if config.Gateway.Mode == config.GatewayModeLocal {
			stdout, stderr, err := util.RunOVNNbctl("--may-exist",
				"--policy=src-ip", "lr-route-add", types.OVNClusterRouter,
				hostSubnet.String(), mgmtIfAddr.IP.String())
			if err != nil {
				return fmt.Errorf("failed to add source IP address based "+
					"routes in distributed router %s, stdout: %q, "+
					"stderr: %q, error: %v", types.OVNClusterRouter, stdout, stderr, err)
			}
		}
	}

	// Create this node's management logical port on the node switch
	portName := types.K8sPrefix + node.Name
	uuid, err := addNodeLogicalSwitchPort(node.Name, portName, "", addresses, "")
	if err != nil {
		return err
	}

	if err := addToPortGroup(clusterPortGroupName, &lpInfo{
		uuid: uuid,
		name: portName,
	}); err != nil {
		klog.Errorf(err.Error())
		return err
	}

	if v4Subnet != nil {
		if err := util.UpdateNodeSwitchExcludeIPs(node.Name, v4Subnet); err != nil {
			return err
		}
	}

	return nil
}

func (oc *Controller) syncGatewayLogicalNetwork(node *kapi.Node, l3GatewayConfig *util.L3GatewayConfig,
	hostSubnets []*net.IPNet) error {
	var err error
	var gwLRPIPs, clusterSubnets []*net.IPNet

	if oc.netconf.NotDefault {
		return nil
	}

	for _, clusterSubnet := range oc.clusterSubnets {
		clusterSubnets = append(clusterSubnets, clusterSubnet.CIDR)
	}

	gwLRPIPs, err = oc.joinSwIPManager.ensureJoinLRPIPs(node.Name)
	if err != nil {
		return fmt.Errorf("failed to allocate join switch port IP address for node %s: %v", node.Name, err)
	}

	drLRPIPs, _ := oc.joinSwIPManager.getJoinLRPCacheIPs(types.OVNClusterRouter)
	err = gatewayInit(node.Name, clusterSubnets, hostSubnets, l3GatewayConfig, oc.SCTPSupport, gwLRPIPs, drLRPIPs)
	if err != nil {
		return fmt.Errorf("failed to init shared interface gateway: %v", err)
	}

	// in the case of shared gateway mode, we need to setup
	// 1. two policy based routes to steer traffic to the k8s node IP
	// 	  - from the management port via the node_local_switch's localnet port
	//    - from the hostsubnet via management port
	// 2. a dnat_and_snat nat entry to SNAT the traffic from the management port
	subnets, err := util.ParseNodeHostSubnetAnnotation(node, oc.netconf.Name)
	if err != nil {
		return fmt.Errorf("failed to get host subnets for network %s and node %s: %v", oc.netconf.Name, node.Name, err)
	}
	mpMAC, err := util.ParseNodeManagementPortMACAddress(node)
	if err != nil {
		return err
	}
	for _, subnet := range subnets {
		hostIfAddr := util.GetNodeManagementIfAddr(subnet)
		l3GatewayConfigIP, err := util.MatchIPNetFamily(utilnet.IsIPv6(hostIfAddr.IP), l3GatewayConfig.IPAddresses)
		if err != nil {
			return err
		}
		if err := addPolicyBasedRoutes(node.Name, hostIfAddr.IP.String(), l3GatewayConfigIP); err != nil {
			return err
		}

		if err := oc.addNodeLocalNatEntries(node, mpMAC.String(), hostIfAddr); err != nil {
			return err
		}
	}

	if l3GatewayConfig.NodePortEnable {
		err = oc.handleNodePortLB(node)
	} else {
		// nodePort disabled, delete gateway load balancers for this node.
		gatewayRouter := "GR_" + node.Name
		for _, proto := range []kapi.Protocol{kapi.ProtocolTCP, kapi.ProtocolUDP, kapi.ProtocolSCTP} {
			lbUUID, _ := oc.getGatewayLoadBalancer(gatewayRouter, proto)
			if lbUUID != "" {
				_, _, err := util.RunOVNNbctl("--if-exists", "destroy", "load_balancer", lbUUID)
				if err != nil {
					klog.Errorf("Failed to destroy %s load balancer for gateway %s: %v", proto, gatewayRouter, err)
				}
			}
		}
	}

	return err
}

func (oc *Controller) ensureNodeLogicalNetwork(nodeName string, hostSubnets []*net.IPNet) error {
	// logical router port MAC is based on IPv4 subnet if there is one, else IPv6
	var nodeLRPMAC net.HardwareAddr
	for _, hostSubnet := range hostSubnets {
		gwIfAddr := util.GetNodeGatewayIfAddr(hostSubnet)
		nodeLRPMAC = util.IPAddrToHWAddr(gwIfAddr.IP)
		if !utilnet.IsIPv6CIDR(hostSubnet) {
			break
		}
	}

	netPrefix := util.GetNetworkPrefix(oc.netconf.Name)
	switchName := netPrefix + nodeName
	clusterRouterName := netPrefix + types.OVNClusterRouter

	lrpArgs := []string{
		"--if-exists", "lrp-del", types.RouterToSwitchPrefix + switchName,
		"--", "lrp-add", clusterRouterName, types.RouterToSwitchPrefix + switchName,
		nodeLRPMAC.String(),
	}

	lsArgs := []string{
		"--may-exist",
		"ls-add", switchName,
		"--", "set", "logical_switch", switchName,
	}

	if oc.netconf.NotDefault {
		lsArgs = append(lsArgs, "external_ids:network_name="+oc.netconf.Name)
	}

	var v4Gateway, v6Gateway net.IP
	for _, hostSubnet := range hostSubnets {
		gwIfAddr := util.GetNodeGatewayIfAddr(hostSubnet)
		lrpArgs = append(lrpArgs, gwIfAddr.String())

		if utilnet.IsIPv6CIDR(hostSubnet) {
			v6Gateway = gwIfAddr.IP

			lsArgs = append(lsArgs,
				"other-config:ipv6_prefix="+hostSubnet.IP.String(),
			)
		} else {
			v4Gateway = gwIfAddr.IP

			mgmtIfAddr := util.GetNodeManagementIfAddr(hostSubnet)
			excludeIPs := mgmtIfAddr.IP.String()
			if !oc.netconf.NotDefault && config.HybridOverlay.Enabled {
				hybridOverlayIfAddr := util.GetNodeHybridOverlayIfAddr(hostSubnet)
				excludeIPs += ".." + hybridOverlayIfAddr.IP.String()
			}
			lsArgs = append(lsArgs,
				"other-config:subnet="+hostSubnet.String(),
				"other-config:exclude_ips="+excludeIPs,
			)
		}
	}

	// Create a router port and provide it the first address on the node's host subnet
	_, stderr, err := util.RunOVNNbctl(lrpArgs...)
	if err != nil {
		klog.Errorf("Failed to add logical port to router, stderr: %q, error: %v", stderr, err)
		return err
	}

	// Create a logical switch and set its subnet.
	stdout, stderr, err := util.RunOVNNbctl(lsArgs...)
	if err != nil {
		klog.Errorf("Failed to create a logical switch %v, stdout: %q, stderr: %q, error: %v", switchName, stdout, stderr, err)
		return err
	}

	// If supported, enable IGMP/MLD snooping and querier on the node.
	if oc.multicastSupport {
		stdout, stderr, err = util.RunOVNNbctl("set", "logical_switch",
			switchName, "other-config:mcast_snoop=\"true\"")
		if err != nil {
			klog.Errorf("Failed to enable IGMP on logical switch %v, stdout: %q, stderr: %q, error: %v",
				switchName, stdout, stderr, err)
			return err
		}

		// Configure IGMP/MLD querier if the gateway IP address is known.
		// Otherwise disable it.
		if v4Gateway != nil || v6Gateway != nil {
			if v4Gateway != nil {
				stdout, stderr, err = util.RunOVNNbctl("set", "logical_switch",
					switchName, "other-config:mcast_querier=\"true\"",
					"other-config:mcast_eth_src=\""+nodeLRPMAC.String()+"\"",
					"other-config:mcast_ip4_src=\""+v4Gateway.String()+"\"")
				if err != nil {
					klog.Errorf("Failed to enable IGMP Querier on logical switch %v, stdout: %q, stderr: %q, error: %v",
						switchName, stdout, stderr, err)
					return err
				}
			}
			if v6Gateway != nil {
				stdout, stderr, err = util.RunOVNNbctl("set", "logical_switch",
					switchName, "other-config:mcast_querier=\"true\"",
					"other-config:mcast_eth_src=\""+nodeLRPMAC.String()+"\"",
					"other-config:mcast_ip6_src=\""+v6Gateway.String()+"\"")
				if err != nil {
					klog.Errorf("Failed to enable MLD Querier on logical switch %v, stdout: %q, stderr: %q, error: %v",
						switchName, stdout, stderr, err)
					return err
				}
			}
		} else {
			stdout, stderr, err = util.RunOVNNbctl("set", "logical_switch",
				switchName, "other-config:mcast_querier=\"false\"")
			if err != nil {
				klog.Errorf("Failed to disable IGMP/MLD Querier on logical switch %v, stdout: %q, stderr: %q, error: %v",
					switchName, stdout, stderr, err)
				return err
			}
			klog.Infof("Disabled IGMP/MLD Querier on logical switch %v (No IPv4/IPv6 Source IP available)",
				switchName)
		}
	}

	// Connect the switch to the router.
	nodeSwToRtrUUID, err := addNodeLogicalSwitchPort(switchName, types.SwitchToRouterPrefix+switchName,
		"router", nodeLRPMAC.String(), "router-port="+types.RouterToSwitchPrefix+switchName)
	if err != nil {
		klog.Errorf("Failed to add logical port to switch, stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
		return err
	}

	if !oc.netconf.NotDefault {
		if err = addToPortGroup(clusterRtrPortGroupName, &lpInfo{
			uuid: nodeSwToRtrUUID,
			name: types.SwitchToRouterPrefix + switchName,
		}); err != nil {
			klog.Errorf(err.Error())
			return err
		}

		// Add our cluster TCP and UDP load balancers to the node switch
		if oc.TCPLoadBalancerUUID == "" {
			return fmt.Errorf("TCP cluster load balancer not created")
		}
		stdout, stderr, err = util.RunOVNNbctl("set", "logical_switch", switchName, "load_balancer="+oc.TCPLoadBalancerUUID)
		if err != nil {
			klog.Errorf("Failed to set logical switch %v's load balancer, stdout: %q, stderr: %q, error: %v", switchName, stdout, stderr, err)
			return err
		}

		if oc.UDPLoadBalancerUUID == "" {
			return fmt.Errorf("UDP cluster load balancer not created")
		}
		stdout, stderr, err = util.RunOVNNbctl("add", "logical_switch", switchName, "load_balancer", oc.UDPLoadBalancerUUID)
		if err != nil {
			klog.Errorf("Failed to add logical switch %v's load balancer, stdout: %q, stderr: %q, error: %v", switchName, stdout, stderr, err)
			return err
		}

		if oc.SCTPSupport {
			if oc.SCTPLoadBalancerUUID == "" {
				return fmt.Errorf("SCTP cluster load balancer not created")
			}
			stdout, stderr, err = util.RunOVNNbctl("add", "logical_switch", switchName, "load_balancer", oc.SCTPLoadBalancerUUID)
			if err != nil {
				klog.Errorf("Failed to add logical switch %v's load balancer, stdout: %q, stderr: %q, error: %v", switchName, stdout, stderr, err)
				return err
			}
		}
	}
	// Add the node to the logical switch cache
	return oc.lsManager.AddNode(nodeName, hostSubnets)
}

func isError(err error) bool {
	return true
}

func (oc *Controller) updateNodeAnnotationWithRetry(nodeName string, hostSubnets []*net.IPNet) error {
	//// FIXME: the real solution is to reconcile the node object. Once we have a work-queue based
	//// implementation where we can add the item back to the work queue when it fails to
	//// reconcile, we can get rid of the PollImmediate.
	//// Retry if it fails because of potential conflict, or temporary API server down
	resultErr := retry.OnError(retry.DefaultBackoff, isError, func() error {
		// Informer cache should not be mutated, so get a copy of the object
		node, err := oc.mc.kube.GetNode(nodeName)
		if err != nil {
			return err
		}

		cnode := node.DeepCopy()
		err = util.UpdateNodeHostSubnetAnnotation(cnode.Annotations, hostSubnets, oc.netconf.Name)
		if err != nil {
			return fmt.Errorf("failed to update node %q annotation for network %s subnet %s",
				node.Name, oc.netconf.Name, util.JoinIPNets(hostSubnets, ","))
		}
		return oc.mc.kube.UpdateNode(cnode)
	})
	if resultErr != nil {
		return fmt.Errorf("failed to update node %s annotation for network %s", nodeName, oc.netconf.Name)
	}
	return nil
}

func (oc *Controller) allocateNodeSubnets(node *kapi.Node) ([]*net.IPNet, []*net.IPNet, error) {
	hostSubnets, err := util.ParseNodeHostSubnetAnnotation(node, oc.netconf.Name)
	if err != nil {
		// Log the error and try to allocate new subnets
		klog.Infof("Failed to get node %s host subnets annotations: %v", node.Name, err)
	}
	allocatedSubnets := []*net.IPNet{}

	// OVN can work in single-stack or dual-stack only.
	currentHostSubnets := len(hostSubnets)
	expectedHostSubnets := 1
	// if dual-stack mode we expect one subnet per each IP family
	if config.IPv4Mode && config.IPv6Mode {
		expectedHostSubnets = 2
	}

	// node already has the expected subnets annotated
	// assume IP families match, i.e. no IPv6 config and node annotation IPv4
	if expectedHostSubnets == currentHostSubnets {
		klog.Infof("Allocated Subnets %v on Node %s", hostSubnets, node.Name)
		return hostSubnets, allocatedSubnets, nil
	}

	// Node doesn't have the expected subnets annotated
	// it may happen it has more subnets assigned that configured in OVN
	// like in a dual-stack to single-stack conversion
	// or that it needs to allocate new subnet because it is a new node
	// or has been converted from single-stack to dual-stack
	klog.Infof("Expected %d subnets on node %s, found %d: %v",
		expectedHostSubnets, node.Name, currentHostSubnets, hostSubnets)
	// release unexpected subnets
	// filter in place slice
	// https://github.com/golang/go/wiki/SliceTricks#filter-in-place
	foundIPv4 := false
	foundIPv6 := false
	n := 0
	for _, subnet := range hostSubnets {
		// if the subnet is not going to be reused release it
		if config.IPv4Mode && utilnet.IsIPv4CIDR(subnet) && !foundIPv4 {
			klog.V(5).Infof("Valid IPv4 allocated subnet %v on node %s", subnet, node.Name)
			hostSubnets[n] = subnet
			n++
			foundIPv4 = true
			continue
		}
		if config.IPv6Mode && utilnet.IsIPv6CIDR(subnet) && !foundIPv6 {
			klog.V(5).Infof("Valid IPv6 allocated subnet %v on node %s", subnet, node.Name)
			hostSubnets[n] = subnet
			n++
			foundIPv6 = true
			continue
		}
		// this subnet is no longer needed
		klog.V(5).Infof("Releasing subnet %v on node %s", subnet, node.Name)
		err = oc.masterSubnetAllocator.ReleaseNetwork(subnet)
		if err != nil {
			klog.Warningf("Error releasing subnet %v on node %s", subnet, node.Name)
		}
	}
	// recreate hostSubnets with the valid subnets
	hostSubnets = hostSubnets[:n]
	// allocate new subnets if needed
	if config.IPv4Mode && !foundIPv4 {
		allocatedHostSubnet, err := oc.masterSubnetAllocator.AllocateIPv4Network()
		if err != nil {
			return nil, nil, fmt.Errorf("error allocating network for node %s: %v", node.Name, err)
		}
		// the allocator returns nil if it can't provide a subnet
		// we should filter them out or they will be appended to the slice
		if allocatedHostSubnet != nil {
			klog.V(5).Infof("Allocating subnet %v on node %s", allocatedHostSubnet, node.Name)
			allocatedSubnets = append(allocatedSubnets, allocatedHostSubnet)
			// Release the allocation on error
			defer func() {
				if err != nil {
					klog.Warningf("Releasing subnet %v on node %s: %v", allocatedHostSubnet, node.Name, err)
					errR := oc.masterSubnetAllocator.ReleaseNetwork(allocatedHostSubnet)
					if errR != nil {
						klog.Warningf("Error releasing subnet %v on node %s", allocatedHostSubnet, node.Name)
					}
				}
			}()
		}
	}
	if config.IPv6Mode && !foundIPv6 {
		allocatedHostSubnet, err := oc.masterSubnetAllocator.AllocateIPv6Network()
		if err != nil {
			return nil, nil, fmt.Errorf("error allocating network for node %s: %v", node.Name, err)
		}
		// the allocator returns nil if it can't provide a subnet
		// we should filter them out or they will be appended to the slice
		if allocatedHostSubnet != nil {
			klog.V(5).Infof("Allocating subnet %v on node %s", allocatedHostSubnet, node.Name)
			allocatedSubnets = append(allocatedSubnets, allocatedHostSubnet)
		}
	}
	// check if we were able to allocate the new subnets require
	// this can only happen if OVN is not configured correctly
	// so it will require a reconfiguration and restart.
	wantedSubnets := expectedHostSubnets - currentHostSubnets
	if wantedSubnets > 0 && len(allocatedSubnets) != wantedSubnets {
		return nil, nil, fmt.Errorf("error allocating networks for node %s: %d subnets expected only new %d subnets allocated",
			node.Name, expectedHostSubnets, len(allocatedSubnets))
	}
	hostSubnets = append(hostSubnets, allocatedSubnets...)
	klog.Infof("Allocated Subnets %v on Node %s", hostSubnets, node.Name)
	return hostSubnets, allocatedSubnets, nil
}

func (oc *Controller) addNode(node *kapi.Node) ([]*net.IPNet, error) {
	oc.clearInitialNodeNetworkUnavailableCondition(node, nil)
	hostSubnets, allocatedSubnets, err := oc.allocateNodeSubnets(node)
	if err != nil {
		return nil, err
	}
	// Release the allocation on error
	defer func() {
		if err != nil {
			for _, allocatedSubnet := range allocatedSubnets {
				klog.Warningf("Releasing subnet %v on node %s: %v", allocatedSubnet, node.Name, err)
				errR := oc.masterSubnetAllocator.ReleaseNetwork(allocatedSubnet)
				if errR != nil {
					klog.Warningf("Error releasing subnet %v on node %s", allocatedSubnet, node.Name)
				}
			}
		}
	}()
	// Ensure that the node's logical network has been created
	err = oc.ensureNodeLogicalNetwork(node.Name, hostSubnets)
	if err != nil {
		return nil, err
	}

	// Set the HostSubnet annotation on the node object to signal
	// to nodes that their logical infrastructure is set up and they can
	// proceed with their initialization
	err = oc.updateNodeAnnotationWithRetry(node.Name, hostSubnets)
	if err != nil {
		return nil, err
	}

	// If node annotation succeeds, update the used subnet count
	for _, hostSubnet := range hostSubnets {
		util.UpdateUsedHostSubnetsCount(hostSubnet,
			&oc.v4HostSubnetsUsed,
			&oc.v6HostSubnetsUsed, true)
	}
	if !oc.netconf.NotDefault {
		metrics.RecordSubnetUsage(oc.v4HostSubnetsUsed, oc.v6HostSubnetsUsed)
	}

	return hostSubnets, nil
}

func (oc *Controller) deleteNodeHostSubnet(nodeName string, subnet *net.IPNet) error {
	err := oc.masterSubnetAllocator.ReleaseNetwork(subnet)
	if err != nil {
		return fmt.Errorf("error deleting subnet %v for node %q: %s", subnet, nodeName, err)
	}
	klog.Infof("Deleted HostSubnet %v for node %s", subnet, nodeName)
	return nil
}

func (oc *Controller) deleteNodeLogicalNetwork(nodeName string) error {
	// Remove the logical switch associated with the node
	netPrefix := util.GetNetworkPrefix(oc.netconf.Name)
	switchName := netPrefix + nodeName
	if _, stderr, err := util.RunOVNNbctl("--if-exist", "ls-del", switchName); err != nil {
		return fmt.Errorf("failed to delete logical switch %s, "+
			"stderr: %q, error: %v", switchName, stderr, err)
	}

	// Remove the patch port that connects distributed router to node's logical switch
	if _, stderr, err := util.RunOVNNbctl("--if-exist", "lrp-del", types.RouterToSwitchPrefix+switchName); err != nil {
		return fmt.Errorf("failed to delete logical router port %s%s, "+
			"stderr: %q, error: %v", types.RouterToSwitchPrefix, switchName, stderr, err)
	}

	return nil
}

func (oc *Controller) deleteNode(nodeName string, hostSubnets []*net.IPNet,
	nodeLocalNatIPs []net.IP) error {
	// Clean up as much as we can but don't hard error
	for _, hostSubnet := range hostSubnets {
		if err := oc.deleteNodeHostSubnet(nodeName, hostSubnet); err != nil {
			klog.Errorf("Error deleting node %s HostSubnet %v: %v", nodeName, hostSubnet, err)
		} else {
			util.UpdateUsedHostSubnetsCount(hostSubnet, &oc.v4HostSubnetsUsed, &oc.v6HostSubnetsUsed, false)
		}
	}
	if !oc.netconf.NotDefault {
		// update metrics
		metrics.RecordSubnetUsage(oc.v4HostSubnetsUsed, oc.v6HostSubnetsUsed)
	}

	if !oc.netconf.NotDefault {
		for _, nodeLocalNatIP := range nodeLocalNatIPs {
			var err error
			if utilnet.IsIPv6(nodeLocalNatIP) {
				err = oc.nodeLocalNatIPv6Allocator.Release(nodeLocalNatIP)
			} else {
				err = oc.nodeLocalNatIPv4Allocator.Release(nodeLocalNatIP)
			}
			if err != nil {
				klog.Errorf("Error deleting node %s's node local NAT IP %s from %v: %v", nodeName, nodeLocalNatIP, nodeLocalNatIPs, err)
			}
		}
	}

	if err := oc.deleteNodeLogicalNetwork(nodeName); err != nil {
		klog.Errorf("Error deleting node %s logical network: %v", nodeName, err)
	}

	if !oc.netconf.NotDefault {
		if err := gatewayCleanup(nodeName); err != nil {
			return fmt.Errorf("failed to clean up node %s gateway: (%v)", nodeName, err)
		}

		if err := oc.joinSwIPManager.releaseJoinLRPIPs(nodeName); err != nil {
			return err
		}

		if err := oc.deleteNodeChassis(nodeName); err != nil {
			return err
		}
	}

	return nil
}

// OVN uses an overlay and doesn't need GCE Routes, we need to
// clear the NetworkUnavailable condition that kubelet adds to initial node
// status when using GCE (done here: https://github.com/kubernetes/kubernetes/blob/master/pkg/controller/cloud/node_controller.go#L237).
// See discussion surrounding this here: https://github.com/kubernetes/kubernetes/pull/34398.
// TODO: make upstream kubelet more flexible with overlays and GCE so this
// condition doesn't get added for network plugins that don't want it, and then
// we can remove this function.
func (oc *Controller) clearInitialNodeNetworkUnavailableCondition(origNode, newNode *kapi.Node) {
	// If it is not a Cloud Provider node, then nothing to do.
	if origNode.Spec.ProviderID == "" {
		return
	}
	// if newNode is not nil, then we are called from UpdateFunc()
	if newNode != nil && reflect.DeepEqual(origNode.Status.Conditions, newNode.Status.Conditions) {
		return
	}

	cleared := false
	resultErr := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var err error

		oldNode, err := oc.mc.kube.GetNode(origNode.Name)
		if err != nil {
			return err
		}
		// Informer cache should not be mutated, so get a copy of the object
		node := oldNode.DeepCopy()

		for i := range node.Status.Conditions {
			if node.Status.Conditions[i].Type == kapi.NodeNetworkUnavailable {
				condition := &node.Status.Conditions[i]
				if condition.Status != kapi.ConditionFalse && condition.Reason == "NoRouteCreated" {
					condition.Status = kapi.ConditionFalse
					condition.Reason = "RouteCreated"
					condition.Message = "ovn-kube cleared kubelet-set NoRouteCreated"
					condition.LastTransitionTime = metav1.Now()
					if err = oc.mc.kube.UpdateNodeStatus(node); err == nil {
						cleared = true
					}
				}
				break
			}
		}
		return err
	})
	if resultErr != nil {
		klog.Errorf("Status update failed for local node %s: %v", origNode.Name, resultErr)
	} else if cleared {
		klog.Infof("Cleared node NetworkUnavailable/NoRouteCreated condition for %s", origNode.Name)
	}
}

// delete chassis of the given nodeName/chassisName map
func deleteChassis(ovnSBClient goovn.Client, chassisMap map[string]string) {
	cmds := make([]*goovn.OvnCommand, 0, len(chassisMap))
	for chassisHostname, chassisName := range chassisMap {
		if chassisName != "" {
			klog.Infof("Deleting stale chassis %s (%s)", chassisHostname, chassisName)
			cmd, err := ovnSBClient.ChassisDel(chassisName)
			if err != nil {
				klog.Errorf("Unable to create the ChassisDel command for chassis: %s from the sbdb", chassisName)
			} else {
				cmds = append(cmds, cmd)
			}
		}
	}

	if len(cmds) != 0 {
		if err := ovnSBClient.Execute(cmds...); err != nil {
			klog.Errorf("Failed to delete chassis for node/chassis map %v: error: %v", chassisMap, err)
		}
	}
}

// this is the worker function that does the periodic sync of nodes from kube API
// and sbdb and deletes chassis that are stale
func (oc *Controller) syncNodesPeriodic() {
	if oc.netconf.NotDefault {
		return
	}

	//node names is a slice of all node names
	nodes, err := oc.mc.kube.GetNodes()
	if err != nil {
		klog.Errorf("Error getting existing nodes from kube API: %v", err)
		return
	}

	nodeNames := make([]string, 0, len(nodes.Items))

	for _, node := range nodes.Items {
		nodeNames = append(nodeNames, node.Name)
	}

	chassisList, err := oc.mc.ovnSBClient.ChassisList()
	if err != nil {
		klog.Errorf("Failed to get chassis list: error: %v", err)
		return
	}

	chassisMap := map[string]string{}
	for _, chassis := range chassisList {
		chassisMap[chassis.Hostname] = chassis.Name
	}

	//delete existing nodes from the chassis map.
	for _, nodeName := range nodeNames {
		delete(chassisMap, nodeName)
	}

	deleteChassis(oc.mc.ovnSBClient, chassisMap)
}

func (oc *Controller) syncNodes(nodes []interface{}) {
	var v4HostSubnetCount, v6HostSubnetCount float64
	for _, ipnet := range oc.clusterSubnets {
		util.CalculateHostSubnetsForClusterEntry(ipnet, &v4HostSubnetCount, &v6HostSubnetCount)
	}

	foundNodes := make(map[string]*kapi.Node)
	for _, tmp := range nodes {
		node, ok := tmp.(*kapi.Node)
		if !ok {
			klog.Errorf("Spurious object in syncNodes: %v", tmp)
			continue
		}
		foundNodes[node.Name] = node

		// collect all host subnet annotations for different networks, even the network does not exist yet
		// return subnets map: key is network name and value is hostsubnet
		hostSubnets, _ := util.ParseNodeHostSubnetAnnotation(node, oc.netconf.Name)
		klog.V(5).Infof("Node %s contains subnets: %v for network %s", node.Name, hostSubnets, oc.netconf.Name)
		for _, hostSubnet := range hostSubnets {
			err := oc.masterSubnetAllocator.MarkAllocatedNetwork(hostSubnet)
			if err != nil {
				utilruntime.HandleError(err)
			}
			util.UpdateUsedHostSubnetsCount(hostSubnet, &oc.v4HostSubnetsUsed, &oc.v6HostSubnetsUsed, true)
		}
		if !oc.netconf.NotDefault {
			nodeLocalNatIPs, _ := util.ParseNodeLocalNatIPAnnotation(node)
			for _, nodeLocalNatIP := range nodeLocalNatIPs {
				var err error
				if utilnet.IsIPv6(nodeLocalNatIP) {
					err = oc.nodeLocalNatIPv6Allocator.Allocate(nodeLocalNatIP)
				} else {
					err = oc.nodeLocalNatIPv4Allocator.Allocate(nodeLocalNatIP)
				}
				if err != nil {
					utilruntime.HandleError(err)
				}
			}
			// For each existing node, reserve its joinSwitch LRP IPs if they already exist.
			gwLRPIPs := oc.getJoinLRPAddresses(node.Name)
			_ = oc.joinSwIPManager.reserveJoinLRPIPs(node.Name, gwLRPIPs)
		}
	}

	chassisMap := map[string]string{}
	if !oc.netconf.NotDefault {
		// update metrics for host subnets, default network only for now. TBD
		metrics.RecordSubnetCount(v4HostSubnetCount, v6HostSubnetCount)
		metrics.RecordSubnetUsage(oc.v4HostSubnetsUsed, oc.v6HostSubnetsUsed)

		// We only deal with cleaning up nodes that shouldn't exist here, since
		// watchNodes() will be called for all existing nodes at startup anyway.
		// Note that this list will include the 'join' cluster switch, which we
		// do not want to delete.
		chassisList, err := oc.mc.ovnSBClient.ChassisList()
		if err != nil {
			klog.Errorf("Failed to get chassis list: error: %v", err)
			return
		}

		for _, chassis := range chassisList {
			chassisMap[chassis.Hostname] = chassis.Name
		}

		//delete existing nodes from the chassis map.
		for nodeName := range foundNodes {
			delete(chassisMap, nodeName)
		}
	}

	cmdArgs := []string{"--data=bare", "--no-heading",
		"--format=csv", "--columns=name,other-config", "find", "logical_switch"}
	if oc.netconf.NotDefault {
		cmdArgs = append(cmdArgs, "external_ids:network_name="+oc.netconf.Name)
	} else {
		cmdArgs = append(cmdArgs, "external_ids:network_name{=}[]")
	}
	nodeSwitches, stderr, err := util.RunOVNNbctl(cmdArgs...)
	if err != nil {
		klog.Errorf("Failed to get node logical switches: stderr: %q, error: %v",
			stderr, err)
		return
	}

	// find node logical switches which have other-config value set
	for _, result := range strings.Split(nodeSwitches, "\n") {
		// Split result into name and other-config
		items := strings.Split(result, ",")
		if len(items) != 2 || len(items[0]) == 0 {
			continue
		}
		nodeName := strings.TrimPrefix(items[0], util.GetNetworkPrefix(oc.netconf.Name))
		if _, ok := foundNodes[nodeName]; ok {
			// node still exists, no cleanup to do
			continue
		}

		var subnets []*net.IPNet
		attrs := strings.Fields(items[1])
		for _, attr := range attrs {
			var subnet *net.IPNet
			if strings.HasPrefix(attr, "subnet=") {
				subnetStr := strings.TrimPrefix(attr, "subnet=")
				_, subnet, _ = net.ParseCIDR(subnetStr)
			} else if strings.HasPrefix(attr, "ipv6_prefix=") {
				prefixStr := strings.TrimPrefix(attr, "ipv6_prefix=")
				_, subnet, _ = net.ParseCIDR(prefixStr + "/64")
			}
			if subnet != nil {
				subnets = append(subnets, subnet)
			}
		}
		if len(subnets) == 0 {
			continue
		}

		if err := oc.deleteNode(nodeName, subnets, nil); err != nil {
			klog.Error(err)
		}
		//remove the node from the chassis map so we don't delete it twice
		delete(chassisMap, nodeName)
	}

	deleteChassis(oc.mc.ovnSBClient, chassisMap)
}

func (oc *Controller) deleteNodeChassis(nodeName string) error {
	var chNames []string

	if oc.netconf.NotDefault {
		return nil
	}

	chassisList, err := oc.mc.ovnSBClient.ChassisGet(nodeName)
	if err != nil {
		return fmt.Errorf("failed to get chassis list for node %s: error: %v", nodeName, err)
	}

	cmds := make([]*goovn.OvnCommand, 0, len(chassisList))
	for _, chassis := range chassisList {
		if chassis.Name == "" {
			klog.Warningf("Chassis name is empty for node: %s", nodeName)
			continue
		}
		cmd, err := oc.mc.ovnSBClient.ChassisDel(chassis.Name)
		if err != nil {
			return fmt.Errorf("unable to create the ChassisDel command for chassis: %s", chassis.Name)
		}
		chNames = append(chNames, chassis.Name)
		cmds = append(cmds, cmd)
	}

	if len(cmds) == 0 {
		return fmt.Errorf("failed to find chassis for node %s", nodeName)
	}

	if err = oc.mc.ovnSBClient.Execute(cmds...); err != nil {
		return fmt.Errorf("failed to delete chassis %q for node %s: error: %v",
			strings.Join(chNames, ","), nodeName, err)
	}
	return nil
}
