package ovn

import (
	"context"
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	goovn "github.com/ebay/go-ovn"
	"github.com/pkg/errors"
	kapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	hocontroller "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/controller"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/ipallocator"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/loadbalancer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

const (
	// IdledServiceAnnotationSuffix is a constant string representing the suffix of the Service annotation key
	// whose value indicates the time stamp in RFC3339 format when a Service was idled
	IdledServiceAnnotationSuffix   = "idled-at"
	OvnNodeAnnotationRetryInterval = 100 * time.Millisecond
	OvnNodeAnnotationRetryTimeout  = 1 * time.Second
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
func (oc *Controller) Start(nodeName string, wg *sync.WaitGroup, ctx context.Context) error {
	// Set up leader election process first
	rl, err := resourcelock.New(
		resourcelock.ConfigMapsResourceLock,
		config.Kubernetes.OVNConfigNamespace,
		"ovn-kubernetes-master",
		oc.client.CoreV1(),
		nil,
		resourcelock.ResourceLockConfig{Identity: nodeName},
	)
	if err != nil {
		return err
	}

	lec := leaderelection.LeaderElectionConfig{
		Lock:            rl,
		LeaseDuration:   time.Duration(config.MasterHA.ElectionLeaseDuration) * time.Second,
		RenewDeadline:   time.Duration(config.MasterHA.ElectionRenewDeadline) * time.Second,
		RetryPeriod:     time.Duration(config.MasterHA.ElectionRetryPeriod) * time.Second,
		ReleaseOnCancel: true,
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
				metrics.StartE2ETimeStampMetricUpdater(oc.stopChan, oc.ovnNBClient)
				if err := oc.StartClusterMaster(nodeName); err != nil {
					panic(err.Error())
				}
				if err := oc.Run(wg, nodeName); err != nil {
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
				if newLeaderName != nodeName {
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

	wg.Add(1)
	go func() {
		leaderElector.Run(ctx)
		klog.Infof("Stopped leader election")
		wg.Done()
	}()

	return nil
}

// cleanup obsolete *gressDefaultDeny port groups
func (oc *Controller) upgradeToNamespacedDenyPGOVNTopology(existingNodeList *kapi.NodeList) error {
	err := deletePortGroup(oc.ovnNBClient, "ingressDefaultDeny")
	if err != nil {
		klog.Errorf("%v", err)
	}
	err = deletePortGroup(oc.ovnNBClient, "egressDefaultDeny")
	if err != nil {
		klog.Errorf("%v", err)
	}
	return nil
}

// delete obsoleted logical OVN entities that are specific for Multiple join switches OVN topology. Also cleanup
// OVN entities for deleted nodes (similar to syncNodes() but for obsoleted Multiple join switches OVN topology)
func (oc *Controller) upgradeToSingleSwitchOVNTopology(existingNodeList *kapi.NodeList) error {
	existingNodes := make(map[string]bool)
	for _, node := range existingNodeList.Items {
		existingNodes[node.Name] = true

		// delete the obsoleted node-join-subnets annotation
		err := oc.kube.SetAnnotationsOnNode(&node, map[string]interface{}{"k8s.ovn.org/node-join-subnets": nil})
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
	ver, err := util.DetermineOVNTopoVersionFromOVN()
	if err != nil {
		return err
	}

	// If current DB version is greater than OvnSingleJoinSwitchTopoVersion, no need to upgrade to single switch topology
	if ver < types.OvnSingleJoinSwitchTopoVersion {
		klog.Infof("Upgrading to Single Switch OVN Topology")
		err = oc.upgradeToSingleSwitchOVNTopology(existingNodes)
	}
	if err == nil && ver < types.OvnNamespacedDenyPGTopoVersion {
		klog.Infof("Upgrading to Namespace Deny PortGroup OVN Topology")
		err = oc.upgradeToNamespacedDenyPGOVNTopology(existingNodes)
	}
	// If version is less than Host -> Service with OpenFlow, we need to remove and cleanup DGP
	if err == nil && ver < types.OvnHostToSvcOFTopoVersion && config.Gateway.Mode == config.GatewayModeShared {
		err = cleanupDGP(existingNodes)
	}
	return err
}

// enableOVNLogicalDataPathGroups sets an OVN flag to enable logical datapath
// groups on OVN 20.12 and later. The option is ignored if OVN doesn't
// understand it. Logical datapath groups reduce the size of the southbound
// database in large clusters. ovn-controllers should be upgraded to a version
// that supports them before the option is turned on by the master.
func (oc *Controller) enableOVNLogicalDatapathGroups() error {
	options, err := oc.ovnNBClient.NBGlobalGetOptions()
	if err != nil {
		klog.Errorf("Failed to get NB global options: %v", err)
		return err
	}
	options["use_logical_dp_groups"] = "true"
	cmd, err := oc.ovnNBClient.NBGlobalSetOptions(options)
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
	klog.Infof("Starting cluster master")
	// The gateway router need to be connected to the distributed router via a per-node join switch.
	// We need a subnet allocator that allocates subnet for this per-node join switch.
	if config.Gateway.Mode == config.GatewayModeLocal {
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

	existingNodes, err := oc.kube.GetNodes()
	if err != nil {
		klog.Errorf("Error in fetching nodes: %v", err)
		return err
	}
	klog.V(5).Infof("Existing number of nodes: %d", len(existingNodes.Items))
	err = oc.upgradeOVNTopology(existingNodes)
	if err != nil {
		klog.Errorf("Failed to upgrade OVN topology to version %d: %v", types.OvnCurrentTopologyVersion, err)
		return err
	}

	klog.Infof("Allocating subnets")
	var v4HostSubnetCount, v6HostSubnetCount float64
	for _, clusterEntry := range config.Default.ClusterSubnets {
		err := oc.masterSubnetAllocator.AddNetworkRange(clusterEntry.CIDR, clusterEntry.HostSubnetLength)
		if err != nil {
			return err
		}
		klog.V(5).Infof("Added network range %s to the allocator", clusterEntry.CIDR)
		util.CalculateHostSubnetsForClusterEntry(clusterEntry, &v4HostSubnetCount, &v6HostSubnetCount)
	}
	for _, node := range existingNodes.Items {
		hostSubnets, _ := util.ParseNodeHostSubnetAnnotation(&node)
		klog.V(5).Infof("Node %s contains subnets: %v", node.Name, hostSubnets)
		for _, hostSubnet := range hostSubnets {
			err := oc.masterSubnetAllocator.MarkAllocatedNetwork(hostSubnet)
			if err != nil {
				utilruntime.HandleError(err)
			}
			util.UpdateUsedHostSubnetsCount(hostSubnet, &oc.v4HostSubnetsUsed, &oc.v6HostSubnetsUsed, true)
		}
		if config.Gateway.Mode == config.GatewayModeLocal {
			nodeLocalNatIPs, _ := util.ParseNodeLocalNatIPAnnotation(&node)
			klog.V(5).Infof("Node %s contains local NAT IPs: %v", node.Name, nodeLocalNatIPs)
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
		}
	}

	// update metrics for host subnets
	metrics.RecordSubnetCount(v4HostSubnetCount, v6HostSubnetCount)
	metrics.RecordSubnetUsage(oc.v4HostSubnetsUsed, oc.v6HostSubnetsUsed)

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

	if err := oc.SetupMaster(masterNodeName); err != nil {
		klog.Errorf("Failed to setup master (%v)", err)
		return err
	}

	if config.HybridOverlay.Enabled {
		oc.hoMaster, err = hocontroller.NewMaster(
			oc.kube,
			oc.watchFactory.NodeInformer(),
			oc.watchFactory.NamespaceInformer(),
			oc.watchFactory.PodInformer(),
			oc.ovnNBClient,
			oc.ovnSBClient,
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
	// Create a single common distributed router for the cluster.
	stdout, stderr, err := util.RunOVNNbctl("--", "--may-exist", "lr-add", types.OVNClusterRouter,
		"--", "set", "logical_router", types.OVNClusterRouter, "external_ids:k8s-cluster-router=yes")
	if err != nil {
		klog.Errorf("Failed to create a single common distributed router for the cluster, "+
			"stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
		return err
	}

	if config.Gateway.Mode == config.GatewayModeLocal {
		if err := addDistributedGWPort(); err != nil {
			return err
		}
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
	oc.clusterPortGroupUUID, err = createPortGroup(oc.ovnNBClient, clusterPortGroupName, clusterPortGroupName)
	if err != nil {
		klog.Errorf("Failed to create cluster port group: %v", err)
		return err
	}

	// Create a cluster-wide port group with all node-to-cluster router
	// logical switch ports.  Currently the only user is multicast but it might
	// be used for other features in the future.
	oc.clusterRtrPortGroupUUID, err = createPortGroup(oc.ovnNBClient, clusterRtrPortGroupName, clusterRtrPortGroupName)
	if err != nil {
		klog.Errorf("Failed to create cluster port group: %v", err)
		return err
	}

	// If supported, enable IGMP relay on the router to forward multicast
	// traffic between nodes.
	if oc.multicastSupport {
		stdout, stderr, err = util.RunOVNNbctl("--", "set", "logical_router",
			types.OVNClusterRouter, "options:mcast_relay=\"true\"")
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

	// We have 3 load-balancers per protocol to implement the East-west traffic	//
	protocols := []kapi.Protocol{kapi.ProtocolTCP, kapi.ProtocolUDP}
	if oc.SCTPSupport {
		protocols = append(protocols, kapi.ProtocolSCTP)
	}
	// Create load-balancers for east-west traffic for each protocol UDP, TCP, SCTP
	// and for Idling services if empty-lb-backends is enabled
	lbExternalIds := []string{types.ClusterLBPrefix}
	// If we enable idling we have to set the option before creating the loadbalancers
	// and create the new set of loadbalancers.
	if config.Kubernetes.OVNEmptyLbEvents {
		_, _, err := util.RunOVNNbctl("set", "nb_global", ".", "options:controller_event=true")
		if err != nil {
			klog.Error("Unable to enable controller events. Unidling not possible")
			return err
		}
		lbExternalIds = append(lbExternalIds, types.ClusterIdlingLBPrefix)
	}
	// Create the LoadBalancers if they don´t exist
	for _, lbExternalID := range lbExternalIds {
		for _, p := range protocols {
			uuid, err := loadbalancer.CreateLoadBalancer(p, lbExternalID)
			if err != nil {
				return errors.Wrapf(err, "Failed to create OVN load balancer for protocol %s", p)
			}
			oc.clusterLBsUUIDs = append(oc.clusterLBsUUIDs, uuid)
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
	gwLRPIfAddrs, err := oc.joinSwIPManager.ensureJoinLRPIPs(types.OVNClusterRouter)
	if err != nil {
		return fmt.Errorf("failed to allocate join switch IP address connected to %s: %v", types.OVNClusterRouter, err)
	}

	// Create OVNJoinSwitch that will be used to connect gateway routers to the distributed router.
	_, stderr, err = util.RunOVNNbctl("--may-exist", "ls-add", types.OVNJoinSwitch)
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
		"--", "lrp-add", types.OVNClusterRouter, drRouterPort, gwLRPMAC.String(),
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
	_, stderr, err = util.RunOVNNbctl("--may-exist", "lsp-add", types.OVNJoinSwitch,
		drSwitchPort, "--", "set", "logical_switch_port", drSwitchPort, "type=router",
		"options:router-port="+drRouterPort, "addresses=router")
	if err != nil {
		klog.Errorf("Failed to add router-type logical switch port %s to %s, stderr: %q, error: %v",
			drSwitchPort, types.OVNJoinSwitch, stderr, err)
		return err
	}

	return nil
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
	macAddress, err := util.ParseNodeManagementPortMACAddress(node)
	if err != nil {
		return err
	}

	if hostSubnets == nil {
		hostSubnets, err = util.ParseNodeHostSubnetAnnotation(node)
		if err != nil {
			return err
		}
	}

	var v4Subnet *net.IPNet
	addresses := macAddress.String()
	for _, hostSubnet := range hostSubnets {
		mgmtIfAddr := util.GetNodeManagementIfAddr(hostSubnet)
		addresses += " " + mgmtIfAddr.IP.String()

		if err := addAllowACLFromNode(node.Name, mgmtIfAddr.IP, oc.ovnNBClient); err != nil {
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

	if err := addToPortGroup(oc.ovnNBClient, clusterPortGroupName, &lpInfo{
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
	hostSubnets []*net.IPNet, hostAddrs sets.String) error {
	var err error
	var gwLRPIPs, clusterSubnets []*net.IPNet
	for _, clusterSubnet := range config.Default.ClusterSubnets {
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

	// Add cluster load balancers to GR for Host -> Cluster IP Service traffic
	if config.Gateway.Mode != config.GatewayModeLocal {
		gr := util.GetGatewayRouterFromNode(node.Name)
		for _, clusterLB := range oc.clusterLBsUUIDs {
			_, stderr, err := util.RunOVNNbctl("--may-exist", "lr-lb-add", gr, clusterLB)
			if err != nil {
				return fmt.Errorf("unable to add cluster LB: %s to %s, stderr: %q, error: %v",
					clusterLB, gr, stderr, err)
			}
		}
	}

	// in the case of shared gateway mode, we need to setup
	// 1. two policy based routes to steer traffic to the k8s node IP
	// 	  - from the management port via the node_local_switch's localnet port
	//    - from the hostsubnet via management port
	// 2. a dnat_and_snat nat entry to SNAT the traffic from the management port
	subnets, err := util.ParseNodeHostSubnetAnnotation(node)
	if err != nil {
		return fmt.Errorf("failed to get host subnets for %s: %v", node.Name, err)
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
		relevantHostIPs, err := util.MatchAllIPStringFamily(utilnet.IsIPv6(hostIfAddr.IP), hostAddrs.List())
		if err != nil && err != util.NoIPError {
			return err
		}
		if err := addPolicyBasedRoutes(node.Name, hostIfAddr.IP.String(), l3GatewayConfigIP, relevantHostIPs); err != nil {
			return err
		}

		if config.Gateway.Mode == config.GatewayModeLocal {
			if err := oc.addNodeLocalNatEntries(node, mpMAC.String(), hostIfAddr); err != nil {
				return err
			}
		}
	}

	if l3GatewayConfig.NodePortEnable {
		err = oc.handleNodePortLB(node)
	} else {
		// nodePort disabled, delete gateway load balancers for this node.
		gatewayRouter := util.GetGatewayRouterFromNode(node.Name)
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

func (oc *Controller) ensureNodeLogicalNetwork(node *kapi.Node, hostSubnets []*net.IPNet) error {
	// logical router port MAC is based on IPv4 subnet if there is one, else IPv6
	var nodeLRPMAC net.HardwareAddr
	nodeName := node.Name
	for _, hostSubnet := range hostSubnets {
		gwIfAddr := util.GetNodeGatewayIfAddr(hostSubnet)
		nodeLRPMAC = util.IPAddrToHWAddr(gwIfAddr.IP)
		if !utilnet.IsIPv6CIDR(hostSubnet) {
			break
		}
	}

	lrpArgs := []string{
		"--if-exists", "lrp-del", types.RouterToSwitchPrefix + nodeName,
		"--", "lrp-add", types.OVNClusterRouter, types.RouterToSwitchPrefix + nodeName,
		nodeLRPMAC.String(),
	}

	lsArgs := []string{
		"--may-exist",
		"ls-add", nodeName,
		"--", "set", "logical_switch", nodeName,
	}

	var v4Gateway, v6Gateway net.IP
	var hostNetworkPolicyIPs []net.IP
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
			hostNetworkPolicyIPs = append(hostNetworkPolicyIPs, mgmtIfAddr.IP)
			excludeIPs := mgmtIfAddr.IP.String()
			if config.HybridOverlay.Enabled {
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
		klog.Errorf("Failed to create a logical switch %v, stdout: %q, stderr: %q, error: %v", nodeName, stdout, stderr, err)
		return err
	}

	// also add the join switch IPs for this node - needed in shared gateway mode
	lrpIPs, err := oc.joinSwIPManager.ensureJoinLRPIPs(nodeName)
	if err != nil {
		return fmt.Errorf("failed to get join switch port IP address for node %s: %v", nodeName, err)
	}

	for _, lrpIP := range lrpIPs {
		hostNetworkPolicyIPs = append(hostNetworkPolicyIPs, lrpIP.IP)
	}

	// add the host network IPs for this node to host network namespace's address set
	if err = func() error {
		hostNetworkNamespace := config.Kubernetes.HostNetworkNamespace
		if hostNetworkNamespace != "" {
			nsInfo, err := oc.waitForNamespaceLocked(hostNetworkNamespace)
			if err != nil {
				klog.Errorf("Failed to get namespace %s (%v)",
					hostNetworkNamespace, err)
				return err
			}
			defer nsInfo.Unlock()
			if nsInfo.addressSet == nil {
				nsInfo.addressSet, err = oc.createNamespaceAddrSetAllPods(hostNetworkNamespace)
				if err != nil {
					return fmt.Errorf("cannot create address set for namespace: %s,"+
						"error: %v", hostNetworkNamespace, err)
				}
			}
			if err = nsInfo.addressSet.AddIPs(hostNetworkPolicyIPs); err != nil {
				return err
			}
		}
		return nil
	}(); err != nil {
		return err
	}

	// If supported, enable IGMP/MLD snooping and querier on the node.
	if oc.multicastSupport {
		stdout, stderr, err = util.RunOVNNbctl("set", "logical_switch",
			nodeName, "other-config:mcast_snoop=\"true\"")
		if err != nil {
			klog.Errorf("Failed to enable IGMP on logical switch %v, stdout: %q, stderr: %q, error: %v",
				nodeName, stdout, stderr, err)
			return err
		}

		// Configure IGMP/MLD querier if the gateway IP address is known.
		// Otherwise disable it.
		if v4Gateway != nil || v6Gateway != nil {
			if v4Gateway != nil {
				stdout, stderr, err = util.RunOVNNbctl("set", "logical_switch",
					nodeName, "other-config:mcast_querier=\"true\"",
					"other-config:mcast_eth_src=\""+nodeLRPMAC.String()+"\"",
					"other-config:mcast_ip4_src=\""+v4Gateway.String()+"\"")
				if err != nil {
					klog.Errorf("Failed to enable IGMP Querier on logical switch %v, stdout: %q, stderr: %q, error: %v",
						nodeName, stdout, stderr, err)
					return err
				}
			}
			if v6Gateway != nil {
				stdout, stderr, err = util.RunOVNNbctl("set", "logical_switch",
					nodeName, "other-config:mcast_querier=\"true\"",
					"other-config:mcast_eth_src=\""+nodeLRPMAC.String()+"\"",
					"other-config:mcast_ip6_src=\""+util.HWAddrToIPv6LLA(nodeLRPMAC).String()+"\"")
				if err != nil {
					klog.Errorf("Failed to enable MLD Querier on logical switch %v, stdout: %q, stderr: %q, error: %v",
						nodeName, stdout, stderr, err)
					return err
				}
			}
		} else {
			stdout, stderr, err = util.RunOVNNbctl("set", "logical_switch",
				nodeName, "other-config:mcast_querier=\"false\"")
			if err != nil {
				klog.Errorf("Failed to disable IGMP/MLD Querier on logical switch %v, stdout: %q, stderr: %q, error: %v",
					nodeName, stdout, stderr, err)
				return err
			}
			klog.Infof("Disabled IGMP/MLD Querier on logical switch %v (No IPv4/IPv6 Source IP available)",
				nodeName)
		}
	}

	// Connect the switch to the router.
	nodeSwToRtrUUID, err := addNodeLogicalSwitchPort(nodeName, types.SwitchToRouterPrefix+nodeName,
		"router", nodeLRPMAC.String(), "router-port="+types.RouterToSwitchPrefix+nodeName)
	if err != nil {
		klog.Errorf("Failed to add logical port to switch, stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
		return err
	}

	if err = addToPortGroup(oc.ovnNBClient, clusterRtrPortGroupName, &lpInfo{
		uuid: nodeSwToRtrUUID,
		name: types.SwitchToRouterPrefix + nodeName,
	}); err != nil {
		klog.Errorf(err.Error())
		return err
	}
	for i, loadBalancerUUID := range oc.clusterLBsUUIDs {
		if i == 0 {
			stdout, stderr, err = util.RunOVNNbctl("set", "logical_switch", nodeName, "load_balancer="+loadBalancerUUID)
		} else {
			stdout, stderr, err = util.RunOVNNbctl("add", "logical_switch", nodeName, "load_balancer", loadBalancerUUID)
		}
		if err != nil {
			klog.Errorf("Failed to set logical switch %v's load balancer, stdout: %q, stderr: %q, error: %v", nodeName, stdout, stderr, err)
			return err
		}
	}

	// Add the node to the logical switch cache
	return oc.lsManager.AddNode(nodeName, hostSubnets)
}

func (oc *Controller) addNodeAnnotations(node *kapi.Node, hostSubnets []*net.IPNet) error {
	nodeAnnotations, err := util.CreateNodeHostSubnetAnnotation(hostSubnets)
	if err != nil {
		return fmt.Errorf("failed to marshal node %q annotation for subnet %s",
			node.Name, util.JoinIPNets(hostSubnets, ","))
	}
	// FIXME: the real solution is to reconcile the node object. Once we have a work-queue based
	// implementation where we can add the item back to the work queue when it fails to
	// reconcile, we can get rid of the PollImmediate.
	err = utilwait.PollImmediate(OvnNodeAnnotationRetryInterval, OvnNodeAnnotationRetryTimeout, func() (bool, error) {
		err = oc.kube.SetAnnotationsOnNode(node, nodeAnnotations)
		if err != nil {
			klog.Warningf("Failed to set node annotation, will retry for: %v",
				OvnNodeAnnotationRetryTimeout)
		}
		return err == nil, nil
	},
	)
	if err != nil {
		return fmt.Errorf("failed to set node-subnets annotation on node %s: %v",
			node.Name, err)
	}
	return nil
}

func (oc *Controller) allocateNodeSubnets(node *kapi.Node) ([]*net.IPNet, []*net.IPNet, error) {
	hostSubnets, err := util.ParseNodeHostSubnetAnnotation(node)
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
		// Ensure that the parsed host subnets are reserved in the allocator
		for _, subnet := range hostSubnets {
			err = oc.masterSubnetAllocator.MarkAllocatedNetwork(subnet)
			if err != nil {
				klog.Warningf("Failed to mark subnet %v as allocated for node %s, error: %v", subnet, node.Name, err)
				return nil, nil, err
			}
		}
		allocatedSubnets = append(allocatedSubnets, hostSubnets...)
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
	// check if we were able to allocate the new subnets require
	// this can only happen if OVN is not configured correctly
	// so it will require a reconfiguration and restart.
	wantedSubnets := expectedHostSubnets - currentHostSubnets
	if wantedSubnets > 0 && len(allocatedSubnets) != wantedSubnets {
		err = fmt.Errorf("error allocating networks for node %s: %d subnets expected only new %d subnets allocated",
			node.Name, expectedHostSubnets, len(allocatedSubnets))
		return nil, nil, err
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
	err = oc.ensureNodeLogicalNetwork(node, hostSubnets)
	if err != nil {
		return nil, err
	}

	// Set the HostSubnet annotation on the node object to signal
	// to nodes that their logical infrastructure is set up and they can
	// proceed with their initialization
	err = oc.addNodeAnnotations(node, hostSubnets)
	if err != nil {
		return nil, err
	}

	// delete stale chassis in SBDB if any
	oc.deleteStaleNodeChassis(node)

	// If node annotation succeeds, update the used subnet count
	for _, hostSubnet := range hostSubnets {
		util.UpdateUsedHostSubnetsCount(hostSubnet,
			&oc.v4HostSubnetsUsed,
			&oc.v6HostSubnetsUsed, true)
	}
	metrics.RecordSubnetUsage(oc.v4HostSubnetsUsed, oc.v6HostSubnetsUsed)

	return hostSubnets, nil
}

// check if any existing chassis entries in the SBDB mismatches with node's chassisID annotation
func (oc *Controller) checkNodeChassisMismatch(node *kapi.Node) (bool, error) {
	chassisID, err := util.ParseNodeChassisIDAnnotation(node)
	if err != nil {
		return false, nil
	}

	chassisList, err := oc.ovnSBClient.ChassisGet(node.Name)
	if err != nil {
		return false, fmt.Errorf("failed to get chassis list for node %s: error: %v", node.Name, err)
	}

	if len(chassisList) == 0 {
		return false, nil
	}

	for _, chassis := range chassisList {
		if chassis.Name == chassisID {
			return false, nil
		}
	}
	return true, nil
}

// delete stale chassis in SBDB if system-id of the specific node has changed.
func (oc *Controller) deleteStaleNodeChassis(node *kapi.Node) {
	mismatch, err := oc.checkNodeChassisMismatch(node)
	if err != nil {
		klog.Errorf("Failed to check if there is any stale chassis for node %s in SBDB: %v", node.Name, err)
	} else if mismatch {
		klog.V(5).Infof("Node %s is now with a new chassis ID, delete its stale chassis in SBDB", node.Name)
		if err = oc.deleteNodeChassis(node.Name); err != nil {
			oc.recorder.Eventf(node, kapi.EventTypeWarning, "ErrorMismatchChassis",
				"Node %s is now with a new chassis ID. Its stale chassis entry is still in the SBDB",
				node.Name)
		}
	}
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
	if _, stderr, err := util.RunOVNNbctl("--if-exist", "ls-del", nodeName); err != nil {
		return fmt.Errorf("failed to delete logical switch %s, "+
			"stderr: %q, error: %v", nodeName, stderr, err)
	}

	// Remove the patch port that connects distributed router to node's logical switch
	if _, stderr, err := util.RunOVNNbctl("--if-exist", "lrp-del", types.RouterToSwitchPrefix+nodeName); err != nil {
		return fmt.Errorf("failed to delete logical router port %s%s, "+
			"stderr: %q, error: %v", types.RouterToSwitchPrefix, nodeName, stderr, err)
	}

	return nil
}

func (oc *Controller) deleteNode(nodeName string, hostSubnets []*net.IPNet, nodeLocalNatIPs []net.IP) {
	// Clean up as much as we can but don't hard error
	for _, hostSubnet := range hostSubnets {
		if err := oc.deleteNodeHostSubnet(nodeName, hostSubnet); err != nil {
			klog.Errorf("Error deleting node %s HostSubnet %v: %v", nodeName, hostSubnet, err)
		} else {
			util.UpdateUsedHostSubnetsCount(hostSubnet, &oc.v4HostSubnetsUsed, &oc.v6HostSubnetsUsed, false)
		}
	}
	// update metrics
	metrics.RecordSubnetUsage(oc.v4HostSubnetsUsed, oc.v6HostSubnetsUsed)

	if config.Gateway.Mode == config.GatewayModeLocal {
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

	if err := gatewayCleanup(nodeName); err != nil {
		klog.Errorf("Failed to clean up node %s gateway: (%v)", nodeName, err)
	}

	if err := oc.joinSwIPManager.releaseJoinLRPIPs(nodeName); err != nil {
		klog.Errorf("Failed to clean up GR LRP IPs for node %s: %v", nodeName, err)
	}

	if err := oc.deleteNodeChassis(nodeName); err != nil {
		klog.Errorf("Failed to remove the chassis associated with node %s in the OVN SB Chassis table: %v", nodeName, err)
	}
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

		oldNode, err := oc.kube.GetNode(origNode.Name)
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
					if err = oc.kube.UpdateNodeStatus(node); err == nil {
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
// from chassis & chassis_private table
func deleteChassis(ovnSBClient goovn.Client, chassisMap map[string]string) {
	cmds := make([]*goovn.OvnCommand, 0, len(chassisMap))
	for chassisHostname, chassisName := range chassisMap {
		if chassisName != "" {
			klog.Infof("Deleting stale chassis %s (%s)", chassisHostname, chassisName)
			chassisDelCmd, err := ovnSBClient.ChassisDel(chassisName)
			if err != nil {
				klog.Errorf("Unable to create the ChassisDel command for chassis: %s from the sbdb", chassisName)
			} else {
				cmds = append(cmds, chassisDelCmd)
			}
			// check for chassis_private table in schema and
			// if present, delete corresponding chassis row in chassis_private table
			sbDbSchema := ovnSBClient.GetSchema()
			if _, ok := sbDbSchema.Tables[goovn.TableChassisPrivate]; ok {
				chassisPrivateDelCmd, err := ovnSBClient.ChassisPrivateDel(chassisName)
				if err != nil {
					klog.Errorf("Unable to create the ChassisPrivateDel command for chassis: %s from the sbdb", chassisName)
				} else {
					cmds = append(cmds, chassisPrivateDelCmd)
				}
			}
		}
	}

	if len(cmds) != 0 {
		if err := ovnSBClient.Execute(cmds...); err != nil {
			klog.Errorf("Failed to delete chassis row from chassis & chassis_private table "+
				"for node/chassis map %v: error: %v", chassisMap, err)
		}
	}
}

// this is the worker function that does the periodic sync of nodes from kube API
// and sbdb and deletes chassis that are stale
func (oc *Controller) syncNodesPeriodic() {
	//node names is a slice of all node names
	nodes, err := oc.kube.GetNodes()
	if err != nil {
		klog.Errorf("Error getting existing nodes from kube API: %v", err)
		return
	}

	nodeNames := make([]string, 0, len(nodes.Items))

	for _, node := range nodes.Items {
		nodeNames = append(nodeNames, node.Name)
	}

	chassisList, err := oc.ovnSBClient.ChassisList()
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

	deleteChassis(oc.ovnSBClient, chassisMap)
}

func (oc *Controller) syncNodes(nodes []interface{}) {
	foundNodes := make(map[string]*kapi.Node)
	for _, tmp := range nodes {
		node, ok := tmp.(*kapi.Node)
		if !ok {
			klog.Errorf("Spurious object in syncNodes: %v", tmp)
			continue
		}
		foundNodes[node.Name] = node
		// For each existing node, reserve its joinSwitch LRP IPs if they already exist.
		gwLRPIPs := oc.getJoinLRPAddresses(node.Name)
		_ = oc.joinSwIPManager.reserveJoinLRPIPs(node.Name, gwLRPIPs)
	}

	// We only deal with cleaning up nodes that shouldn't exist here, since
	// watchNodes() will be called for all existing nodes at startup anyway.
	// Note that this list will include the 'join' cluster switch, which we
	// do not want to delete.
	chassisList, err := oc.ovnSBClient.ChassisList()
	if err != nil {
		klog.Errorf("Failed to get chassis list: error: %v", err)
		return
	}

	chassisMap := map[string]string{}
	for _, chassis := range chassisList {
		chassisMap[chassis.Hostname] = chassis.Name
	}

	//delete existing nodes from the chassis map.
	for nodeName := range foundNodes {
		delete(chassisMap, nodeName)
	}

	nodeSwitches, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--format=csv", "--columns=name,other-config", "find", "logical_switch")
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
		nodeName := items[0]
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

		oc.deleteNode(nodeName, subnets, nil)
		//remove the node from the chassis map so we don't delete it twice
		delete(chassisMap, nodeName)
	}

	deleteChassis(oc.ovnSBClient, chassisMap)
}

func (oc *Controller) deleteNodeChassis(nodeName string) error {
	var chNames []string

	chassisList, err := oc.ovnSBClient.ChassisGet(nodeName)
	if err != nil {
		return fmt.Errorf("failed to get chassis list for node %s: error: %v", nodeName, err)
	}

	cmds := make([]*goovn.OvnCommand, 0, len(chassisList))
	for _, chassis := range chassisList {
		if chassis.Name == "" {
			klog.Warningf("Chassis name is empty for node: %s", nodeName)
			continue
		}
		chDeleteCmd, err := oc.ovnSBClient.ChassisDel(chassis.Name)
		if err != nil {
			return fmt.Errorf("unable to create the ChassisDel command for chassis: %s", chassis.Name)
		} else {
			cmds = append(cmds, chDeleteCmd)
		}
		// check for chassis_private table in db-schema and
		// if present, delete corresponding chassis row from chassis_private table
		sbDbSchema := oc.ovnSBClient.GetSchema()
		if _, ok := sbDbSchema.Tables[goovn.TableChassisPrivate]; ok {
			chPrivateDeleteCmd, err := oc.ovnSBClient.ChassisPrivateDel(chassis.Name)
			if err != nil {
				return fmt.Errorf("unable to create the ChassisPrivateDel command for chassis: %s", chassis.Name)
			} else {
				cmds = append(cmds, chPrivateDeleteCmd)
			}
		}
		chNames = append(chNames, chassis.Name)
	}

	if len(cmds) == 0 {
		return nil
	}

	if err = oc.ovnSBClient.Execute(cmds...); err != nil {
		return fmt.Errorf("failed to delete chassis row %q from chassis & chassis_private table "+
			"for node %s: error: %v", strings.Join(chNames, ","), nodeName, err)
	}
	return nil
}
