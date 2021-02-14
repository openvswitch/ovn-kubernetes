package node

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	kapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	honode "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/controller"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node/controllers/upgrade"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// OvnNode is the object holder for utilities meant for node management
type OvnNode struct {
	name         string
	client       clientset.Interface
	Kube         kube.Interface
	watchFactory factory.NodeWatchFactory
	stopChan     chan struct{}
	recorder     record.EventRecorder
	gateway      Gateway
}

// NewNode creates a new controller for node management
func NewNode(kubeClient kubernetes.Interface, wf factory.NodeWatchFactory, name string, stopChan chan struct{}, eventRecorder record.EventRecorder) *OvnNode {
	return &OvnNode{
		name:         name,
		client:       kubeClient,
		Kube:         &kube.Kube{KClient: kubeClient},
		watchFactory: wf,
		stopChan:     stopChan,
		recorder:     eventRecorder,
	}
}

func setupOVNNode(node *kapi.Node) error {
	var err error

	encapIP := config.Default.EncapIP
	if encapIP == "" {
		encapIP, err = util.GetNodePrimaryIP(node)
		if err != nil {
			return fmt.Errorf("failed to obtain local IP from node %q: %v", node.Name, err)
		}
	} else {
		if ip := net.ParseIP(encapIP); ip == nil {
			return fmt.Errorf("invalid encapsulation IP provided %q", encapIP)
		}
	}

	_, stderr, err := util.RunOVSVsctl("set",
		"Open_vSwitch",
		".",
		fmt.Sprintf("external_ids:ovn-encap-type=%s", config.Default.EncapType),
		fmt.Sprintf("external_ids:ovn-encap-ip=%s", encapIP),
		fmt.Sprintf("external_ids:ovn-remote-probe-interval=%d",
			config.Default.InactivityProbe),
		fmt.Sprintf("external_ids:ovn-openflow-probe-interval=%d",
			config.Default.OpenFlowProbe),
		fmt.Sprintf("external_ids:hostname=\"%s\"", node.Name),
		"external_ids:ovn-monitor-all=true",
	)
	if err != nil {
		return fmt.Errorf("error setting OVS external IDs: %v\n  %q", err, stderr)
	}
	// If EncapPort is not the default tell sbdb to use specified port.
	if config.Default.EncapPort != config.DefaultEncapPort {
		systemID, err := util.GetNodeChassisID()
		if err != nil {
			return err
		}
		uuid, _, err := util.RunOVNSbctl("--data=bare", "--no-heading", "--columns=_uuid", "find", "Encap",
			fmt.Sprintf("chassis_name=%s", systemID))
		if err != nil {
			return err
		}
		if len(uuid) == 0 {
			return fmt.Errorf("unable to find encap uuid to set geneve port for chassis %s", systemID)
		}
		_, stderr, errSet := util.RunOVNSbctl("set", "encap", uuid,
			fmt.Sprintf("options:dst_port=%d", config.Default.EncapPort),
		)
		if errSet != nil {
			return fmt.Errorf("error setting OVS encap-port: %v\n  %q", errSet, stderr)
		}
	}
	if config.Monitoring.NetFlowTargets != nil {
		collectors := ""
		for _, v := range config.Monitoring.NetFlowTargets {
			collectors += "\"" + util.JoinHostPortInt32(v.Host.String(), v.Port) + "\"" + ","
		}
		collectors = strings.TrimSuffix(collectors, ",")

		_, stderr, err := util.RunOVSVsctl(
			"--",
			"--id=@netflow",
			"create",
			"netflow",
			fmt.Sprintf("targets=[%s]", collectors),
			"active_timeout=60",
			"--",
			"set", "bridge", "br-int", "netflow=@netflow",
		)
		if err != nil {
			return fmt.Errorf("error setting NetFlow: %v\n  %q", err, stderr)
		}
	}
	if config.Monitoring.SFlowTargets != nil {
		collectors := ""
		for _, v := range config.Monitoring.SFlowTargets {
			collectors += "\"" + util.JoinHostPortInt32(v.Host.String(), v.Port) + "\"" + ","
		}
		collectors = strings.TrimSuffix(collectors, ",")

		_, stderr, err := util.RunOVSVsctl(
			"--",
			"--id=@sflow",
			"create",
			"sflow",
			"agent="+types.SFlowAgent,
			fmt.Sprintf("targets=[%s]", collectors),
			"--",
			"set", "bridge", "br-int", "sflow=@sflow",
		)
		if err != nil {
			return fmt.Errorf("error setting SFlow: %v\n  %q", err, stderr)
		}
	}
	if config.Monitoring.IPFIXTargets != nil {
		collectors := ""
		for _, v := range config.Monitoring.IPFIXTargets {
			collectors += "\"" + util.JoinHostPortInt32(v.Host.String(), v.Port) + "\"" + ","
		}
		collectors = strings.TrimSuffix(collectors, ",")

		_, stderr, err := util.RunOVSVsctl(
			"--",
			"--id=@ipfix",
			"create",
			"ipfix",
			fmt.Sprintf("targets=[%s]", collectors),
			"cache_active_timeout=60",
			"--",
			"set", "bridge", "br-int", "ipfix=@ipfix",
		)
		if err != nil {
			return fmt.Errorf("error setting IPFIX: %v\n  %q", err, stderr)
		}
	}
	return nil
}

func isOVNControllerReady(name string) (bool, error) {
	runDir := util.GetOvnRunDir()

	pid, err := ioutil.ReadFile(runDir + "ovn-controller.pid")
	if err != nil {
		return false, fmt.Errorf("unknown pid for ovn-controller process: %v", err)
	}

	err = wait.PollImmediate(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		ctlFile := runDir + fmt.Sprintf("ovn-controller.%s.ctl", strings.TrimSuffix(string(pid), "\n"))
		ret, _, err := util.RunOVSAppctl("-t", ctlFile, "connection-status")
		if err == nil {
			klog.Infof("Node %s connection status = %s", name, ret)
			return ret == "connected", nil
		}
		return false, err
	})
	if err != nil {
		return false, fmt.Errorf("timed out waiting sbdb for node %s: %v", name, err)
	}

	err = wait.PollImmediate(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		_, _, err := util.RunOVSVsctl("--", "br-exists", "br-int")
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return false, fmt.Errorf("timed out checking whether br-int exists or not on node %s: %v", name, err)
	}

	err = wait.PollImmediate(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		stdout, _, err := util.RunOVSOfctl("dump-aggregate", "br-int")
		if err != nil {
			klog.V(5).Infof("Error dumping aggregate flows: %v "+
				"for node: %s", err, name)
			return false, nil
		}
		ret := strings.Contains(stdout, "flow_count=0")
		if ret {
			klog.V(5).Infof("Got a flow count of 0 when "+
				"dumping flows for node: %s", name)
		}
		return !ret, nil
	})
	if err != nil {
		return false, fmt.Errorf("timed out dumping br-int flow entries for node %s: %v", name, err)
	}

	return true, nil
}

// Starting with v21.03.0 OVN sets OVS.Interface.external-id:ovn-installed
// and OVNSB.Port_Binding.up when all OVS flows associated to a
// logical port have been successfully programmed.
func getOVNIfUpCheckMode() (bool, error) {
	if _, stderr, err := util.RunOVNSbctl("--columns=up", "list", "Port_Binding"); err != nil {
		if strings.Contains(stderr, "does not contain a column") {
			klog.Infof("Falling back to using legacy CNI OVS flow readiness checks")
			return false, nil
		}
		return false, fmt.Errorf("failed to check if port_binding is supported in OVN, stderr: %q, error: %v",
			stderr, err)
	}
	klog.Infof("Detected support for port binding with external IDs")
	return true, nil
}

// Start learns the subnets assigned to it by the master controller
// and calls the SetupNode script which establishes the logical switch
func (n *OvnNode) Start(wg *sync.WaitGroup) error {
	var err error
	var node *kapi.Node
	var subnets []*net.IPNet
	var mgmtPortConfig *managementPortConfig
	var cniServer *cni.Server
	var isOvnUpEnabled bool
	var mgmtPort ManagementPort

	klog.Infof("OVN Kube Node initialization, Mode: %s", config.OvnKubeNode.Mode)

	// Setting debug log level during node bring up to expose bring up process.
	// Log level is returned to configured value when bring up is complete.
	var level klog.Level
	if err := level.Set("5"); err != nil {
		klog.Errorf("Setting klog \"loglevel\" to 5 failed, err: %v", err)
	}

	if node, err = n.Kube.GetNode(n.name); err != nil {
		return fmt.Errorf("error retrieving node %s: %v", n.name, err)
	}

	if config.OvnKubeNode.Mode != types.NodeModeSmartNICHost {
		for _, auth := range []config.OvnAuthConfig{config.OvnNorth, config.OvnSouth} {
			if err := auth.SetDBAuth(); err != nil {
				return err
			}
		}

		err = setupOVNNode(node)
		if err != nil {
			return err
		}
	}

	// First wait for the node logical switch to be created by the Master, timeout is 300s.
	err = wait.PollImmediate(500*time.Millisecond, 300*time.Second, func() (bool, error) {
		if node, err = n.Kube.GetNode(n.name); err != nil {
			klog.Infof("Waiting to retrieve node %s: %v", n.name, err)
			return false, nil
		}
		subnets, err = util.ParseNodeHostSubnetAnnotation(node)
		if err != nil {
			klog.Infof("Waiting for node %s to start, no annotation found on node for subnet: %v", n.name, err)
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("timed out waiting for node's: %q logical switch: %v", n.name, err)
	}
	klog.Infof("Node %s ready for ovn initialization with subnet %s", n.name, util.JoinIPNets(subnets, ","))

	// Create CNI Server
	if config.OvnKubeNode.Mode != types.NodeModeSmartNIC {
		isOvnUpEnabled, err = getOVNIfUpCheckMode()
		if err != nil {
			return err
		}
		kclient, ok := n.Kube.(*kube.Kube)
		if !ok {
			return fmt.Errorf("cannot get kubeclient for starting CNI server")
		}
		cniServer, err = cni.NewCNIServer("", isOvnUpEnabled, n.watchFactory, kclient.KClient)
		if err != nil {
			return err
		}
	}

	// Setup Management port and gateway
	mgmtPort = NewManagementPort(n.name, subnets)

	if config.OvnKubeNode.Mode == types.NodeModeSmartNICHost {
		// Initialize management port resources on the node.
		// Updating node annotation and waiting for management port on smartNIC host is not needed,
		// so we pass nil for both.
		mgmtPortConfig, err = mgmtPort.Create(nil, nil)
		if err != nil {
			return err
		}
		klog.Infof("Management port ready.")
	} else {
		if _, err = isOVNControllerReady(n.name); err != nil {
			return err
		}
		nodeAnnotator := kube.NewNodeAnnotator(n.Kube, node)
		waiter := newStartupWaiter()
		// Initialize management port resources on the node
		mgmtPortConfig, err = mgmtPort.Create(nodeAnnotator, waiter)
		if err != nil {
			return err
		}

		// Initialize gateway resources on the node
		if err := n.initGateway(subnets, nodeAnnotator, waiter, mgmtPortConfig); err != nil {
			return err
		}

		if err := nodeAnnotator.Run(); err != nil {
			return fmt.Errorf("failed to set node %s annotations: %v", n.name, err)
		}

		// Wait for management port and gateway resources to be created by the master
		klog.Infof("Waiting for gateway and management port readiness...")
		start := time.Now()
		if err := waiter.Wait(); err != nil {
			return err
		}
		go n.gateway.Run(n.stopChan, wg)
		klog.Infof("Gateway and management port readiness took %v", time.Since(start))

		// Upgrade for Node. If we upgrade workers before masters, then we need to keep service routing via
		// mgmt port until masters have been updated and modified OVN config. Run a goroutine to handle this case

		// note this will change in the future to control-plane:
		// https://github.com/kubernetes/kubernetes/pull/95382
		masterNode, err := labels.NewRequirement("node-role.kubernetes.io/master", selection.Exists, nil)
		if err != nil {
			return err
		}

		labelSelector := labels.NewSelector()
		labelSelector = labelSelector.Add(*masterNode)

		informerFactory := informers.NewSharedInformerFactoryWithOptions(n.client, 0,
			informers.WithTweakListOptions(func(options *metav1.ListOptions) {
				options.LabelSelector = labelSelector.String()
			}))

		upgradeController := upgrade.NewController(n.Kube, informerFactory.Core().V1().Nodes())
		initialTopoVersion := upgradeController.GetInitialTopoVersion()
		bridgeName := n.gateway.GetGatewayBridgeIface()

		needLegacySvcRoute := true
		if initialTopoVersion >= types.OvnHostToSvcOFTopoVersion && config.GatewayModeShared == config.Gateway.Mode {
			// Configure route for svc towards shared gw bridge
			// Have to have the route to bridge for multi-NIC mode, where the default gateway may go to a non-OVS interface
			if err := configureSvcRouteViaBridge(bridgeName); err != nil {
				return err
			}
			needLegacySvcRoute = false
		}

		// Determine if we need to run upgrade checks
		if initialTopoVersion != types.OvnCurrentTopologyVersion {
			if needLegacySvcRoute && config.GatewayModeShared == config.Gateway.Mode {
				klog.Info("System may be upgrading, falling back to to legacy K8S Service via mp0")
				// add back legacy route for service via mp0
				link, err := util.LinkSetUp(types.K8sMgmtIntfName)
				if err != nil {
					return fmt.Errorf("unable to get link for %s, error: %v", types.K8sMgmtIntfName, err)
				}
				var gwIP net.IP
				for _, subnet := range config.Kubernetes.ServiceCIDRs {
					if utilnet.IsIPv4CIDR(subnet) {
						gwIP = mgmtPortConfig.ipv4.gwIP
					} else {
						gwIP = mgmtPortConfig.ipv6.gwIP
					}
					err := util.LinkRoutesAdd(link, gwIP, []*net.IPNet{subnet})
					if err != nil && !os.IsExist(err) {
						return fmt.Errorf("unable to add legacy route for services via mp0, error: %v", err)
					}
				}
			}
			// need to run upgrade controller
			informerStop := make(chan struct{})
			informerFactory.Start(informerStop)
			go func() {
				if err := upgradeController.Run(n.stopChan, informerStop); err != nil {
					klog.Fatalf("Error while running upgrade controller: %v", err)
				}
				// upgrade complete now see what needs upgrading
				// migrate service route from ovn-k8s-mp0 to shared gw bridge
				if initialTopoVersion < types.OvnHostToSvcOFTopoVersion && config.GatewayModeShared == config.Gateway.Mode {
					if err := upgradeServiceRoute(bridgeName); err != nil {
						klog.Fatalf("Failed to upgrade service route for node, error: %v", err)
					}
				}
				// ensure CNI support for port binding built into OVN, as masters have been upgraded
				if initialTopoVersion < types.OvnPortBindingTopoVersion && cniServer != nil {
					cniServer.EnableOVNPortUpSupport()
				}
			}()
		}
	}

	if config.HybridOverlay.Enabled {
		// Not supported with Smart-NIC, enforced in config
		// TODO(adrianc): Revisit above comment
		nodeController, err := honode.NewNode(
			n.Kube,
			n.name,
			n.watchFactory.NodeInformer(),
			n.watchFactory.LocalPodInformer(),
			informer.NewDefaultEventHandler,
		)
		if err != nil {
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			nodeController.Run(n.stopChan)
		}()
	}

	if err := level.Set(strconv.Itoa(config.Logging.Level)); err != nil {
		klog.Errorf("Reset of initial klog \"loglevel\" failed, err: %v", err)
	}

	if config.OvnKubeNode.Mode != types.NodeModeSmartNIC {
		// start management port health check
		go util.RunPeriodicallyUntilStop(
			func() {
				mgmtPort.CheckManagementPortHealth(mgmtPortConfig)
			},
			30*time.Second,
			n.stopChan)
	}

	if config.OvnKubeNode.Mode != types.NodeModeSmartNICHost {
		// start health check to ensure there are no stale OVS internal ports
		go util.RunPeriodicallyUntilStop(checkForStaleOVSInterfaces, 60*time.Second, n.stopChan)
		n.WatchEndpoints()
	}

	if config.OvnKubeNode.Mode != types.NodeModeSmartNIC {
		// conditionally write cni config file
		confFile := filepath.Join(config.CNI.ConfDir, config.CNIConfFileName)
		_, err = os.Stat(confFile)
		if os.IsNotExist(err) {
			err = config.WriteCNIConfig()
			if err != nil {
				return err
			}
		}
	}

	if config.OvnKubeNode.Mode == types.NodeModeSmartNIC {
		n.watchSmartNicPods(isOvnUpEnabled)
	} else {
		// start the cni server
		err = cniServer.Start(cni.HandleCNIRequest)
	}

	return err
}

func (n *OvnNode) WatchEndpoints() {
	n.watchFactory.AddEndpointsHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, new interface{}) {
			epNew := new.(*kapi.Endpoints)
			epOld := old.(*kapi.Endpoints)
			newEpAddressMap := buildEndpointAddressMap(epNew.Subsets)
			for item := range buildEndpointAddressMap(epOld.Subsets) {
				if _, ok := newEpAddressMap[item]; !ok {
					err := deleteConntrack(item.ip, item.port, item.protocol)
					if err != nil {
						klog.Errorf("Failed to delete conntrack entry for %s: %v", item.ip, err)
					}
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			ep := obj.(*kapi.Endpoints)
			for item := range buildEndpointAddressMap(ep.Subsets) {
				err := deleteConntrack(item.ip, item.port, item.protocol)
				if err != nil {
					klog.Errorf("Failed to delete conntrack entry for %s: %v", item.ip, err)
				}

			}
		},
	}, nil)
}

type epAddressItem struct {
	ip       string
	port     int32
	protocol kapi.Protocol
}

//buildEndpointAddressMap builds a map of all UDP and SCTP ports in the endpoint subset along with that port's IP address
func buildEndpointAddressMap(epSubsets []kapi.EndpointSubset) map[epAddressItem]struct{} {
	epMap := make(map[epAddressItem]struct{})
	for _, subset := range epSubsets {
		for _, address := range subset.Addresses {
			for _, port := range subset.Ports {
				if port.Protocol == kapi.ProtocolUDP || port.Protocol == kapi.ProtocolSCTP {
					epMap[epAddressItem{
						ip:       address.IP,
						port:     port.Port,
						protocol: port.Protocol,
					}] = struct{}{}
				}
			}
		}
	}

	return epMap
}

func configureSvcRouteViaBridge(bridge string) error {
	gwIPs, _, err := getGatewayNextHops()
	if err != nil {
		return fmt.Errorf("unable to get the gateway next hops, error: %v", err)
	}
	link, err := util.LinkSetUp(bridge)
	if err != nil {
		return fmt.Errorf("unable to get link for %s, error: %v", bridge, err)
	}
	for _, subnet := range config.Kubernetes.ServiceCIDRs {
		gwIP, err := util.MatchIPFamily(utilnet.IsIPv6CIDR(subnet), gwIPs)
		if err != nil {
			return fmt.Errorf("unable to find gateway IP for subnet: %v, found IPs: %v", subnet, gwIPs)
		}
		err = util.LinkRoutesAdd(link, gwIP[0], []*net.IPNet{subnet})
		if err != nil && !os.IsExist(err) {
			return fmt.Errorf("unable to add route for service via shared gw bridge, error: %v", err)
		}
	}
	return nil
}

func upgradeServiceRoute(bridgeName string) error {
	klog.Info("Updating K8S Service route")
	// Flush old routes
	link, err := util.LinkSetUp(types.K8sMgmtIntfName)
	if err != nil {
		return fmt.Errorf("unable to get link: %s, error: %v", types.K8sMgmtIntfName, err)
	}
	if err := util.LinkRoutesDel(link, config.Kubernetes.ServiceCIDRs); err != nil {
		return fmt.Errorf("unable to delete routes on upgrade, error: %v", err)
	}
	// add route via OVS bridge
	if err := configureSvcRouteViaBridge(bridgeName); err != nil {
		return fmt.Errorf("unable to add svc route via OVS bridge interface, error: %v", err)
	}
	klog.Info("Successfully updated Kubernetes service route towards OVS")
	// Clean up gw0 and local ovs bridge as best effort
	if err := deleteLocalNodeAccessBridge(); err != nil {
		klog.Warningf("Error while removing Local Node Access Bridge, error: %v", err)
	}
	return nil
}
