package node

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	honode "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/controller"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"
)

// OvnNode is the object holder for utilities meant for node management
type OvnNode struct {
	name         string
	Kube         kube.Interface
	exec         util.ExecHelper
	watchFactory *factory.WatchFactory
	stopChan     chan struct{}
	recorder     record.EventRecorder
}

// NewNode creates a new controller for node management
func NewNode(kubeClient kubernetes.Interface, exec util.ExecHelper, wf *factory.WatchFactory, name string, stopChan chan struct{}, eventRecorder record.EventRecorder) *OvnNode {
	return &OvnNode{
		name:         name,
		Kube:         &kube.Kube{KClient: kubeClient},
		exec:         exec,
		watchFactory: wf,
		stopChan:     stopChan,
		recorder:     eventRecorder,
	}
}

func setupOVNNode(exec util.ExecHelper, node *kapi.Node) error {
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

	_, stderr, err := exec.RunOVSVsctl("set",
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
		systemID, err := util.GetNodeChassisID(exec)
		if err != nil {
			return err
		}
		uuid, _, err := exec.RunOVNSbctl("--data=bare", "--no-heading", "--columns=_uuid", "find", "Encap",
			fmt.Sprintf("chassis_name=%s", systemID))
		if err != nil {
			return err
		}
		if len(uuid) == 0 {
			return fmt.Errorf("unable to find encap uuid to set geneve port for chassis %s", systemID)
		}
		_, stderr, errSet := exec.RunOVNSbctl("set", "encap", uuid,
			fmt.Sprintf("options:dst_port=%d", config.Default.EncapPort),
		)
		if errSet != nil {
			return fmt.Errorf("error setting OVS encap-port: %v\n  %q", errSet, stderr)
		}
	}
	return nil
}

func (n *OvnNode) isOVNControllerReady() (bool, error) {
	err := wait.PollImmediate(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		ret, _, err := n.exec.RunOVNControllerAppCtl("connection-status")
		if err == nil {
			klog.Infof("Node %s connection status = %s", n.name, ret)
			return ret == "connected", nil
		}
		return false, err
	})
	if err != nil {
		return false, fmt.Errorf("timed out waiting sbdb for node %s: %v", n.name, err)
	}

	err = wait.PollImmediate(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		_, _, err := n.exec.RunOVSVsctl("--", "br-exists", "br-int")
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return false, fmt.Errorf("timed out checking whether br-int exists or not on node %s: %v", n.name, err)
	}

	err = wait.PollImmediate(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		stdout, _, err := n.exec.RunOVSOfctl("dump-aggregate", "br-int")
		if err != nil {
			klog.V(5).Infof("Error dumping aggregate flows: %v "+
				"for node: %s", err, n.name)
			return false, nil
		}
		ret := strings.Contains(stdout, "flow_count=0")
		if ret {
			klog.V(5).Infof("Got a flow count of 0 when "+
				"dumping flows for node: %s", n.name)
		}
		return !ret, nil
	})
	if err != nil {
		return false, fmt.Errorf("timed out dumping br-int flow entries for node %s: %v", n.name, err)
	}

	return true, nil
}

// Start learns the subnets assigned to it by the master controller
// and calls the SetupNode script which establishes the logical switch
func (n *OvnNode) Start(wg *sync.WaitGroup) error {
	var err error
	var node *kapi.Node
	var subnets []*net.IPNet

	// Setting debug log level during node bring up to expose bring up process.
	// Log level is returned to configured value when bring up is complete.
	var level klog.Level
	if err := level.Set("5"); err != nil {
		klog.Errorf("Setting klog \"loglevel\" to 5 failed, err: %v", err)
	}

	for _, auth := range []config.OvnAuthConfig{config.OvnNorth, config.OvnSouth} {
		if err := auth.SetDBAuth(); err != nil {
			return err
		}
	}

	if node, err = n.Kube.GetNode(n.name); err != nil {
		return fmt.Errorf("error retrieving node %s: %v", n.name, err)
	}
	err = setupOVNNode(n.exec, node)
	if err != nil {
		return err
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

	if _, err = n.isOVNControllerReady(); err != nil {
		return err
	}

	nodeAnnotator := kube.NewNodeAnnotator(n.Kube, node)
	waiter := newStartupWaiter()

	// Initialize gateway resources on the node
	if err := n.initGateway(subnets, nodeAnnotator, waiter); err != nil {
		return err
	}

	// Initialize management port resources on the node
	if err := n.createManagementPort(subnets, nodeAnnotator, waiter); err != nil {
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
	klog.Infof("Gateway and management port readiness took %v", time.Since(start))

	if config.HybridOverlay.Enabled {
		factory := n.watchFactory.GetFactory()
		nodeController, err := honode.NewNode(
			n.Kube,
			n.exec,
			n.name,
			factory.Core().V1().Nodes().Informer(),
			factory.Core().V1().Pods().Informer(),
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

	// start health check to ensure there are no stale OVS internal ports
	go checkForStaleOVSInterfaces(n.exec, n.stopChan)

	confFile := filepath.Join(config.CNI.ConfDir, config.CNIConfFileName)
	_, err = os.Stat(confFile)
	if os.IsNotExist(err) {
		err = config.WriteCNIConfig()
		if err != nil {
			return err
		}
	}

	kclient, ok := n.Kube.(*kube.Kube)
	if !ok {
		return fmt.Errorf("cannot get kubeclient for starting CNI server")
	}
	n.WatchEndpoints()

	// start the cni server
	cniServer := cni.NewCNIServer("", kclient.KClient)
	err = cniServer.Start(cni.HandleCNIRequest)

	return err
}

func (n *OvnNode) WatchEndpoints() {
	n.watchFactory.AddEndpointsHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, new interface{}) {
			epNew := new.(*kapi.Endpoints)
			epOld := old.(*kapi.Endpoints)
			if reflect.DeepEqual(epNew.Subsets, epOld.Subsets) {
				return
			}
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
