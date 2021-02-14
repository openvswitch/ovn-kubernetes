package node

import (
	"fmt"
	"net"
	"strings"

	"k8s.io/klog/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// ManagementPort is an interface that provides creation and healthcheck for ovn-k8s management port
type ManagementPort interface {
	// Create Management port, use annotator to update node annotation with management port details
	// and waiter to set up condition to wait on for management port creation
	Create(nodeAnnotator kube.Annotator, waiter *startupWaiter) (*managementPortConfig, error)
	// when invoked, checks for management port health and reports any warnings/errors to log
	CheckManagementPortHealth(cfg *managementPortConfig)
}

// NewManagementPort creates a new ManagementPort
func NewManagementPort(nodeName string, hostSubnets []*net.IPNet) ManagementPort {
	// Kubernetes emits events when pods are created. The event will contain
	// only lowercase letters of the hostname even though the kubelet is
	// started with a hostname that contains lowercase and uppercase letters.
	// When the kubelet is started with a hostname containing lowercase and
	// uppercase letters, this causes a mismatch between what the watcher
	// will try to fetch and what kubernetes provides, thus failing to
	// create the port on the logical switch.
	// Until the above is changed, switch to a lowercase hostname
	nodeName = strings.ToLower(nodeName)

	switch config.OvnKubeNode.Mode {
	default:
		return &managementPort{
			nodeName:    nodeName,
			hostSubnets: hostSubnets,
		}
	case types.NodeModeSmartNIC:
		return &managementPortSmartNIC{
			nodeName:    nodeName,
			hostSubnets: hostSubnets,
			vfRepName:   config.OvnKubeNode.MgmtPortNetdev,
		}
	case types.NodeModeSmartNICHost:
		return &managementPortSmartNICHost{
			hostSubnets: hostSubnets,
			netdevName:  config.OvnKubeNode.MgmtPortNetdev,
		}
	}
}

type managementPort struct {
	nodeName    string
	hostSubnets []*net.IPNet
}

func (mp *managementPort) Create(nodeAnnotator kube.Annotator, waiter *startupWaiter) (*managementPortConfig, error) {
	// Create a OVS internal interface.
	legacyMgmtIntfName := util.GetLegacyK8sMgmtIntfName(mp.nodeName)
	stdout, stderr, err := util.RunOVSVsctl(
		"--", "--if-exists", "del-port", "br-int", legacyMgmtIntfName,
		"--", "--may-exist", "add-port", "br-int", types.K8sMgmtIntfName,
		"--", "set", "interface", types.K8sMgmtIntfName,
		"type=internal", "mtu_request="+fmt.Sprintf("%d", config.Default.MTU),
		"external-ids:iface-id="+types.K8sPrefix+mp.nodeName)
	if err != nil {
		klog.Errorf("Failed to add port to br-int, stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
		return nil, err
	}
	macAddress, err := util.GetOVSPortMACAddress(types.K8sMgmtIntfName)
	if err != nil {
		klog.Errorf("Failed to get management port MAC address: %v", err)
		return nil, err
	}
	// persist the MAC address so that upon node reboot we get back the same mac address.
	_, stderr, err = util.RunOVSVsctl("set", "interface", types.K8sMgmtIntfName,
		fmt.Sprintf("mac=%s", strings.ReplaceAll(macAddress.String(), ":", "\\:")))
	if err != nil {
		klog.Errorf("Failed to persist MAC address %q for %q: stderr:%s (%v)", macAddress.String(),
			types.K8sMgmtIntfName, stderr, err)
		return nil, err
	}

	cfg, err := createPlatformManagementPort(types.K8sMgmtIntfName, mp.hostSubnets)
	if err != nil {
		return nil, err
	}

	if err := util.SetNodeManagementPortMACAddress(nodeAnnotator, macAddress); err != nil {
		return nil, err
	}

	waiter.AddWait(managementPortReady, nil)
	return cfg, nil
}

func (mpc *managementPort) CheckManagementPortHealth(cfg *managementPortConfig) {
	checkManagementPortHealth(cfg)
}

func managementPortReady() (bool, error) {
	// Get the OVS interface name for the Management Port
	ofport, _, err := util.RunOVSVsctl("--if-exists", "get", "interface", types.K8sMgmtIntfName, "ofport")
	if err != nil {
		return false, nil
	}

	// OpenFlow table 65 performs logical-to-physical translation. It matches the packet’s logical
	// egress  port. Its actions output the packet to the port attached to the OVN integration bridge
	// that represents that logical  port.
	stdout, _, err := util.RunOVSOfctl("--no-stats", "--no-names", "dump-flows", "br-int",
		"table=65,out_port="+ofport)
	if err != nil {
		return false, nil
	}
	if !strings.Contains(stdout, "actions=output:"+ofport) {
		return false, nil
	}
	klog.Info("Management port is ready")
	return true, nil
}
