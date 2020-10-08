package util

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"

	"github.com/urfave/cli/v2"

	"k8s.io/klog"
	utilnet "k8s.io/utils/net"
)

const (
	K8sPrefix = "k8s-"
	// K8sMgmtIntfName name to be used as an OVS internal port on the node
	K8sMgmtIntfName = "ovn-k8s-mp0"

	// PhysicalNetworkName is the name that maps to an OVS bridge that provides
	// access to physical/external network
	PhysicalNetworkName = "physnet"

	// LocalNetworkName is the name that maps to an OVS bridge that provides
	// access to local service
	LocalNetworkName = "locnet"

	V6NodeLocalNatSubnet           = "fd99::/64"
	V6NodeLocalNatSubnetPrefix     = 64
	V6NodeLocalNatSubnetNextHop    = "fd99::1"
	V6NodeLocalDistributedGwPortIP = "fd99::2"

	V4NodeLocalNatSubnet           = "169.254.0.0/20"
	V4NodeLocalNatSubnetPrefix     = 20
	V4NodeLocalNatSubnetNextHop    = "169.254.0.1"
	V4NodeLocalDistributedGwPortIP = "169.254.0.2"
)

// StringArg gets the named command-line argument or returns an error if it is empty
func StringArg(context *cli.Context, name string) (string, error) {
	val := context.String(name)
	if val == "" {
		return "", fmt.Errorf("argument --%s should be non-null", name)
	}
	return val, nil
}

// GetLegacyK8sMgmtIntfName returns legacy management ovs-port name
func GetLegacyK8sMgmtIntfName(nodeName string) string {
	if len(nodeName) > 11 {
		return K8sPrefix + (nodeName[:11])
	}
	return K8sPrefix + nodeName
}

// GetNodeChassisID returns the machine's OVN chassis ID
func GetNodeChassisID(exec ExecHelper) (string, error) {
	chassisID, stderr, err := exec.RunOVSVsctl("--if-exists", "get",
		"Open_vSwitch", ".", "external_ids:system-id")
	if err != nil {
		klog.Errorf("No system-id configured in the local host, "+
			"stderr: %q, error: %v", stderr, err)
		return "", err
	}
	if chassisID == "" {
		return "", fmt.Errorf("no system-id configured in the local host")
	}

	return chassisID, nil
}

var updateNodeSwitchLock sync.Mutex

// UpdateNodeSwitchExcludeIPs should be called after adding the management port
// and after adding the hybrid overlay port, and ensures that each port's IP
// is added to the logical switch's exclude_ips. This prevents ovn-northd log
// spam about duplicate IP addresses.
// See https://github.com/ovn-org/ovn-kubernetes/pull/779
func UpdateNodeSwitchExcludeIPs(exec ExecHelper, nodeName string, subnet *net.IPNet) error {
	if utilnet.IsIPv6CIDR(subnet) {
		// We don't exclude any IPs in IPv6
		return nil
	}

	updateNodeSwitchLock.Lock()
	defer updateNodeSwitchLock.Unlock()

	stdout, stderr, err := exec.RunOVNNbctl("lsp-list", nodeName)
	if err != nil {
		return fmt.Errorf("failed to list logical switch %q ports: stderr: %q, error: %v", nodeName, stderr, err)
	}

	var haveManagementPort, haveHybridOverlayPort bool
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "("+K8sPrefix+nodeName+")") {
			haveManagementPort = true
		} else if strings.Contains(line, "("+GetHybridOverlayPortName(nodeName)+")") {
			// we always need to set to false because we do not reserve the IP on the LSP for HO
			haveHybridOverlayPort = false
		}
	}

	mgmtIfAddr := GetNodeManagementIfAddr(subnet)
	hybridOverlayIfAddr := GetNodeHybridOverlayIfAddr(subnet)
	var excludeIPs string
	if config.HybridOverlay.Enabled {
		if haveHybridOverlayPort && haveManagementPort {
			// no excluded IPs required
		} else if !haveHybridOverlayPort && !haveManagementPort {
			// exclude both
			excludeIPs = mgmtIfAddr.IP.String() + ".." + hybridOverlayIfAddr.IP.String()
		} else if haveHybridOverlayPort {
			// exclude management port IP
			excludeIPs = mgmtIfAddr.IP.String()
		} else if haveManagementPort {
			// exclude hybrid overlay port IP
			excludeIPs = hybridOverlayIfAddr.IP.String()
		}
	} else if !haveManagementPort {
		// exclude management port IP
		excludeIPs = mgmtIfAddr.IP.String()
	}

	args := []string{"--", "--if-exists", "remove", "logical_switch", nodeName, "other-config", "exclude_ips"}
	if len(excludeIPs) > 0 {
		args = []string{"--", "--if-exists", "set", "logical_switch", nodeName, "other-config:exclude_ips=" + excludeIPs}
	}

	_, stderr, err = exec.RunOVNNbctl(args...)
	if err != nil {
		return fmt.Errorf("failed to set node %q switch exclude_ips, "+
			"stderr: %q, error: %v", nodeName, stderr, err)
	}
	return nil
}

// GetHybridOverlayPortName returns the name of the hybrid overlay switch port
// for a given node
func GetHybridOverlayPortName(nodeName string) string {
	return "int-" + nodeName
}

type annotationNotSetError struct {
	msg string
}

func (anse annotationNotSetError) Error() string {
	return anse.msg
}

// newAnnotationNotSetError returns an error for an annotation that is not set
func newAnnotationNotSetError(format string, args ...interface{}) error {
	return annotationNotSetError{msg: fmt.Sprintf(format, args...)}
}

// IsAnnotationNotSetError returns true if the error indicates that an annotation is not set
func IsAnnotationNotSetError(err error) bool {
	_, ok := err.(annotationNotSetError)
	return ok
}
