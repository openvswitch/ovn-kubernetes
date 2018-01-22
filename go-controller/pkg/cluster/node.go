package cluster

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/openshift/origin/pkg/util/netutils"

	"github.com/openvswitch/ovn-kubernetes/go-controller/pkg/config"
	"github.com/openvswitch/ovn-kubernetes/go-controller/pkg/ovn"
	"github.com/openvswitch/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
)

// StartClusterNode learns the subnet assigned to it by the master controller
// and calls the SetupNode script which establishes the logical switch
func (cluster *OvnClusterController) StartClusterNode(name string) error {
	count := 30
	var err error
	var node *kapi.Node
	var subnet *net.IPNet

	for count > 0 {
		if count != 30 {
			time.Sleep(time.Second)
		}
		count--

		// setup the node, create the logical switch
		node, err = cluster.Kube.GetNode(name)
		if err != nil {
			logrus.Errorf("Error starting node %s, no node found - %v", name, err)
			continue
		}

		sub, ok := node.Annotations[OvnHostSubnet]
		if !ok {
			logrus.Errorf("Error starting node %s, no annotation found on node for subnet - %v", name, err)
			continue
		}
		_, subnet, err = net.ParseCIDR(sub)
		if err != nil {
			logrus.Errorf("Invalid hostsubnet found for node %s - %v", node.Name, err)
			return err
		}
		break
	}

	if count == 0 {
		logrus.Errorf("Failed to get node/node-annotation for %s - %v", name, err)
		return err
	}

	nodeIP, err := netutils.GetNodeIP(node.Name)
	if err != nil {
		logrus.Errorf("Failed to obtain node's IP: %v", err)
		return err
	}

	logrus.Infof("Node %s ready for ovn initialization with subnet %s", node.Name, subnet.String())

	err = util.StartOVS()
	if err != nil {
		return err
	}

	args := []string{
		"set",
		"Open_vSwitch",
		".",
		fmt.Sprintf("external_ids:ovn-nb=\"%s\"", cluster.NorthDBClientAuth.GetURL()),
		fmt.Sprintf("external_ids:ovn-remote=\"%s\"", cluster.SouthDBClientAuth.GetURL()),
		fmt.Sprintf("external_ids:ovn-encap-ip=%s", nodeIP),
		"external_ids:ovn-encap-type=\"geneve\"",
		fmt.Sprintf("external_ids:k8s-api-server=\"%s\"", cluster.KubeServer),
		fmt.Sprintf("external_ids:k8s-api-token=\"%s\"", cluster.Token),
	}
	out, err := exec.Command("ovs-vsctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Error setting OVS external IDs: %v\n  %q", err, string(out))
	}

	err = util.RestartOvnController()
	if err != nil {
		return err
	}

	// Fetch config file to override default values.
	config.FetchConfig()

	// Update config globals that OVN exec utils use
	cluster.NorthDBClientAuth.SetConfig()

	if err := ovn.CreateManagementPort(node.Name, subnet.String(), cluster.ClusterIPNet.String()); err != nil {
		return err
	}

	// Install the CNI config file after all initialization is done
	if runtime.GOOS != "win32" {
		// MkdirAll() returns no error if the path already exists
		err = os.MkdirAll(config.CniConfPath, os.ModeDir)
		if err != nil {
			return err
		}

		// Always create the CNI config for consistency.
		cniConf := config.CniConfPath + "/10-ovn-kubernetes.conf"
		f, err := os.OpenFile(cniConf, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer f.Close()
		confJSON := fmt.Sprintf("{\"name\":\"ovn-kubernetes\", \"type\":\"%s\"}", config.CniPlugin)
		_, err = f.Write([]byte(confJSON))
		if err != nil {
			return err
		}
	}

	return nil
}
