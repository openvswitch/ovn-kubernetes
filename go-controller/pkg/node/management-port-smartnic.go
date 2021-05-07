package node

import (
	"fmt"
	"net"

	"k8s.io/klog/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

type managementPortSmartNIC struct {
	nodeName    string
	hostSubnets []*net.IPNet
	vfRepName   string
}

func (mp *managementPortSmartNIC) Create(nodeAnnotator kube.Annotator, waiter *startupWaiter) (*managementPortConfig, error) {
	// Get management port representor name
	link, err := util.GetNetLinkOps().LinkByName(mp.vfRepName)
	if err != nil {
		// It may fail in case this is not the first run after reboot and management port has already been renamed.
		link, err = util.GetNetLinkOps().LinkByName(types.K8sMgmtIntfName)
		if err != nil {
			return nil, fmt.Errorf("failed to get link device for %s. %v", mp.vfRepName, err)
		}
	}

	// configure management port: rename, set MTU and set link up and connect representor port to br-int
	klog.Infof("Create management port smart-nic: %s", link.Attrs().Name)
	setName := link.Attrs().Name != types.K8sMgmtIntfName
	setMTU := link.Attrs().MTU != config.Default.MTU

	if setName || setMTU {
		if err = util.GetNetLinkOps().LinkSetDown(link); err != nil {
			return nil, fmt.Errorf("failed to set link down for device %s. %v", mp.vfRepName, err)
		}

		if setName {
			if err = util.GetNetLinkOps().LinkSetName(link, types.K8sMgmtIntfName); err != nil {
				// NOTE(adrianc): rename may fail with "file exists" in case an interface is already named
				// ovn-k8s-mp0, this may happen if mgmt-port-netdev changes during deployment. ATM we are
				// not handling it.
				// TODO: handle mgmt-port-netdev change.
				return nil, fmt.Errorf("failed to set link name for device %s. %v", mp.vfRepName, err)
			}
		}

		if setMTU {
			if err = util.GetNetLinkOps().LinkSetMTU(link, config.Default.MTU); err != nil {
				return nil, fmt.Errorf("failed to set link MTU for device %s. %v", link.Attrs().Name, err)
			}
		}
	}

	if err = util.GetNetLinkOps().LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("failed to set link up for device %s. %v", link.Attrs().Name, err)
	}

	// Plug management port VF representor to OVS.
	stdout, stderr, err := util.RunOVSVsctl(
		"--", "--may-exist", "add-port", "br-int", types.K8sMgmtIntfName,
		"--", "set", "interface", types.K8sMgmtIntfName,
		"external-ids:iface-id="+types.K8sPrefix+mp.nodeName)
	if err != nil {
		klog.Errorf("Failed to add port \"%s\" to br-int, stdout: %q, stderr: %q, error: %v",
			types.K8sMgmtIntfName, stdout, stderr, err)
		return nil, err
	}

	mpcfg := &managementPortConfig{
		ifName: types.K8sMgmtIntfName,
		link:   link,
	}

	mgmtPortMac := util.IPAddrToHWAddr(util.GetNodeManagementIfAddr(mp.hostSubnets[0]).IP)
	if err := util.SetNodeManagementPortMACAddress(nodeAnnotator, mgmtPortMac); err != nil {
		return nil, err
	}
	waiter.AddWait(managementPortReady, nil)
	return mpcfg, nil
}

func (mpo *managementPortSmartNIC) CheckManagementPortHealth(cfg *managementPortConfig) {
	// TODO(adrianc): should we add some checks here?
}

type managementPortSmartNICHost struct {
	hostSubnets []*net.IPNet
	netdevName  string
}

func (mp *managementPortSmartNICHost) Create(nodeAnnotator kube.Annotator, waiter *startupWaiter) (*managementPortConfig, error) {
	// get Netdev that is used for management port.
	link, err := util.GetNetLinkOps().LinkByName(mp.netdevName)
	if err != nil {
		// this may not the first time invoked on the node after reboot
		// netdev may have already been renamed to ovn-k8s-mp0.
		link, err = util.GetNetLinkOps().LinkByName(types.K8sMgmtIntfName)
		if err != nil {
			return nil, fmt.Errorf("failed to get link device for %s. %v", mp.netdevName, err)
		}
	}

	// configure management port: name, mac, MTU, iptables
	// mac addr, derived from the first entry in host subnets using the .2 address as mac with a fixed prefix.
	klog.Infof("Setup management port smart-nic host: %s", link.Attrs().Name)
	mgmtPortMac := util.IPAddrToHWAddr(util.GetNodeManagementIfAddr(mp.hostSubnets[0]).IP)
	setMac := link.Attrs().HardwareAddr.String() != mgmtPortMac.String()
	setName := link.Attrs().Name != types.K8sMgmtIntfName
	setMTU := link.Attrs().MTU != config.Default.MTU

	if setMac || setName || setMTU {
		err := util.GetNetLinkOps().LinkSetDown(link)
		if err != nil {
			return nil, fmt.Errorf("failed to set link down for %s. %v", mp.netdevName, err)
		}

		if setMac {
			err := util.GetNetLinkOps().LinkSetHardwareAddr(link, mgmtPortMac)
			if err != nil {
				return nil, fmt.Errorf("failed to set management port MAC address. %v", err)
			}
		}

		if setName {
			err := util.GetNetLinkOps().LinkSetName(link, types.K8sMgmtIntfName)
			if err != nil {
				// NOTE(adrianc): rename may fail with "file exists" in case an interface is already named
				// ovn-k8s-mp0, this may happen if mgmt-port-netdev changes during deployment. ATM we are
				// not handling it.
				// TODO: handle mgmt-port-netdev change.
				return nil, fmt.Errorf("failed to set management port name. %v", err)
			}
		}

		if setMTU {
			err := util.GetNetLinkOps().LinkSetMTU(link, config.Default.MTU)
			if err != nil {
				return nil, fmt.Errorf("failed to set management port MTU. %v", err)
			}
		}
	}

	// Set link up
	err = util.GetNetLinkOps().LinkSetUp(link)
	if err != nil {
		return nil, fmt.Errorf("failed to set link up for %s. %v", types.K8sMgmtIntfName, err)
	}

	// Setup Iptable and routes
	cfg, err := createPlatformManagementPort(types.K8sMgmtIntfName, mp.hostSubnets)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func (mp *managementPortSmartNICHost) CheckManagementPortHealth(cfg *managementPortConfig) {
	checkManagementPortHealth(cfg)
}
