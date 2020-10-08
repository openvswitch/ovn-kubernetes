package ovn

import (
	"fmt"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/klog"
)

const (
	// ovnClusterRouter is the name of the distributed router
	ovnClusterRouter = "ovn_cluster_router"

	joinSwitchPrefix             = "join_"
	externalSwitchPrefix         = "ext_"
	gwRouterPrefix               = "GR_"
	routerToSwitchPrefix         = "rtos-"
	switchToRouterPrefix         = "stor-"
	joinSwitchToGwRouterPrefix   = "jtor-"
	gwRouterToJoinSwitchPrefix   = "rtoj-"
	distRouterToJoinSwitchPrefix = "dtoj-"
	joinSwitchToDistRouterPrefix = "jtod-"
	extSwitchToGwRouterPrefix    = "etor-"
	gwRouterToExtSwitchPrefix    = "rtoe-"

	nodeLocalSwitch = "node_local_switch"

	// priority of logical router policies on the ovnClusterRouter
	egressFirewallStartPriority           = "10000"
	minimumReservedEgressFirewallPriority = "2000"
	mgmtPortPolicyPriority                = "1005"
	nodeSubnetPolicyPriority              = "1004"
	interNodePolicyPriority               = "1003"
	defaultNoRereoutePriority             = "101"
	egressIPReroutePriority               = "100"
)

func (ovn *Controller) getOvnGateways() ([]string, string, error) {
	// Return all created gateways.
	out, stderr, err := ovn.exec.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=name", "find",
		"logical_router",
		"options:chassis!=null")
	return strings.Fields(out), stderr, err
}

func (ovn *Controller) getGatewayPhysicalIPs(gatewayRouter string) ([]string, error) {
	physicalIPs, _, err := ovn.exec.RunOVNNbctl("get", "logical_router",
		gatewayRouter, "external_ids:physical_ips")
	if err == nil {
		return strings.Split(physicalIPs, ","), nil
	}

	physicalIP, _, err := ovn.exec.RunOVNNbctl("get", "logical_router",
		gatewayRouter, "external_ids:physical_ip")
	if err != nil {
		return nil, err
	}

	return []string{physicalIP}, nil
}

func (ovn *Controller) getGatewayLoadBalancer(gatewayRouter string, protocol kapi.Protocol) (string, error) {
	externalIDKey := string(protocol) + "_lb_gateway_router"
	loadBalancer, _, err := ovn.exec.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "load_balancer",
		"external_ids:"+externalIDKey+"="+
			gatewayRouter)
	if err != nil {
		return "", err
	}
	if loadBalancer == "" {
		return "", fmt.Errorf("load balancer item in OVN DB is an empty string")
	}
	return loadBalancer, nil
}

func (ovn *Controller) createGatewayVIPs(protocol kapi.Protocol, sourcePort int32, targetIPs []string, targetPort int32) error {
	klog.V(5).Infof("Creating Gateway VIPs - %s, %d, [%v], %d", protocol, sourcePort, targetIPs, targetPort)

	// Each gateway has a separate load-balancer for N/S traffic

	gatewayRouters, _, err := ovn.getOvnGateways()
	if err != nil {
		return err
	}

	for _, gatewayRouter := range gatewayRouters {
		loadBalancer, err := ovn.getGatewayLoadBalancer(gatewayRouter, protocol)
		if err != nil {
			klog.Errorf("Gateway router %s does not have load balancer (%v)",
				gatewayRouter, err)
			continue
		}
		physicalIPs, err := ovn.getGatewayPhysicalIPs(gatewayRouter)
		if err != nil {
			klog.Errorf("Gateway router %s does not have physical ip (%v)", gatewayRouter, err)
			continue
		}
		// With the physical_ip:sourcePort as the VIP, add an entry in
		// 'load_balancer'.
		err = ovn.createLoadBalancerVIPs(loadBalancer, physicalIPs, sourcePort, targetIPs, targetPort)
		if err != nil {
			klog.Errorf("Failed to create VIP in load balancer %s - %v", loadBalancer, err)
			continue
		}
	}
	return nil
}

func (ovn *Controller) deleteGatewayVIPs(protocol kapi.Protocol, sourcePort int32) {
	klog.V(5).Infof("Searching to remove Gateway VIPs - %s, %d", protocol, sourcePort)
	gatewayRouters, _, err := ovn.getOvnGateways()
	if err != nil {
		klog.Errorf("Error while searching for gateways: %v", err)
		return
	}

	for _, gatewayRouter := range gatewayRouters {
		loadBalancer, err := ovn.getGatewayLoadBalancer(gatewayRouter, protocol)
		if err != nil {
			klog.Errorf("Gateway router %s does not have load balancer (%v)", gatewayRouter, err)
			continue
		}
		physicalIPs, err := ovn.getGatewayPhysicalIPs(gatewayRouter)
		if err != nil {
			klog.Errorf("Gateway router %s does not have physical ip (%v)", gatewayRouter, err)
			continue
		}
		for _, physicalIP := range physicalIPs {
			// With the physical_ip:sourcePort as the VIP, delete an entry in 'load_balancer'.
			vip := util.JoinHostPortInt32(physicalIP, sourcePort)
			klog.V(5).Infof("Removing gateway VIP: %s from load balancer: %s", vip, loadBalancer)
			if err := ovn.deleteLoadBalancerVIP(loadBalancer, vip); err != nil {
				klog.Error(err)
			}
		}
	}
}

func (ovn *Controller) deleteExternalVIPs(service *kapi.Service, svcPort kapi.ServicePort) error {
	if len(service.Spec.ExternalIPs) == 0 {
		return nil
	}
	gateways, stderr, err := ovn.getOvnGateways()
	if err != nil {
		return fmt.Errorf("error: failed to get ovn gateways, stderr: %s, err: %v)", stderr, err)
	}
	for _, extIP := range service.Spec.ExternalIPs {
		klog.V(5).Infof("Searching to remove ExternalIP VIPs - %s, %d", svcPort.Protocol, svcPort.Port)
		for _, gateway := range gateways {
			loadBalancer, err := ovn.getGatewayLoadBalancer(gateway, svcPort.Protocol)
			if err != nil {
				klog.Errorf("Gateway router: %s does not have load balancer, err: %v", gateway, err)
				continue
			}
			vip := util.JoinHostPortInt32(extIP, svcPort.Port)
			if err := ovn.deleteLoadBalancerVIP(loadBalancer, vip); err != nil {
				klog.Error(err)
			}
		}
	}
	return nil
}

// getGatewayLoadBalancers find TCP, SCTP, UDP load-balancers from gateway router.
func getGatewayLoadBalancers(exec util.ExecHelper, gatewayRouter string) (string, string, string, error) {
	lbTCP, stderr, err := exec.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "load_balancer",
		"external_ids:TCP_lb_gateway_router="+gatewayRouter)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get gateway router %q TCP "+
			"load balancer, stderr: %q, error: %v", gatewayRouter, stderr, err)
	}

	lbUDP, stderr, err := exec.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "load_balancer",
		"external_ids:UDP_lb_gateway_router="+gatewayRouter)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get gateway router %q UDP "+
			"load balancer, stderr: %q, error: %v", gatewayRouter, stderr, err)
	}

	lbSCTP, stderr, err := exec.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "load_balancer",
		"external_ids:SCTP_lb_gateway_router="+gatewayRouter)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get gateway router %q SCTP "+
			"load balancer, stderr: %q, error: %v", gatewayRouter, stderr, err)
	}
	return lbTCP, lbUDP, lbSCTP, nil
}
