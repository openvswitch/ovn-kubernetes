package ovn

import (
	"fmt"
	"net"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/klog"
)

// gatewayCleanup removes all the NB DB objects created for a node's gateway
func gatewayCleanup(exec util.ExecHelper, nodeName string) error {
	gatewayRouter := gwRouterPrefix + nodeName

	// Get the gateway router port's IP address (connected to join switch)
	var routerIP net.IP
	var nextHops []net.IP
	routerIPNetworks, stderr, err := exec.RunOVNNbctl("--if-exist", "get",
		"logical_router_port", gwRouterToJoinSwitchPrefix+gatewayRouter, "networks")
	if err != nil {
		return fmt.Errorf("failed to get logical router port for gateway router %s, "+
			"stderr: %q, error: %v", gatewayRouter, stderr, err)
	}

	// eg: `["100.64.1.1/29", "fd98:1::/125"]`
	routerIPNetworks = strings.Trim(routerIPNetworks, "[]")
	if routerIPNetworks != "" {
		for _, routerIPNetwork := range strings.Split(routerIPNetworks, ", ") {
			routerIPNetwork = strings.Trim(routerIPNetwork, "\"")
			routerIP, _, err = net.ParseCIDR(routerIPNetwork)
			if err != nil {
				return fmt.Errorf("could not parse logical router port %q: %v",
					routerIPNetwork, err)
			}
			if routerIP != nil {
				nextHops = append(nextHops, routerIP)
			}
		}
	}

	staticRouteCleanup(exec, nextHops)

	// Remove the join switch that connects ovn_cluster_router to gateway router
	_, stderr, err = exec.RunOVNNbctl("--if-exist", "ls-del", joinSwitchPrefix+nodeName)
	if err != nil {
		return fmt.Errorf("failed to delete the join logical switch %s, "+
			"stderr: %q, error: %v", joinSwitchPrefix+nodeName, stderr, err)
	}

	// Remove the gateway router associated with nodeName
	_, stderr, err = exec.RunOVNNbctl("--if-exist", "lr-del",
		gatewayRouter)
	if err != nil {
		return fmt.Errorf("failed to delete gateway router %s, stderr: %q, "+
			"error: %v", gatewayRouter, stderr, err)
	}

	// Remove external switch
	externalSwitch := externalSwitchPrefix + nodeName
	_, stderr, err = exec.RunOVNNbctl("--if-exist", "ls-del",
		externalSwitch)
	if err != nil {
		return fmt.Errorf("failed to delete external switch %s, stderr: %q, "+
			"error: %v", externalSwitch, stderr, err)
	}

	// Remove the patch port on the distributed router that connects to join switch
	_, stderr, err = exec.RunOVNNbctl("--if-exist", "lrp-del", distRouterToJoinSwitchPrefix+nodeName)
	if err != nil {
		return fmt.Errorf("failed to delete the patch port dtoj-%s on distributed router "+
			"stderr: %q, error: %v", nodeName, stderr, err)
	}

	// If exists, remove the TCP, UDP load-balancers created for north-south traffic for gateway router.
	k8sNSLbTCP, k8sNSLbUDP, k8sNSLbSCTP, err := getGatewayLoadBalancers(exec, gatewayRouter)
	if err != nil {
		return err
	}
	protoLBMap := map[kapi.Protocol]string{
		kapi.ProtocolTCP:  k8sNSLbTCP,
		kapi.ProtocolUDP:  k8sNSLbUDP,
		kapi.ProtocolSCTP: k8sNSLbSCTP,
	}
	for proto, uuid := range protoLBMap {
		if uuid != "" {
			_, stderr, err = exec.RunOVNNbctl("lb-del", uuid)
			if err != nil {
				return fmt.Errorf("failed to delete Gateway router %s's %s load balancer %s, stderr: %q, "+
					"error: %v", gatewayRouter, proto, uuid, stderr, err)
			}
		}
	}

	// We don't know the gateway mode as this is running in the master, try to delete the additional local
	// gateway for the shared gateway mode. it will be no op if this is done for other gateway modes.
	delPbrAndNatRules(exec, nodeName)
	return nil
}

func delPbrAndNatRules(exec util.ExecHelper, nodeName string) {
	// delete the dnat_and_snat entry that we added for the management port IP
	// Note: we don't need to delete any MAC bindings that are dynamically learned from OVN SB DB
	// because there will be none since this NAT is only for outbound traffic and not for inbound
	mgmtPortName := util.K8sPrefix + nodeName
	externalIP, stderr, err := exec.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=external_ip", "find", "nat", fmt.Sprintf("logical_port=%s", mgmtPortName))
	if err != nil {
		klog.Errorf("Failed to fetch the dnat_and_snat entry for the management port %s "+
			"stderr: %s, error: %v", mgmtPortName, stderr, err)
		externalIP = ""
	}
	if externalIP != "" {
		_, stderr, err = exec.RunOVNNbctl("--if-exists", "lr-nat-del", ovnClusterRouter, "dnat_and_snat", externalIP)
		if err != nil {
			klog.Errorf("Failed to delete the dnat_and_snat ip %s associated with the management "+
				"port %s: stderr: %s, error: %v", externalIP, mgmtPortName, stderr, err)
		}
	}

	// find the pbr rules associated with the node and delete them
	matches, stderr, err := exec.RunOVNNbctl("--data=bare", "--no-heading", "--columns=match",
		"find", "logical_router_policy")
	if err != nil {
		klog.Errorf("Failed to fetch the policy route for the node subnet "+
			"stdout: %s, stderr: %s, error: %v", matches, stderr, err)
		matches = ""
	}
	// matches inport for a policy, must use ending quote to substring match to avoid matching other nodes accidentally
	// i.e. rtos-ovn-worker would match rtos-ovn-worker2
	nodeSubnetMatchSubStr := fmt.Sprintf("rtos-%s\"", nodeName)
	// for inter node, match the comment in the policy, and include extra space to avoid accidental submatch
	interNodeMatchSubStr := fmt.Sprintf("inter-%s ", nodeName)
	// mgmt port policy matches node name in comment, use extra spaces to avoid accidental match of other nodes
	mgmtPortPolicyMatchSubStr := fmt.Sprintf(" %s ", nodeName)
	for _, match := range strings.Split(matches, "\n\n") {
		var priority string
		if strings.Contains(match, nodeSubnetMatchSubStr) {
			priority = nodeSubnetPolicyPriority
		} else if strings.Contains(match, interNodeMatchSubStr) {
			priority = interNodePolicyPriority
		} else if strings.Contains(match, mgmtPortPolicyMatchSubStr) {
			priority = mgmtPortPolicyPriority
		} else {
			continue
		}
		_, stderr, err = exec.RunOVNNbctl("lr-policy-del", ovnClusterRouter, priority, match)
		if err != nil {
			klog.Errorf("Failed to remove the policy routes (%s, %s) associated with the node %s: stderr: %s, error: %v",
				priority, match, nodeName, stderr, err)
		}
	}
}

func staticRouteCleanup(exec util.ExecHelper, nextHops []net.IP) {
	for _, nextHop := range nextHops {
		// Get a list of all the routes in cluster router with the next hop IP.
		var uuids string
		uuids, stderr, err := exec.RunOVNNbctl("--data=bare", "--no-heading",
			"--columns=_uuid", "find", "logical_router_static_route",
			"nexthop=\""+nextHop.String()+"\"")
		if err != nil {
			klog.Errorf("Failed to fetch all routes with "+
				"IP %s as nexthop, stderr: %q, "+
				"error: %v", nextHop.String(), stderr, err)
			continue
		}

		// Remove all the routes in cluster router with this IP as the nexthop.
		routes := strings.Fields(uuids)
		for _, route := range routes {
			_, stderr, err = exec.RunOVNNbctl("--if-exists", "remove",
				"logical_router", ovnClusterRouter, "static_routes", route)
			if err != nil {
				klog.Errorf("Failed to delete static route %s"+
					", stderr: %q, err = %v", route, stderr, err)
				continue
			}
		}
	}
}
