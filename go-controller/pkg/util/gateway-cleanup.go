package util

import (
	"fmt"
	"net"
	"strings"

	"k8s.io/klog"
)

// GatewayCleanup removes all the NB DB objects created for a node's gateway
func GatewayCleanup(nodeName string, nodeSubnet *net.IPNet) error {
	// Get the cluster router
	clusterRouter := GetK8sClusterRouter()
	gatewayRouter := GWRouterPrefix + nodeName

	// Get the gateway router port's IP address (connected to join switch)
	var routerIP net.IP
	var nextHops []net.IP
	routerIPNetwork, stderr, err := RunOVNNbctl("--if-exist", "get",
		"logical_router_port", "rtoj-"+gatewayRouter, "networks")
	if err != nil {
		return fmt.Errorf("failed to get logical router port for gateway router %s, "+
			"stderr: %q, error: %v", gatewayRouter, stderr, err)
	}

	routerIPNetwork = strings.Trim(routerIPNetwork, "[]\"")
	if routerIPNetwork != "" {
		routerIP, _, err = net.ParseCIDR(routerIPNetwork)
		if err != nil {
			return fmt.Errorf("could not parse logical router port %q: %v",
				routerIPNetwork, err)
		}
	}
	if routerIP != nil {
		nextHops = append(nextHops, routerIP)
	}

	if nodeSubnet != nil {
		_, mgtPortIP := GetNodeWellKnownAddresses(nodeSubnet)
		nextHops = append(nextHops, mgtPortIP.IP)
	}
	staticRouteCleanup(clusterRouter, nextHops)

	// Remove the join switch that connects ovn_cluster_router to gateway router
	_, stderr, err = RunOVNNbctl("--if-exist", "ls-del", JoinSwitchPrefix+nodeName)
	if err != nil {
		return fmt.Errorf("failed to delete the join logical switch %s, "+
			"stderr: %q, error: %v", JoinSwitchPrefix+nodeName, stderr, err)
	}

	// Remove the gateway router associated with nodeName
	_, stderr, err = RunOVNNbctl("--if-exist", "lr-del",
		gatewayRouter)
	if err != nil {
		return fmt.Errorf("failed to delete gateway router %s, stderr: %q, "+
			"error: %v", gatewayRouter, stderr, err)
	}

	// Remove external switch
	externalSwitch := ExternalSwitchPrefix + nodeName
	_, stderr, err = RunOVNNbctl("--if-exist", "ls-del",
		externalSwitch)
	if err != nil {
		return fmt.Errorf("failed to delete external switch %s, stderr: %q, "+
			"error: %v", externalSwitch, stderr, err)
	}

	// Remove the patch port on the distributed router that connects to join switch
	_, stderr, err = RunOVNNbctl("--if-exist", "lrp-del", "dtoj-"+nodeName)
	if err != nil {
		return fmt.Errorf("failed to delete the patch port dtoj-%s on distributed router "+
			"stderr: %q, error: %v", nodeName, stderr, err)
	}

	// If exists, remove the TCP, UDP load-balancers created for north-south traffic for gateway router.
	k8sNSLbTCP, k8sNSLbUDP, k8sNSLbSCTP, err := getGatewayLoadBalancers(gatewayRouter)
	if err != nil {
		return err
	}
	if k8sNSLbTCP != "" {
		_, stderr, err = RunOVNNbctl("lb-del", k8sNSLbTCP)
		if err != nil {
			return fmt.Errorf("failed to delete Gateway router %s's TCP load balancer %s, stderr: %q, "+
				"error: %v", gatewayRouter, k8sNSLbTCP, stderr, err)
		}
	}
	if k8sNSLbUDP != "" {
		_, stderr, err = RunOVNNbctl("lb-del", k8sNSLbUDP)
		if err != nil {
			return fmt.Errorf("failed to delete Gateway router %s's UDP load balancer %s, stderr: %q, "+
				"error: %v", gatewayRouter, k8sNSLbUDP, stderr, err)
		}
	}
	if k8sNSLbSCTP != "" {
		_, stderr, err = RunOVNNbctl("lb-del", k8sNSLbSCTP)
		if err != nil {
			return fmt.Errorf("failed to delete Gateway router %s's SCTP load balancer %s, stderr: %q, "+
				"error: %v", gatewayRouter, k8sNSLbSCTP, stderr, err)
		}
	}
	return nil
}

func staticRouteCleanup(clusterRouter string, nextHops []net.IP) {
	for _, nextHop := range nextHops {
		// Get a list of all the routes in cluster router with the next hop IP.
		var uuids string
		uuids, stderr, err := RunOVNNbctl("--data=bare", "--no-heading",
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
			_, stderr, err = RunOVNNbctl("--if-exists", "remove",
				"logical_router", clusterRouter, "static_routes", route)
			if err != nil {
				klog.Errorf("Failed to delete static route %s"+
					", stderr: %q, err = %v", route, stderr, err)
				continue
			}
		}
	}
}
