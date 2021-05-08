package ovn

import (
	"fmt"
	"net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/gateway"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

func (ovn *Controller) getGatewayPhysicalIPs(gatewayRouter string) ([]string, error) {
	return gateway.GetGatewayPhysicalIPs(gatewayRouter)
}

func (ovn *Controller) getGatewayLoadBalancer(gatewayRouter string, protocol kapi.Protocol) (string, error) {
	return gateway.GetGatewayLoadBalancer(gatewayRouter, protocol)
}

// getGatewayLoadBalancers find TCP, SCTP, UDP load-balancers from gateway router.
func getGatewayLoadBalancers(gatewayRouter string) (string, string, string, error) {
	return gateway.GetGatewayLoadBalancers(gatewayRouter)
}

// getJoinLRPAddresses check if IPs of gateway logical router port are within the join switch IP range, and return them if true.
func (oc *Controller) getJoinLRPAddresses(nodeName string) []*net.IPNet {
	// try to get the IPs from the logical router port
	gwLRPIPs := []*net.IPNet{}
	gwLrpName := types.GWRouterToJoinSwitchPrefix + types.GWRouterPrefix + nodeName
	joinSubnets := oc.joinSwIPManager.lsm.GetSwitchSubnets(nodeName)
	ifAddrs, err := util.GetLRPAddrs(gwLrpName)
	if err == nil {
		for _, ifAddr := range ifAddrs {
			for _, subnet := range joinSubnets {
				if subnet.Contains(ifAddr.IP) {
					gwLRPIPs = append(gwLRPIPs, &net.IPNet{IP: ifAddr.IP, Mask: subnet.Mask})
					break
				}
			}
		}
	}

	if len(gwLRPIPs) != len(joinSubnets) {
		var errStr string
		if len(gwLRPIPs) == 0 {
			errStr = fmt.Sprintf("Failed to get IPs for logical router port %s", gwLrpName)
		} else {
			errStr = fmt.Sprintf("Invalid IPs %s (possibly not in the range of subnet %s)",
				util.JoinIPNetIPs(gwLRPIPs, " "), util.JoinIPNetIPs(joinSubnets, " "))
		}
		klog.Warningf("%s for logical router port %s", errStr, gwLrpName)
		return []*net.IPNet{}
	}
	return gwLRPIPs
}
