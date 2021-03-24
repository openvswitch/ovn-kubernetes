package ovn

import (
	"fmt"
	"net"
	"strings"
	"time"

	goovn "github.com/ebay/go-ovn"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/ipallocator"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

// Builds the logical switch port name for a given pod.
func podLogicalPortName(pod *kapi.Pod) string {
	return pod.Namespace + "_" + pod.Name
}

func (oc *Controller) syncPods(pods []interface{}) {
	// get the list of logical switch ports (equivalent to pods)
	expectedLogicalPorts := make(map[string]bool)
	for _, podInterface := range pods {
		pod, ok := podInterface.(*kapi.Pod)
		if !ok {
			klog.Errorf("Spurious object in syncPods: %v", podInterface)
			continue
		}
		annotations, err := util.UnmarshalPodAnnotation(pod.Annotations)
		if util.PodScheduled(pod) && util.PodWantsNetwork(pod) && err == nil {
			logicalPort := podLogicalPortName(pod)
			expectedLogicalPorts[logicalPort] = true
			if err = oc.lsManager.AllocateIPs(pod.Spec.NodeName, annotations.IPs); err != nil {
				klog.Errorf("Couldn't allocate IPs: %s for pod: %s on node: %s"+
					" error: %v", util.JoinIPNetIPs(annotations.IPs, " "), logicalPort,
					pod.Spec.NodeName, err)
			}
		}
	}

	// get the list of logical ports from OVN
	output, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=name", "find", "logical_switch_port", "external_ids:pod=true")
	if err != nil {
		klog.Errorf("Error in obtaining list of logical ports, "+
			"stderr: %q, err: %v",
			stderr, err)
		return
	}
	existingLogicalPorts := strings.Fields(output)
	for _, existingPort := range existingLogicalPorts {
		if _, ok := expectedLogicalPorts[existingPort]; !ok {
			// not found, delete this logical port
			klog.Infof("Stale logical port found: %s. This logical port will be deleted.", existingPort)
			out, stderr, err := util.RunOVNNbctl("--if-exists", "lsp-del",
				existingPort)
			if err != nil {
				klog.Errorf("Error in deleting pod's logical port "+
					"stdout: %q, stderr: %q err: %v",
					out, stderr, err)
			}
		}
	}
}

func (oc *Controller) deleteLogicalPort(pod *kapi.Pod) {
	if pod.Spec.HostNetwork {
		return
	}

	podDesc := pod.Namespace + "/" + pod.Name
	klog.Infof("Deleting pod: %s", podDesc)

	logicalPort := podLogicalPortName(pod)
	portInfo, err := oc.logicalPortCache.get(logicalPort)
	if err != nil {
		klog.Errorf(err.Error())
		// If ovnkube-master restarts, it is also possible the Pod's logical switch port
		// is not readded into the cache. Delete logical switch port anyway.
		err = util.OvnNBLSPDel(oc.ovnNBClient, logicalPort)
		if err != nil {
			klog.Errorf(err.Error())
		}

		// Even if the port is not in the cache, IPs annotated in the Pod annotation may already be allocated,
		// need to release them to avoid leakage.
		logicalSwitch := pod.Spec.NodeName
		if logicalSwitch != "" {
			annotation, err := util.UnmarshalPodAnnotation(pod.Annotations)
			if err == nil {
				podIfAddrs := annotation.IPs
				_ = oc.lsManager.ReleaseIPs(logicalSwitch, podIfAddrs)
			}
		}
		return
	}

	// FIXME: if any of these steps fails we need to stop and try again later...

	if err := oc.deletePodFromNamespace(pod.Namespace, portInfo); err != nil {
		klog.Errorf(err.Error())
	}

	err = util.OvnNBLSPDel(oc.ovnNBClient, logicalPort)
	if err != nil {
		klog.Errorf(err.Error())
	}

	if err := oc.lsManager.ReleaseIPs(portInfo.logicalSwitch, portInfo.ips); err != nil {
		klog.Errorf(err.Error())
	}

	if config.Gateway.DisableSNATMultipleGWs {
		oc.deletePerPodGRSNAT(pod.Spec.NodeName, portInfo.ips)
	}
	oc.deleteGWRoutesForPod(pod.Namespace, portInfo.ips)
	oc.deletePodExternalGW(pod)
	oc.logicalPortCache.remove(logicalPort)
}

func (oc *Controller) waitForNodeLogicalSwitch(nodeName string) error {
	// Wait for the node logical switch to be created by the ClusterController.
	// The node switch will be created when the node's logical network infrastructure
	// is created by the node watch.
	if err := wait.PollImmediate(30*time.Millisecond, 30*time.Second, func() (bool, error) {
		return oc.lsManager.GetSwitchSubnets(nodeName) != nil, nil
	}); err != nil {
		return fmt.Errorf("timed out waiting for logical switch %q subnet: %v", nodeName, err)
	}
	return nil
}

func (oc *Controller) addRoutesGatewayIP(pod *kapi.Pod, podAnnotation *util.PodAnnotation, nodeSubnets []*net.IPNet) error {
	// if there are other network attachments for the pod, then check if those network-attachment's
	// annotation has default-route key. If present, then we need to skip adding default route for
	// OVN interface
	networks, err := util.GetPodNetSelAnnotation(pod, util.NetworkAttachmentAnnotation)
	if err != nil {
		return fmt.Errorf("error while getting network attachment definition for [%s/%s]: %v",
			pod.Namespace, pod.Name, err)
	}
	otherDefaultRouteV4 := false
	otherDefaultRouteV6 := false
	for _, network := range networks {
		for _, gatewayRequest := range network.GatewayRequest {
			if utilnet.IsIPv6(gatewayRequest) {
				otherDefaultRouteV6 = true
			} else {
				otherDefaultRouteV4 = true
			}
		}
	}

	for _, podIfAddr := range podAnnotation.IPs {
		isIPv6 := utilnet.IsIPv6CIDR(podIfAddr)
		nodeSubnet, err := util.MatchIPNetFamily(isIPv6, nodeSubnets)
		if err != nil {
			return err
		}

		gatewayIPnet := util.GetNodeGatewayIfAddr(nodeSubnet)

		otherDefaultRoute := otherDefaultRouteV4
		if isIPv6 {
			otherDefaultRoute = otherDefaultRouteV6
		}
		var gatewayIP net.IP
		hasRoutingExternalGWs := len(oc.getRoutingExternalGWs(pod.Namespace).gws) > 0
		hasPodRoutingGWs := len(oc.getRoutingPodGWs(pod.Namespace)) > 0
		if otherDefaultRoute || (hasRoutingExternalGWs && hasPodRoutingGWs) {
			for _, clusterSubnet := range config.Default.ClusterSubnets {
				if isIPv6 == utilnet.IsIPv6CIDR(clusterSubnet.CIDR) {
					podAnnotation.Routes = append(podAnnotation.Routes, util.PodRoute{
						Dest:    clusterSubnet.CIDR,
						NextHop: gatewayIPnet.IP,
					})
				}
			}
			for _, serviceSubnet := range config.Kubernetes.ServiceCIDRs {
				if isIPv6 == utilnet.IsIPv6CIDR(serviceSubnet) {
					podAnnotation.Routes = append(podAnnotation.Routes, util.PodRoute{
						Dest:    serviceSubnet,
						NextHop: gatewayIPnet.IP,
					})
				}
			}
		} else {
			gatewayIP = gatewayIPnet.IP
		}

		if len(config.HybridOverlay.ClusterSubnets) > 0 && !hasRoutingExternalGWs && !hasPodRoutingGWs {
			// Add a route for each hybrid overlay subnet via the hybrid
			// overlay port on the pod's logical switch.
			nextHop := util.GetNodeHybridOverlayIfAddr(nodeSubnet).IP
			for _, clusterSubnet := range config.HybridOverlay.ClusterSubnets {
				if utilnet.IsIPv6CIDR(clusterSubnet.CIDR) == isIPv6 {
					podAnnotation.Routes = append(podAnnotation.Routes, util.PodRoute{
						Dest:    clusterSubnet.CIDR,
						NextHop: nextHop,
					})
				}
			}
		}
		if gatewayIP != nil {
			podAnnotation.Gateways = append(podAnnotation.Gateways, gatewayIP)
		}
	}
	return nil
}

func (oc *Controller) getRoutingExternalGWs(ns string) gatewayInfo {
	res := gatewayInfo{}
	nsInfo := oc.getNamespaceLocked(ns)
	if nsInfo == nil {
		return res
	}
	defer nsInfo.Unlock()
	// return a copy of the object so it can be handled without the
	// namespace locked
	res.bfdEnabled = nsInfo.routingExternalGWs.bfdEnabled
	res.gws = make([]net.IP, len(nsInfo.routingExternalGWs.gws))
	copy(res.gws, nsInfo.routingExternalGWs.gws)
	return res
}

func (oc *Controller) getRoutingPodGWs(ns string) map[string]gatewayInfo {
	nsInfo := oc.getNamespaceLocked(ns)
	if nsInfo == nil {
		return nil
	}
	defer nsInfo.Unlock()
	// return a copy of the object so it can be handled without the
	// namespace locked
	res := make(map[string]gatewayInfo)
	for k, v := range nsInfo.routingExternalPodGWs {
		item := gatewayInfo{
			bfdEnabled: v.bfdEnabled,
			gws:        make([]net.IP, len(v.gws)),
		}
		copy(item.gws, v.gws)
		res[k] = item
	}
	return res
}

func (oc *Controller) addLogicalPort(pod *kapi.Pod) (err error) {
	// If a node does node have an assigned hostsubnet don't wait for the logical switch to appear
	if oc.lsManager.IsNonHostSubnetSwitch(pod.Spec.NodeName) {
		return nil
	}

	// Keep track of how long syncs take.
	start := time.Now()
	defer func() {
		klog.Infof("[%s/%s] addLogicalPort took %v", pod.Namespace, pod.Name, time.Since(start))
	}()

	logicalSwitch := pod.Spec.NodeName
	err = oc.waitForNodeLogicalSwitch(logicalSwitch)
	if err != nil {
		return err
	}

	portName := podLogicalPortName(pod)
	klog.V(5).Infof("Creating logical port for %s on switch %s", portName, logicalSwitch)

	var podMac net.HardwareAddr
	var podIfAddrs []*net.IPNet
	var cmds []*goovn.OvnCommand
	var addresses []string
	var cmd *goovn.OvnCommand
	var releaseIPs bool
	needsIP := true

	// Check if the pod's logical switch port already exists. If it
	// does don't re-add the port to OVN as this will change its
	// UUID and and the port cache, address sets, and port groups
	// will still have the old UUID.
	lsp, err := oc.ovnNBClient.LSPGet(portName)
	if err != nil && err != goovn.ErrorNotFound && err != goovn.ErrorSchema {
		return fmt.Errorf("unable to get the lsp: %s from the nbdb: %s", portName, err)
	}

	if lsp == nil {
		cmd, err = oc.ovnNBClient.LSPAdd(logicalSwitch, portName)
		if err != nil {
			return fmt.Errorf("unable to create the LSPAdd command for port: %s from the nbdb", portName)
		}
		cmds = append(cmds, cmd)
	} else {
		klog.Infof("LSP already exists for port: %s", portName)
	}

	annotation, err := util.UnmarshalPodAnnotation(pod.Annotations)

	// the IPs we allocate in this function need to be released back to the
	// IPAM pool if there is some error in any step of addLogicalPort past
	// the point the IPs were assigned via the IPAM manager.
	// this needs to be done only when releaseIPs is set to true (the case where
	// we truly have assigned podIPs in this call) AND when there is no error in
	// the rest of the functionality of addLogicalPort. It is important to use a
	// named return variable for defer to work correctly.

	defer func() {
		if releaseIPs && err != nil {
			if relErr := oc.lsManager.ReleaseIPs(logicalSwitch, podIfAddrs); relErr != nil {
				klog.Errorf("Error when releasing IPs for node: %s, err: %q",
					logicalSwitch, relErr)
			} else {
				klog.Infof("Released IPs: %s for node: %s", util.JoinIPNetIPs(podIfAddrs, " "), logicalSwitch)
			}
		}
	}()

	if err == nil {
		podMac = annotation.MAC
		podIfAddrs = annotation.IPs

		// If the pod already has annotations use the existing static
		// IP/MAC from the annotation.
		cmd, err = oc.ovnNBClient.LSPSetDynamicAddresses(portName, "")
		if err != nil {
			return fmt.Errorf("unable to create LSPSetDynamicAddresses command for port: %s", portName)
		}
		cmds = append(cmds, cmd)

		// ensure we have reserved the IPs in the annotation
		if err = oc.lsManager.AllocateIPs(logicalSwitch, podIfAddrs); err != nil && err != ipallocator.ErrAllocated {
			return fmt.Errorf("unable to ensure IPs allocated for already annotated pod: %s, IPs: %s, error: %v",
				pod.Name, util.JoinIPNetIPs(podIfAddrs, " "), err)
		} else {
			needsIP = false
		}
	}

	if needsIP {
		// try to get the IP from existing port in OVN first
		podMac, podIfAddrs, err = oc.getPortAddresses(logicalSwitch, portName)
		if err != nil {
			return fmt.Errorf("failed to get pod addresses for pod %s on node: %s, err: %v",
				portName, logicalSwitch, err)
		}
		needsNewAllocation := false
		// ensure we have reserved the IPs found in OVN
		if len(podIfAddrs) == 0 {
			needsNewAllocation = true
		} else if err = oc.lsManager.AllocateIPs(logicalSwitch, podIfAddrs); err != nil && err != ipallocator.ErrAllocated {
			klog.Warningf("Unable to allocate IPs found on existing OVN port: %s, for pod %s on node: %s"+
				" error: %v", util.JoinIPNetIPs(podIfAddrs, " "), portName, logicalSwitch, err)

			needsNewAllocation = true
		}
		if needsNewAllocation {
			// Previous attempts to use already configured IPs failed, need to assign new
			podMac, podIfAddrs, err = oc.assignPodAddresses(logicalSwitch)
			if err != nil {
				return fmt.Errorf("failed to assign pod addresses for pod %s on node: %s, err: %v",
					portName, logicalSwitch, err)
			}
		}

		releaseIPs = true
		var networks []*types.NetworkSelectionElement

		networks, err = util.GetPodNetSelAnnotation(pod, util.DefNetworkAnnotation)
		// handle error cases separately first to ensure binding to err, otherwise the
		// defer will fail
		if err != nil {
			return fmt.Errorf("error while getting custom MAC config for port %q from "+
				"default-network's network-attachment: %v", portName, err)
		} else if networks != nil && len(networks) != 1 {
			err = fmt.Errorf("invalid network annotation size while getting custom MAC config"+
				" for port %q", portName)
			return err
		}

		if networks != nil && networks[0].MacRequest != "" {
			klog.V(5).Infof("Pod %s/%s requested custom MAC: %s", pod.Namespace, pod.Name, networks[0].MacRequest)
			podMac, err = net.ParseMAC(networks[0].MacRequest)
			if err != nil {
				return fmt.Errorf("failed to parse mac %s requested in annotation for pod %s: Error %v",
					networks[0].MacRequest, pod.Name, err)
			}
		}
		podAnnotation := util.PodAnnotation{
			IPs: podIfAddrs,
			MAC: podMac,
		}
		var nodeSubnets []*net.IPNet
		if nodeSubnets = oc.lsManager.GetSwitchSubnets(logicalSwitch); nodeSubnets == nil {
			return fmt.Errorf("cannot retrieve subnet for assigning gateway routes for pod %s, node: %s",
				pod.Name, logicalSwitch)
		}
		err = oc.addRoutesGatewayIP(pod, &podAnnotation, nodeSubnets)
		if err != nil {
			return err
		}
		var marshalledAnnotation map[string]string
		marshalledAnnotation, err = util.MarshalPodAnnotation(&podAnnotation)
		if err != nil {
			return fmt.Errorf("error creating pod network annotation: %v", err)
		}

		klog.V(5).Infof("Annotation values: ip=%v ; mac=%s ; gw=%s\nAnnotation=%s",
			podIfAddrs, podMac, podAnnotation.Gateways, marshalledAnnotation)
		if err = oc.kube.SetAnnotationsOnPod(pod.Namespace, pod.Name, marshalledAnnotation); err != nil {
			return fmt.Errorf("failed to set annotation on pod %s: %v", pod.Name, err)
		}
		releaseIPs = false
	}

	// set addresses on the port
	addresses = make([]string, len(podIfAddrs)+1)
	addresses[0] = podMac.String()
	for idx, podIfAddr := range podIfAddrs {
		addresses[idx+1] = podIfAddr.IP.String()
	}
	// LSP addresses in OVN are a single space-separated value
	cmd, err = oc.ovnNBClient.LSPSetAddress(portName, strings.Join(addresses, " "))
	if err != nil {
		return fmt.Errorf("unable to create LSPSetAddress command for port: %s", portName)
	}
	cmds = append(cmds, cmd)

	// add external ids
	extIds := map[string]string{"namespace": pod.Namespace, "pod": "true"}
	cmd, err = oc.ovnNBClient.LSPSetExternalIds(portName, extIds)
	if err != nil {
		return fmt.Errorf("unable to create LSPSetExternalIds command for port: %s", portName)
	}
	cmds = append(cmds, cmd)

	// execute all the commands together.
	err = oc.ovnNBClient.Execute(cmds...)
	if err != nil {
		return fmt.Errorf("error while creating logical port %s error: %v",
			portName, err)
	}

	lsp, err = oc.ovnNBClient.LSPGet(portName)
	if err != nil || lsp == nil {
		return fmt.Errorf("failed to get the logical switch port: %s from the ovn client, error: %s", portName, err)
	}

	// Add the pod's logical switch port to the port cache
	portInfo := oc.logicalPortCache.add(logicalSwitch, portName, lsp.UUID, podMac, podIfAddrs)

	// Wait for namespace to exist, no calls after this should ever use waitForNamespaceLocked
	if err = oc.addPodToNamespace(pod.Namespace, portInfo); err != nil {
		return err
	}

	// add src-ip routes to GR if external gw annotation is set
	routingExternalGWs := oc.getRoutingExternalGWs(pod.Namespace)
	routingPodGWs := oc.getRoutingPodGWs(pod.Namespace)

	// if we have any external or pod Gateways, add routes
	gateways := make([]gatewayInfo, 0)

	if len(routingExternalGWs.gws) > 0 {
		gateways = append(gateways, routingExternalGWs)
	}
	for _, gw := range routingPodGWs {
		if len(gw.gws) > 0 {
			gateways = append(gateways, gw)
		} else {
			klog.Warningf("Found routingPodGW with no gateways ip set for namespace %s", pod.Namespace)
		}
	}

	if len(gateways) > 0 {
		err = oc.addGWRoutesForPod(gateways, podIfAddrs, pod.Namespace, pod.Spec.NodeName)
		if err != nil {
			return err
		}
	} else if config.Gateway.DisableSNATMultipleGWs {
		// Add NAT rules to pods if disable SNAT is set and does not have
		// namespace annotations to go through external egress router
		if err = oc.addPerPodGRSNAT(pod, podIfAddrs); err != nil {
			return err
		}
	}

	// check if this pod is serving as an external GW
	err = oc.addPodExternalGW(pod)
	if err != nil {
		return fmt.Errorf("failed to handle external GW check: %v", err)
	}

	// CNI depends on the flows from port security, delay setting it until end
	cmd, err = oc.ovnNBClient.LSPSetPortSecurity(portName, strings.Join(addresses, " "))
	if err != nil {
		return fmt.Errorf("unable to create LSPSetPortSecurity command for port: %s", portName)
	}

	err = oc.ovnNBClient.Execute(cmd)
	if err != nil {
		return fmt.Errorf("error while setting port security on port: %s error: %v",
			portName, err)
	}

	// Add this pod to any peer sets for network policies synchronously
	podIPs := make([]net.IP, 0, len(podIfAddrs))
	for _, addr := range podIfAddrs {
		podIPs = append(podIPs, addr.IP)
	}
	if err := oc.podSetController.AddPodDirectly(pod, podIPs); err != nil {
		// failure here is OK; the PodSetController informer will also be triggered
		// and that will retry on failure
		klog.V(2).Infof("Failed to add pod to peer address sets in AddLogicalPort: %v", err)
	}

	// observe the pod creation latency metric.
	metrics.RecordPodCreated(pod)
	return nil
}

// Given a node, gets the next set of addresses (from the IPAM) for each of the node's
// subnets to assign to the new pod
func (oc *Controller) assignPodAddresses(nodeName string) (net.HardwareAddr, []*net.IPNet, error) {
	var (
		podMAC   net.HardwareAddr
		podCIDRs []*net.IPNet
		err      error
	)
	podCIDRs, err = oc.lsManager.AllocateNextIPs(nodeName)
	if err != nil {
		return nil, nil, err
	}
	if len(podCIDRs) > 0 {
		podMAC = util.IPAddrToHWAddr(podCIDRs[0].IP)
	}
	return podMAC, podCIDRs, nil
}

// Given a pod and the node on which it is scheduled, get all addresses currently assigned
// to it from the nbdb.
func (oc *Controller) getPortAddresses(nodeName, portName string) (net.HardwareAddr, []*net.IPNet, error) {
	podMac, podIPs, err := util.GetPortAddresses(portName, oc.ovnNBClient)
	if err != nil {
		return nil, nil, err
	}

	if podMac == nil || len(podIPs) == 0 {
		return nil, nil, nil
	}

	var podIPNets []*net.IPNet

	nodeSubnets := oc.lsManager.GetSwitchSubnets(nodeName)

	for _, ip := range podIPs {
		for _, subnet := range nodeSubnets {
			if subnet.Contains(ip) {
				podIPNets = append(podIPNets,
					&net.IPNet{
						IP:   ip,
						Mask: subnet.Mask,
					})
				break
			}
		}
	}
	return podMac, podIPNets, nil
}
