package ovn

import (
	"fmt"
	"net"
	"strings"
	"time"

	goovn "github.com/ebay/go-ovn"
	networkattachmentdefinitionapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/ipallocator"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

// Builds the logical switch port name for a given pod.
func podLogicalPortName(pod *kapi.Pod, netName string) string {
	return util.GetNetworkPrefix(netName) + pod.Namespace + "_" + pod.Name
}

// See if this pod needs to plumb over this Contoller's network, and return its NetworkSelectionElement if it exists.
//
// Note that since each network attachment definition has its own cidr defined, the same network controller cannot
// exist in the same pod more than once, or it is configuration error.
func (oc *Controller) isNetworkOnPod(pod *kapi.Pod, allNetworks []*networkattachmentdefinitionapi.NetworkSelectionElement) (bool,
	*networkattachmentdefinitionapi.NetworkSelectionElement) {
	podDesc := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
	if !oc.netconf.NotDefault {
		defaultNetwork, err := util.GetK8sPodDefaultNetwork(pod)
		if err != nil {
			// multus won't add this Pod if this fails, should never happen
			klog.Errorf("Failed to get default network for pod %s: %v", podDesc, err)
			return false, nil
		}
		if defaultNetwork == nil {
			return true, nil
		} else if defaultNetwork.Name != "ovn-kubernetes" {
			klog.Errorf("Pod %s's default network %s is non-OVN CNI %s", podDesc, defaultNetwork.Name, "ovn-kubernetes")
			return false, nil
		}
		return true, defaultNetwork
	}

	// For non-default network controller, try to see if its name exists in the Pod's k8s.v1.cni.cncf.io/networks, if no,
	// return false;
	for _, network := range allNetworks {
		if network.Name == oc.netconf.Name {
			return true, network
		}
	}
	return false, nil

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
		allNetworks, err := util.GetK8sPodAllNetworks(pod)
		if err != nil {
			continue
		}
		on, _ := oc.isNetworkOnPod(pod, *allNetworks)
		annotations, err := util.UnmarshalPodAnnotation(pod.Annotations, oc.netconf.Name)
		if podScheduled(pod) && util.PodWantsNetwork(pod) && on && err == nil {
			logicalPort := podLogicalPortName(pod, oc.netconf.Name)
			expectedLogicalPorts[logicalPort] = true
			if err = oc.lsManager.AllocateIPs(pod.Spec.NodeName, annotations.IPs); err != nil {
				klog.Errorf("Couldn't allocate IPs: %s for pod: %s on node: %s"+
					" error: %v", util.JoinIPNetIPs(annotations.IPs, " "), logicalPort,
					pod.Spec.NodeName, err)
			}
		}
	}

	// get the list of logical ports from OVN
	existingLogicalPorts := []string{}
	cmdArgs := []string{"--data=bare", "--no-heading", "--columns=name", "find", "logical_switch_port",
		"external_ids:pod=true"}
	if oc.netconf.NotDefault {
		cmdArgs = append(cmdArgs, "external_ids:network_name="+oc.netconf.Name)
	} else {
		cmdArgs = append(cmdArgs, "external_ids:network_name{=}[]")
	}
	output, stderr, err := util.RunOVNNbctl(cmdArgs...)
	if err != nil {
		klog.Errorf("Error in obtaining list of logical ports, "+
			"stderr: %q, err: %v",
			stderr, err)
		return
	}
	for _, item := range strings.Split(output, "\n") {
		if len(item) == 0 {
			continue
		}
		existingLogicalPorts = append(existingLogicalPorts, item)
	}

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

	allNetworks, err := util.GetK8sPodAllNetworks(pod)
	if err != nil {
		return
	}
	on, _ := oc.isNetworkOnPod(pod, *allNetworks)
	if !on {
		// the Pod is attached to this specific network
		return
	}

	podDesc := pod.Namespace + "/" + pod.Name
	klog.Infof("Deleting pod: %s", podDesc)

	logicalPort := podLogicalPortName(pod, oc.netconf.Name)
	portInfo, err := oc.logicalPortCache.get(logicalPort)
	if err != nil {
		klog.Errorf(err.Error())
		// If ovnkube-master restarts, it is also possible the Pod's logical switch port
		// is not readded into the cache. Delete logical switch port anyway.
		err = util.OvnNBLSPDel(oc.mc.ovnNBClient, logicalPort)
		if err != nil {
			klog.Errorf(err.Error())
		}

		// Even if the port is not in the cache, IPs annotated in the Pod annotation may already be allocated,
		// need to release them to avoid leakage.
		logicalSwitch := pod.Spec.NodeName
		if logicalSwitch != "" {
			annotation, err := util.UnmarshalPodAnnotation(pod.Annotations, oc.netconf.Name)
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

	err = util.OvnNBLSPDel(oc.mc.ovnNBClient, logicalPort)
	if err != nil {
		klog.Errorf(err.Error())
	}

	if err := oc.lsManager.ReleaseIPs(portInfo.nodeName, portInfo.ips); err != nil {
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

func (oc *Controller) addRoutesGatewayIP(pod *kapi.Pod, podAnnotation *util.PodAnnotation, nodeSubnets []*net.IPNet,
	network *networkattachmentdefinitionapi.NetworkSelectionElement,
	networks []*networkattachmentdefinitionapi.NetworkSelectionElement) (err error) {

	if oc.netconf.NotDefault {
		// non default network, see if its network-attachment's annotation has default-route key.
		// If present, then we need to add default route for it
		podAnnotation.Gateways = append(podAnnotation.Gateways, network.GatewayRequest...)
		for _, podIfAddr := range podAnnotation.IPs {
			isIPv6 := utilnet.IsIPv6CIDR(podIfAddr)
			nodeSubnet, err := util.MatchIPNetFamily(isIPv6, nodeSubnets)
			if err != nil {
				return err
			}
			gatewayIPnet := util.GetNodeGatewayIfAddr(nodeSubnet)

			for _, clusterSubnet := range oc.clusterSubnets {
				if isIPv6 == utilnet.IsIPv6CIDR(clusterSubnet.CIDR) {
					podAnnotation.Routes = append(podAnnotation.Routes, util.PodRoute{
						Dest:    clusterSubnet.CIDR,
						NextHop: gatewayIPnet.IP,
					})
				}
			}
		}
		return nil
	}

	// For default network only: network may be ni for default network
	// if there are other network attachments for the pod, then check if those network-attachment's
	// annotation has default-route key. If present, then we need to skip adding default route for
	// OVN interface
	otherDefaultRouteV4 := false
	otherDefaultRouteV6 := false
	for _, n := range networks {
		for _, gatewayRequest := range n.GatewayRequest {
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
		hasRoutingExternalGWs := len(oc.getRoutingExternalGWs(pod.Namespace)) > 0
		hasPodRoutingGWs := len(oc.getRoutingPodGWs(pod.Namespace)) > 0
		if otherDefaultRoute || (hasRoutingExternalGWs && hasPodRoutingGWs) {
			for _, clusterSubnet := range oc.clusterSubnets {
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

func (oc *Controller) getRoutingExternalGWs(ns string) []net.IP {
	nsInfo := oc.getNamespaceLocked(ns)
	if nsInfo == nil {
		return nil
	}
	defer nsInfo.Unlock()
	return nsInfo.routingExternalGWs
}

func (oc *Controller) getRoutingPodGWs(ns string) map[string][]net.IP {
	nsInfo := oc.getNamespaceLocked(ns)
	if nsInfo == nil {
		return nil
	}
	defer nsInfo.Unlock()
	return nsInfo.routingExternalPodGWs
}

func (oc *Controller) updatePodAnnotationWithRetry(origPod *kapi.Pod, podInfo *util.PodAnnotation) error {
	resultErr := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// Informer cache should not be mutated, so get a copy of the object
		pod, err := oc.mc.kube.GetPod(origPod.Namespace, origPod.Name)
		if err != nil {
			return err
		}

		cpod := pod.DeepCopy()
		err = util.MarshalPodAnnotation(&cpod.Annotations, podInfo, oc.netconf.Name)
		if err != nil {
			return err
		}
		return oc.mc.kube.UpdatePod(cpod)
	})
	if resultErr != nil {
		return fmt.Errorf("failed to update annotation on pod %s/%s: %v", origPod.Namespace, origPod.Name, resultErr)
	}
	return nil
}

func (oc *Controller) addLogicalPort(pod *kapi.Pod) (err error) {
	// If a node does node have an assigned hostsubnet don't wait for the logical switch to appear
	if oc.lsManager.IsNonHostSubnetSwitch(pod.Spec.NodeName) {
		return nil
	}

	networks, err := util.GetK8sPodAllNetworks(pod)
	if err != nil {
		return err
	}
	on, network := oc.isNetworkOnPod(pod, *networks)
	if !on {
		// the pod is not attached to this specific network
		klog.V(5).Infof("Pod %s/%s is not attached on this network: %s", pod.Namespace, pod.Name, oc.netconf.Name)
		return nil
	}

	// Keep track of how long syncs take.
	start := time.Now()
	defer func() {
		klog.Infof("[%s/%s] addLogicalPort for network %s took %v", pod.Namespace, pod.Name, oc.netconf.Name, time.Since(start))
	}()

	netPrefix := util.GetNetworkPrefix(oc.netconf.Name)
	logicalSwitch := netPrefix + pod.Spec.NodeName
	err = oc.waitForNodeLogicalSwitch(pod.Spec.NodeName)
	if err != nil {
		return err
	}

	portName := podLogicalPortName(pod, oc.netconf.Name)
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
	lsp, err := oc.mc.ovnNBClient.LSPGet(portName)
	if err != nil && err != goovn.ErrorNotFound && err != goovn.ErrorSchema {
		return fmt.Errorf("unable to get the lsp: %s from the nbdb: %s", portName, err)
	}

	if lsp == nil {
		cmd, err = oc.mc.ovnNBClient.LSPAdd(logicalSwitch, portName)
		if err != nil {
			return fmt.Errorf("unable to create the LSPAdd command for port: %s from the nbdb", portName)
		}
		cmds = append(cmds, cmd)
	} else {
		klog.Infof("LSP already exists for port: %s", portName)
	}

	annotation, err := util.UnmarshalPodAnnotation(pod.Annotations, oc.netconf.Name)

	// the IPs we allocate in this function need to be released back to the
	// IPAM pool if there is some error in any step of addLogicalPort past
	// the point the IPs were assigned via the IPAM manager.
	// this needs to be done only when releaseIPs is set to true (the case where
	// we truly have assigned podIPs in this call) AND when there is no error in
	// the rest of the functionality of addLogicalPort. It is important to use a
	// named return variable for defer to work correctly.

	defer func() {
		if releaseIPs && err != nil {
			if relErr := oc.lsManager.ReleaseIPs(pod.Spec.NodeName, podIfAddrs); relErr != nil {
				klog.Errorf("Error when releasing IPs for node: %s, err: %q",
					pod.Spec.NodeName, relErr)
			} else {
				klog.Infof("Released IPs: %s for node: %s", util.JoinIPNetIPs(podIfAddrs, " "), pod.Spec.NodeName)
			}
		}
	}()

	if err == nil {
		podMac = annotation.MAC
		podIfAddrs = annotation.IPs

		// If the pod already has annotations use the existing static
		// IP/MAC from the annotation.
		cmd, err = oc.mc.ovnNBClient.LSPSetDynamicAddresses(portName, "")
		if err != nil {
			return fmt.Errorf("unable to create LSPSetDynamicAddresses command for port: %s", portName)
		}
		cmds = append(cmds, cmd)

		// ensure we have reserved the IPs in the annotation
		if err = oc.lsManager.AllocateIPs(pod.Spec.NodeName, podIfAddrs); err != nil && err != ipallocator.ErrAllocated {
			return fmt.Errorf("unable to ensure IPs allocated for already annotated pod: %s, IPs: %s, error: %v",
				pod.Name, util.JoinIPNetIPs(podIfAddrs, " "), err)
		} else {
			needsIP = false
		}
	}

	if needsIP {
		// try to get the IP from existing port in OVN first
		podMac, podIfAddrs, err = oc.getPortAddresses(pod.Spec.NodeName, portName)
		if err != nil {
			return fmt.Errorf("failed to get pod addresses for pod %s on node: %s, err: %v",
				portName, pod.Spec.NodeName, err)
		}
		needsNewAllocation := false
		// ensure we have reserved the IPs found in OVN
		if len(podIfAddrs) == 0 {
			needsNewAllocation = true
		} else if err = oc.lsManager.AllocateIPs(pod.Spec.NodeName, podIfAddrs); err != nil && err != ipallocator.ErrAllocated {
			klog.Warningf("Unable to allocate IPs found on existing OVN port: %s, for pod %s on node: %s"+
				" error: %v", util.JoinIPNetIPs(podIfAddrs, " "), portName, pod.Spec.NodeName, err)

			needsNewAllocation = true
		}
		if needsNewAllocation {
			// Previous attempts to use already configured IPs failed, need to assign new
			podMac, podIfAddrs, err = oc.assignPodAddresses(pod.Spec.NodeName)
			if err != nil {
				return fmt.Errorf("failed to assign pod addresses for pod %s on node: %s, err: %v",
					portName, pod.Spec.NodeName, err)
			}
		}

		releaseIPs = true
		if network != nil && network.MacRequest != "" {
			klog.V(5).Infof("Pod %s/%s for network %s requested custom MAC: %s", pod.Namespace, pod.Name,
				oc.netconf.Name, network.MacRequest)
			podMac, err = net.ParseMAC(network.MacRequest)
			if err != nil {
				return fmt.Errorf("failed to parse mac %s requested in annotation for pod %s on network %s: Error %v",
					network.MacRequest, pod.Name, oc.netconf.Name, err)
			}
		}
		podAnnotation := util.PodAnnotation{
			IPs: podIfAddrs,
			MAC: podMac,
		}
		var nodeSubnets []*net.IPNet
		if nodeSubnets = oc.lsManager.GetSwitchSubnets(pod.Spec.NodeName); nodeSubnets == nil {
			return fmt.Errorf("cannot retrieve subnet for assigning gateway routes for pod %s, node: %s, network %s",
				pod.Name, pod.Spec.NodeName, oc.netconf.Name)
		}
		err = oc.addRoutesGatewayIP(pod, &podAnnotation, nodeSubnets, network, *networks)
		if err != nil {
			return err
		}
		klog.V(5).Infof("Annotation values for network %s: ip=%v ; mac=%s ; gw=%s\n",
			podIfAddrs, podMac, oc.netconf.Name, podAnnotation.Gateways)

		if err = oc.updatePodAnnotationWithRetry(pod, &podAnnotation); err != nil {
			return err
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
	cmd, err = oc.mc.ovnNBClient.LSPSetAddress(portName, strings.Join(addresses, " "))
	if err != nil {
		return fmt.Errorf("unable to create LSPSetAddress command for port: %s", portName)
	}
	cmds = append(cmds, cmd)

	// add external ids
	extIds := map[string]string{"namespace": pod.Namespace, "pod": "true"}
	if oc.netconf.NotDefault {
		extIds["network_name"] = oc.netconf.Name
	}
	cmd, err = oc.mc.ovnNBClient.LSPSetExternalIds(portName, extIds)
	if err != nil {
		return fmt.Errorf("unable to create LSPSetExternalIds command for port: %s", portName)
	}
	cmds = append(cmds, cmd)

	// execute all the commands together.
	err = oc.mc.ovnNBClient.Execute(cmds...)
	if err != nil {
		return fmt.Errorf("error while creating logical port %s error: %v",
			portName, err)
	}

	lsp, err = oc.mc.ovnNBClient.LSPGet(portName)
	if err != nil || lsp == nil {
		return fmt.Errorf("failed to get the logical switch port: %s from the ovn client, error: %s", portName, err)
	}

	// Add the pod's logical switch port to the port cache
	portInfo := oc.logicalPortCache.add(pod.Spec.NodeName, portName, lsp.UUID, podMac, podIfAddrs)

	if !oc.netconf.NotDefault {
		// Wait for namespace to exist, no calls after this should ever use waitForNamespaceLocked
		if err = oc.addPodToNamespace(pod.Namespace, portInfo); err != nil {
			return err
		}

		// add src-ip routes to GR if external gw annotation is set
		routingExternalGWs := oc.getRoutingExternalGWs(pod.Namespace)
		routingPodGWs := oc.getRoutingPodGWs(pod.Namespace)

		// if we have any external or pod Gateways, add routes
		if len(routingExternalGWs) > 0 || len(routingPodGWs) > 0 {
			routingGWs := routingExternalGWs
			for _, ipNets := range routingPodGWs {
				routingGWs = append(routingGWs, ipNets...)
			}
			err = oc.addGWRoutesForPod(routingGWs, podIfAddrs, pod.Namespace, pod.Spec.NodeName)
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
	}

	// CNI depends on the flows from port security, delay setting it until end
	cmd, err = oc.mc.ovnNBClient.LSPSetPortSecurity(portName, strings.Join(addresses, " "))
	if err != nil {
		return fmt.Errorf("unable to create LSPSetPortSecurity command for port: %s", portName)
	}

	err = oc.mc.ovnNBClient.Execute(cmd)
	if err != nil {
		return fmt.Errorf("error while setting port security on port: %s error: %v",
			portName, err)
	}

	// observe the pod creation latency metric, default network for now
	if !oc.netconf.NotDefault {
		metrics.RecordPodCreated(pod)
	}
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
	podMac, podIPs, err := util.GetPortAddresses(portName, oc.mc.ovnNBClient)
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
