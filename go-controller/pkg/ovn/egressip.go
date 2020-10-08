package ovn

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressipv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog"
	utilnet "k8s.io/utils/net"
)

const (
	// In case we restart we need accept executing ovn-nbctl commands with this error.
	// The ovn-nbctl API does not support `--may-exist` for `lr-policy-add`
	policyAlreadyExistsMsg = "Same routing policy already existed"
)

type modeEgressIP interface {
	addPodEgressIP(eIP *egressipv1.EgressIP, pod *kapi.Pod) error
	deletePodEgressIP(eIP *egressipv1.EgressIP, pod *kapi.Pod) error
	needsRetry(pod *kapi.Pod) bool
}

func (oc *Controller) addEgressIP(eIP *egressipv1.EgressIP) error {
	// If the status is set at this point, then we know it's valid from syncEgressIP and we have no assignment to do.
	// Just initialize all watchers (which should not re-create any already existing items in the OVN DB)
	if len(eIP.Status.Items) == 0 {
		if err := oc.assignEgressIPs(eIP); err != nil {
			return fmt.Errorf("unable to assign egress IP: %s, error: %v", eIP.Name, err)
		}
	}

	oc.egressIPNamespaceHandlerMutex.Lock()
	defer oc.egressIPNamespaceHandlerMutex.Unlock()

	sel, err := metav1.LabelSelectorAsSelector(&eIP.Spec.NamespaceSelector)
	if err != nil {
		return fmt.Errorf("invalid namespaceSelector on EgressIP %s: %v", eIP.Name, err)
	}
	h := oc.watchFactory.AddFilteredNamespaceHandler("", sel,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				namespace := obj.(*kapi.Namespace)
				klog.V(5).Infof("EgressIP: %s has matched on namespace: %s", eIP.Name, namespace.Name)
				if err := oc.addNamespaceEgressIP(eIP, namespace); err != nil {
					klog.Errorf("error: unable to add namespace handler for EgressIP: %s, err: %v", eIP.Name, err)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {},
			DeleteFunc: func(obj interface{}) {
				namespace := obj.(*kapi.Namespace)
				klog.V(5).Infof("EgressIP: %s stopped matching on namespace: %s", eIP.Name, namespace.Name)
				if err := oc.deleteNamespaceEgressIP(eIP, namespace); err != nil {
					klog.Errorf("error: unable to delete namespace handler for EgressIP: %s, err: %v", eIP.Name, err)
				}
			},
		}, nil)
	oc.egressIPNamespaceHandlerCache[getEgressIPKey(eIP)] = *h
	return nil
}

func (oc *Controller) deleteEgressIP(eIP *egressipv1.EgressIP) error {
	oc.releaseEgressIPs(eIP)

	oc.egressIPNamespaceHandlerMutex.Lock()
	defer oc.egressIPNamespaceHandlerMutex.Unlock()
	if nH, exists := oc.egressIPNamespaceHandlerCache[getEgressIPKey(eIP)]; exists {
		oc.watchFactory.RemoveNamespaceHandler(&nH)
		delete(oc.egressIPNamespaceHandlerCache, getEgressIPKey(eIP))
	}

	oc.egressIPPodHandlerMutex.Lock()
	defer oc.egressIPPodHandlerMutex.Unlock()
	if pH, exists := oc.egressIPPodHandlerCache[getEgressIPKey(eIP)]; exists {
		oc.watchFactory.RemovePodHandler(&pH)
		delete(oc.egressIPPodHandlerCache, getEgressIPKey(eIP))
	}

	namespaces, err := oc.kube.GetNamespaces(eIP.Spec.NamespaceSelector)
	if err != nil {
		return err
	}
	for _, namespace := range namespaces.Items {
		if err := oc.deleteNamespacePodsEgressIP(eIP, &namespace); err != nil {
			return err
		}
	}
	return nil
}

func (oc *Controller) syncEgressIPs(eIPs []interface{}) {
	oc.eIPAllocatorMutex.Lock()
	defer oc.eIPAllocatorMutex.Unlock()
	for _, eIP := range eIPs {
		eIP, ok := eIP.(*egressipv1.EgressIP)
		if !ok {
			klog.Errorf("Spurious object in syncEgressIPs: %v", eIP)
			continue
		}
		var validAssignment bool
		for _, eIPStatus := range eIP.Status.Items {
			validAssignment = false
			eNode, exists := oc.eIPAllocator[eIPStatus.Node]
			if !exists {
				klog.Errorf("Allocator error: EgressIP: %s claims to have an allocation on a node which is unassignable for egress IP: %s", eIP.Name, eIPStatus.Node)
				break
			}
			if eNode.tainted {
				klog.Errorf("Allocator error: EgressIP: %s claims multiple egress IPs on same node: %s, will attempt rebalancing", eIP.Name, eIPStatus.Node)
				break
			}
			ip := net.ParseIP(eIPStatus.EgressIP)
			if ip == nil {
				klog.Errorf("Allocator error: EgressIP allocation contains unparsable IP address: %s", eIPStatus.EgressIP)
				break
			}
			if utilnet.IsIPv6(ip) && eNode.v6Subnet != nil {
				if !eNode.v6Subnet.Contains(ip) {
					klog.Errorf("Allocator error: EgressIP allocation: %s on subnet: %s which cannot host it", ip.String(), eNode.v6Subnet.String())
					break
				}
			} else if !utilnet.IsIPv6(ip) && eNode.v4Subnet != nil {
				if !eNode.v4Subnet.Contains(ip) {
					klog.Errorf("Allocator error: EgressIP allocation: %s on subnet: %s which cannot host it", ip.String(), eNode.v4Subnet.String())
					break
				}
			} else {
				klog.Errorf("Allocator error: EgressIP allocation on node: %s which does not support its IP protocol version", eIPStatus.Node)
				break
			}
			validAssignment = true
			eNode.tainted = true
		}
		// In the unlikely event that any status has been misallocated previously:
		// unassign that by updating the entire status and re-allocate properly in addEgressIP
		if !validAssignment {
			eIP.Status = egressipv1.EgressIPStatus{
				Items: []egressipv1.EgressIPStatusItem{},
			}
			if err := oc.updateEgressIPWithRetry(eIP); err != nil {
				klog.Error(err)
				continue
			}
			namespaces, err := oc.kube.GetNamespaces(eIP.Spec.NamespaceSelector)
			if err != nil {
				klog.Errorf("Unable to list namespaces matched by EgressIP: %s, err: %v", getEgressIPKey(eIP), err)
				continue
			}
			for _, namespace := range namespaces.Items {
				if err := oc.deleteNamespacePodsEgressIP(eIP, &namespace); err != nil {
					klog.Error(err)
				}
			}
		}
		for _, eNode := range oc.eIPAllocator {
			eNode.tainted = false
		}
	}
}

func (oc *Controller) updateEgressIPWithRetry(eIP *egressipv1.EgressIP) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		return oc.kube.UpdateEgressIP(eIP)
	})
}

func (oc *Controller) addNamespaceEgressIP(eIP *egressipv1.EgressIP, namespace *kapi.Namespace) error {
	oc.egressIPPodHandlerMutex.Lock()
	defer oc.egressIPPodHandlerMutex.Unlock()

	sel, err := metav1.LabelSelectorAsSelector(&eIP.Spec.PodSelector)
	if err != nil {
		return fmt.Errorf("invalid podSelector on EgressIP %s: %v", eIP.Name, err)
	}
	h := oc.watchFactory.AddFilteredPodHandler(namespace.Name, sel,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				pod := obj.(*kapi.Pod)
				klog.V(5).Infof("EgressIP: %s has matched on pod: %s in namespace: %s", eIP.Name, pod.Name, namespace.Name)
				if err := oc.modeEgressIP.addPodEgressIP(eIP, pod); err != nil {
					klog.Errorf("Unable to add pod: %s/%s to EgressIP: %s, err: %v", pod.Namespace, pod.Name, eIP.Name, err)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				newPod := newObj.(*kapi.Pod)
				// FYI: the only pod update we care about here is the pod being assigned an IP, which
				// it didn't have when we received the ADD. If the label is changed and it stops matching:
				// this watcher receives a delete.
				if oc.modeEgressIP.needsRetry(newPod) {
					klog.V(5).Infof("EgressIP: %s update for pod: %s in namespace: %s", eIP.Name, newPod.Name, namespace.Name)
					if err := oc.modeEgressIP.addPodEgressIP(eIP, newPod); err != nil {
						klog.Errorf("Unable to add pod: %s/%s to EgressIP: %s, err: %v", newPod.Namespace, newPod.Name, eIP.Name, err)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				pod := obj.(*kapi.Pod)
				// FYI: we can be in a situation where we processed a pod ADD for which there was no IP
				// address assigned. If the pod is deleted before the IP address is assigned,
				// we should not process that delete (as nothing exists in OVN for it)
				klog.V(5).Infof("EgressIP: %s has stopped matching on pod: %s in namespace: %s, needs delete: %v", eIP.Name, pod.Name, namespace.Name, !oc.modeEgressIP.needsRetry(pod))
				if !oc.modeEgressIP.needsRetry(pod) {
					if err := oc.modeEgressIP.deletePodEgressIP(eIP, pod); err != nil {
						klog.Errorf("Unable to delete pod: %s/%s to EgressIP: %s, err: %v", pod.Namespace, pod.Name, eIP.Name, err)
					}
				}
			},
		}, nil)
	oc.egressIPPodHandlerCache[getEgressIPKey(eIP)] = *h
	return nil
}

func (oc *Controller) deleteNamespaceEgressIP(eIP *egressipv1.EgressIP, namespace *kapi.Namespace) error {
	oc.egressIPPodHandlerMutex.Lock()
	defer oc.egressIPPodHandlerMutex.Unlock()
	if pH, exists := oc.egressIPPodHandlerCache[getEgressIPKey(eIP)]; exists {
		oc.watchFactory.RemovePodHandler(&pH)
		delete(oc.egressIPPodHandlerCache, getEgressIPKey(eIP))
	}
	if err := oc.deleteNamespacePodsEgressIP(eIP, namespace); err != nil {
		return err
	}
	return nil
}

func (oc *Controller) deleteNamespacePodsEgressIP(eIP *egressipv1.EgressIP, namespace *kapi.Namespace) error {
	pods, err := oc.kube.GetPods(namespace.Name, eIP.Spec.PodSelector)
	if err != nil {
		return err
	}
	for _, pod := range pods.Items {
		if !oc.modeEgressIP.needsRetry(&pod) {
			if err := oc.modeEgressIP.deletePodEgressIP(eIP, &pod); err != nil {
				return err
			}
		}
	}
	return nil
}

func (oc *Controller) assignEgressIPs(eIP *egressipv1.EgressIP) error {
	oc.eIPAllocatorMutex.Lock()
	assignments := []egressipv1.EgressIPStatusItem{}
	defer func() {
		eIP.Status.Items = assignments
		oc.eIPAllocatorMutex.Unlock()
	}()
	if len(oc.eIPAllocator) == 0 {
		oc.egressAssignmentRetry.Store(eIP.Name, true)
		eIPRef := kapi.ObjectReference{
			Kind: "EgressIP",
			Name: eIP.Name,
		}
		oc.recorder.Eventf(&eIPRef, kapi.EventTypeWarning, "NoMatchingNodeFound", "no assignable nodes for EgressIP: %s, please tag at least one node with label: %s", eIP.Name, util.GetNodeEgressLabel())
		return fmt.Errorf("no assignable nodes")
	}
	eNodes, existingAllocations := oc.getSortedEgressData()
	klog.V(5).Infof("Current assignments are: %+v", existingAllocations)
	for _, egressIP := range eIP.Spec.EgressIPs {
		klog.V(5).Infof("Will attempt assignment for egress IP: %s", egressIP)
		eIPC := net.ParseIP(egressIP)
		if eIPC == nil {
			eIPRef := kapi.ObjectReference{
				Kind: "EgressIP",
				Name: eIP.Name,
			}
			oc.recorder.Eventf(&eIPRef, kapi.EventTypeWarning, "InvalidEgressIP", "egress IP: %s for object EgressIP: %s is not a valid IP address", egressIP, eIP.Name)
			klog.Errorf("Unable to parse provided EgressIP: %s, invalid", egressIP)
			continue
		}
		for i := 0; i < len(eNodes); i++ {
			klog.V(5).Infof("Attempting assignment on egress node: %+v", eNodes[i])
			if _, exists := existingAllocations[eIPC.String()]; exists {
				klog.V(5).Infof("EgressIP: %s is already allocated, skipping", eIPC.String())
				break
			}
			if eNodes[i].tainted {
				klog.V(5).Infof("Node: %s is already in use by another egress IP for this EgressIP: %s, trying another node", eNodes[i].name, eIP.Name)
				continue
			}
			if (utilnet.IsIPv6(eIPC) && eNodes[i].v6Subnet != nil && eNodes[i].v6Subnet.Contains(eIPC)) ||
				(!utilnet.IsIPv6(eIPC) && eNodes[i].v4Subnet != nil && eNodes[i].v4Subnet.Contains(eIPC)) {
				eNodes[i].tainted, oc.eIPAllocator[eNodes[i].name].allocations[eIPC.String()] = true, true
				assignments = append(assignments, egressipv1.EgressIPStatusItem{
					EgressIP: eIPC.String(),
					Node:     eNodes[i].name,
				})
				klog.V(5).Infof("Successful assignment of egress IP: %s on node: %+v", egressIP, eNodes[i])
				break
			}
		}
	}
	if len(assignments) == 0 {
		oc.egressAssignmentRetry.Store(eIP.Name, true)
		eIPRef := kapi.ObjectReference{
			Kind: "EgressIP",
			Name: eIP.Name,
		}
		oc.recorder.Eventf(&eIPRef, kapi.EventTypeWarning, "NoMatchingNodeFound", "No matching nodes found, which can host any of the egress IPs: %v for object EgressIP: %s", eIP.Spec.EgressIPs, eIP.Name)
		return fmt.Errorf("no matching host found")
	}
	if len(assignments) < len(eIP.Spec.EgressIPs) {
		oc.egressAssignmentRetry.Store(eIP.Name, true)
		eIPRef := kapi.ObjectReference{
			Kind: "EgressIP",
			Name: eIP.Name,
		}
		oc.recorder.Eventf(&eIPRef, kapi.EventTypeWarning, "UnassignedRequest", "Not all egress IPs for EgressIP: %s could be assigned, please tag more nodes", eIP.Name)
	}
	return nil
}

func (oc *Controller) releaseEgressIPs(eIP *egressipv1.EgressIP) {
	oc.eIPAllocatorMutex.Lock()
	defer oc.eIPAllocatorMutex.Unlock()
	for _, status := range eIP.Status.Items {
		klog.V(5).Infof("Releasing egress IP assignment: %s", status.EgressIP)
		if node, exists := oc.eIPAllocator[status.Node]; exists {
			delete(node.allocations, status.EgressIP)
		}
		klog.V(5).Infof("Remaining allocations on node are: %+v", oc.eIPAllocator[status.Node])
	}
}

func (oc *Controller) getSortedEgressData() ([]eNode, map[string]bool) {
	nodes := []eNode{}
	allAllocations := make(map[string]bool)
	for _, eNode := range oc.eIPAllocator {
		nodes = append(nodes, *eNode)
		for ip := range eNode.allocations {
			allAllocations[ip] = true
		}
	}
	sort.Slice(nodes, func(i, j int) bool {
		return len(nodes[i].allocations) < len(nodes[j].allocations)
	})
	return nodes, allAllocations
}

func getEgressIPKey(eIP *egressipv1.EgressIP) string {
	return eIP.Name
}

func getPodKey(pod *kapi.Pod) string {
	return fmt.Sprintf("%s_%s", pod.Namespace, pod.Name)
}

type egressIPMode struct {
	exec           util.ExecHelper
	podRetry       sync.Map
	gatewayIPCache sync.Map
}

func (e *egressIPMode) addPodEgressIP(eIP *egressipv1.EgressIP, pod *kapi.Pod) error {
	podIPs := e.getPodIPs(pod)
	if podIPs == nil {
		e.podRetry.Store(getPodKey(pod), true)
		return nil
	}
	if e.needsRetry(pod) {
		e.podRetry.Delete(getPodKey(pod))
	}
	for _, status := range eIP.Status.Items {
		if err := e.createEgressPolicy(podIPs, status, eIP.Name); err != nil {
			return fmt.Errorf("unable to create logical router policy for status: %v, err: %v", status, err)
		}
		if err := e.createNATRule(podIPs, status, eIP.Name); err != nil {
			return fmt.Errorf("unable to create NAT rule for status: %v, err: %v", status, err)
		}
	}
	return nil
}

func (e *egressIPMode) deletePodEgressIP(eIP *egressipv1.EgressIP, pod *kapi.Pod) error {
	podIPs := e.getPodIPs(pod)
	if podIPs == nil {
		return nil
	}
	for _, status := range eIP.Status.Items {
		if err := e.deleteEgressPolicy(podIPs, status, eIP.Name); err != nil {
			return fmt.Errorf("unable to delete logical router policy for status: %v, err: %v", status, err)
		}
		if err := e.deleteNATRule(podIPs, status, eIP.Name); err != nil {
			return fmt.Errorf("unable to delete NAT rule for status: %v, err: %v", status, err)
		}
	}
	return nil
}

func (e *egressIPMode) createNATRule(podIPs []net.IP, status egressipv1.EgressIPStatusItem, egressIPName string) error {
	for _, podIP := range podIPs {
		if (utilnet.IsIPv6String(status.EgressIP) && utilnet.IsIPv6(podIP)) || (!utilnet.IsIPv6String(status.EgressIP) && !utilnet.IsIPv6(podIP)) {
			natIDs, err := e.findNatIDs(egressIPName, podIP.String(), status.EgressIP)
			if err != nil {
				return err
			}
			if natIDs == nil {
				_, stderr, err := e.exec.RunOVNNbctl(
					"--id=@nat",
					"create",
					"nat",
					"type=snat",
					fmt.Sprintf("logical_port=k8s-%s", status.Node),
					fmt.Sprintf("external_ip=%s", status.EgressIP),
					fmt.Sprintf("logical_ip=%s", podIP),
					fmt.Sprintf("external_ids:name=%s", egressIPName),
					"--",
					"add",
					"logical_router",
					fmt.Sprintf("GR_%s", status.Node),
					"nat",
					"@nat",
				)
				if err != nil {
					return fmt.Errorf("unable to create nat rule, stderr: %s, err: %v", stderr, err)
				}
			}
		}
	}
	return nil
}

func (e *egressIPMode) deleteNATRule(podIPs []net.IP, status egressipv1.EgressIPStatusItem, egressIPName string) error {
	for _, podIP := range podIPs {
		if (utilnet.IsIPv6String(status.EgressIP) && utilnet.IsIPv6(podIP)) || (!utilnet.IsIPv6String(status.EgressIP) && !utilnet.IsIPv6(podIP)) {
			natIDs, err := e.findNatIDs(egressIPName, podIP.String(), status.EgressIP)
			if err != nil {
				return err
			}
			for _, natID := range natIDs {
				_, stderr, err := e.exec.RunOVNNbctl(
					"remove",
					"logical_router",
					fmt.Sprintf("GR_%s", status.Node),
					"nat",
					natID,
				)
				if err != nil {
					return fmt.Errorf("unable to remove nat from logical_router, stderr: %s, err: %v", stderr, err)
				}
			}
		}
	}
	return nil
}

func (e *egressIPMode) findNatIDs(egressIPName, podIP, egressIP string) ([]string, error) {
	natIDs, stderr, err := e.exec.RunOVNNbctl(
		"--format=csv",
		"--data=bare",
		"--no-heading",
		"--columns=_uuid",
		"find",
		"nat",
		fmt.Sprintf("external_ids:name=%s", egressIPName),
		fmt.Sprintf("logical_ip=%s", podIP),
		fmt.Sprintf("external_ip=%s", egressIP),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to find nat ID, stderr: %s, err: %v", stderr, err)
	}
	if natIDs == "" {
		return nil, nil
	}
	return strings.Split(natIDs, "\n"), nil
}

func (e *egressIPMode) getGatewayRouterJoinIP(node string, wantsIPv6 bool) (net.IP, error) {
	var gatewayIPs []net.IP
	if item, exists := e.gatewayIPCache.Load(node); exists {
		var ok bool
		if gatewayIPs, ok = item.([]net.IP); !ok {
			return nil, fmt.Errorf("unable to cast node: %s gatewayIP cache item to correct type", node)
		}
	} else {
		err := utilwait.ExponentialBackoff(retry.DefaultRetry, func() (bool, error) {
			var err error
			gatewayIPs, err = util.GetNodeGatewayRouterNetInfo(e.exec, node)
			if err != nil {
				klog.Errorf("Attempt at finding node gateway router network information failed, err: %v", err)
			}
			return err == nil, nil
		})
		if err != nil {
			return nil, err
		}
		e.gatewayIPCache.Store(node, gatewayIPs)
	}

	if ip, err := util.MatchIPFamily(wantsIPv6, gatewayIPs); ip != nil {
		return ip, nil
	} else {
		return nil, fmt.Errorf("could not find node %s gateway router: %v", node, err)
	}
}

func (e *egressIPMode) getPodIPs(pod *kapi.Pod) []net.IP {
	if len(pod.Status.PodIPs) == 0 {
		return nil
	}
	podIPs := []net.IP{}
	for _, podIP := range pod.Status.PodIPs {
		podIPs = append(podIPs, net.ParseIP(podIP.IP))
	}
	return podIPs
}

func (e *egressIPMode) needsRetry(pod *kapi.Pod) bool {
	_, retry := e.podRetry.Load(getPodKey(pod))
	return retry
}

// createEgressPolicy uses logical router policies to force egress traffic to the egress node, for that we need
// to retrive the internal gateway router IP attached to the egress node.
func (e *egressIPMode) createEgressPolicy(podIps []net.IP, status egressipv1.EgressIPStatusItem, egressIPName string) error {
	isEgressIPv6 := utilnet.IsIPv6String(status.EgressIP)
	gatewayRouterIP, err := e.getGatewayRouterJoinIP(status.Node, isEgressIPv6)
	if err != nil {
		return fmt.Errorf("unable to retrieve gateway IP for node: %s, err: %v", status.Node, err)
	}
	for _, podIP := range podIps {
		var err error
		var stderr, filterOption string
		if isEgressIPv6 && utilnet.IsIPv6(podIP) {
			filterOption = fmt.Sprintf("ip6.src == %s", podIP.String())
		} else if !isEgressIPv6 && !utilnet.IsIPv6(podIP) {
			filterOption = fmt.Sprintf("ip4.src == %s", podIP.String())
		}
		policyIDs, err := findReroutePolicyIDs(e.exec, filterOption, egressIPName, gatewayRouterIP)
		if err != nil {
			return err
		}
		if policyIDs == nil {
			_, stderr, err = e.exec.RunOVNNbctl(
				"--id=@lr-policy",
				"create",
				"logical_router_policy",
				"action=reroute",
				fmt.Sprintf("match=\"%s\"", filterOption),
				fmt.Sprintf("priority=%v", egressIPReroutePriority),
				fmt.Sprintf("nexthop=%s", gatewayRouterIP),
				fmt.Sprintf("external_ids:name=%s", egressIPName),
				"--",
				"add",
				"logical_router",
				ovnClusterRouter,
				"policies",
				"@lr-policy",
			)
			if err != nil {
				return fmt.Errorf("unable to create logical router policy: %s, stderr: %s, err: %v", status.EgressIP, stderr, err)
			}
		}
	}
	return nil
}

func (e *egressIPMode) deleteEgressPolicy(podIps []net.IP, status egressipv1.EgressIPStatusItem, egressIPName string) error {
	isEgressIPv6 := utilnet.IsIPv6String(status.EgressIP)
	gatewayRouterIP, err := e.getGatewayRouterJoinIP(status.Node, isEgressIPv6)
	if err != nil {
		return fmt.Errorf("unable to retrieve gateway IP for node: %s, err: %v", status.Node, err)
	}
	for _, podIP := range podIps {
		var filterOption string
		if utilnet.IsIPv6(podIP) && utilnet.IsIPv6String(status.EgressIP) {
			filterOption = fmt.Sprintf("ip6.src == %s", podIP.String())
		} else if !utilnet.IsIPv6(podIP) && !utilnet.IsIPv6String(status.EgressIP) {
			filterOption = fmt.Sprintf("ip4.src == %s", podIP.String())
		}
		policyIDs, err := findReroutePolicyIDs(e.exec, filterOption, egressIPName, gatewayRouterIP)
		if err != nil {
			return err
		}
		for _, policyID := range policyIDs {
			_, stderr, err := e.exec.RunOVNNbctl(
				"remove",
				"logical_router",
				ovnClusterRouter,
				"policies",
				policyID,
			)
			if err != nil {
				return fmt.Errorf("unable to remove logical router policy: %s, stderr: %s, err: %v", status.EgressIP, stderr, err)
			}
		}
	}
	return nil
}

func findReroutePolicyIDs(exec util.ExecHelper, filterOption, egressIPName string, gatewayRouterIP net.IP) ([]string, error) {
	policyIDs, stderr, err := exec.RunOVNNbctl(
		"--format=csv",
		"--data=bare",
		"--no-heading",
		"--columns=_uuid",
		"find",
		"logical_router_policy",
		fmt.Sprintf("match=\"%s\"", filterOption),
		fmt.Sprintf("priority=%v", egressIPReroutePriority),
		fmt.Sprintf("external_ids:name=%s", egressIPName),
		fmt.Sprintf("nexthop=%s", gatewayRouterIP),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to find logical router policy for EgressIP: %s, stderr: %s, err: %v", egressIPName, stderr, err)
	}
	if policyIDs == "" {
		return nil, nil
	}
	return strings.Split(policyIDs, "\n"), nil
}

func (oc *Controller) addEgressNode(egressNode *kapi.Node) error {
	klog.V(5).Infof("Egress node: %s about to be initialized", egressNode.Name)
	if err := oc.initEgressIPAllocator(egressNode); err != nil {
		return fmt.Errorf("egress node initialization error: %v", err)
	}
	oc.egressAssignmentRetry.Range(func(key, value interface{}) bool {
		eIPName := key.(string)
		klog.V(5).Infof("Re-assignment for EgressIP: %s attempted by new node: %s", eIPName, egressNode.Name)
		eIP, err := oc.kube.GetEgressIP(eIPName)
		if err != nil {
			klog.Errorf("Re-assignment for EgressIP: unable to retrieve EgressIP: %s from the api-server, err: %v", eIPName, err)
			return true
		}
		if err := oc.reassignEgressIP(eIP); err != nil {
			klog.Errorf("Re-assignment for EgressIP: %s failed, err: %v", eIP.Name, err)
			return true
		}
		oc.egressAssignmentRetry.Delete(eIP.Name)
		return true
	})
	return nil
}

func (oc *Controller) deleteEgressNode(egressNode *kapi.Node) error {
	oc.eIPAllocatorMutex.Lock()
	delete(oc.eIPAllocator, egressNode.Name)
	oc.eIPAllocatorMutex.Unlock()

	klog.V(5).Infof("Egress node: %s about to be removed", egressNode.Name)
	egressIPs, err := oc.kube.GetEgressIPs()
	if err != nil {
		return fmt.Errorf("unable to list egressIPs, err: %v", err)
	}
	for _, eIP := range egressIPs.Items {
		needsReassignment := false
		for _, status := range eIP.Status.Items {
			if status.Node == egressNode.Name {
				needsReassignment = true
				break
			}
		}
		if needsReassignment {
			if err := oc.reassignEgressIP(&eIP); err != nil {
				klog.Errorf("EgressIP: %s re-assignmnent error: %v", eIP.Name, err)
			}
		}
	}
	return nil
}

func (oc *Controller) reassignEgressIP(eIP *egressipv1.EgressIP) error {
	klog.V(5).Infof("EgressIP: %s about to be re-assigned", eIP.Name)
	if err := oc.deleteEgressIP(eIP); err != nil {
		return fmt.Errorf("old egress IP deletion failed, err: %v", err)
	}
	eIP = eIP.DeepCopy()
	eIP.Status = egressipv1.EgressIPStatus{
		Items: []egressipv1.EgressIPStatusItem{},
	}
	if err := oc.addEgressIP(eIP); err != nil {
		return fmt.Errorf("new egress IP assignment failed, err: %v", err)
	}
	if err := oc.updateEgressIPWithRetry(eIP); err != nil {
		return fmt.Errorf("update of new egress IP failed, err: %v", err)
	}
	return nil
}

func (oc *Controller) initEgressIPAllocator(node *kapi.Node) (err error) {
	oc.eIPAllocatorMutex.Lock()
	defer oc.eIPAllocatorMutex.Unlock()
	var v4Subnet, v6Subnet *net.IPNet
	v4IfAddr, v6IfAddr, err := util.ParseNodePrimaryIfAddr(node)
	if err != nil {
		return fmt.Errorf("unable to use node for egress assignment, err: %v", err)
	}
	if v4IfAddr != "" {
		_, v4Subnet, err = net.ParseCIDR(v4IfAddr)
		if err != nil {
			return err
		}
	}
	if v6IfAddr != "" {
		_, v6Subnet, err = net.ParseCIDR(v6IfAddr)
		if err != nil {
			return err
		}
	}
	oc.eIPAllocator[node.Name] = &eNode{
		name:        node.Name,
		v4Subnet:    v4Subnet,
		v6Subnet:    v6Subnet,
		allocations: make(map[string]bool),
	}
	return nil
}

func (oc *Controller) addNodeForEgress(node *v1.Node) error {
	v4Addr, v6Addr := oc.getNodeInternalAddrs(node)
	v4ClusterSubnet, v6ClusterSubnet := oc.getClusterSubnets()
	if err := oc.createDefaultNoRerouteNodePolicies(v4Addr, v6Addr, v4ClusterSubnet, v6ClusterSubnet); err != nil {
		return err
	}
	return nil
}

func (oc *Controller) deleteNodeForEgress(node *v1.Node) error {
	v4Addr, v6Addr := oc.getNodeInternalAddrs(node)
	v4ClusterSubnet, v6ClusterSubnet := oc.getClusterSubnets()
	if err := oc.deleteDefaultNoRerouteNodePolicies(v4Addr, v6Addr, v4ClusterSubnet, v6ClusterSubnet); err != nil {
		return err
	}
	return nil
}

func (oc *Controller) initClusterEgressPolicies(nodes []interface{}) {
	v4ClusterSubnet, v6ClusterSubnet := oc.getClusterSubnets()
	oc.createDefaultNoReroutePodPolicies(v4ClusterSubnet, v6ClusterSubnet)
}

func (oc *Controller) getClusterSubnets() (*net.IPNet, *net.IPNet) {
	var v4ClusterSubnet, v6ClusterSubnet *net.IPNet
	for _, clusterSubnet := range config.Default.ClusterSubnets {
		if !utilnet.IsIPv6CIDR(clusterSubnet.CIDR) {
			v4ClusterSubnet = clusterSubnet.CIDR
		} else {
			v6ClusterSubnet = clusterSubnet.CIDR
		}
	}
	return v4ClusterSubnet, v6ClusterSubnet
}

func (oc *Controller) getNodeInternalAddrs(node *v1.Node) (net.IP, net.IP) {
	var v4Addr, v6Addr net.IP
	for _, nodeAddr := range node.Status.Addresses {
		if nodeAddr.Type == v1.NodeInternalIP {
			ip := net.ParseIP(nodeAddr.Address)
			if !utilnet.IsIPv6(ip) {
				v4Addr = ip
			} else {
				v6Addr = ip
			}
		}
	}
	return v4Addr, v6Addr
}

// createDefaultNoReroutePodPolicies ensures egress pods east<->west traffic with regular pods,
// i.e: ensuring that an egress pod can still communicate with a regular pod / service backed by regular pods
func (oc *Controller) createDefaultNoReroutePodPolicies(v4ClusterSubnet, v6ClusterSubnet *net.IPNet) {
	if v4ClusterSubnet != nil {
		_, stderr, err := oc.exec.RunOVNNbctl("lr-policy-add", ovnClusterRouter, defaultNoRereoutePriority,
			fmt.Sprintf("ip4.src == %s && ip4.dst == %s", v4ClusterSubnet.String(), v4ClusterSubnet.String()), "allow")
		if err != nil && !strings.Contains(stderr, policyAlreadyExistsMsg) {
			klog.Errorf("Unable to create IPv4 default no-reroute logical router policy, stderr: %s, err: %v", stderr, err)
		}
	}
	if v6ClusterSubnet != nil {
		_, stderr, err := oc.exec.RunOVNNbctl("lr-policy-add", ovnClusterRouter, defaultNoRereoutePriority,
			fmt.Sprintf("ip6.src == %s && ip6.dst == %s", v6ClusterSubnet.String(), v6ClusterSubnet.String()), "allow")
		if err != nil && !strings.Contains(stderr, policyAlreadyExistsMsg) {
			klog.Errorf("Unable to create IPv6 default no-reroute logical router policy, stderr: %s, err: %v", stderr, err)
		}
	}
}

// createDefaultNoRerouteNodePolicies ensures egress pods east<->west traffic with hostNetwork pods,
// i.e: ensuring that an egress pod can still communicate with a hostNetwork pod / service backed by hostNetwork pods
func (oc *Controller) createDefaultNoRerouteNodePolicies(v4NodeAddr, v6NodeAddr net.IP, v4ClusterSubnet, v6ClusterSubnet *net.IPNet) error {
	if v4NodeAddr != nil && v4ClusterSubnet != nil {
		_, stderr, err := oc.exec.RunOVNNbctl("lr-policy-add", ovnClusterRouter, defaultNoRereoutePriority,
			fmt.Sprintf("ip4.src == %s && ip4.dst == %s/32", v4ClusterSubnet.String(), v4NodeAddr.String()), "allow")
		if err != nil && !strings.Contains(stderr, policyAlreadyExistsMsg) {
			return fmt.Errorf("unable to create IPv4 default no-reroute logical router policy, stderr: %s, err: %v", stderr, err)
		}
	}
	if v6NodeAddr != nil && v6ClusterSubnet != nil {
		_, stderr, err := oc.exec.RunOVNNbctl("lr-policy-add", ovnClusterRouter, defaultNoRereoutePriority,
			fmt.Sprintf("ip6.src == %s && ip6.dst == %s/128", v6ClusterSubnet.String(), v6NodeAddr.String()), "allow")
		if err != nil && !strings.Contains(stderr, policyAlreadyExistsMsg) {
			return fmt.Errorf("unable to create IPv6 default no-reroute logical router policy, stderr: %s, err: %v", stderr, err)
		}
	}
	return nil
}

func (oc *Controller) deleteDefaultNoRerouteNodePolicies(v4NodeAddr, v6NodeAddr net.IP, v4ClusterSubnet, v6ClusterSubnet *net.IPNet) error {
	if v4NodeAddr != nil && v4ClusterSubnet != nil {
		_, stderr, err := oc.exec.RunOVNNbctl("lr-policy-del", ovnClusterRouter, defaultNoRereoutePriority,
			fmt.Sprintf("ip4.src == %s && ip4.dst == %s/32", v4ClusterSubnet.String(), v4NodeAddr.String()))
		if err != nil && !strings.Contains(stderr, policyAlreadyExistsMsg) {
			return fmt.Errorf("unable to create IPv4 default no-reroute logical router policy, stderr: %s, err: %v", stderr, err)
		}
	}
	if v6NodeAddr != nil && v6ClusterSubnet != nil {
		_, stderr, err := oc.exec.RunOVNNbctl("lr-policy-del", ovnClusterRouter, defaultNoRereoutePriority,
			fmt.Sprintf("ip6.src == %s && ip6.dst == %s/128", v6ClusterSubnet.String(), v6NodeAddr.String()))
		if err != nil && !strings.Contains(stderr, policyAlreadyExistsMsg) {
			return fmt.Errorf("unable to create IPv6 default no-reroute logical router policy, stderr: %s, err: %v", stderr, err)
		}
	}
	return nil
}
