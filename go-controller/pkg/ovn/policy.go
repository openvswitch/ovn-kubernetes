package ovn

import (
	"fmt"
	"net"
	"sync"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	kapi "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
	utilnet "k8s.io/utils/net"
)

type namespacePolicy struct {
	sync.Mutex
	name            string
	namespace       string
	ingressPolicies []*gressPolicy
	egressPolicies  []*gressPolicy
	podHandlerList  []*factory.Handler
	nsHandlerList   []*factory.Handler
	localPods       map[string]*lpInfo //pods effected by this policy
	portGroupUUID   string             //uuid for OVN port_group
	portGroupName   string
	deleted         bool //deleted policy
}

func NewNamespacePolicy(policy *knet.NetworkPolicy) *namespacePolicy {
	np := &namespacePolicy{
		name:            policy.Name,
		namespace:       policy.Namespace,
		ingressPolicies: make([]*gressPolicy, 0),
		egressPolicies:  make([]*gressPolicy, 0),
		podHandlerList:  make([]*factory.Handler, 0),
		nsHandlerList:   make([]*factory.Handler, 0),
		localPods:       make(map[string]*lpInfo),
	}
	return np
}

const (
	toLport   = "to-lport"
	fromLport = "from-lport"
	noneMatch = "None"
	// Default deny acl rule priority
	defaultDenyPriority = "1000"
	// Default allow acl rule priority
	defaultAllowPriority = "1001"
	// Default multicast deny acl rule priority
	defaultMcastDenyPriority = "1011"
	// Default multicast allow acl rule priority
	defaultMcastAllowPriority = "1012"
)

func (oc *Controller) syncNetworkPolicies(networkPolicies []interface{}) {
	expectedPolicies := make(map[string]map[string]bool)
	for _, npInterface := range networkPolicies {
		policy, ok := npInterface.(*knet.NetworkPolicy)
		if !ok {
			klog.Errorf("Spurious object in syncNetworkPolicies: %v",
				npInterface)
			continue
		}

		if nsMap, ok := expectedPolicies[policy.Namespace]; ok {
			nsMap[policy.Name] = true
		} else {
			expectedPolicies[policy.Namespace] = map[string]bool{
				policy.Name: true,
			}
		}
	}

	err := oc.addressSetFactory.ForEachAddressSet(func(addrSetName, namespaceName, policyName string) {
		if policyName != "" && !expectedPolicies[namespaceName][policyName] {
			// policy doesn't exist on k8s. Delete the port group
			portGroupName := fmt.Sprintf("%s_%s", namespaceName, policyName)
			hashedLocalPortGroup := hashedPortGroup(portGroupName)
			deletePortGroup(oc.exec, hashedLocalPortGroup)

			// delete the address sets for this old policy from OVN
			if err := oc.addressSetFactory.DestroyAddressSetInBackingStore(addrSetName); err != nil {
				klog.Errorf(err.Error())
			}
		}
	})
	if err != nil {
		klog.Errorf("Error in syncing network policies: %v", err)
	}
}

func (oc *Controller) addAllowACLFromNode(logicalSwitch string, mgmtPortIP net.IP) error {
	ipFamily := "ip4"
	if utilnet.IsIPv6(mgmtPortIP) {
		ipFamily = "ip6"
	}
	match := fmt.Sprintf("%s.src==%s", ipFamily, mgmtPortIP.String())
	_, stderr, err := oc.exec.RunOVNNbctl("--may-exist", "acl-add", logicalSwitch,
		"to-lport", defaultAllowPriority, match, "allow-related")
	if err != nil {
		return fmt.Errorf("failed to create the node acl for "+
			"logical_switch=%s, stderr: %q (%v)", logicalSwitch, stderr, err)
	}

	return nil
}

func getACLMatch(portGroupName, match string, policyType knet.PolicyType) string {
	var aclMatch string
	if policyType == knet.PolicyTypeIngress {
		aclMatch = "outport == @" + portGroupName
	} else {
		aclMatch = "inport == @" + portGroupName
	}

	if match != "" {
		aclMatch += " && " + match
	}

	return "match=\"" + aclMatch + "\""
}

func (oc *Controller) addACLPortGroup(portGroupUUID, portGroupName, direction, priority, match, action string, policyType knet.PolicyType) error {
	match = getACLMatch(portGroupName, match, policyType)
	uuid, stderr, err := oc.exec.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "ACL", match, "action="+action,
		fmt.Sprintf("external-ids:default-deny-policy-type=%s", policyType))
	if err != nil {
		return fmt.Errorf("find failed to get the default deny rule for "+
			"policy type %s stderr: %q (%v)", policyType, stderr, err)
	}

	if uuid != "" {
		return nil
	}

	_, stderr, err = oc.exec.RunOVNNbctl("--id=@acl", "create", "acl",
		fmt.Sprintf("priority=%s", priority),
		fmt.Sprintf("direction=%s", direction), match, "action="+action,
		fmt.Sprintf("external-ids:default-deny-policy-type=%s", policyType),
		"--", "add", "port_group", portGroupUUID,
		"acls", "@acl")
	if err != nil {
		return fmt.Errorf("error executing create ACL command for "+
			"policy type %s stderr: %q (%v)", policyType, stderr, err)
	}
	return nil
}

func (oc *Controller) deleteACLPortGroup(portGroupName, direction, priority, match, action string, policyType knet.PolicyType) error {
	match = getACLMatch(portGroupName, match, policyType)
	uuid, stderr, err := oc.exec.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "ACL", match, "action="+action,
		fmt.Sprintf("external-ids:default-deny-policy-type=%s", policyType))
	if err != nil {
		return fmt.Errorf("find failed to get the rule for "+
			"policy type %s stderr: %q (%v)", policyType, stderr, err)
	}

	if uuid == "" {
		return nil
	}

	_, stderr, err = oc.exec.RunOVNNbctl("remove", "port_group",
		portGroupName, "acls", uuid)
	if err != nil {
		return fmt.Errorf("remove failed to delete the rule for "+
			"port_group=%s, stderr: %q (%v)", portGroupName, stderr, err)
	}

	return nil
}

func (oc *Controller) addToPortGroup(portGroup string, portInfo *lpInfo) error {
	_, stderr, err := oc.exec.RunOVNNbctl("--if-exists", "remove",
		"port_group", portGroup, "ports", portInfo.uuid, "--",
		"add", "port_group", portGroup, "ports", portInfo.uuid)
	if err != nil {
		return fmt.Errorf("failed to add logicalPort %s to portGroup %s "+
			"stderr: %q (%v)", portInfo.name, portGroup, stderr, err)
	}
	return nil
}

func (oc *Controller) deleteFromPortGroup(portGroup string, portInfo *lpInfo) error {
	_, stderr, err := oc.exec.RunOVNNbctl("--if-exists", "remove",
		"port_group", portGroup, "ports", portInfo.uuid)
	if err != nil {
		return fmt.Errorf("failed to delete logicalPort %s to portGroup %s "+
			"stderr: %q (%v)", portInfo.name, portGroup, stderr, err)
	}
	return nil
}

func (oc *Controller) createDefaultDenyPortGroup(policyType knet.PolicyType) error {
	var portGroupName string
	if policyType == knet.PolicyTypeIngress {
		if oc.portGroupIngressDeny != "" {
			return nil
		}
		portGroupName = "ingressDefaultDeny"
	} else if policyType == knet.PolicyTypeEgress {
		if oc.portGroupEgressDeny != "" {
			return nil
		}
		portGroupName = "egressDefaultDeny"
	}
	portGroupUUID, err := createPortGroup(oc.exec, portGroupName, portGroupName)
	if err != nil {
		return fmt.Errorf("failed to create port_group for %s (%v)",
			portGroupName, err)
	}
	err = oc.addACLPortGroup(portGroupUUID, portGroupName, toLport,
		defaultDenyPriority, "", "drop", policyType)
	if err != nil {
		return fmt.Errorf("failed to create default deny ACL for port group %v", err)
	}

	err = oc.addACLPortGroup(portGroupUUID, portGroupName, toLport,
		defaultAllowPriority, "arp", "allow", policyType)
	if err != nil {
		return fmt.Errorf("failed to create default allow ARP ACL for port group %v", err)
	}

	if policyType == knet.PolicyTypeIngress {
		oc.portGroupIngressDeny = portGroupUUID
	} else if policyType == knet.PolicyTypeEgress {
		oc.portGroupEgressDeny = portGroupUUID
	}
	return nil
}

// Creates the match string used for ACLs allowing incoming multicast into a
// namespace, that is, from IPs that are in the namespace's address set.
func getMulticastACLMatch(nsInfo *namespaceInfo) string {
	return "ip4.src == $" + nsInfo.addressSet.GetIPv4HashName() + " && ip4.mcast"
}

// Creates a policy to allow multicast traffic within 'ns':
// - a port group containing all logical ports associated with 'ns'
// - one "from-lport" ACL allowing egress multicast traffic from the pods
//   in 'ns'
// - one "to-lport" ACL allowing ingress multicast traffic to pods in 'ns'.
//   This matches only traffic originated by pods in 'ns' (based on the
//   namespace address set).
func (oc *Controller) createMulticastAllowPolicy(ns string, nsInfo *namespaceInfo) error {
	err := nsInfo.updateNamespacePortGroup(ns)
	if err != nil {
		return err
	}

	err = oc.addACLPortGroup(nsInfo.portGroupUUID, hashedPortGroup(ns), fromLport,
		defaultMcastAllowPriority, "ip4.mcast", "allow",
		knet.PolicyTypeEgress)
	if err != nil {
		return fmt.Errorf("failed to create allow egress multicast ACL for %s (%v)",
			ns, err)
	}

	err = oc.addACLPortGroup(nsInfo.portGroupUUID, hashedPortGroup(ns), toLport,
		defaultMcastAllowPriority, getMulticastACLMatch(nsInfo), "allow",
		knet.PolicyTypeIngress)
	if err != nil {
		return fmt.Errorf("failed to create allow ingress multicast ACL for %s (%v)",
			ns, err)
	}

	// Add all ports from this namespace to the multicast allow group.
	pods, err := oc.watchFactory.GetPods(ns)
	if err != nil {
		klog.Warningf("Failed to get pods for namespace %q: %v", ns, err)
	}
	for _, pod := range pods {
		portName := podLogicalPortName(pod)
		if portInfo, err := oc.logicalPortCache.get(portName); err != nil {
			klog.Errorf(err.Error())
		} else if err := oc.podAddAllowMulticastPolicy(ns, portInfo); err != nil {
			klog.Warningf("Failed to add port %s to port group ACL: %v", portName, err)
		}
	}

	return nil
}

func (oc *Controller) deleteMulticastACLs(ns, portGroupHash string, nsInfo *namespaceInfo) error {
	err := oc.deleteACLPortGroup(portGroupHash, fromLport,
		defaultMcastAllowPriority, "ip4.mcast", "allow",
		knet.PolicyTypeEgress)
	if err != nil {
		return fmt.Errorf("failed to delete allow egress multicast ACL for %s (%v)",
			ns, err)
	}

	err = oc.deleteACLPortGroup(portGroupHash, toLport,
		defaultMcastAllowPriority, getMulticastACLMatch(nsInfo), "allow",
		knet.PolicyTypeIngress)
	if err != nil {
		return fmt.Errorf("failed to delete allow ingress multicast ACL for %s (%v)",
			ns, err)
	}

	return nil
}

// Delete the policy to allow multicast traffic within 'ns'.
func (oc *Controller) deleteMulticastAllowPolicy(ns string, nsInfo *namespaceInfo) error {
	portGroupHash := hashedPortGroup(ns)

	err := oc.deleteMulticastACLs(ns, portGroupHash, nsInfo)
	if err != nil {
		return err
	}

	_ = nsInfo.updateNamespacePortGroup(ns)
	return nil
}

// Creates a global default deny multicast policy:
// - one ACL dropping egress multicast traffic from all pods: this is to
//   protect OVN controller from processing IP multicast reports from nodes
//   that are not allowed to receive multicast raffic.
// - one ACL dropping ingress multicast traffic to all pods.
// Caller must hold the namespace's namespaceInfo object lock.
func (oc *Controller) createDefaultDenyMulticastPolicy() error {
	portGroupName := "mcastPortGroupDeny"
	portGroupUUID, err := createPortGroup(oc.exec, portGroupName, portGroupName)
	if err != nil {
		return fmt.Errorf("failed to create port_group for %s (%v)",
			portGroupName, err)
	}

	// By default deny any egress multicast traffic from any pod. This drops
	// IP multicast membership reports therefore denying any multicast traffic
	// to be forwarded to pods.
	err = oc.addACLPortGroup(portGroupUUID, portGroupName, fromLport,
		defaultMcastDenyPriority, "ip4.mcast", "drop", knet.PolicyTypeEgress)
	if err != nil {
		return fmt.Errorf("failed to create default deny multicast egress ACL (%v)",
			err)
	}

	// By default deny any ingress multicast traffic to any pod.
	err = oc.addACLPortGroup(portGroupUUID, portGroupName, toLport,
		defaultMcastDenyPriority, "ip4.mcast", "drop", knet.PolicyTypeIngress)
	if err != nil {
		return fmt.Errorf("failed to create default deny multicast ingress ACL (%v)",
			err)
	}

	return nil
}

func (oc *Controller) podAddDefaultDenyMulticastPolicy(portInfo *lpInfo) error {
	if err := oc.addToPortGroup("mcastPortGroupDeny", portInfo); err != nil {
		return fmt.Errorf("failed to add port %s to default multicast deny ACL: %v", portInfo.name, err)
	}
	return nil
}

func (oc *Controller) podDeleteDefaultDenyMulticastPolicy(portInfo *lpInfo) error {
	if err := oc.deleteFromPortGroup("mcastPortGroupDeny", portInfo); err != nil {
		return fmt.Errorf("failed to delete port %s from default multicast deny ACL: %v", portInfo.name, err)
	}
	return nil
}

// podAddAllowMulticastPolicy adds the pod's logical switch port to the namespace's
// multicast port group. Caller must hold the namespace's namespaceInfo object
// lock.
func (oc *Controller) podAddAllowMulticastPolicy(ns string, portInfo *lpInfo) error {
	return oc.addToPortGroup(hashedPortGroup(ns), portInfo)
}

// podDeleteAllowMulticastPolicy removes the pod's logical switch port from the
// namespace's multicast port group. Caller must hold the namespace's
// namespaceInfo object lock.
func (oc *Controller) podDeleteAllowMulticastPolicy(ns string, portInfo *lpInfo) error {
	return oc.deleteFromPortGroup(hashedPortGroup(ns), portInfo)
}

func (oc *Controller) localPodAddDefaultDeny(
	policy *knet.NetworkPolicy, portInfo *lpInfo) {
	oc.lspMutex.Lock()
	defer oc.lspMutex.Unlock()

	err := oc.createDefaultDenyPortGroup(knet.PolicyTypeIngress)
	if err != nil {
		klog.Errorf(err.Error())
		return
	}
	err = oc.createDefaultDenyPortGroup(knet.PolicyTypeEgress)
	if err != nil {
		klog.Errorf(err.Error())
		return
	}

	// Default deny rule.
	// 1. Any pod that matches a network policy should get a default
	// ingress deny rule.  This is irrespective of whether there
	// is a ingress section in the network policy. But, if
	// PolicyTypes in the policy has only "egress" in it, then
	// it is a 'egress' only network policy and we should not
	// add any default deny rule for ingress.
	// 2. If there is any "egress" section in the policy or
	// the PolicyTypes has 'egress' in it, we add a default
	// egress deny rule.

	// Handle condition 1 above.
	if !(len(policy.Spec.PolicyTypes) == 1 && policy.Spec.PolicyTypes[0] == knet.PolicyTypeEgress) {
		if oc.lspIngressDenyCache[portInfo.name] == 0 {
			if err := oc.addToPortGroup(oc.portGroupIngressDeny, portInfo); err != nil {
				klog.Warningf("Failed to add port %s to ingress deny ACL: %v", portInfo.name, err)
			}
		}
		oc.lspIngressDenyCache[portInfo.name]++
	}

	// Handle condition 2 above.
	if (len(policy.Spec.PolicyTypes) == 1 && policy.Spec.PolicyTypes[0] == knet.PolicyTypeEgress) ||
		len(policy.Spec.Egress) > 0 || len(policy.Spec.PolicyTypes) == 2 {
		if oc.lspEgressDenyCache[portInfo.name] == 0 {
			if err := oc.addToPortGroup(oc.portGroupEgressDeny, portInfo); err != nil {
				klog.Warningf("Failed to add port %s to egress deny ACL: %v", portInfo.name, err)
			}
		}
		oc.lspEgressDenyCache[portInfo.name]++
	}
}

func (oc *Controller) localPodDelDefaultDeny(
	np *namespacePolicy, portInfo *lpInfo) {
	oc.lspMutex.Lock()
	defer oc.lspMutex.Unlock()

	if !(len(np.ingressPolicies) == 0 && len(np.egressPolicies) > 0) {
		if oc.lspIngressDenyCache[portInfo.name] > 0 {
			oc.lspIngressDenyCache[portInfo.name]--
			if oc.lspIngressDenyCache[portInfo.name] == 0 {
				if err := oc.deleteFromPortGroup(oc.portGroupIngressDeny, portInfo); err != nil {
					klog.Warningf("Failed to remove port %s from ingress deny ACL: %v", portInfo.name, err)
				}
			}
		}
	}

	if (len(np.ingressPolicies) == 0 && len(np.egressPolicies) > 0) ||
		len(np.egressPolicies) > 0 || (len(np.egressPolicies) > 0 && len(np.ingressPolicies) > 0) {
		if oc.lspEgressDenyCache[portInfo.name] > 0 {
			oc.lspEgressDenyCache[portInfo.name]--
			if oc.lspEgressDenyCache[portInfo.name] == 0 {
				if err := oc.deleteFromPortGroup(oc.portGroupEgressDeny, portInfo); err != nil {
					klog.Warningf("Failed to remove port %s from egress deny ACL: %v", portInfo.name, err)
				}
			}
		}
	}
}

func (oc *Controller) handleLocalPodSelectorAddFunc(
	policy *knet.NetworkPolicy, np *namespacePolicy,
	obj interface{}) {
	pod := obj.(*kapi.Pod)

	if pod.Spec.NodeName == "" {
		return
	}

	// Get the logical port info
	logicalPort := podLogicalPortName(pod)
	portInfo, err := oc.logicalPortCache.get(logicalPort)
	if err != nil {
		klog.Errorf(err.Error())
		return
	}

	np.Lock()
	defer np.Unlock()

	if np.deleted {
		return
	}

	if _, ok := np.localPods[logicalPort]; ok {
		return
	}

	oc.localPodAddDefaultDeny(policy, portInfo)

	if np.portGroupUUID == "" {
		return
	}

	_, stderr, err := oc.exec.RunOVNNbctl("--if-exists", "remove",
		"port_group", np.portGroupUUID, "ports", portInfo.uuid, "--",
		"add", "port_group", np.portGroupUUID, "ports", portInfo.uuid)
	if err != nil {
		klog.Errorf("Failed to add logicalPort %s to portGroup %s "+
			"stderr: %q (%v)", logicalPort, np.portGroupUUID, stderr, err)
	}

	np.localPods[logicalPort] = portInfo
}

func (oc *Controller) handleLocalPodSelectorDelFunc(
	policy *knet.NetworkPolicy, np *namespacePolicy,
	obj interface{}) {
	pod := obj.(*kapi.Pod)

	if pod.Spec.NodeName == "" {
		return
	}

	// Get the logical port info
	logicalPort := podLogicalPortName(pod)
	portInfo, err := oc.logicalPortCache.get(logicalPort)
	if err != nil {
		klog.Errorf(err.Error())
		return
	}

	np.Lock()
	defer np.Unlock()

	if np.deleted {
		return
	}

	if _, ok := np.localPods[logicalPort]; !ok {
		return
	}
	delete(np.localPods, logicalPort)
	oc.localPodDelDefaultDeny(np, portInfo)

	oc.lspMutex.Lock()
	delete(oc.lspIngressDenyCache, logicalPort)
	delete(oc.lspEgressDenyCache, logicalPort)
	oc.lspMutex.Unlock()

	if np.portGroupUUID == "" {
		return
	}

	_, stderr, err := oc.exec.RunOVNNbctl("--if-exists", "remove",
		"port_group", np.portGroupUUID, "ports", portInfo.uuid)
	if err != nil {
		klog.Errorf("Failed to delete logicalPort %s from portGroup %s "+
			"stderr: %q (%v)", portInfo.uuid, np.portGroupUUID, stderr, err)
	}
}

func (oc *Controller) handleLocalPodSelector(
	policy *knet.NetworkPolicy, np *namespacePolicy) {

	// NetworkPolicy is validated by the apiserver; this can't fail.
	sel, _ := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)

	h := oc.watchFactory.AddFilteredPodHandler(policy.Namespace, sel,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				oc.handleLocalPodSelectorAddFunc(policy, np, obj)
			},
			DeleteFunc: func(obj interface{}) {
				oc.handleLocalPodSelectorDelFunc(policy, np, obj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oc.handleLocalPodSelectorAddFunc(policy, np, newObj)
			},
		}, nil)

	np.podHandlerList = append(np.podHandlerList, h)
}

// we only need to create an address set if there is a podSelector or namespaceSelector
func hasAnyLabelSelector(peers []knet.NetworkPolicyPeer) bool {
	for _, peer := range peers {
		if peer.PodSelector != nil || peer.NamespaceSelector != nil {
			return true
		}
	}
	return false
}

// addNetworkPolicy creates and applies OVN ACLs to pod logical switch
// ports from Kubernetes NetworkPolicy objects using OVN Port Groups
func (oc *Controller) addNetworkPolicy(policy *knet.NetworkPolicy) {
	klog.Infof("Adding network policy %s in namespace %s", policy.Name,
		policy.Namespace)

	nsInfo, err := oc.waitForNamespaceLocked(policy.Namespace)
	if err != nil {
		klog.Errorf("Failed to wait for namespace %s event (%v)",
			policy.Namespace, err)
		return
	}
	_, alreadyExists := nsInfo.networkPolicies[policy.Name]
	if alreadyExists {
		nsInfo.Unlock()
		return
	}

	np := NewNamespacePolicy(policy)
	nsInfo.networkPolicies[policy.Name] = np
	np.Lock()
	nsInfo.Unlock()

	// Create a port group for the policy. All the pods that this policy
	// selects will be eventually added to this port group.
	readableGroupName := fmt.Sprintf("%s_%s", policy.Namespace, policy.Name)
	np.portGroupName = hashedPortGroup(readableGroupName)

	np.portGroupUUID, err = createPortGroup(oc.exec, readableGroupName, np.portGroupName)
	if err != nil {
		klog.Errorf("Failed to create port_group for network policy %s in "+
			"namespace %s", policy.Name, policy.Namespace)
		return
	}

	type policyHandler struct {
		gress             *gressPolicy
		namespaceSelector *metav1.LabelSelector
		podSelector       *metav1.LabelSelector
	}
	var policyHandlers []policyHandler
	// Go through each ingress rule.  For each ingress rule, create an
	// addressSet for the peer pods.
	for i, ingressJSON := range policy.Spec.Ingress {
		klog.V(5).Infof("Network policy ingress is %+v", ingressJSON)

		ingress := newGressPolicy(oc.exec, knet.PolicyTypeIngress, i, policy.Namespace, policy.Name)

		// Each ingress rule can have multiple ports to which we allow traffic.
		for _, portJSON := range ingressJSON.Ports {
			ingress.addPortPolicy(&portJSON)
		}

		if hasAnyLabelSelector(ingressJSON.From) {
			if err := ingress.ensurePeerAddressSet(oc.addressSetFactory); err != nil {
				klog.Errorf(err.Error())
				continue
			}
		}

		for _, fromJSON := range ingressJSON.From {
			// Add IPBlock to ingress network policy
			if fromJSON.IPBlock != nil {
				ingress.addIPBlock(fromJSON.IPBlock)
			}

			policyHandlers = append(policyHandlers, policyHandler{
				gress:             ingress,
				namespaceSelector: fromJSON.NamespaceSelector,
				podSelector:       fromJSON.PodSelector,
			})
		}
		ingress.localPodAddACL(np.portGroupName, np.portGroupUUID)
		np.ingressPolicies = append(np.ingressPolicies, ingress)
	}

	// Go through each egress rule.  For each egress rule, create an
	// addressSet for the peer pods.
	for i, egressJSON := range policy.Spec.Egress {
		klog.V(5).Infof("Network policy egress is %+v", egressJSON)

		egress := newGressPolicy(oc.exec, knet.PolicyTypeEgress, i, policy.Namespace, policy.Name)

		// Each egress rule can have multiple ports to which we allow traffic.
		for _, portJSON := range egressJSON.Ports {
			egress.addPortPolicy(&portJSON)
		}

		if hasAnyLabelSelector(egressJSON.To) {
			if err := egress.ensurePeerAddressSet(oc.addressSetFactory); err != nil {
				klog.Errorf(err.Error())
				continue
			}
		}

		for _, toJSON := range egressJSON.To {
			// Add IPBlock to egress network policy
			if toJSON.IPBlock != nil {
				egress.addIPBlock(toJSON.IPBlock)
			}

			policyHandlers = append(policyHandlers, policyHandler{
				gress:             egress,
				namespaceSelector: toJSON.NamespaceSelector,
				podSelector:       toJSON.PodSelector,
			})
		}
		egress.localPodAddACL(np.portGroupName, np.portGroupUUID)
		np.egressPolicies = append(np.egressPolicies, egress)
	}
	np.Unlock()

	// For all the pods in the local namespace that this policy
	// effects, add them to the port group.
	oc.handleLocalPodSelector(policy, np)

	for _, handler := range policyHandlers {
		if handler.namespaceSelector != nil && handler.podSelector != nil {
			// For each rule that contains both peer namespace selector and
			// peer pod selector, we create a watcher for each matching namespace
			// that populates the addressSet
			oc.handlePeerNamespaceAndPodSelector(policy,
				handler.namespaceSelector, handler.podSelector,
				handler.gress, np)
		} else if handler.namespaceSelector != nil {
			// For each peer namespace selector, we create a watcher that
			// populates ingress.peerAddressSets
			oc.handlePeerNamespaceSelector(policy,
				handler.namespaceSelector, handler.gress, np)
		} else if handler.podSelector != nil {
			// For each peer pod selector, we create a watcher that
			// populates the addressSet
			oc.handlePeerPodSelector(policy, handler.podSelector,
				handler.gress, np)
		}
	}
}

// deletes the namespacePolicy for policy and returns it, locked
func (oc *Controller) deleteNetworkPolicyLocked(policy *knet.NetworkPolicy) *namespacePolicy {
	nsInfo := oc.getNamespaceLocked(policy.Namespace)
	if nsInfo == nil {
		return nil
	}
	defer nsInfo.Unlock()

	np := nsInfo.networkPolicies[policy.Name]
	if np == nil {
		return nil
	}
	np.Lock()
	delete(nsInfo.networkPolicies, policy.Name)
	return np
}

func (oc *Controller) deleteNetworkPolicy(policy *knet.NetworkPolicy) {
	klog.Infof("Deleting network policy %s in namespace %s",
		policy.Name, policy.Namespace)

	np := oc.deleteNetworkPolicyLocked(policy)
	if np == nil {
		klog.V(5).Infof("Failed to get namespace lock when deleting policy %s in namespace %s",
			policy.Name, policy.Namespace)
		return
	}
	defer np.Unlock()

	oc.destroyNamespacePolicy(np)
}

func (oc *Controller) destroyNamespacePolicy(np *namespacePolicy) {
	np.deleted = true
	oc.shutdownHandlers(np)

	for _, portInfo := range np.localPods {
		oc.localPodDelDefaultDeny(np, portInfo)
	}

	// Delete the port group
	deletePortGroup(oc.exec, np.portGroupName)

	// Delete ingress/egress address sets
	for _, policy := range np.ingressPolicies {
		if err := policy.destroy(); err != nil {
			klog.Errorf(err.Error())
		}
	}
	for _, policy := range np.egressPolicies {
		if err := policy.destroy(); err != nil {
			klog.Errorf(err.Error())
		}
	}
}

// handlePeerPodSelectorAddUpdate adds the IP address of a pod that has been
// selected as a peer by a NetworkPolicy's ingress/egress section to that
// ingress/egress address set
func (oc *Controller) handlePeerPodSelectorAddUpdate(gp *gressPolicy, obj interface{}) {
	pod := obj.(*kapi.Pod)
	if err := gp.addPeerPod(pod); err != nil {
		klog.Errorf(err.Error())
	}
}

// handlePeerPodSelectorDelete removes the IP address of a pod that no longer
// matches a NetworkPolicy ingress/egress section's selectors from that
// ingress/egress address set
func (oc *Controller) handlePeerPodSelectorDelete(gp *gressPolicy, obj interface{}) {
	pod := obj.(*kapi.Pod)
	if err := gp.deletePeerPod(pod); err != nil {
		klog.Errorf(err.Error())
	}
}

func (oc *Controller) handlePeerPodSelector(
	policy *knet.NetworkPolicy, podSelector *metav1.LabelSelector,
	gp *gressPolicy, np *namespacePolicy) {

	// NetworkPolicy is validated by the apiserver; this can't fail.
	sel, _ := metav1.LabelSelectorAsSelector(podSelector)

	h := oc.watchFactory.AddFilteredPodHandler(policy.Namespace, sel,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				oc.handlePeerPodSelectorAddUpdate(gp, obj)
			},
			DeleteFunc: func(obj interface{}) {
				oc.handlePeerPodSelectorDelete(gp, obj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oc.handlePeerPodSelectorAddUpdate(gp, newObj)
			},
		}, nil)
	np.podHandlerList = append(np.podHandlerList, h)
}

func (oc *Controller) handlePeerNamespaceAndPodSelector(
	policy *knet.NetworkPolicy,
	namespaceSelector *metav1.LabelSelector,
	podSelector *metav1.LabelSelector,
	gp *gressPolicy,
	np *namespacePolicy) {

	// NetworkPolicy is validated by the apiserver; this can't fail.
	nsSel, _ := metav1.LabelSelectorAsSelector(namespaceSelector)
	podSel, _ := metav1.LabelSelectorAsSelector(podSelector)

	namespaceHandler := oc.watchFactory.AddFilteredNamespaceHandler("", nsSel,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				namespace := obj.(*kapi.Namespace)
				np.Lock()
				alreadyDeleted := np.deleted
				np.Unlock()
				if alreadyDeleted {
					return
				}

				// The AddFilteredPodHandler call might call handlePeerPodSelectorAddUpdate
				// on existing pods so we can't be holding the lock at this point
				podHandler := oc.watchFactory.AddFilteredPodHandler(namespace.Name, podSel,
					cache.ResourceEventHandlerFuncs{
						AddFunc: func(obj interface{}) {
							oc.handlePeerPodSelectorAddUpdate(gp, obj)
						},
						DeleteFunc: func(obj interface{}) {
							oc.handlePeerPodSelectorDelete(gp, obj)
						},
						UpdateFunc: func(oldObj, newObj interface{}) {
							oc.handlePeerPodSelectorAddUpdate(gp, newObj)
						},
					}, nil)
				np.Lock()
				defer np.Unlock()
				if np.deleted {
					oc.watchFactory.RemovePodHandler(podHandler)
					return
				}
				np.podHandlerList = append(np.podHandlerList, podHandler)
			},
			DeleteFunc: func(obj interface{}) {
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
			},
		}, nil)
	np.nsHandlerList = append(np.nsHandlerList, namespaceHandler)
}

func (oc *Controller) handlePeerNamespaceSelector(
	policy *knet.NetworkPolicy,
	namespaceSelector *metav1.LabelSelector,
	gress *gressPolicy, np *namespacePolicy) {

	// NetworkPolicy is validated by the apiserver; this can't fail.
	sel, _ := metav1.LabelSelectorAsSelector(namespaceSelector)

	h := oc.watchFactory.AddFilteredNamespaceHandler("", sel,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				namespace := obj.(*kapi.Namespace)
				np.Lock()
				defer np.Unlock()
				if !np.deleted {
					gress.addNamespaceAddressSet(namespace.Name, np.portGroupName)
				}
			},
			DeleteFunc: func(obj interface{}) {
				namespace := obj.(*kapi.Namespace)
				np.Lock()
				defer np.Unlock()
				if !np.deleted {
					gress.delNamespaceAddressSet(namespace.Name, np.portGroupName)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
			},
		}, nil)
	np.nsHandlerList = append(np.nsHandlerList, h)
}

func (oc *Controller) shutdownHandlers(np *namespacePolicy) {
	for _, handler := range np.podHandlerList {
		oc.watchFactory.RemovePodHandler(handler)
	}
	for _, handler := range np.nsHandlerList {
		oc.watchFactory.RemoveNamespaceHandler(handler)
	}
}
