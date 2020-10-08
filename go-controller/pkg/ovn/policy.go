package ovn

import (
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"

	goovn "github.com/ebay/go-ovn"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

type networkPolicy struct {
	sync.Mutex
	name            string
	namespace       string
	policyTypes     []knet.PolicyType
	ingressPolicies []*gressPolicy
	egressPolicies  []*gressPolicy
	podHandlerList  []*factory.Handler
	svcHandlerList  []*factory.Handler
	nsHandlerList   []*factory.Handler
	localPods       map[string]*lpInfo //pods effected by this policy
	portGroupUUID   string             //uuid for OVN port_group
	portGroupName   string
	deleted         bool //deleted policy
}

func NewNetworkPolicy(policy *knet.NetworkPolicy) *networkPolicy {
	np := &networkPolicy{
		name:            policy.Name,
		namespace:       policy.Namespace,
		policyTypes:     policy.Spec.PolicyTypes,
		ingressPolicies: make([]*gressPolicy, 0),
		egressPolicies:  make([]*gressPolicy, 0),
		podHandlerList:  make([]*factory.Handler, 0),
		svcHandlerList:  make([]*factory.Handler, 0),
		nsHandlerList:   make([]*factory.Handler, 0),
		localPods:       make(map[string]*lpInfo),
	}
	return np
}

const (
	toLport   = "to-lport"
	fromLport = "from-lport"
	noneMatch = "None"
	// Default ACL logging severity
	defaultACLLoggingSeverity = "info"
	// IPv6 multicast traffic destined to dynamic groups must have the "T" bit
	// set to 1: https://tools.ietf.org/html/rfc3307#section-4.3
	ipv6DynamicMulticastMatch = "(ip6.dst[120..127] == 0xff && ip6.dst[116] == 1)"
	// Default deny acl rule priority
	defaultDenyPriority = "1000"
	// Default allow acl rule priority
	defaultAllowPriority = "1001"
	// Default multicast deny acl rule priority
	defaultMcastDenyPriority = "1011"
	// Default multicast allow acl rule priority
	defaultMcastAllowPriority = "1012"
	// Default routed multicast allow acl rule priority
	defaultRoutedMcastAllowPriority = "1013"
)

func getACLLoggingSeverity(aclLogging string) string {
	if aclLogging != "" {
		return aclLogging
	}
	return defaultACLLoggingSeverity
}

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
			deletePortGroup(hashedLocalPortGroup)

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

func addAllowACLFromNode(logicalSwitch string, mgmtPortIP net.IP, ovnNBClient goovn.Client) error {
	ipFamily := "ip4"
	if utilnet.IsIPv6(mgmtPortIP) {
		ipFamily = "ip6"
	}
	match := fmt.Sprintf("%s.src==%s", ipFamily, mgmtPortIP.String())

	priority, _ := strconv.Atoi(defaultAllowPriority)
	aclcmd, err := ovnNBClient.ACLAdd(logicalSwitch, "to-lport", match, "allow-related", priority, nil, false, "", "")

	// NOTE: goovn.ErrorExist is returned if the ACL already exists, in such a case ignore that error.
	// Additional Context-> Per Tim Rozet's review comments, there could be scenarios where ovnkube restarts, in which
	// case, it would use kubernetes events to reconstruct ACLs and there is a possibility that some of the ACLs may
	// already be present in the NBDB.
	if err == nil {
		if err = ovnNBClient.Execute(aclcmd); err != nil {
			return fmt.Errorf("failed to create the node acl for logical_switch: %s, %v", logicalSwitch, err)
		}
	} else if err != goovn.ErrorExist {
		return fmt.Errorf("ACLAdd() error when creating node acl for logical switch: %s, %v", logicalSwitch, err)
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

func getACLPortGroupUUID(match, action string, policyType knet.PolicyType) (string, error) {
	uuid, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "ACL", match, "action="+action,
		fmt.Sprintf("external-ids:default-deny-policy-type=%s", policyType))
	if err != nil {
		return "", fmt.Errorf("find failed to get the default deny rule for "+
			"policy type %s stderr: %q (%v)", policyType, stderr, err)
	}

	return uuid, nil
}

func addACLPortGroup(policyNamespace, portGroupUUID, direction, priority, match, action string, policyType knet.PolicyType, aclLogging string) error {
	uuid, err := getACLPortGroupUUID(match, action, policyType)
	if err != nil {
		return err
	}
	if uuid != "" {
		return nil
	}
	if policyNamespace == "" {
		policyNamespace = portGroupUUID
	}

	_, stderr, err := util.RunOVNNbctl("--id=@acl", "create", "acl",
		fmt.Sprintf("priority=%s", priority),
		fmt.Sprintf("direction=%s", direction), match, "action="+action,
		fmt.Sprintf("log=%t", aclLogging != ""), fmt.Sprintf("severity=%s", getACLLoggingSeverity(aclLogging)),
		fmt.Sprintf("meter=%s", types.OvnACLLoggingMeter),
		fmt.Sprintf("name=%.63s", policyNamespace),
		fmt.Sprintf("external-ids:default-deny-policy-type=%s", policyType),
		"--", "add", "port_group", portGroupUUID,
		"acls", "@acl")
	if err != nil {
		return fmt.Errorf("error executing create ACL command for "+
			"policy type %s stderr: %q (%v)", policyType, stderr, err)
	}
	return nil
}

func deleteACLPortGroup(portGroupName, direction, priority, match, action string, policyType knet.PolicyType) error {
	match = getACLMatch(portGroupName, match, policyType)
	uuid, err := getACLPortGroupUUID(match, action, policyType)
	if err != nil {
		return err
	}

	if uuid == "" {
		return nil
	}

	_, stderr, err := util.RunOVNNbctl("remove", "port_group",
		portGroupName, "acls", uuid)
	if err != nil {
		return fmt.Errorf("remove failed to delete the rule for "+
			"port_group=%s, stderr: %q (%v)", portGroupName, stderr, err)
	}

	return nil
}

func addToPortGroup(portGroup string, portInfo *lpInfo) error {
	_, stderr, err := util.RunOVNNbctl("--if-exists", "remove",
		"port_group", portGroup, "ports", portInfo.uuid, "--",
		"add", "port_group", portGroup, "ports", portInfo.uuid)
	if err != nil {
		return fmt.Errorf("failed to add logicalPort %s to portGroup %s "+
			"stderr: %q (%v)", portInfo.name, portGroup, stderr, err)
	}
	return nil
}

func deleteFromPortGroup(portGroup string, portInfo *lpInfo) error {
	_, stderr, err := util.RunOVNNbctl("--if-exists", "remove",
		"port_group", portGroup, "ports", portInfo.uuid)
	if err != nil {
		return fmt.Errorf("failed to delete logicalPort %s to portGroup %s "+
			"stderr: %q (%v)", portInfo.name, portGroup, stderr, err)
	}
	return nil
}

func defaultDenyPortGroup(namespace, gressSuffix string) string {
	return hashedPortGroup(namespace) + "_" + gressSuffix
}

func (oc *Controller) createDefaultDenyPortGroup(ns string, nsInfo *namespaceInfo, policyType knet.PolicyType, aclLogging string) error {
	var portGroupName string
	if policyType == knet.PolicyTypeIngress {
		portGroupName = defaultDenyPortGroup(ns, "ingressDefaultDeny")
	} else if policyType == knet.PolicyTypeEgress {
		portGroupName = defaultDenyPortGroup(ns, "egressDefaultDeny")
	}
	portGroupUUID, err := createPortGroup(portGroupName, portGroupName)
	if err != nil {
		return fmt.Errorf("failed to create port_group for %s (%v)",
			portGroupName, err)
	}
	match := getACLMatch(portGroupName, "", policyType)
	err = addACLPortGroup(ns, portGroupUUID, toLport,
		defaultDenyPriority, match, "drop", policyType, aclLogging)
	if err != nil {
		return fmt.Errorf("failed to create default deny ACL for port group %v", err)
	}

	match = getACLMatch(portGroupName, "arp", policyType)
	err = addACLPortGroup(ns, portGroupUUID, toLport,
		defaultAllowPriority, match, "allow", policyType, "")
	if err != nil {
		return fmt.Errorf("failed to create default allow ARP ACL for port group %v", err)
	}

	if policyType == knet.PolicyTypeIngress {
		nsInfo.portGroupIngressDenyUUID = portGroupUUID
	} else if policyType == knet.PolicyTypeEgress {
		nsInfo.portGroupEgressDenyUUID = portGroupUUID
	}
	return nil
}

// modify ACL logging
func (oc *Controller) setACLDenyLogging(ns string, nsInfo *namespaceInfo, aclLogging string) error {

	aclLoggingSev := getACLLoggingSeverity(aclLogging)

	match := getACLMatch(defaultDenyPortGroup(ns, "ingressDefaultDeny"), "", knet.PolicyTypeIngress)
	uuid, err := getACLPortGroupUUID(match, "drop", knet.PolicyTypeIngress)
	if err != nil {
		return err
	}
	if uuid == "" {
		// not suppose to happen
		return fmt.Errorf("failed to find the ACL for pg=%s: %v", nsInfo.portGroupIngressDenyUUID, err)
	}
	if _, stderr, err := util.RunOVNNbctl("set", "acl", uuid,
		fmt.Sprintf("log=%t", aclLogging != ""), fmt.Sprintf("severity=%s", aclLoggingSev)); err != nil {
		return fmt.Errorf("failed to modify the pg=%s, stderr: %q (%v)", nsInfo.portGroupIngressDenyUUID, stderr, err)
	}

	match = getACLMatch(defaultDenyPortGroup(ns, "egressDefaultDeny"), "", knet.PolicyTypeEgress)
	uuid, err = getACLPortGroupUUID(match, "drop", knet.PolicyTypeEgress)
	if err != nil {
		return err
	}
	if uuid == "" {
		// not suppose to happen
		return fmt.Errorf("failed to find the ACL for pg=%s: %v", nsInfo.portGroupEgressDenyUUID, err)
	}
	if _, stderr, err := util.RunOVNNbctl("set", "acl", uuid,
		fmt.Sprintf("log=%t", aclLogging != ""), fmt.Sprintf("severity=%s", aclLoggingSev)); err != nil {
		return fmt.Errorf("failed to modify the pg=%s, stderr: %q (%v)", nsInfo.portGroupEgressDenyUUID, stderr, err)
	}

	return nil
}

func getACLMatchAF(ipv4Match, ipv6Match string) string {
	if config.IPv4Mode && config.IPv6Mode {
		return "(" + ipv4Match + " || " + ipv6Match + ")"
	} else if config.IPv4Mode {
		return ipv4Match
	} else {
		return ipv6Match
	}
}

// Creates the match string used for ACLs matching on multicast traffic.
func getMulticastACLMatch() string {
	return "(ip4.mcast || mldv1 || mldv2 || " + ipv6DynamicMulticastMatch + ")"
}

func getMulticastACLIgrMatchV4(addrSetName string) string {
	return "(ip4.src == $" + addrSetName + " && ip4.mcast)"
}

func getMulticastACLIgrMatchV6(addrSetName string) string {
	return "(ip6.src == $" + addrSetName + " && " + ipv6DynamicMulticastMatch + ")"
}

// Creates the match string used for ACLs allowing incoming multicast into a
// namespace, that is, from IPs that are in the namespace's address set.
func getMulticastACLIgrMatch(nsInfo *namespaceInfo) string {
	var ipv4Match, ipv6Match string
	addrSetNameV4, addrSetNameV6 := nsInfo.addressSet.GetASHashNames()
	if config.IPv4Mode {
		ipv4Match = getMulticastACLIgrMatchV4(addrSetNameV4)
	}
	if config.IPv6Mode {
		ipv6Match = getMulticastACLIgrMatchV6(addrSetNameV6)
	}
	return getACLMatchAF(ipv4Match, ipv6Match)
}

// Creates the match string used for ACLs allowing outgoing multicast from a
// namespace.
func getMulticastACLEgrMatch() string {
	var ipv4Match, ipv6Match string
	if config.IPv4Mode {
		ipv4Match = "ip4.mcast"
	}
	if config.IPv6Mode {
		ipv6Match = "(mldv1 || mldv2 || " + ipv6DynamicMulticastMatch + ")"
	}
	return getACLMatchAF(ipv4Match, ipv6Match)
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

	portGroupName := hashedPortGroup(ns)
	match := getACLMatch(portGroupName, getMulticastACLEgrMatch(),
		knet.PolicyTypeEgress)
	err = addACLPortGroup(ns, nsInfo.portGroupUUID, fromLport,
		defaultMcastAllowPriority, match, "allow", knet.PolicyTypeEgress, "")
	if err != nil {
		return fmt.Errorf("failed to create allow egress multicast ACL for %s (%v)",
			ns, err)
	}

	match = getACLMatch(portGroupName, getMulticastACLIgrMatch(nsInfo),
		knet.PolicyTypeIngress)
	err = addACLPortGroup(ns, nsInfo.portGroupUUID, toLport,
		defaultMcastAllowPriority, match, "allow", knet.PolicyTypeIngress, "")
	if err != nil {
		return fmt.Errorf("failed to create allow ingress multicast ACL for %s (%v)",
			ns, err)
	}

	// Add all ports from this namespace to the multicast allow group.
	pods, err := oc.mc.watchFactory.GetPods(ns)
	if err != nil {
		klog.Warningf("Failed to get pods for namespace %q: %v", ns, err)
	}
	for _, pod := range pods {
		portName := podLogicalPortName(pod, oc.netconf.Name)
		if portInfo, err := oc.logicalPortCache.get(portName); err != nil {
			klog.Errorf(err.Error())
		} else if err := podAddAllowMulticastPolicy(ns, portInfo); err != nil {
			klog.Warningf("Failed to add port %s to port group ACL: %v", portName, err)
		}
	}

	return nil
}

func deleteMulticastACLs(ns, portGroupHash string, nsInfo *namespaceInfo) error {
	err := deleteACLPortGroup(portGroupHash, fromLport,
		defaultMcastAllowPriority, getMulticastACLEgrMatch(), "allow",
		knet.PolicyTypeEgress)
	if err != nil {
		return fmt.Errorf("failed to delete allow egress multicast ACL for %s (%v)",
			ns, err)
	}

	err = deleteACLPortGroup(portGroupHash, toLport, defaultMcastAllowPriority,
		getMulticastACLIgrMatch(nsInfo), "allow", knet.PolicyTypeIngress)
	if err != nil {
		return fmt.Errorf("failed to delete allow ingress multicast ACL for %s (%v)",
			ns, err)
	}

	return nil
}

// Delete the policy to allow multicast traffic within 'ns'.
func deleteMulticastAllowPolicy(ns string, nsInfo *namespaceInfo) error {
	portGroupHash := hashedPortGroup(ns)

	err := deleteMulticastACLs(ns, portGroupHash, nsInfo)
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
	// By default deny any egress multicast traffic from any pod. This drops
	// IP multicast membership reports therefore denying any multicast traffic
	// to be forwarded to pods.
	match := "match=\"" + getMulticastACLMatch() + "\""
	err := addACLPortGroup("", oc.clusterPortGroupUUID, fromLport,
		defaultMcastDenyPriority, match, "drop", knet.PolicyTypeEgress, "")
	if err != nil {
		return fmt.Errorf("failed to create default deny multicast egress ACL: %v", err)
	}

	// By default deny any ingress multicast traffic to any pod.
	err = addACLPortGroup("", oc.clusterPortGroupUUID, toLport,
		defaultMcastDenyPriority, match, "drop", knet.PolicyTypeIngress, "")
	if err != nil {
		return fmt.Errorf("failed to create default deny multicast ingress ACL: %v", err)
	}

	// Remove old multicastDefaultDeny port group now that all ports
	// have been added to the clusterPortGroup by WatchPods()
	deletePortGroup("mcastPortGroupDeny")
	return nil
}

// Creates a global default allow multicast policy:
// - one ACL allowing multicast traffic from cluster router ports
// - one ACL allowing multicast traffic to cluster router ports.
// Caller must hold the namespace's namespaceInfo object lock.
func (oc *Controller) createDefaultAllowMulticastPolicy() error {
	mcastMatch := getMulticastACLMatch()
	match := getACLMatch(clusterRtrPortGroupName, mcastMatch, knet.PolicyTypeEgress)
	err := addACLPortGroup("", oc.clusterRtrPortGroupUUID, fromLport,
		defaultRoutedMcastAllowPriority, match, "allow", knet.PolicyTypeEgress, "")
	if err != nil {
		return fmt.Errorf("failed to create default allow multicast egress ACL: %v", err)
	}

	match = getACLMatch(clusterRtrPortGroupName, mcastMatch, knet.PolicyTypeIngress)
	err = addACLPortGroup("", oc.clusterRtrPortGroupUUID, toLport,
		defaultRoutedMcastAllowPriority, match, "allow", knet.PolicyTypeIngress, "")
	if err != nil {
		return fmt.Errorf("failed to create default allow multicast ingress ACL: %v", err)
	}
	return nil
}

// podAddAllowMulticastPolicy adds the pod's logical switch port to the namespace's
// multicast port group. Caller must hold the namespace's namespaceInfo object
// lock.
func podAddAllowMulticastPolicy(ns string, portInfo *lpInfo) error {
	return addToPortGroup(hashedPortGroup(ns), portInfo)
}

// podDeleteAllowMulticastPolicy removes the pod's logical switch port from the
// namespace's multicast port group. Caller must hold the namespace's
// namespaceInfo object lock.
func podDeleteAllowMulticastPolicy(ns string, portInfo *lpInfo) error {
	return deleteFromPortGroup(hashedPortGroup(ns), portInfo)
}

func (oc *Controller) localPodAddDefaultDeny(nsInfo *namespaceInfo,
	policy *knet.NetworkPolicy, portInfo *lpInfo) {
	oc.lspMutex.Lock()
	defer oc.lspMutex.Unlock()

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
			if err := addToPortGroup(nsInfo.portGroupIngressDenyUUID, portInfo); err != nil {
				klog.Warningf("Failed to add port %s to ingress deny ACL: %v", portInfo.name, err)
			}
		}
		oc.lspIngressDenyCache[portInfo.name]++
	}

	// Handle condition 2 above.
	if (len(policy.Spec.PolicyTypes) == 1 && policy.Spec.PolicyTypes[0] == knet.PolicyTypeEgress) ||
		len(policy.Spec.Egress) > 0 || len(policy.Spec.PolicyTypes) == 2 {
		if oc.lspEgressDenyCache[portInfo.name] == 0 {
			if err := addToPortGroup(nsInfo.portGroupEgressDenyUUID, portInfo); err != nil {
				klog.Warningf("Failed to add port %s to egress deny ACL: %v", portInfo.name, err)
			}
		}
		oc.lspEgressDenyCache[portInfo.name]++
	}
}

func (oc *Controller) localPodDelDefaultDeny(
	np *networkPolicy, nsInfo *namespaceInfo, portInfo *lpInfo) {
	oc.lspMutex.Lock()
	defer oc.lspMutex.Unlock()

	// Remove port from ingress deny port-group for [Ingress] and [ingress,egress] PolicyTypes
	// If NOT [egress] PolicyType
	if !(len(np.policyTypes) == 1 && np.policyTypes[0] == knet.PolicyTypeEgress) {
		if oc.lspIngressDenyCache[portInfo.name] > 0 {
			oc.lspIngressDenyCache[portInfo.name]--
			if oc.lspIngressDenyCache[portInfo.name] == 0 {
				if err := deleteFromPortGroup(nsInfo.portGroupIngressDenyUUID, portInfo); err != nil {
					klog.Warningf("Failed to remove port %s from ingress deny ACL: %v", portInfo.name, err)
				}
			}
		}
	}
	// Remove port from egress deny port group for [egress] and [ingress,egress] PolicyTypes
	// if [egress] PolicyType OR there are any egress rules OR [ingress,egress] PolicyType
	if (len(np.policyTypes) == 1 && np.policyTypes[0] == knet.PolicyTypeEgress) ||
		len(np.egressPolicies) > 0 || len(np.policyTypes) == 2 {
		if oc.lspEgressDenyCache[portInfo.name] > 0 {
			oc.lspEgressDenyCache[portInfo.name]--
			if oc.lspEgressDenyCache[portInfo.name] == 0 {
				if err := deleteFromPortGroup(nsInfo.portGroupEgressDenyUUID, portInfo); err != nil {
					klog.Warningf("Failed to remove port %s from egress deny ACL: %v", portInfo.name, err)
				}
			}
		}
	}
}

func (oc *Controller) handleLocalPodSelectorAddFunc(
	policy *knet.NetworkPolicy, np *networkPolicy, nsInfo *namespaceInfo,
	obj interface{}) {
	pod := obj.(*kapi.Pod)

	if pod.Spec.NodeName == "" {
		return
	}

	// Get the logical port info
	logicalPort := podLogicalPortName(pod, oc.netconf.Name)
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

	oc.localPodAddDefaultDeny(nsInfo, policy, portInfo)

	if np.portGroupUUID == "" {
		return
	}

	_, stderr, err := util.RunOVNNbctl("--if-exists", "remove",
		"port_group", np.portGroupUUID, "ports", portInfo.uuid, "--",
		"add", "port_group", np.portGroupUUID, "ports", portInfo.uuid)
	if err != nil {
		klog.Errorf("Failed to add logicalPort %s to portGroup %s "+
			"stderr: %q (%v)", logicalPort, np.portGroupUUID, stderr, err)
	}

	np.localPods[logicalPort] = portInfo
}

func (oc *Controller) handleLocalPodSelectorDelFunc(
	policy *knet.NetworkPolicy, np *networkPolicy, nsInfo *namespaceInfo,
	obj interface{}) {
	pod := obj.(*kapi.Pod)

	if pod.Spec.NodeName == "" {
		return
	}

	// Get the logical port info
	logicalPort := podLogicalPortName(pod, oc.netconf.Name)
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
	oc.localPodDelDefaultDeny(np, nsInfo, portInfo)

	oc.lspMutex.Lock()
	delete(oc.lspIngressDenyCache, logicalPort)
	delete(oc.lspEgressDenyCache, logicalPort)
	oc.lspMutex.Unlock()

	if np.portGroupUUID == "" {
		return
	}

	_, stderr, err := util.RunOVNNbctl("--if-exists", "remove",
		"port_group", np.portGroupUUID, "ports", portInfo.uuid)
	if err != nil {
		klog.Errorf("Failed to delete logicalPort %s from portGroup %s "+
			"stderr: %q (%v)", portInfo.uuid, np.portGroupUUID, stderr, err)
	}
}

func (oc *Controller) handleLocalPodSelector(
	policy *knet.NetworkPolicy, np *networkPolicy, nsInfo *namespaceInfo) {

	// NetworkPolicy is validated by the apiserver; this can't fail.
	sel, _ := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)

	h := oc.mc.watchFactory.AddFilteredPodHandler(policy.Namespace, sel,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				oc.handleLocalPodSelectorAddFunc(policy, np, nsInfo, obj)
			},
			DeleteFunc: func(obj interface{}) {
				oc.handleLocalPodSelectorDelFunc(policy, np, nsInfo, obj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oc.handleLocalPodSelectorAddFunc(policy, np, nsInfo, newObj)
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

	np := NewNetworkPolicy(policy)

	if len(nsInfo.networkPolicies) == 0 {
		err := oc.createDefaultDenyPortGroup(policy.Namespace, nsInfo, knet.PolicyTypeIngress, nsInfo.aclLogging.Deny)
		if err != nil {
			nsInfo.Unlock()
			klog.Errorf(err.Error())
			return
		}
		err = oc.createDefaultDenyPortGroup(policy.Namespace, nsInfo, knet.PolicyTypeEgress, nsInfo.aclLogging.Deny)
		if err != nil {
			nsInfo.Unlock()
			klog.Errorf(err.Error())
			return
		}
	}
	nsInfo.networkPolicies[policy.Name] = np

	nsInfo.Unlock()
	np.Lock()

	// Create a port group for the policy. All the pods that this policy
	// selects will be eventually added to this port group.
	readableGroupName := fmt.Sprintf("%s_%s", policy.Namespace, policy.Name)
	np.portGroupName = hashedPortGroup(readableGroupName)

	np.portGroupUUID, err = createPortGroup(readableGroupName, np.portGroupName)
	if err != nil {
		klog.Errorf("Failed to create port_group for network policy %s in "+
			"namespace %s", policy.Name, policy.Namespace)
		return
	}

	if nsInfo.aclLogging.Deny != "" || nsInfo.aclLogging.Allow != "" {
		klog.Infof("ACL logging for network policy %s in namespace %s set to deny=%s, allow=%s",
			policy.Name, policy.Namespace, nsInfo.aclLogging.Deny, nsInfo.aclLogging.Allow)
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

		ingress := newGressPolicy(knet.PolicyTypeIngress, i, policy.Namespace, policy.Name)

		// Each ingress rule can have multiple ports to which we allow traffic.
		for _, portJSON := range ingressJSON.Ports {
			ingress.addPortPolicy(&portJSON)
		}

		if hasAnyLabelSelector(ingressJSON.From) {
			klog.V(5).Infof("Network policy %s with ingress rule %s has a selector", policy.Name, ingress.policyName)
			if err := ingress.ensurePeerAddressSet(oc.addressSetFactory); err != nil {
				klog.Errorf(err.Error())
				continue
			}
			// Start service handlers ONLY if there's an ingress Address Set
			oc.handlePeerService(policy, ingress, np)
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
		ingress.localPodAddACL(np.portGroupName, np.portGroupUUID, nsInfo.aclLogging.Allow)
		np.ingressPolicies = append(np.ingressPolicies, ingress)
	}

	// Go through each egress rule.  For each egress rule, create an
	// addressSet for the peer pods.
	for i, egressJSON := range policy.Spec.Egress {
		klog.V(5).Infof("Network policy egress is %+v", egressJSON)

		egress := newGressPolicy(knet.PolicyTypeEgress, i, policy.Namespace, policy.Name)

		// Each egress rule can have multiple ports to which we allow traffic.
		for _, portJSON := range egressJSON.Ports {
			egress.addPortPolicy(&portJSON)
		}

		if hasAnyLabelSelector(egressJSON.To) {
			klog.V(5).Infof("Network policy %s with egress rule %s has a selector", policy.Name, egress.policyName)
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
		egress.localPodAddACL(np.portGroupName, np.portGroupUUID, nsInfo.aclLogging.Allow)
		np.egressPolicies = append(np.egressPolicies, egress)
	}
	np.Unlock()

	// For all the pods in the local namespace that this policy
	// effects, add them to the port group.
	oc.handleLocalPodSelector(policy, np, nsInfo)

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

func (oc *Controller) deleteNetworkPolicy(policy *knet.NetworkPolicy) {
	klog.Infof("Deleting network policy %s in namespace %s",
		policy.Name, policy.Namespace)

	nsInfo := oc.getNamespaceLocked(policy.Namespace)
	if nsInfo == nil {
		klog.V(5).Infof("Failed to get namespace lock when deleting policy %s in namespace %s",
			policy.Name, policy.Namespace)
		return
	}
	defer nsInfo.Unlock()

	np := nsInfo.networkPolicies[policy.Name]
	if np == nil {
		return
	}

	delete(nsInfo.networkPolicies, policy.Name)

	oc.destroyNetworkPolicy(np, nsInfo)
}

func (oc *Controller) destroyNetworkPolicy(np *networkPolicy, nsInfo *namespaceInfo) {
	np.Lock()
	defer np.Unlock()
	np.deleted = true
	oc.shutdownHandlers(np)

	for _, portInfo := range np.localPods {
		oc.localPodDelDefaultDeny(np, nsInfo, portInfo)
	}

	if len(nsInfo.networkPolicies) == 0 {
		deletePortGroup(defaultDenyPortGroup(np.namespace, "ingressDefaultDeny"))
		deletePortGroup(defaultDenyPortGroup(np.namespace, "egressDefaultDeny"))
	}

	// Delete the port group
	deletePortGroup(np.portGroupName)

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
	if pod.Spec.NodeName == "" {
		return
	}
	if err := gp.addPeerPod(pod); err != nil {
		klog.Errorf(err.Error())
	}
}

// handlePeerPodSelectorDelete removes the IP address of a pod that no longer
// matches a NetworkPolicy ingress/egress section's selectors from that
// ingress/egress address set
func (oc *Controller) handlePeerPodSelectorDelete(gp *gressPolicy, obj interface{}) {
	pod := obj.(*kapi.Pod)
	if pod.Spec.NodeName == "" {
		return
	}
	if err := gp.deletePeerPod(pod); err != nil {
		klog.Errorf(err.Error())
	}
}

// handlePeerServiceSelectorAddUpdate adds the VIP of a service that selects
// pods that are selected by the Network Policy
func (oc *Controller) handlePeerServiceAdd(gp *gressPolicy, obj interface{}) {
	service := obj.(*kapi.Service)
	klog.V(5).Infof("A Service: %s matches the namespace as the gress policy: %s", service.Name, gp.policyName)
	if err := gp.addPeerSvcVip(service); err != nil {
		klog.Errorf(err.Error())
	}
}

// handlePeerServiceDelete removes the VIP of a service that selects
// pods that are selected by the Network Policy
func (oc *Controller) handlePeerServiceDelete(gp *gressPolicy, obj interface{}) {
	service := obj.(*kapi.Service)
	if err := gp.deletePeerSvcVip(service); err != nil {
		klog.Errorf(err.Error())
	}
}

// Watch Services that are in the same Namespace as the NP
// To account for hairpined traffic
func (oc *Controller) handlePeerService(
	policy *knet.NetworkPolicy, gp *gressPolicy, np *networkPolicy) {

	h := oc.mc.watchFactory.AddFilteredServiceHandler(policy.Namespace,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				// Service is matched so add VIP to addressSet
				oc.handlePeerServiceAdd(gp, obj)
			},
			DeleteFunc: func(obj interface{}) {
				// If Service that has matched pods are deleted remove VIP
				oc.handlePeerServiceDelete(gp, obj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				// If Service Is updated make sure same pods are still matched
				oldSvc := oldObj.(kapi.Service)
				newSvc := newObj.(kapi.Service)
				if reflect.DeepEqual(newSvc.Spec.ExternalIPs, oldSvc.Spec.ExternalIPs) &&
					reflect.DeepEqual(newSvc.Spec.ClusterIP, oldSvc.Spec.ClusterIP) &&
					reflect.DeepEqual(newSvc.Spec.Type, oldSvc.Spec.Type) &&
					reflect.DeepEqual(newSvc.Status.LoadBalancer.Ingress, oldSvc.Status.LoadBalancer.Ingress) {

					klog.V(5).Infof("Skipping service update for: %s as change does not apply to any of .Spec.Ports, "+
						".Spec.ExternalIP, .Spec.ClusterIP, .Spec.Type, .Status.LoadBalancer.Ingress", newSvc.Name)
					return
				}

				oc.handlePeerServiceDelete(gp, oldObj)
				oc.handlePeerServiceAdd(gp, newObj)
			},
		}, nil)
	np.svcHandlerList = append(np.svcHandlerList, h)
}

func (oc *Controller) handlePeerPodSelector(
	policy *knet.NetworkPolicy, podSelector *metav1.LabelSelector,
	gp *gressPolicy, np *networkPolicy) {

	// NetworkPolicy is validated by the apiserver; this can't fail.
	sel, _ := metav1.LabelSelectorAsSelector(podSelector)

	h := oc.mc.watchFactory.AddFilteredPodHandler(policy.Namespace, sel,
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
	np *networkPolicy) {

	// NetworkPolicy is validated by the apiserver; this can't fail.
	nsSel, _ := metav1.LabelSelectorAsSelector(namespaceSelector)
	podSel, _ := metav1.LabelSelectorAsSelector(podSelector)

	namespaceHandler := oc.mc.watchFactory.AddFilteredNamespaceHandler("", nsSel,
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
				podHandler := oc.mc.watchFactory.AddFilteredPodHandler(namespace.Name, podSel,
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
					oc.mc.watchFactory.RemovePodHandler(podHandler)
					return
				}
				np.podHandlerList = append(np.podHandlerList, podHandler)
			},
			DeleteFunc: func(obj interface{}) {
				// when the namespace labels no longer apply
				// remove the namespaces pods from the address_set
				namespace := obj.(*kapi.Namespace)
				pods, _ := oc.mc.watchFactory.GetPods(namespace.Name)

				for _, pod := range pods {
					oc.handlePeerPodSelectorDelete(gp, pod)
				}

			},
			UpdateFunc: func(oldObj, newObj interface{}) {
			},
		}, nil)
	np.nsHandlerList = append(np.nsHandlerList, namespaceHandler)
}

func (oc *Controller) handlePeerNamespaceSelector(
	policy *knet.NetworkPolicy,
	namespaceSelector *metav1.LabelSelector,
	gress *gressPolicy, np *networkPolicy) {

	// NetworkPolicy is validated by the apiserver; this can't fail.
	sel, _ := metav1.LabelSelectorAsSelector(namespaceSelector)

	h := oc.mc.watchFactory.AddFilteredNamespaceHandler("", sel,
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

func (oc *Controller) shutdownHandlers(np *networkPolicy) {
	for _, handler := range np.podHandlerList {
		oc.mc.watchFactory.RemovePodHandler(handler)
	}
	for _, handler := range np.nsHandlerList {
		oc.mc.watchFactory.RemoveNamespaceHandler(handler)
	}
	for _, handler := range np.svcHandlerList {
		oc.mc.watchFactory.RemoveServiceHandler(handler)
	}
}
