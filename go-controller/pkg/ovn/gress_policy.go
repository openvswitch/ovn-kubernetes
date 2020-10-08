package ovn

import (
	"fmt"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	v1 "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"
	utilnet "k8s.io/utils/net"
)

type gressPolicy struct {
	exec util.ExecHelper

	policyNamespace string
	policyName      string
	policyType      knet.PolicyType
	idx             int

	// peerAddressSet points to the addressSet that holds all peer pod
	// IP addresess.
	peerAddressSet AddressSet

	// peerV4AddressSets has Address sets for all namespaces and pod selectors for IPv4
	peerV4AddressSets sets.String
	// peerV6AddressSets has Address sets for all namespaces and pod selectors for IPv6
	peerV6AddressSets sets.String

	// portPolicies represents all the ports to which traffic is allowed for
	// the rule in question.
	portPolicies []*portPolicy

	ipBlock []*knet.IPBlock
}

type portPolicy struct {
	protocol string
	port     int32
}

func (pp *portPolicy) getL4Match() (string, error) {
	if pp.protocol == TCP {
		if pp.port != 0 {
			return fmt.Sprintf("tcp && tcp.dst==%d", pp.port), nil
		}
		return "tcp", nil
	} else if pp.protocol == UDP {
		if pp.port != 0 {
			return fmt.Sprintf("udp && udp.dst==%d", pp.port), nil
		}
		return "udp", nil
	} else if pp.protocol == SCTP {
		if pp.port != 0 {
			return fmt.Sprintf("sctp && sctp.dst==%d", pp.port), nil
		}
		return "sctp", nil
	}
	return "", fmt.Errorf("unknown port protocol %v", pp.protocol)
}

func newGressPolicy(exec util.ExecHelper, policyType knet.PolicyType, idx int, namespace, name string) *gressPolicy {
	return &gressPolicy{
		exec:              exec,
		policyNamespace:   namespace,
		policyName:        name,
		policyType:        policyType,
		idx:               idx,
		peerV4AddressSets: sets.String{},
		peerV6AddressSets: sets.String{},
		portPolicies:      make([]*portPolicy, 0),
	}
}

func (gp *gressPolicy) ensurePeerAddressSet(factory AddressSetFactory) error {
	if gp.peerAddressSet != nil {
		return nil
	}

	direction := strings.ToLower(string(gp.policyType))
	asName := fmt.Sprintf("%s.%s.%s.%d", gp.policyNamespace, gp.policyName, direction, gp.idx)
	as, err := factory.NewAddressSet(asName, nil)
	if err != nil {
		return err
	}

	gp.peerAddressSet = as
	if config.IPv4Mode {
		gp.peerV4AddressSets.Insert("$" + as.GetIPv4HashName())
	}
	if config.IPv6Mode {
		gp.peerV6AddressSets.Insert("$" + as.GetIPv6HashName())
	}
	return nil
}

func (gp *gressPolicy) addPeerPod(pod *v1.Pod) error {
	ips, err := util.GetAllPodIPs(pod)
	if err != nil {
		return err
	}
	return gp.peerAddressSet.AddIPs(ips)
}

func (gp *gressPolicy) deletePeerPod(pod *v1.Pod) error {
	ips, err := util.GetAllPodIPs(pod)
	if err != nil {
		return err
	}
	return gp.peerAddressSet.DeleteIPs(ips)
}

// If the port is not specified, it implies all ports for that protocol
func (gp *gressPolicy) addPortPolicy(portJSON *knet.NetworkPolicyPort) {
	pp := &portPolicy{protocol: string(*portJSON.Protocol),
		port: 0,
	}
	if portJSON.Port != nil {
		pp.port = portJSON.Port.IntVal
	}
	gp.portPolicies = append(gp.portPolicies, pp)
}

func (gp *gressPolicy) addIPBlock(ipblockJSON *knet.IPBlock) {
	gp.ipBlock = append(gp.ipBlock, ipblockJSON)
}

func (gp *gressPolicy) getL3MatchFromAddressSet() string {
	var l3Match string
	if len(gp.peerV4AddressSets) == 0 && len(gp.peerV6AddressSets) == 0 {
		l3Match = constructEmptyMatchString()
	} else {
		// List() method on the set will return the sorted strings
		// Hence we'll be constructing the sorted adress set string here
		l3Match = gp.constructMatchString(gp.peerV4AddressSets.List(), gp.peerV6AddressSets.List())
	}
	return l3Match
}

func constructEmptyMatchString() string {
	switch {
	case config.IPv4Mode && config.IPv6Mode:
		return "(ip4 || ip6)"
	case config.IPv6Mode:
		return "ip6"
	default:
		return "ip4"
	}
}

func (gp *gressPolicy) constructMatchString(v4AddressSets, v6AddressSets []string) string {
	var direction, v4MatchStr, v6MatchStr, matchStr string
	if gp.policyType == knet.PolicyTypeIngress {
		direction = "src"
	} else {
		direction = "dst"
	}

	//  At this point there will be address sets in one or both of them.
	//  Contents in both address sets mean dual stack, else one will be empty because we will only populate
	//  entries for enabled stacks
	if len(v4AddressSets) > 0 {
		v4AddressSetStr := strings.Join(v4AddressSets, ", ")
		v4MatchStr = fmt.Sprintf("%s.%s == {%s}", "ip4", direction, v4AddressSetStr)
		matchStr = v4MatchStr
	}
	if len(v6AddressSets) > 0 {
		v6AddressSetStr := strings.Join(v6AddressSets, ", ")
		v6MatchStr = fmt.Sprintf("%s.%s == {%s}", "ip6", direction, v6AddressSetStr)
		matchStr = v6MatchStr
	}
	if len(v4AddressSets) > 0 && len(v6AddressSets) > 0 {
		matchStr = fmt.Sprintf("(%s || %s)", v4MatchStr, v6MatchStr)
	}
	return matchStr
}

func (gp *gressPolicy) sizeOfAddressSet() int {
	return gp.peerV4AddressSets.Len() + gp.peerV6AddressSets.Len()
}

func (gp *gressPolicy) getMatchFromIPBlock(lportMatch, l4Match string) []string {
	var ipBlockMatches []string
	if gp.policyType == knet.PolicyTypeIngress {
		ipBlockMatches = constructIPBlockStringsForACL("src", gp.ipBlock, lportMatch, l4Match)
	} else {
		ipBlockMatches = constructIPBlockStringsForACL("dst", gp.ipBlock, lportMatch, l4Match)
	}
	return ipBlockMatches
}

// addNamespaceAddressSet adds a new namespace address set to the gress policy
func (gp *gressPolicy) addNamespaceAddressSet(name, portGroupName string) {
	v4HashName := "$" + getIPv4ASHashedName(name)
	v6HashName := "$" + getIPv6ASHashedName(name)

	if gp.peerV4AddressSets.Has(v4HashName) || gp.peerV6AddressSets.Has(v6HashName) {
		return
	}
	oldL3Match := gp.getL3MatchFromAddressSet()
	if config.IPv4Mode {
		gp.peerV4AddressSets.Insert(v4HashName)
	}
	if config.IPv6Mode {
		gp.peerV6AddressSets.Insert(v6HashName)
	}
	gp.localPodUpdateACL(oldL3Match, gp.getL3MatchFromAddressSet(), portGroupName)
}

// delNamespaceAddressSet removes a namespace address set from the gress policy

func (gp *gressPolicy) delNamespaceAddressSet(name, portGroupName string) {
	v4HashName := "$" + getIPv4ASHashedName(name)
	v6HashName := "$" + getIPv6ASHashedName(name)

	if !gp.peerV4AddressSets.Has(v4HashName) && !gp.peerV6AddressSets.Has(v6HashName) {
		return
	}
	oldL3Match := gp.getL3MatchFromAddressSet()
	if config.IPv4Mode {
		gp.peerV4AddressSets.Delete(v4HashName)
	}
	if config.IPv6Mode {
		gp.peerV6AddressSets.Delete(v6HashName)
	}
	gp.localPodUpdateACL(oldL3Match, gp.getL3MatchFromAddressSet(), portGroupName)
}

// localPodAddACL adds an ACL that implements the gress policy's rules to the
// given Port Group (which should contain all pod logical switch ports selected
// by the parent NetworkPolicy)
func (gp *gressPolicy) localPodAddACL(portGroupName, portGroupUUID string) {
	l3Match := gp.getL3MatchFromAddressSet()
	var lportMatch string
	var cidrMatches []string
	if gp.policyType == knet.PolicyTypeIngress {
		lportMatch = fmt.Sprintf("outport == @%s", portGroupName)
	} else {
		lportMatch = fmt.Sprintf("inport == @%s", portGroupName)
	}

	if len(gp.portPolicies) == 0 {
		match := fmt.Sprintf("match=\"%s && %s\"", l3Match, lportMatch)
		l4Match := noneMatch

		if len(gp.ipBlock) > 0 {
			// Add ACL allow rule for IPBlock CIDR
			cidrMatches = gp.getMatchFromIPBlock(lportMatch, l4Match)
			for _, cidrMatch := range cidrMatches {
				if err := gp.addACLAllow(cidrMatch, l4Match, portGroupUUID, true); err != nil {
					klog.Warningf(err.Error())
				}
			}
		}
		// if there are pod/namespace selector, then allow packets from/to that address_set or
		// if the NetworkPolicyPeer is empty, then allow from all sources or to all destinations.
		if gp.sizeOfAddressSet() > 0 || len(gp.ipBlock) == 0 {
			if err := gp.addACLAllow(match, l4Match, portGroupUUID, false); err != nil {
				klog.Warningf(err.Error())
			}
		}
	}
	for _, port := range gp.portPolicies {
		l4Match, err := port.getL4Match()
		if err != nil {
			continue
		}
		match := fmt.Sprintf("match=\"%s && %s && %s\"", l3Match, l4Match, lportMatch)
		if len(gp.ipBlock) > 0 {
			// Add ACL allow rule for IPBlock CIDR
			cidrMatches = gp.getMatchFromIPBlock(lportMatch, l4Match)
			for _, cidrMatch := range cidrMatches {
				if err := gp.addACLAllow(cidrMatch, l4Match, portGroupUUID, true); err != nil {
					klog.Warningf(err.Error())
				}
			}
		}
		if gp.sizeOfAddressSet() > 0 || len(gp.ipBlock) == 0 {
			if err := gp.addACLAllow(match, l4Match, portGroupUUID, false); err != nil {
				klog.Warningf(err.Error())
			}
		}
	}
}

// addACLAllow adds an "allow" ACL with a given match to the given Port Group
func (gp *gressPolicy) addACLAllow(match, l4Match, portGroupUUID string, ipBlockCidr bool) error {
	var direction, action string
	direction = toLport
	if gp.policyType == knet.PolicyTypeIngress {
		action = "allow-related"
	} else {
		action = "allow"
	}

	uuid, stderr, err := gp.exec.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "ACL",
		fmt.Sprintf("external-ids:l4Match=\"%s\"", l4Match),
		fmt.Sprintf("external-ids:ipblock_cidr=%t", ipBlockCidr),
		fmt.Sprintf("external-ids:namespace=%s", gp.policyNamespace),
		fmt.Sprintf("external-ids:policy=%s", gp.policyName),
		fmt.Sprintf("external-ids:%s_num=%d", gp.policyType, gp.idx),
		fmt.Sprintf("external-ids:policy_type=%s", gp.policyType))
	if err != nil {
		return fmt.Errorf("find failed to get the allow rule for "+
			"namespace=%s, policy=%s, stderr: %q (%v)",
			gp.policyNamespace, gp.policyName, stderr, err)
	}

	if uuid != "" {
		return nil
	}

	_, stderr, err = gp.exec.RunOVNNbctl("--id=@acl", "create",
		"acl", fmt.Sprintf("priority=%s", defaultAllowPriority),
		fmt.Sprintf("direction=%s", direction), match,
		fmt.Sprintf("action=%s", action),
		fmt.Sprintf("external-ids:l4Match=\"%s\"", l4Match),
		fmt.Sprintf("external-ids:ipblock_cidr=%t", ipBlockCidr),
		fmt.Sprintf("external-ids:namespace=%s", gp.policyNamespace),
		fmt.Sprintf("external-ids:policy=%s", gp.policyName),
		fmt.Sprintf("external-ids:%s_num=%d", gp.policyType, gp.idx),
		fmt.Sprintf("external-ids:policy_type=%s", gp.policyType),
		"--", "add", "port_group", portGroupUUID, "acls", "@acl")
	if err != nil {
		return fmt.Errorf("failed to create the acl allow rule for "+
			"namespace=%s, policy=%s, stderr: %q (%v)", gp.policyNamespace,
			gp.policyName, stderr, err)
	}

	return nil
}

// modifyACLAllow updates an "allow" ACL with a new match
func (gp *gressPolicy) modifyACLAllow(oldMatch, newMatch string) error {
	uuid, stderr, err := gp.exec.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "ACL", oldMatch,
		fmt.Sprintf("external-ids:namespace=%s", gp.policyNamespace),
		fmt.Sprintf("external-ids:policy=%s", gp.policyName),
		fmt.Sprintf("external-ids:%s_num=%d", gp.policyType, gp.idx),
		fmt.Sprintf("external-ids:policy_type=%s", gp.policyType))
	if err != nil {
		return fmt.Errorf("find failed to get the allow rule for "+
			"namespace=%s, policy=%s, stderr: %q (%v)",
			gp.policyNamespace, gp.policyName, stderr, err)
	}
	if uuid == "" {
		return nil
	}

	// We already have an ACL. We will update it.
	if _, stderr, err = gp.exec.RunOVNNbctl("set", "acl", uuid, newMatch); err != nil {
		return fmt.Errorf("failed to modify the allow-from rule for "+
			"namespace=%s, policy=%s, stderr: %q (%v)",
			gp.policyNamespace, gp.policyName, stderr, err)
	}

	return nil
}

func constructIPBlockStringsForACL(direction string, ipBlocks []*knet.IPBlock, lportMatch, l4Match string) []string {
	var matchStrings []string
	var matchStr, ipVersion string
	for _, ipBlock := range ipBlocks {
		if utilnet.IsIPv6CIDRString(ipBlock.CIDR) {
			ipVersion = "ip6"
		} else {
			ipVersion = "ip4"
		}
		if len(ipBlock.Except) == 0 {
			matchStr = fmt.Sprintf("match=\"%s.%s == %s", ipVersion, direction, ipBlock.CIDR)

		} else {
			matchStr = fmt.Sprintf("match=\"%s.%s == %s && %s.%s != {%s}", ipVersion, direction, ipBlock.CIDR,
				ipVersion, direction, strings.Join(ipBlock.Except, ", "))
		}
		if l4Match == noneMatch {
			matchStr = fmt.Sprintf("%s && %s\"", matchStr, lportMatch)
		} else {
			matchStr = fmt.Sprintf("%s && %s && %s\"", matchStr, l4Match, lportMatch)
		}
		matchStrings = append(matchStrings, matchStr)
	}
	return matchStrings
}

// localPodUpdateACL updates an existing ACL that implements the gress policy's rules
func (gp *gressPolicy) localPodUpdateACL(oldl3Match, newl3Match, portGroupName string) {
	var lportMatch string
	if gp.policyType == knet.PolicyTypeIngress {
		lportMatch = fmt.Sprintf("outport == @%s", portGroupName)
	} else {
		lportMatch = fmt.Sprintf("inport == @%s", portGroupName)
	}
	if len(gp.portPolicies) == 0 {
		oldMatch := fmt.Sprintf("match=\"%s && %s\"", oldl3Match, lportMatch)
		newMatch := fmt.Sprintf("match=\"%s && %s\"", newl3Match, lportMatch)
		if err := gp.modifyACLAllow(oldMatch, newMatch); err != nil {
			klog.Warningf(err.Error())
		}
	}
	for _, port := range gp.portPolicies {
		l4Match, err := port.getL4Match()
		if err != nil {
			continue
		}
		oldMatch := fmt.Sprintf("match=\"%s && %s && %s\"", oldl3Match, l4Match, lportMatch)
		newMatch := fmt.Sprintf("match=\"%s && %s && %s\"", newl3Match, l4Match, lportMatch)
		if err := gp.modifyACLAllow(oldMatch, newMatch); err != nil {
			klog.Warningf(err.Error())
		}
	}
}

func (gp *gressPolicy) destroy() error {
	if gp.peerAddressSet != nil {
		if err := gp.peerAddressSet.Destroy(); err != nil {
			return err
		}
		gp.peerAddressSet = nil
	}
	return nil
}
