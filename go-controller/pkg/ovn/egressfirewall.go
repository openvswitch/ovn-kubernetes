package ovn

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	egressfirewallapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

const (
	egressFirewallAppliedCorrectly = "EgressFirewall Rules applied"
	egressFirewallAddError         = "EgressFirewall Rules not correctly added"
	egressFirewallUpdateError      = "EgressFirewall Rules not correctly updated"
)

var (
	unknownIPv4Destination = "0.0.0.0/0"
	unknownIPv6Destination = "::/0"
)

type egressFirewall struct {
	name        string
	namespace   string
	egressRules []*egressFirewallRule
}

type egressFirewallRule struct {
	id     int
	access egressfirewallapi.EgressFirewallRuleType
	ports  []egressfirewallapi.EgressFirewallPort
	to     destination
}

type destination struct {
	cidrSelector string
	dnsName      string
}

// cloneEgressFirewall shallow copies the egressfirewallapi.EgressFirewall object provided.
// This concretely means that it create a new egressfirewallapi.EgressFirewall with the name and
// namespace set, but without any rules specified.
func cloneEgressFirewall(originalEgressfirewall *egressfirewallapi.EgressFirewall) *egressFirewall {
	ef := &egressFirewall{
		name:        originalEgressfirewall.Name,
		namespace:   originalEgressfirewall.Namespace,
		egressRules: make([]*egressFirewallRule, 0),
	}
	return ef
}

func newEgressFirewallRule(rawEgressFirewallRule egressfirewallapi.EgressFirewallRule, id int) (*egressFirewallRule, error) {
	efr := &egressFirewallRule{
		id:     id,
		access: rawEgressFirewallRule.Type,
	}

	if rawEgressFirewallRule.To.DNSName != "" {
		efr.to.dnsName = rawEgressFirewallRule.To.DNSName
	} else {

		_, _, err := net.ParseCIDR(rawEgressFirewallRule.To.CIDRSelector)
		if err != nil {
			return nil, err
		}
		efr.to.cidrSelector = rawEgressFirewallRule.To.CIDRSelector
	}
	efr.ports = rawEgressFirewallRule.Ports

	return efr, nil
}

// This function is used to sync egress firewall setup. It does two cleanups

// - 	Cleanup the old local GW mode implementation (using LRP)
//  	For this it just deletes all LRP setup done for egress firewall

// -	Cleanup the old shared GW mode implementation (using ACLs on the all switches with direction=from-lport)
//  	For this it just deletes all the ACL setup done for egress firewall on all switches with direction=from-lport

// NOTE: Utilize the fact that we know that all egress firewall related setup must have a priority: types.MinimumReservedEgressFirewallPriority <= priority <= types.EgressFirewallStartPriority
func (oc *Controller) syncEgressFirewall(egressFirwalls []interface{}) {
	egressFirewallACLIDs, stderr, err := util.RunOVNNbctl(
		"--data=bare",
		"--no-heading",
		"--columns=_uuid",
		"--format=table",
		"find",
		"acl",
		fmt.Sprintf("priority<=%s", types.EgressFirewallStartPriority),
		fmt.Sprintf("priority>=%s", types.MinimumReservedEgressFirewallPriority),
		fmt.Sprintf("direction=%s", types.DirectionFromLPort),
	)
	if err != nil {
		klog.Errorf("Unable to list egress firewall logical router policies, cannot cleanup old stale data, stderr: %s, err: %v", stderr, err)
		return
	}
	if egressFirewallACLIDs != "" {
		nodes, err := oc.watchFactory.GetNodes()
		if err != nil {
			klog.Errorf("Unable to cleanup egress firewall ACLs remaining from local gateway mode, cannot list nodes, err: %v", err)
			return
		}
		logicalSwitches := []string{types.OVNJoinSwitch}
		for _, node := range nodes {
			logicalSwitches = append(logicalSwitches, node.Name)
		}
		for _, logicalSwitch := range logicalSwitches {
			switchACLs, stderr, err := util.RunOVNNbctl(
				"--data=bare",
				"--no-heading",
				"--columns=acls",
				"list",
				"logical_switch",
				logicalSwitch,
			)
			if err != nil {
				klog.Errorf("Unable to remove egress firewall acl, cannot list ACLs on switch: %s, stderr: %s, err: %v", logicalSwitch, stderr, err)
			}
			for _, egressFirewallACLID := range strings.Split(egressFirewallACLIDs, "\n") {
				if strings.Contains(switchACLs, egressFirewallACLID) {
					_, stderr, err := util.RunOVNNbctl(
						"remove",
						"logical_switch",
						logicalSwitch,
						"acls",
						egressFirewallACLID,
					)
					if err != nil {
						klog.Errorf("Unable to remove egress firewall acl: %s on %s, cannot cleanup old stale data, stderr: %s, err: %v", egressFirewallACLID, logicalSwitch, stderr, err)
					}
				}
			}
		}
	}
	// In any gateway mode, make sure to delete all LRPs on ovn_cluster_router.
	// This covers old local GW mode -> shared GW and old local GW mode -> new local GW mode
	egressFirewallPolicyIDs, stderr, err := util.RunOVNNbctl(
		"--data=bare",
		"--no-heading",
		"--columns=_uuid",
		"--format=table",
		"find",
		"logical_router_policy",
		fmt.Sprintf("priority<=%s", types.EgressFirewallStartPriority),
		fmt.Sprintf("priority>=%s", types.MinimumReservedEgressFirewallPriority),
	)
	if err != nil {
		klog.Errorf("Unable to list egress firewall logical router policies, cannot cleanup old stale data, stderr: %s, err: %v", stderr, err)
		return
	}
	if egressFirewallPolicyIDs != "" {
		for _, egressFirewallPolicyID := range strings.Split(egressFirewallPolicyIDs, "\n") {
			_, stderr, err := util.RunOVNNbctl(
				"remove",
				"logical_router",
				types.OVNClusterRouter,
				"policies",
				egressFirewallPolicyID,
			)
			if err != nil {
				klog.Errorf("Unable to remove egress firewall policy: %s on %s, cannot cleanup old stale data, stderr: %s, err: %v", egressFirewallPolicyID, types.OVNClusterRouter, stderr, err)
			}
		}
	}
}

func (oc *Controller) addEgressFirewall(egressFirewall *egressfirewallapi.EgressFirewall) error {
	klog.Infof("Adding egressFirewall %s in namespace %s", egressFirewall.Name, egressFirewall.Namespace)
	nsInfo, err := oc.waitForNamespaceLocked(egressFirewall.Namespace)
	if err != nil {
		return fmt.Errorf("failed to wait for namespace %s event (%v)",
			egressFirewall.Namespace, err)
	}
	defer nsInfo.Unlock()

	if nsInfo.egressFirewall != nil {
		return fmt.Errorf("error attempting to add egressFirewall %s to namespace %s when it already has an egressFirewall",
			egressFirewall.Name, egressFirewall.Namespace)
	}

	ef := cloneEgressFirewall(egressFirewall)
	nsInfo.egressFirewall = ef
	var addErrors error
	//the highest priority rule is reserved blocking all external traffic during update
	egressFirewallStartPriorityInt, err := strconv.Atoi(types.EgressFirewallStartPriority)
	egressFirewallStartPriorityInt = egressFirewallStartPriorityInt - 1
	if err != nil {
		return fmt.Errorf("failed to convert egressFirewallStartPriority to Integer: cannot add egressFirewall for namespace %s", egressFirewall.Namespace)
	}
	minimumReservedEgressFirewallPriorityInt, err := strconv.Atoi(types.MinimumReservedEgressFirewallPriority)
	if err != nil {
		return fmt.Errorf("failed to convert minumumReservedEgressFirewallPriority to Integer: cannot add egressFirewall for namespace %s", egressFirewall.Namespace)
	}
	for i, egressFirewallRule := range egressFirewall.Spec.Egress {
		// process Rules into egressFirewallRules for egressFirewall struct
		if i > egressFirewallStartPriorityInt-minimumReservedEgressFirewallPriorityInt {
			klog.Warningf("egressFirewall for namespace %s has too many rules, the rest will be ignored",
				egressFirewall.Namespace)
			break
		}
		efr, err := newEgressFirewallRule(egressFirewallRule, i)
		if err != nil {
			addErrors = errors.Wrapf(addErrors, "error: cannot create EgressFirewall Rule to destination %s for namespace %s - %v",
				egressFirewallRule.To.CIDRSelector, egressFirewall.Namespace, err)
			continue

		}
		ef.egressRules = append(ef.egressRules, efr)
	}
	if addErrors != nil {
		return addErrors
	}

	if nsInfo.addressSet == nil {
		// TODO(trozet): remove dependency on nsInfo object and just determine hash names to create Egress FW with
		return fmt.Errorf("unable to add egress firewall, namespace: %s has no address set", egressFirewall.Namespace)
	}

	ipv4HashedAS, ipv6HashedAS := nsInfo.addressSet.GetASHashNames()
	err = oc.addEgressFirewallRules(ipv4HashedAS, ipv6HashedAS, egressFirewall.Namespace, egressFirewallStartPriorityInt)
	if err != nil {
		return err
	}

	return nil
}

func (oc *Controller) updateEgressFirewall(oldEgressFirewall, newEgressFirewall *egressfirewallapi.EgressFirewall) error {
	// block all external traffic in this namespace
	nsInfo, err := oc.waitForNamespaceLocked(newEgressFirewall.Namespace)
	if err != nil {
		return fmt.Errorf("cannot update egressfirewall in %s:%v", newEgressFirewall.Namespace, err)
	}
	addressSet := nsInfo.addressSet
	nsInfo.Unlock()
	priority, err := strconv.Atoi(types.EgressFirewallStartPriority)
	if err != nil {
		return fmt.Errorf("cannot update egressfirewall in %s:%v", newEgressFirewall.Namespace, err)
	}

	ipv4ASHashName, ipv6ASHashName := addressSet.GetASHashNames()
	match := generateMatch(ipv4ASHashName, ipv6ASHashName, []matchTarget{
		{matchKindV4CIDR, unknownIPv4Destination},
		{matchKindV6CIDR, unknownIPv6Destination},
	},
		[]egressfirewallapi.EgressFirewallPort{},
	)

	err = oc.createEgressFirewallRules(priority, match, "drop", newEgressFirewall.Namespace+"-blockAll")
	if err != nil {
		return fmt.Errorf("cannot update egressfirewall in %s:%v", newEgressFirewall.Namespace, err)
	}

	updateErrors := oc.deleteEgressFirewall(oldEgressFirewall)
	// add the new egressfirewall

	updateErrors = errors.Wrapf(updateErrors, "%v", oc.addEgressFirewall(newEgressFirewall))
	// delete rules blocking all external traffic
	err = oc.deleteEgressFirewallRules(newEgressFirewall.Namespace + "-blockAll")
	if err != nil {
		updateErrors = errors.Wrapf(updateErrors, "%v", err)
	}
	return updateErrors
}

func (oc *Controller) deleteEgressFirewall(egressFirewall *egressfirewallapi.EgressFirewall) error {
	klog.Infof("Deleting egress Firewall %s in namespace %s", egressFirewall.Name, egressFirewall.Namespace)
	deleteDNS := false

	nsInfo := oc.getNamespaceLocked(egressFirewall.Namespace)
	if nsInfo != nil {
		// clear it so an error does not prevent future egressFirewalls
		for _, rule := range nsInfo.egressFirewall.egressRules {
			if len(rule.to.dnsName) > 0 {
				deleteDNS = true
				break
			}
		}
		nsInfo.egressFirewall = nil
		nsInfo.Unlock()
	}
	if deleteDNS {
		oc.egressFirewallDNS.Delete(egressFirewall.Namespace)
	}

	return oc.deleteEgressFirewallRules(egressFirewall.Namespace)
}

func (oc *Controller) updateEgressFirewallWithRetry(egressfirewall *egressfirewallapi.EgressFirewall) error {
	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		return oc.kube.UpdateEgressFirewall(egressfirewall)
	})
	if retryErr != nil {
		return fmt.Errorf("error in updating status on EgressFirewall %s/%s: %v",
			egressfirewall.Namespace, egressfirewall.Name, retryErr)
	}
	return nil
}

func (oc *Controller) addEgressFirewallRules(hashedAddressSetNameIPv4, hashedAddressSetNameIPv6, namespace string, efStartPriority int) error {
	var err error
	ef := oc.namespaces[namespace].egressFirewall
	for _, rule := range ef.egressRules {
		var action string
		var matchTargets []matchTarget
		if rule.access == egressfirewallapi.EgressFirewallRuleAllow {
			action = "allow"
		} else {
			action = "drop"
		}
		if rule.to.cidrSelector != "" {
			if utilnet.IsIPv6CIDRString(rule.to.cidrSelector) {
				matchTargets = []matchTarget{{matchKindV6CIDR, rule.to.cidrSelector}}
			} else {
				matchTargets = []matchTarget{{matchKindV4CIDR, rule.to.cidrSelector}}
			}
		} else {
			// rule based on DNS NAME
			dnsNameAddressSets, err := oc.egressFirewallDNS.Add(ef.namespace, rule.to.dnsName)
			if err != nil {
				return fmt.Errorf("error with EgressFirewallDNS - %v", err)
			}
			dnsNameIPv4ASHashName, dnsNameIPv6ASHashName := dnsNameAddressSets.GetASHashNames()
			if dnsNameIPv4ASHashName != "" {
				matchTargets = append(matchTargets, matchTarget{matchKindV4AddressSet, dnsNameIPv4ASHashName})
			}
			if dnsNameIPv6ASHashName != "" {
				matchTargets = append(matchTargets, matchTarget{matchKindV6AddressSet, dnsNameIPv6ASHashName})
			}
		}
		match := generateMatch(hashedAddressSetNameIPv4, hashedAddressSetNameIPv6, matchTargets, rule.ports)
		err = oc.createEgressFirewallRules(efStartPriority-rule.id, match, action, ef.namespace)
		if err != nil {
			return err
		}
	}
	return nil
}

// createEgressFirewallRules uses the previously generated elements and creates the
// logical_router_policy/join_switch_acl for a specific egressFirewallRouter
func (oc *Controller) createEgressFirewallRules(priority int, match, action, externalID string) error {
	logicalSwitches := []string{}
	if config.Gateway.Mode == config.GatewayModeLocal {
		nodes, err := oc.watchFactory.GetNodes()
		if err != nil {
			return fmt.Errorf("unable to setup egress firewall ACLs on cluster nodes, err: %v", err)
		}
		for _, node := range nodes {
			logicalSwitches = append(logicalSwitches, node.Name)
		}
	} else {
		logicalSwitches = append(logicalSwitches, types.OVNJoinSwitch)
	}
	uuids, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find", "ACL", match, "action="+action,
		fmt.Sprintf("external-ids:egressFirewall=%s", externalID))
	if err != nil {
		return fmt.Errorf("error executing find ACL command, stderr: %q, %+v", stderr, err)
	}
	for _, logicalSwitch := range logicalSwitches {
		if uuids == "" {
			_, stderr, err := util.RunOVNNbctl("--id=@acl", "create", "acl",
				fmt.Sprintf("priority=%d", priority),
				fmt.Sprintf("direction=%s", types.DirectionToLPort), match, "action="+action,
				fmt.Sprintf("external-ids:egressFirewall=%s", externalID),
				"--", "add", "logical_switch", logicalSwitch,
				"acls", "@acl")
			if err != nil {
				return fmt.Errorf("error executing create ACL command, stderr: %q, %+v", stderr, err)
			}
		} else {
			for _, uuid := range strings.Split(uuids, "\n") {
				_, stderr, err := util.RunOVNNbctl("add", "logical_switch", logicalSwitch, "acls", uuid)
				if err != nil {
					return fmt.Errorf("error adding ACL to joinsSwitch %s failed, stderr: %q, %+v",
						logicalSwitch, stderr, err)
				}
			}
		}
	}
	return nil
}

// deleteEgressFirewallRules delete the specific logical router policy/join switch Acls
func (oc *Controller) deleteEgressFirewallRules(externalID string) error {
	var deletionErrors error
	logicalSwitches := []string{}
	if config.Gateway.Mode == config.GatewayModeLocal {
		nodes, err := oc.watchFactory.GetNodes()
		if err != nil {
			deletionErrors = errors.Wrapf(deletionErrors, "unable to setup egress firewall ACLs on cluster nodes, err: %v", err)
		}
		for _, node := range nodes {
			logicalSwitches = append(logicalSwitches, node.Name)
		}
	} else {
		logicalSwitches = []string{types.OVNJoinSwitch}
	}
	stdout, stderr, err := util.RunOVNNbctl("--data=bare", "--no-heading", "--columns=_uuid", "find", "ACL",
		fmt.Sprintf("external-ids:egressFirewall=%s", externalID))
	if err != nil {
		return fmt.Errorf("error deleting egressFirewall with external-ids %s, cannot get ACL policies - %s:%s",
			externalID, err, stderr)
	}
	uuids := strings.Fields(stdout)
	for _, logicalSwitch := range logicalSwitches {
		for _, uuid := range uuids {
			_, stderr, err := util.RunOVNNbctl("remove", "logical_switch", logicalSwitch, "acls", uuid)
			if err != nil {
				deletionErrors = errors.Wrapf(deletionErrors, "failed to delete the ACL rules for "+
					"egressFirewall with external-ids %s on logical switch %s, stderr: %q (%v)", externalID,
					types.OVNJoinSwitch, stderr, err)
			}
		}
	}
	return deletionErrors
}

type matchTarget struct {
	kind  matchKind
	value string
}

type matchKind int

const (
	matchKindV4CIDR matchKind = iota
	matchKindV6CIDR
	matchKindV4AddressSet
	matchKindV6AddressSet
)

func (m *matchTarget) toExpr() (string, error) {
	switch m.kind {
	case matchKindV4CIDR:
		return fmt.Sprintf("ip4.dst == %s", m.value), nil
	case matchKindV6CIDR:
		return fmt.Sprintf("ip6.dst == %s", m.value), nil
	case matchKindV4AddressSet:
		if m.value != "" {
			return fmt.Sprintf("ip4.dst == $%s", m.value), nil
		}
		return "", nil
	case matchKindV6AddressSet:
		if m.value != "" {
			return fmt.Sprintf("ip6.dst == $%s", m.value), nil
		}
		return "", nil
	}
	return "", fmt.Errorf("invalid MatchKind")
}

// generateMatch generates the "match" section of ACL generation for egressFirewallRules.
// It is referentially transparent as all the elements have been validated before this function is called
// sample output:
// match=\"(ip4.dst == 1.2.3.4/32) && ip4.src == $testv4\"
// or
// match=\"(ip4.dst == 8.0.0.0/6) && ip4.src == $testv4 && ip4.dst != 10.128.0.0/14\"
// if a destination CIDR is specified which overlaps with any defined cluster subnet.
func generateMatch(ipv4Source, ipv6Source string, destinations []matchTarget, dstPorts []egressfirewallapi.EgressFirewallPort) string {
	var src string
	var dst string
	var extraMatch string
	switch {
	case len(ipv4Source) > 0 && len(ipv6Source) > 0:
		src = fmt.Sprintf("(ip4.src == $%s || ip6.src == $%s)", ipv4Source, ipv6Source)
	case len(ipv4Source) > 0:
		src = fmt.Sprintf("ip4.src == $%s", ipv4Source)
	case len(ipv6Source) > 0:
		src = fmt.Sprintf("ip6.src == $%s", ipv6Source)
	}

	for _, entry := range destinations {
		if entry.value == "" {
			continue
		}
		ipDst, err := entry.toExpr()
		if err != nil {
			klog.Error(err)
			continue
		}
		if dst == "" {
			dst = ipDst
		} else {
			dst = strings.Join([]string{dst, ipDst}, " || ")
		}
	}

	match := fmt.Sprintf("match=\"(%s) && %s", dst, src)
	if len(dstPorts) > 0 {
		match = fmt.Sprintf("%s && %s", match, egressGetL4Match(dstPorts))
	}

	if config.Gateway.Mode == config.GatewayModeLocal {
		extraMatch = getClusterSubnetsExclusion(destinations)
	} else {
		extraMatch = fmt.Sprintf("inport == \\\"%s%s\\\"", types.JoinSwitchToGWRouterPrefix, types.OVNClusterRouter)
	}
	if extraMatch != "" {
		return fmt.Sprintf("%s && %s\"", match, extraMatch)
	}
	return fmt.Sprintf("%s\"", match)
}

// egressGetL4Match generates the rules for when ports are specified in an egressFirewall Rule
// since the ports can be specified in any order in an egressFirewallRule the best way to build up
// a single rule is to build up each protocol as you walk through the list and place the appropriate logic
// between the elements.
func egressGetL4Match(ports []egressfirewallapi.EgressFirewallPort) string {
	var udpString string
	var tcpString string
	var sctpString string
	for _, port := range ports {
		if kapi.Protocol(port.Protocol) == kapi.ProtocolUDP && udpString != "udp" {
			if port.Port == 0 {
				udpString = "udp"
			} else {
				udpString = fmt.Sprintf("%s udp.dst == %d ||", udpString, port.Port)
			}
		} else if kapi.Protocol(port.Protocol) == kapi.ProtocolTCP && tcpString != "tcp" {
			if port.Port == 0 {
				tcpString = "tcp"
			} else {
				tcpString = fmt.Sprintf("%s tcp.dst == %d ||", tcpString, port.Port)
			}
		} else if kapi.Protocol(port.Protocol) == kapi.ProtocolSCTP && sctpString != "sctp" {
			if port.Port == 0 {
				sctpString = "sctp"
			} else {
				sctpString = fmt.Sprintf("%s sctp.dst == %d ||", sctpString, port.Port)
			}
		}
	}
	// build the l4 match
	var l4Match string
	type tuple struct {
		protocolName     string
		protocolFormated string
	}
	list := []tuple{
		{
			protocolName:     "udp",
			protocolFormated: udpString,
		},
		{
			protocolName:     "tcp",
			protocolFormated: tcpString,
		},
		{
			protocolName:     "sctp",
			protocolFormated: sctpString,
		},
	}
	for _, entry := range list {
		if entry.protocolName == entry.protocolFormated {
			if l4Match == "" {
				l4Match = fmt.Sprintf("(%s)", entry.protocolName)
			} else {
				l4Match = fmt.Sprintf("%s || (%s)", l4Match, entry.protocolName)
			}
		} else {
			if l4Match == "" && entry.protocolFormated != "" {
				l4Match = fmt.Sprintf("(%s && (%s))", entry.protocolName, entry.protocolFormated[:len(entry.protocolFormated)-2])
			} else if entry.protocolFormated != "" {
				l4Match = fmt.Sprintf("%s || (%s && (%s))", l4Match, entry.protocolName, entry.protocolFormated[:len(entry.protocolFormated)-2])
			}
		}
	}
	return fmt.Sprintf("(%s)", l4Match)
}

func getClusterSubnetsExclusion(destinations []matchTarget) string {
	var exclusion string
	for _, destination := range destinations {
		for _, clusterSubnet := range config.Default.ClusterSubnets {
			if destination.value != unknownIPv4Destination && destination.value != unknownIPv6Destination {
				_, destinationNet, _ := net.ParseCIDR(destination.value)
				if !destinationNet.Contains(clusterSubnet.CIDR.IP) && !clusterSubnet.CIDR.Contains(destinationNet.IP) {
					continue
				}
			}
			isSubnetIPv6 := utilnet.IsIPv6CIDR(clusterSubnet.CIDR)
			isDestinationIPv6 := utilnet.IsIPv6CIDRString(destination.value)
			if isSubnetIPv6 == isDestinationIPv6 {
				if exclusion != "" {
					exclusion += " && "
				}
				if isSubnetIPv6 && isDestinationIPv6 {
					exclusion += fmt.Sprintf("%s.dst != %s", "ip6", clusterSubnet.CIDR)
				} else if !isSubnetIPv6 && !isDestinationIPv6 {
					exclusion += fmt.Sprintf("%s.dst != %s", "ip4", clusterSubnet.CIDR)
				}
			}
		}
	}
	return exclusion
}
