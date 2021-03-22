// +build linux

package node

import (
	"fmt"
	"net"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/pkg/errors"
	kapi "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

const (
	iptableNodePortChain   = "OVN-KUBE-NODEPORT"
	iptableExternalIPChain = "OVN-KUBE-EXTERNALIP"
)

func clusterIPTablesProtocols() []iptables.Protocol {
	var protocols []iptables.Protocol
	if config.IPv4Mode {
		protocols = append(protocols, iptables.ProtocolIPv4)
	}
	if config.IPv6Mode {
		protocols = append(protocols, iptables.ProtocolIPv6)
	}
	return protocols
}

type iptRule struct {
	table    string
	chain    string
	args     []string
	protocol iptables.Protocol
}

func addIptRules(rules []iptRule) ([]string, error) {
	var addErrors error
	warnings := []string{}
	for _, r := range rules {
		ipt, _ := util.GetIPTablesHelper(r.protocol)
		if _, err := ipt.List(r.table, r.chain); err != nil {
			klog.V(5).Infof("Creating chain: %s in table: %s for protocol: %v ", r.chain, r.table, r.protocol)
			warnings = append(warnings, fmt.Sprintf("missing iptables chain %s in the %s table, adding it",
				r.chain, r.table))
			if err = ipt.NewChain(r.table, r.chain); err != nil {
				klog.V(5).Infof("Chain: \"%s\" in table: \"%s\" already exists, skipping creation", r.table, r.chain)
				return warnings, fmt.Errorf("failed to add iptables chain %s to the %s table: %v", r.chain, r.table, err)
			}
		}
		exists, err := ipt.Exists(r.table, r.chain, r.args...)
		if !exists && err == nil {
			klog.V(5).Infof("Adding rule in table: %s, chain: %s with args: \"%s\" for protocol: %v ", r.table,
				r.chain, strings.Join(r.args, " "), r.protocol)
			warnings = append(warnings, fmt.Sprintf("missing iptables %s/%s rule %q, adding it",
				r.chain, r.table, strings.Join(r.args, " ")))
			err = ipt.Insert(r.table, r.chain, 1, r.args...)
		}
		if err != nil {
			addErrors = errors.Wrapf(addErrors, "failed to add iptables %s/%s rule %q: %v",
				r.table, r.chain, strings.Join(r.args, " "), err)
		}
	}
	return warnings, addErrors
}

func delIptRules(rules []iptRule) ([]string, error) {
	var delErrors error
	warnings := []string{}
	for _, r := range rules {
		ipt, _ := util.GetIPTablesHelper(r.protocol)
		if exists, err := ipt.Exists(r.table, r.chain, r.args...); err == nil && exists {
			klog.V(5).Infof("Deleting rule in table: %s, chain: %s with args: \"%s\" for protocol: %v ", r.table,
				r.chain, strings.Join(r.args, " "), r.protocol)
			warnings = append(warnings, fmt.Sprintf("extra iptables %s/%s rule %q, deleting it",
				r.chain, r.table, strings.Join(r.args, " ")))
			err := ipt.Delete(r.table, r.chain, r.args...)
			if err != nil {
				delErrors = errors.Wrapf(delErrors, "failed to delete iptables %s/%s rule %q: %v",
					r.table, r.chain, strings.Join(r.args, " "), err)
			}
		}
	}
	return warnings, delErrors
}

func getSharedGatewayInitRules(chain string, proto iptables.Protocol) []iptRule {
	return []iptRule{
		{
			table:    "nat",
			chain:    "OUTPUT",
			args:     []string{"-j", chain},
			protocol: proto,
		},
	}
}

func getLocalGatewayInitRules(chain string, proto iptables.Protocol) []iptRule {
	return []iptRule{
		{
			table:    "nat",
			chain:    "PREROUTING",
			args:     []string{"-j", chain},
			protocol: proto,
		},
		{
			table:    "nat",
			chain:    "OUTPUT",
			args:     []string{"-j", chain},
			protocol: proto,
		},
	}
}

func getLegacyLocalGatewayInitRules(chain string, proto iptables.Protocol) []iptRule {
	return []iptRule{
		{
			table:    "filter",
			chain:    "FORWARD",
			args:     []string{"-j", chain},
			protocol: proto,
		},
	}
}

func getLegacySharedGatewayInitRules(chain string, proto iptables.Protocol) []iptRule {
	return []iptRule{
		{
			table:    "nat",
			chain:    "PREROUTING",
			args:     []string{"-j", chain},
			protocol: proto,
		},
		{
			table:    "filter",
			chain:    "OUTPUT",
			args:     []string{"-j", chain},
			protocol: proto,
		},
		{
			table:    "filter",
			chain:    "FORWARD",
			args:     []string{"-j", chain},
			protocol: proto,
		},
	}
}

func getNodePortIPTRules(svcPort kapi.ServicePort, targetIP string, targetPort int32) []iptRule {
	var protocol iptables.Protocol
	if utilnet.IsIPv6String(targetIP) {
		protocol = iptables.ProtocolIPv6
	} else {
		protocol = iptables.ProtocolIPv4
	}
	natArgs := []string{
		"-p", string(svcPort.Protocol),
		"-m", "addrtype",
		"--dst-type", "LOCAL",
		"--dport", fmt.Sprintf("%d", svcPort.NodePort),
		"-j", "DNAT",
		"--to-destination", util.JoinHostPortInt32(targetIP, targetPort),
	}
	return []iptRule{
		{
			table:    "nat",
			chain:    iptableNodePortChain,
			args:     natArgs,
			protocol: protocol,
		},
	}
}

func getExternalIPTRules(svcPort kapi.ServicePort, externalIP, dstIP string) []iptRule {
	var protocol iptables.Protocol
	if utilnet.IsIPv6String(externalIP) {
		protocol = iptables.ProtocolIPv6
	} else {
		protocol = iptables.ProtocolIPv4
	}
	return []iptRule{
		{
			table: "nat",
			chain: iptableExternalIPChain,
			args: []string{
				"-p", string(svcPort.Protocol),
				"-d", externalIP,
				"--dport", fmt.Sprintf("%v", svcPort.Port),
				"-j", "DNAT",
				"--to-destination", util.JoinHostPortInt32(dstIP, svcPort.Port),
			},
			protocol: protocol,
		},
	}
}

func getLocalGatewayNATRules(ifname string, cidr *net.IPNet) []iptRule {
	// Allow packets to/from the gateway interface in case defaults deny
	var protocol iptables.Protocol
	if utilnet.IsIPv6(cidr.IP) {
		protocol = iptables.ProtocolIPv6
	} else {
		protocol = iptables.ProtocolIPv4
	}
	return []iptRule{
		{
			table: "filter",
			chain: "FORWARD",
			args: []string{
				"-i", ifname,
				"-j", "ACCEPT",
			},
			protocol: protocol,
		},
		{
			table: "filter",
			chain: "FORWARD",
			args: []string{
				"-o", ifname,
				"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
				"-j", "ACCEPT",
			},
			protocol: protocol,
		},
		{
			table: "filter",
			chain: "INPUT",
			args: []string{
				"-i", ifname,
				"-m", "comment", "--comment", "from OVN to localhost",
				"-j", "ACCEPT",
			},
			protocol: protocol,
		},
		{
			table: "nat",
			chain: "POSTROUTING",
			args: []string{
				"-s", cidr.String(),
				"-j", "MASQUERADE",
			},
			protocol: protocol,
		},
	}
}

// initLocalGatewayNATRules sets up iptables rules for interfaces
func initLocalGatewayNATRules(ifname string, cidr *net.IPNet) error {
	_, err := addIptRules(getLocalGatewayNATRules(ifname, cidr))
	return err
}

func handleGatewayIPTables(iptCallback func(rules []iptRule) ([]string, error), genGatewayChainRules func(chain string, proto iptables.Protocol) []iptRule) ([]string, error) {
	warnings := []string{}
	rules := make([]iptRule, 0)
	for _, chain := range []string{iptableNodePortChain, iptableExternalIPChain} {
		for _, proto := range clusterIPTablesProtocols() {
			ipt, err := util.GetIPTablesHelper(proto)
			if err != nil {
				return warnings, err
			}
			if _, err := ipt.List("nat", chain); err != nil {
				warnings = append(warnings, fmt.Sprintf("missing iptables chain %s in the nat table, adding it", chain))
				if err := ipt.NewChain("nat", chain); err != nil {
					klog.V(5).Infof("Chain: \"%s\" in table: \"%s\" already exists, skipping creation", "nat", chain)
				}
			}
			rules = append(rules, genGatewayChainRules(chain, proto)...)
		}
	}
	ws, err := iptCallback(rules)
	warnings = append(warnings, ws...)
	if err != nil {
		return warnings, fmt.Errorf("failed to handle iptables rules %v: %v", rules, err)
	}
	return warnings, nil
}

func initSharedGatewayIPTables() ([]string, error) {
	warnings, err := handleGatewayIPTables(addIptRules, getSharedGatewayInitRules)
	if err != nil {
		return warnings, err
	}
	w, err := handleGatewayIPTables(delIptRules, getLegacySharedGatewayInitRules)
	warnings = append(warnings, w...)
	return warnings, err
}

func initLocalGatewayIPTables() error {
	if _, err := handleGatewayIPTables(addIptRules, getLocalGatewayInitRules); err != nil {
		return err
	}
	if _, err := handleGatewayIPTables(delIptRules, getLegacyLocalGatewayInitRules); err != nil {
		return err
	}
	return nil
}

func cleanupSharedGatewayIPTChains() {
	for _, chain := range []string{iptableNodePortChain, iptableExternalIPChain} {
		// We clean up both IPv4 and IPv6, regardless of what is currently in use
		for _, proto := range []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6} {
			ipt, err := util.GetIPTablesHelper(proto)
			if err != nil {
				return
			}
			_ = ipt.ClearChain("nat", chain)
			_ = ipt.DeleteChain("nat", chain)
		}
	}
}

func recreateIPTRules(table, chain string, keepIPTRules []iptRule) {
	for _, proto := range clusterIPTablesProtocols() {
		ipt, _ := util.GetIPTablesHelper(proto)
		if err := ipt.ClearChain(table, chain); err != nil {
			klog.Errorf("Error clearing chain: %s in table: %s, err: %v", chain, table, err)
		}
	}
	if _, err := addIptRules(keepIPTRules); err != nil {
		klog.Error(err)
	}
}

// getGatewayIPTRules returns NodePort and ExternalIP iptables rules for service. If nodeIP is non-nil, then
// only incoming traffic on that IP will be accepted for NodePort rules; otherwise incoming traffic on the NodePort
// on all IPs will be accepted. If gatewayIP is "", then NodePort traffic will be DNAT'ed to the service port on
// the service's ClusterIP. Otherwise, it will be DNAT'ed to the NodePort on the gatewayIP.
func getGatewayIPTRules(service *kapi.Service, gatewayIPs []string) []iptRule {
	rules := make([]iptRule, 0)
	clusterIPs := util.GetClusterIPs(service)
	for _, svcPort := range service.Spec.Ports {
		if util.ServiceTypeHasNodePort(service) {
			err := util.ValidatePort(svcPort.Protocol, svcPort.NodePort)
			if err != nil {
				klog.Errorf("Skipping service: %s, invalid service NodePort: %v", svcPort.Name, err)
				continue
			}
			err = util.ValidatePort(svcPort.Protocol, svcPort.Port)
			if err != nil {
				klog.Errorf("Skipping service: %s, invalid service port %v", svcPort.Name, err)
				continue
			}
			if gatewayIPs == nil {
				for _, clusterIP := range clusterIPs {
					rules = append(rules, getNodePortIPTRules(svcPort, clusterIP, svcPort.Port)...)
				}
			} else {
				for _, gatewayIP := range gatewayIPs {
					rules = append(rules, getNodePortIPTRules(svcPort, gatewayIP, svcPort.Port)...)
				}
			}
		}
		for _, externalIP := range service.Spec.ExternalIPs {
			err := util.ValidatePort(svcPort.Protocol, svcPort.Port)
			if err != nil {
				klog.Errorf("Skipping service: %s, invalid service port %v", svcPort.Name, err)
				continue
			}
			if clusterIP, err := util.MatchIPStringFamily(utilnet.IsIPv6String(externalIP), clusterIPs); err == nil {
				rules = append(rules, getExternalIPTRules(svcPort, externalIP, clusterIP)...)
			}
		}
	}
	return rules
}
