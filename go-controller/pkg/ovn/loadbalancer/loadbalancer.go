package loadbalancer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	utilnet "k8s.io/utils/net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

const (
	// used to indicate if the service is running on node load balancers
	NodeLoadBalancer = "NodeLoadBalancer"
	// used to indicate if the service is running on idling load balancers
	IdlingLoadBalancer = "IdlingLoadBalancer"
)

type NotFoundError struct {
	What string
}

func (e NotFoundError) Error() string {
	return e.What + " not found"
}

var LBNotFound = NotFoundError{What: "Load balancer"}

// GetOVNKubeLoadBalancer returns the LoadBalancer matching the protocol
func GetOVNKubeLoadBalancer(protocol kapi.Protocol) (string, error) {
	return getLoadBalancerByProtocolType(protocol, types.ClusterLBPrefix)
}

// GetOVNKubeIdlingLoadBalancer returns the LoadBalancer matching the protocol
func GetOVNKubeIdlingLoadBalancer(protocol kapi.Protocol) (string, error) {
	return getLoadBalancerByProtocolType(protocol, types.ClusterIdlingLBPrefix)
}

func getLoadBalancerByProtocolType(protocol kapi.Protocol, idkey string) (string, error) {
	id, value := fmt.Sprintf("%s-%s", idkey, strings.ToLower(string(protocol))), "yes"
	res, _, err := util.FindOVNLoadBalancer(id, value)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to get ovnkube balancer %v %s", protocol, idkey)
	}
	if res == "" {
		return "", LBNotFound
	}
	return res, nil
}

// CreateLoadBalancer creates the loadbalancer if it doesn´t exist to avoid
// consumers to create duplicate loadbalancers with the same name and externalID
func CreateLoadBalancer(protocol kapi.Protocol, idkey string) (string, error) {
	lbUUID, err := getLoadBalancerByProtocolType(protocol, idkey)
	if err != nil && !errors.Is(err, LBNotFound) {
		return "", errors.Wrapf(err, "Failed to get OVN load balancer for protocol %s", protocol)
	}
	// create the load balancer if it doesn't exist yet
	if lbUUID == "" {
		lbUUID, err = createLoadBalancer(protocol, idkey)
		if err != nil {
			return "", errors.Wrapf(err, "Failed to create OVN load balancer for protocol %s", protocol)
		}
	}
	return lbUUID, nil
}

// createLoadBalancer creates a loadbalancer for the specified protocol
// all loadbalancers but idling ones reject packets for vips without endpoints by default
func createLoadBalancer(protocol kapi.Protocol, idkey string) (string, error) {
	id := fmt.Sprintf("external_ids:%s-%s=yes", idkey, strings.ToLower(string(protocol)))
	proto := fmt.Sprintf("protocol=%s", strings.ToLower(string(protocol)))
	reject := true
	if idkey == types.ClusterIdlingLBPrefix {
		reject = false
	}
	options := fmt.Sprintf("options:reject=%t", reject)
	lbID, stderr, err := util.RunOVNNbctl("create", "load_balancer", id, proto, options)
	if err != nil {
		klog.Errorf("Failed to create %s load balancer, stderr: %q, error: %v", protocol, stderr, err)
		return "", err
	}
	return lbID, nil
}

// GetLoadBalancerVIPs returns a map whose keys are VIPs (IP:port) on loadBalancer
func GetLoadBalancerVIPs(loadBalancer string) (map[string]string, error) {
	var vips map[string]string
	outStr, _, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"get", "load_balancer", loadBalancer, "vips")
	if err != nil {
		return nil, err
	}
	if outStr == "" {
		return vips, nil
	}
	// sample outStr:
	// - {"192.168.0.1:80"="10.1.1.1:80,10.2.2.2:80"}
	// - {"[fd01::]:80"="[fd02::]:80,[fd03::]:80"}
	outStrMap := strings.Replace(outStr, "=", ":", -1)
	err = json.Unmarshal([]byte(outStrMap), &vips)
	if err != nil {
		return nil, err
	}
	return vips, nil
}

// DeleteLoadBalancerVIP removes the VIP as well as any reject ACLs associated to the LB
func DeleteLoadBalancerVIP(loadBalancer, vip string) error {
	vipQuotes := fmt.Sprintf("\"%s\"", vip)
	stdout, stderr, err := util.RunOVNNbctl("--if-exists", "remove", "load_balancer", loadBalancer, "vips", vipQuotes)
	if err != nil {
		// if we hit an error and fail to remove load balancer, we skip removing the rejectACL
		return fmt.Errorf("error in deleting load balancer vip %s for %s"+
			"stdout: %q, stderr: %q, error: %v",
			vip, loadBalancer, stdout, stderr, err)
	}
	return nil
}

// DeleteLoadBalancerVIPs removes the VIPs across lbs in a single shot
func DeleteLoadBalancerVIPs(loadBalancers, vips []string) error {
	txn := util.NewNBTxn()
	for _, loadBalancer := range loadBalancers {
		for _, vip := range vips {
			vipQuotes := fmt.Sprintf("\"%s\"", vip)
			txn.Add("--if-exists", "remove", "load_balancer", loadBalancer, "vips", vipQuotes)
		}
	}
	stdout, stderr, err := txn.Commit()
	if err != nil {
		// if we hit an error and fail to remove load balancer, we skip removing the rejectACL
		return fmt.Errorf("error in deleting load balancer vip %v for %v"+
			"stdout: %q, stderr: %q, error: %v",
			vips, loadBalancers, stdout, stderr, err)
	}
	return nil
}

// UpdateLoadBalancer updates the VIP for sourceIP:sourcePort to point to targets (an
// array of IP:port strings)
func UpdateLoadBalancer(lb, vip string, targets []string) error {
	lbTarget := fmt.Sprintf(`vips:"%s"="%s"`, vip, strings.Join(targets, ","))

	out, stderr, err := util.RunOVNNbctl("set", "load_balancer", lb, lbTarget)
	if err != nil {
		return fmt.Errorf("error in configuring load balancer: %s "+
			"stdout: %q, stderr: %q, error: %v", lb, out, stderr, err)
	}

	return nil
}

// GetLogicalSwitchesForLoadBalancer get the switches associated to a LoadBalancer
func GetLogicalSwitchesForLoadBalancer(lb string) ([]string, error) {
	out, _, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=_uuid", "find",
		"logical_switch", fmt.Sprintf("load_balancer{>=}%s", lb))
	if err != nil {
		return nil, err
	}
	return strings.Fields(out), nil
}

// GetLogicalRoutersForLoadBalancer get the routers associated to a LoadBalancer
func GetLogicalRoutersForLoadBalancer(lb string) ([]string, error) {
	out, _, err := util.RunOVNNbctl("--data=bare", "--no-heading",
		"--columns=name", "find",
		"logical_router", fmt.Sprintf("load_balancer{>=}%s", lb))
	if err != nil {
		return nil, err
	}
	return strings.Fields(out), nil
}

// GetGRLogicalSwitchForLoadBalancer returns the external switch name if the load balancer is on a GR
func GetGRLogicalSwitchForLoadBalancer(lb string) (string, error) {
	routers, err := GetLogicalRoutersForLoadBalancer(lb)
	if err != nil {
		return "", err
	}
	if len(routers) == 0 {
		return "", nil
	}

	// if this is a GR we know the corresponding join and external switches, otherwise this is an unhandled
	// case
	for _, r := range routers {
		if strings.HasPrefix(r, types.GWRouterPrefix) {
			routerName := strings.TrimPrefix(r, types.GWRouterPrefix)
			return types.ExternalSwitchPrefix + routerName, nil
		}
	}
	return "", fmt.Errorf("router detected with load balancer that is not a GR")
}

// GenerateACLName generates a deterministic ACL name based on the load_balancer parameters
func GenerateACLName(lb string, sourceIP string, sourcePort int32) string {
	aclName := fmt.Sprintf("%s-%s:%d", lb, sourceIP, sourcePort)
	// ACL names are limited to 63 characters
	if len(aclName) > 63 {
		var ipPortLen int
		srcPortStr := fmt.Sprintf("%d", sourcePort)
		// Add the length of the IP (max 15 with periods, max 39 with colons),
		// plus length of sourcePort (max 5 char),
		// plus 1 for additional ':' to separate,
		// plus 1 for '-' between lb and IP.
		// With full IPv6 address and 5 char port, max ipPortLen is 62
		// With full IPv4 address and 5 char port, max ipPortLen is 24.
		ipPortLen = len(sourceIP) + len(srcPortStr) + 1 + 1
		lbTrim := 63 - ipPortLen
		// Shorten the Load Balancer name to allow full IP:port
		tmpLb := lb[:lbTrim]
		klog.Infof("Limiting ACL Name from %s to %s-%s:%d to keep under 63 characters", aclName, tmpLb, sourceIP, sourcePort)
		aclName = fmt.Sprintf("%s-%s:%d", tmpLb, sourceIP, sourcePort)
	}
	return aclName
}

func GetWorkerLoadBalancer(node string, protocol kapi.Protocol) (string, error) {
	var out string
	var err error
	if protocol == kapi.ProtocolTCP {
		out, _, err = util.FindOVNLoadBalancer(types.WorkerLBTCP, node)
	} else if protocol == kapi.ProtocolUDP {
		out, _, err = util.FindOVNLoadBalancer(types.WorkerLBUDP, node)
	} else if protocol == kapi.ProtocolSCTP {
		out, _, err = util.FindOVNLoadBalancer(types.WorkerLBSCTP, node)
	}
	if err != nil {
		return "", err
	}
	if out == "" {
		return "", fmt.Errorf("no %s load balancer found in the database for worker %s", protocol, node)
	}

	return out, nil
}

// GetWorkerLoadBalancers find TCP, SCTP, UDP load-balancers from worker
func GetWorkerLoadBalancers(node string) (string, string, string, error) {
	lbTCP, stderr, err := util.FindOVNLoadBalancer(types.WorkerLBTCP, node)
	if err != nil {
		return "", "", "", errors.Wrapf(err, "failed to get gateway router %q TCP "+
			"load balancer, stderr: %q", node, stderr)
	}

	lbUDP, stderr, err := util.FindOVNLoadBalancer(types.WorkerLBUDP, node)
	if err != nil {
		return "", "", "", errors.Wrapf(err, "failed to get gateway router %q UDP "+
			"load balancer, stderr: %q", node, stderr)
	}

	lbSCTP, stderr, err := util.FindOVNLoadBalancer(types.WorkerLBSCTP, node)
	if err != nil {
		return "", "", "", errors.Wrapf(err, "failed to get gateway router %q SCTP "+
			"load balancer, stderr: %q", node, stderr)
	}
	return lbTCP, lbUDP, lbSCTP, nil
}

// CreateLoadBalancerVIPs either creates or updates a set of load balancer VIPs mapping
// from sourcePort on each IP of a given address family in sourceIPs, to targetPort on
// each IP of the same address family in targetIPs
func CreateLoadBalancerVIPs(lb string,
	sourceIPs []string, sourcePort int32,
	targetIPs []string, targetPort int32) error {
	klog.V(5).Infof("Creating lb with %s, [%v], %d, [%v], %d", lb, sourceIPs, sourcePort, targetIPs, targetPort)

	for _, sourceIP := range sourceIPs {
		isIPv6 := utilnet.IsIPv6String(sourceIP)

		var targets []string
		for _, targetIP := range targetIPs {
			if utilnet.IsIPv6String(targetIP) == isIPv6 {
				targets = append(targets, util.JoinHostPortInt32(targetIP, targetPort))
			}
		}
		vip := util.JoinHostPortInt32(sourceIP, sourcePort)
		err := UpdateLoadBalancer(lb, vip, targets)
		if err != nil {
			return err
		}
	}
	return nil
}
