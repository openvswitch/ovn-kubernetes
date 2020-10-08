package node

import (
	"fmt"
	"hash/fnv"
	"net"
	"reflect"
	"regexp"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
	utilnet "k8s.io/utils/net"
)

const (
	// defaultOpenFlowCookie identifies default open flow rules added to the host OVS bridge.
	// The hex number 0xdeff105, aka defflos, is meant to sound like default flows.
	defaultOpenFlowCookie = "0xdeff105"
)

func addService(exec util.ExecHelper, service *kapi.Service, inport, outport, gwBridge string, nodeIP *net.IPNet) {
	if !util.ServiceTypeHasNodePort(service) && len(service.Spec.ExternalIPs) == 0 {
		return
	}

	for _, svcPort := range service.Spec.Ports {
		protocol := strings.ToLower(string(svcPort.Protocol))
		protocol6 := protocol + "6"
		if util.ServiceTypeHasNodePort(service) {
			if err := util.ValidatePort(svcPort.Protocol, svcPort.NodePort); err != nil {
				klog.Errorf("Skipping service add for svc: %s, err: %v", svcPort.Name, err)
				continue
			}
			if config.IPv4Mode {
				_, stderr, err := exec.RunOVSOfctl("add-flow", gwBridge,
					fmt.Sprintf("priority=100, in_port=%s, %s, tp_dst=%d, actions=%s",
						inport, protocol, svcPort.NodePort, outport))
				if err != nil {
					klog.Errorf("Failed to add openflow flow on %s for nodePort: "+
						"%d, stderr: %q, error: %v", gwBridge, svcPort.NodePort, stderr, err)
				}
			}
			if config.IPv6Mode {
				_, stderr, err := exec.RunOVSOfctl("add-flow", gwBridge,
					fmt.Sprintf("priority=100, in_port=%s, %s, tp_dst=%d, actions=%s",
						inport, protocol6, svcPort.NodePort, outport))
				if err != nil {
					klog.Errorf("Failed to add openflow flow on %s for nodePort: "+
						"%d, stderr: %q, error: %v", gwBridge, svcPort.NodePort, stderr, err)
				}
			}
			// Flows for cloud load balancers on Azure/GCP
			flows := make([]string, 0)

			// Established traffic is handled by default conntrack rules
			// Table 1 handles forwarding traffic to pods
			// Table 2 handles return NAT traffic for node port and forwards out of the host
			// NodePort/Ingress access in the OVS bridge will only ever come from outside of the host
			for _, ing := range service.Status.LoadBalancer.Ingress {
				if ing.IP == "" {
					continue
				}
				ingIP := net.ParseIP(ing.IP)
				if ingIP == nil {
					klog.Errorf("Failed to parse ingress IP: %s", ing.IP)
					continue
				}
				cookie, err := svcToCookie(service.Name, ingIP, svcPort.Port)
				if err != nil {
					klog.Errorf("Unable to generate cookie for svc: %s, %s, %d, error: %v",
						service.Name, ingIP.String(), svcPort.Port, err)
					continue
				}
				flowProtocol := protocol
				nw_dst := "nw_dst"
				nw_src := "nw_src"
				if utilnet.IsIPv6String(ing.IP) {
					flowProtocol = protocol6
					nw_dst = "ipv6_dst"
					nw_src = "ipv6_src"
				}
				// Send to CT from external net with DNAT, eventually will land in table 1 (traffic to pods)
				flows = append(flows,
					fmt.Sprintf("cookie=%s,priority=101,in_port=%s,ct_state=-trk,%s,%s=%s,tp_dst=%d,"+
						"actions=ct(commit,table=0,zone=%d,nat(dst=%s)",
						cookie, inport, flowProtocol, nw_dst, ing.IP, svcPort.Port, config.Default.ConntrackZone,
						util.JoinHostPortInt32(nodeIP.IP.String(), svcPort.NodePort)))
				// Incoming return traffic from pods, send to CT, unDNAT, goto table 2
				flows = append(flows,
					fmt.Sprintf("cookie=%s,priority=101,in_port=%s,%s,%s=%s,tp_src=%d,"+
						"actions=ct(table=2,zone=%d,nat)",
						cookie, outport, flowProtocol, nw_src, nodeIP.IP, svcPort.NodePort, config.Default.ConntrackZone))
			}

			for _, flow := range flows {
				_, stderr, err := exec.RunOVSOfctl("add-flow", gwBridge, flow)
				if err != nil {
					klog.Errorf("Failed to add openflow flow on %s for ingress, stderr: %q, error: %v, flow: %s",
						gwBridge, stderr, err, flow)
				}
			}
		}
		for _, externalIP := range service.Spec.ExternalIPs {
			if err := util.ValidatePort(svcPort.Protocol, svcPort.Port); err != nil {
				klog.Errorf("Skipping service add for svc: %s, err: %v", svcPort.Name, err)
				continue
			}
			flowProtocol := protocol
			nw_dst := "nw_dst"
			if utilnet.IsIPv6String(externalIP) {
				flowProtocol = protocol6
				nw_dst = "ipv6_dst"
			}
			_, stderr, err := exec.RunOVSOfctl("add-flow", gwBridge,
				fmt.Sprintf("priority=100, in_port=%s, %s, %s=%s, tp_dst=%d, actions=%s",
					inport, flowProtocol, nw_dst, externalIP, svcPort.Port, outport))
			if err != nil {
				klog.Errorf("Failed to add openflow flow on %s for ExternalIP: "+
					"%s, stderr: %q, error: %v", gwBridge, externalIP, stderr, err)
			}
		}
	}

	addSharedGatewayIptRules(service, nodeIP)
}

func deleteService(exec util.ExecHelper, service *kapi.Service, inport, gwBridge string, nodeIP *net.IPNet) {
	if !util.ServiceTypeHasNodePort(service) && len(service.Spec.ExternalIPs) == 0 {
		return
	}

	for _, svcPort := range service.Spec.Ports {
		protocol := strings.ToLower(string(svcPort.Protocol))
		protocol6 := protocol + "6"
		if util.ServiceTypeHasNodePort(service) {
			if err := util.ValidatePort(svcPort.Protocol, svcPort.NodePort); err != nil {
				klog.Errorf("Skipping service delete, for svc: %s, err: %v", svcPort.Name, err)
				continue
			}
			if config.IPv4Mode {
				_, stderr, err := exec.RunOVSOfctl("del-flows", gwBridge,
					fmt.Sprintf("in_port=%s, %s, tp_dst=%d",
						inport, protocol, svcPort.NodePort))
				if err != nil {
					klog.Errorf("Failed to delete openflow flow on %s for nodePort: "+
						"%d, stderr: %q, error: %v", gwBridge, svcPort.NodePort, stderr, err)
				}
			}
			if config.IPv6Mode {
				_, stderr, err := exec.RunOVSOfctl("del-flows", gwBridge,
					fmt.Sprintf("in_port=%s, %s, tp_dst=%d",
						inport, protocol6, svcPort.NodePort))
				if err != nil {
					klog.Errorf("Failed to delete openflow flow on %s for nodePort: "+
						"%d, stderr: %q, error: %v", gwBridge, svcPort.NodePort, stderr, err)
				}
			}
		}
		for _, externalIP := range service.Spec.ExternalIPs {
			if err := util.ValidatePort(svcPort.Protocol, svcPort.Port); err != nil {
				klog.Errorf("Skipping service delete, for svc: %s, err: %v", svcPort.Name, err)
				continue
			}
			flowProtocol := protocol
			nw_dst := "nw_dst"
			if utilnet.IsIPv6String(externalIP) {
				flowProtocol = protocol6
				nw_dst = "ipv6_dst"
			}
			_, stderr, err := exec.RunOVSOfctl("del-flows", gwBridge,
				fmt.Sprintf("in_port=%s, %s, %s=%s, tp_dst=%d",
					inport, flowProtocol, nw_dst, externalIP, svcPort.Port))
			if err != nil {
				klog.Errorf("Failed to delete openflow flow on %s for ExternalIP: "+
					"%s, stderr: %q, error: %v", gwBridge, externalIP, stderr, err)
			}
		}
		for _, ing := range service.Status.LoadBalancer.Ingress {
			if ing.IP == "" {
				continue
			}
			ingIP := net.ParseIP(ing.IP)
			if ingIP == nil {
				klog.Errorf("Failed to parse ingress IP: %s", ing.IP)
				continue
			}
			cookie, err := svcToCookie(service.Name, ingIP, svcPort.Port)
			if err != nil {
				klog.Errorf("Unable to generate cookie for svc: %s, %s, %d, error: %v",
					service.Name, ingIP.String(), svcPort.Port, err)
			}
			_, stderr, err := exec.RunOVSOfctl("del-flows", gwBridge,
				fmt.Sprintf("cookie=%s/-1", cookie))
			if err != nil {
				klog.Errorf("Failed to delete openflow flow on %s for Ingress: "+
					"%s, stderr: %q, error: %v", gwBridge, ingIP, stderr, err)
			}
		}
	}

	delSharedGatewayIptRules(service, nodeIP)
}

func syncServices(exec util.ExecHelper, services []interface{}, inport, gwBridge string, nodeIP *net.IPNet) {
	ports := make(map[string]string)
	ingressCookies := make(map[string]struct{})
	for _, serviceInterface := range services {
		service, ok := serviceInterface.(*kapi.Service)
		if !ok {
			klog.Errorf("Spurious object in syncServices: %v",
				serviceInterface)
			continue
		}

		if !util.ServiceTypeHasNodePort(service) && len(service.Spec.ExternalIPs) == 0 {
			continue
		}

		for _, svcPort := range service.Spec.Ports {
			if util.ServiceTypeHasNodePort(service) {
				if err := util.ValidatePort(svcPort.Protocol, svcPort.NodePort); err != nil {
					klog.Errorf("syncServices error for service port %s: %v", svcPort.Name, err)
					continue
				}
				protocol := strings.ToLower(string(svcPort.Protocol))
				nodePortKey := fmt.Sprintf("%s_%d", protocol, svcPort.NodePort)
				ports[nodePortKey] = ""
			}
			for _, externalIP := range service.Spec.ExternalIPs {
				if err := util.ValidatePort(svcPort.Protocol, svcPort.Port); err != nil {
					klog.Errorf("syncServices error for service port %s: %v", svcPort.Name, err)
					continue
				}
				protocol := strings.ToLower(string(svcPort.Protocol))
				externalPortKey := fmt.Sprintf("%s_%d", protocol, svcPort.Port)
				ports[externalPortKey] = externalIP
			}
			for _, ing := range service.Status.LoadBalancer.Ingress {
				ingIP := net.ParseIP(ing.IP)
				if ingIP == nil {
					klog.Errorf("Failed to parse ingress IP: %s", ing.IP)
					continue
				}
				cookie, err := svcToCookie(service.Name, ingIP, svcPort.Port)
				if err != nil {
					klog.Errorf("Unable to generate cookie for svc: %s, %s, %d, error: %v",
						service.Name, ingIP.String(), svcPort.Port, err)
				}
				ingressCookies[cookie] = struct{}{}
			}
		}
	}

	syncSharedGatewayIptRules(services, nodeIP)

	stdout, stderr, err := exec.RunOVSOfctl("dump-flows",
		gwBridge)
	if err != nil {
		klog.Errorf("dump-flows failed: %q (%v)", stderr, err)
		return
	}
	flows := strings.Split(stdout, "\n")

	re, err := regexp.Compile(`tp_dst=(.*?)[, ]`)
	if err != nil {
		klog.Errorf("Regexp compile failed: %v", err)
		return
	}

	for _, flow := range flows {
		group := re.FindStringSubmatch(flow)
		if group == nil {
			continue
		}

		var key string
		if strings.Contains(flow, "tcp6") {
			key = fmt.Sprintf("tcp6_%s", group[1])
		} else if strings.Contains(flow, "udp6") {
			key = fmt.Sprintf("udp6_%s", group[1])
		} else if strings.Contains(flow, "sctp6") {
			key = fmt.Sprintf("sctp6_%s", group[1])
		} else if strings.Contains(flow, "tcp") {
			key = fmt.Sprintf("tcp_%s", group[1])
		} else if strings.Contains(flow, "udp") {
			key = fmt.Sprintf("udp_%s", group[1])
		} else if strings.Contains(flow, "sctp") {
			key = fmt.Sprintf("sctp_%s", group[1])
		} else {
			continue
		}

		// FIXME (trozet) this code is buggy, the else statement can never be reached, so external ip flows will hang
		// around on the switch after sync
		// refactor this into flow caching later
		if externalIP, ok := ports[key]; !ok {
			pair := strings.Split(key, "_")
			protocol, port := pair[0], pair[1]
			if externalIP == "" {
				// Check if this is a known cloud load balancer flow
				for cookie := range ingressCookies {
					if strings.Contains(flow, cookie) {
						continue
					}
				}
				stdout, _, err := exec.RunOVSOfctl(
					"del-flows", gwBridge,
					fmt.Sprintf("in_port=%s, %s, tp_dst=%s",
						inport, protocol, port))
				if err != nil {
					klog.Errorf("del-flows of %s failed: %q",
						gwBridge, stdout)
				}
			} else {
				nw_dst := "nw_dst"
				flowProtocol := protocol
				if utilnet.IsIPv6String(externalIP) {
					nw_dst = "ipv6_dst"
					flowProtocol = protocol + "6"
				}
				stdout, _, err := exec.RunOVSOfctl(
					"del-flows", gwBridge,
					fmt.Sprintf("in_port=%s, %s, %s=%s, tp_dst=%s",
						inport, flowProtocol, nw_dst, externalIP, port))
				if err != nil {
					klog.Errorf("del-flows of %s failed: %q",
						gwBridge, stdout)
				}
			}
		}
	}
}

func nodePortWatcher(exec util.ExecHelper, nodeName, gwBridge, gwIntf string, nodeIP []*net.IPNet, wf *factory.WatchFactory) error {
	// the name of the patch port created by ovn-controller is of the form
	// patch-<logical_port_name_of_localnet_port>-to-br-int
	patchPort := "patch-" + gwBridge + "_" + nodeName + "-to-br-int"
	// Get ofport of patchPort
	ofportPatch, stderr, err := exec.RunOVSVsctl("--if-exists", "get",
		"interface", patchPort, "ofport")
	if err != nil {
		return fmt.Errorf("failed to get ofport of %s, stderr: %q, error: %v",
			patchPort, stderr, err)
	}

	// Get ofport of physical interface
	ofportPhys, stderr, err := exec.RunOVSVsctl("--if-exists", "get",
		"interface", gwIntf, "ofport")
	if err != nil {
		return fmt.Errorf("failed to get ofport of %s, stderr: %q, error: %v",
			gwIntf, stderr, err)
	}

	// In the shared gateway mode, the NodePort service is handled by the OpenFlow flows configured
	// on the OVS bridge in the host. These flows act only on the packets coming in from outside
	// of the node. If someone on the node is trying to access the NodePort service, those packets
	// will not be processed by the OpenFlow flows, so we need to add iptable rules that DNATs the
	// NodePortIP:NodePort to ClusterServiceIP:Port.
	if err := initSharedGatewayIPTables(); err != nil {
		return err
	}

	wf.AddServiceHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			service := obj.(*kapi.Service)
			addService(exec, service, ofportPhys, ofportPatch, gwBridge, nodeIP[0])
		},
		UpdateFunc: func(old, new interface{}) {
			svcNew := new.(*kapi.Service)
			svcOld := old.(*kapi.Service)
			if reflect.DeepEqual(svcNew.Spec, svcOld.Spec) && reflect.DeepEqual(svcNew.Status, svcOld.Status) {
				return
			}
			deleteService(exec, svcOld, ofportPhys, gwBridge, nodeIP[0])
			addService(exec, svcNew, ofportPhys, ofportPatch, gwBridge, nodeIP[0])
		},
		DeleteFunc: func(obj interface{}) {
			service := obj.(*kapi.Service)
			deleteService(exec, service, ofportPhys, gwBridge, nodeIP[0])
		},
	}, func(services []interface{}) {
		syncServices(exec, services, ofportPhys, gwBridge, nodeIP[0])
	})

	return nil
}

// since we share the host's k8s node IP, add OpenFlow flows
// -- to steer the NodePort traffic arriving on the host to the OVN logical topology and
// -- to also connection track the outbound north-south traffic through l3 gateway so that
//    the return traffic can be steered back to OVN logical topology
// -- to also handle unDNAT return traffic back out of the host
func addDefaultConntrackRules(exec util.ExecHelper, nodeName, gwBridge, gwIntf string, stopChan chan struct{}) error {
	// the name of the patch port created by ovn-controller is of the form
	// patch-<logical_port_name_of_localnet_port>-to-br-int
	localnetLpName := gwBridge + "_" + nodeName
	patchPort := "patch-" + localnetLpName + "-to-br-int"
	// Get ofport of patchPort, but before that make sure ovn-controller created
	// one for us (waits for about ovsCommandTimeout seconds)
	ofportPatch, stderr, err := exec.RunOVSVsctl("wait-until", "Interface", patchPort, "ofport>0",
		"--", "get", "Interface", patchPort, "ofport")
	if err != nil {
		return fmt.Errorf("failed while waiting on patch port %q to be created by ovn-controller and "+
			"while getting ofport. stderr: %q, error: %v", patchPort, stderr, err)
	}

	// Get ofport of physical interface
	ofportPhys, stderr, err := exec.RunOVSVsctl("get", "interface", gwIntf, "ofport")
	if err != nil {
		return fmt.Errorf("failed to get ofport of %s, stderr: %q, error: %v",
			gwIntf, stderr, err)
	}

	// replace the left over OpenFlow flows with the FLOOD action flow
	_, stderr, err = util.AddFloodActionOFFlow(exec, gwBridge)
	if err != nil {
		return fmt.Errorf("failed to replace-flows on bridge %q stderr:%s (%v)", gwBridge, stderr, err)
	}

	nFlows := 0
	if config.IPv4Mode {
		// table 0, packets coming from pods headed externally. Commit connections
		// so that reverse direction goes back to the pods.
		_, stderr, err = exec.RunOVSOfctl("add-flow", gwBridge,
			fmt.Sprintf("cookie=%s, priority=100, in_port=%s, ip, "+
				"actions=ct(commit, zone=%d), output:%s",
				defaultOpenFlowCookie, ofportPatch, config.Default.ConntrackZone, ofportPhys))
		if err != nil {
			return fmt.Errorf("failed to add openflow flow to %s, stderr: %q, "+
				"error: %v", gwBridge, stderr, err)
		}
		nFlows++

		// table 0, packets coming from external. Send it through conntrack and
		// resubmit to table 1 to know the state of the connection.
		_, stderr, err = exec.RunOVSOfctl("add-flow", gwBridge,
			fmt.Sprintf("cookie=%s, priority=50, in_port=%s, ip, "+
				"actions=ct(zone=%d, table=1)", defaultOpenFlowCookie, ofportPhys, config.Default.ConntrackZone))
		if err != nil {
			return fmt.Errorf("failed to add openflow flow to %s, stderr: %q, "+
				"error: %v", gwBridge, stderr, err)
		}
		nFlows++
	}
	if config.IPv6Mode {
		// table 0, packets coming from pods headed externally. Commit connections
		// so that reverse direction goes back to the pods.
		_, stderr, err = exec.RunOVSOfctl("add-flow", gwBridge,
			fmt.Sprintf("cookie=%s, priority=100, in_port=%s, ipv6, "+
				"actions=ct(commit, zone=%d), output:%s",
				defaultOpenFlowCookie, ofportPatch, config.Default.ConntrackZone, ofportPhys))
		if err != nil {
			return fmt.Errorf("failed to add openflow flow to %s, stderr: %q, "+
				"error: %v", gwBridge, stderr, err)
		}
		nFlows++

		// table 0, packets coming from external. Send it through conntrack and
		// resubmit to table 1 to know the state of the connection.
		_, stderr, err = exec.RunOVSOfctl("add-flow", gwBridge,
			fmt.Sprintf("cookie=%s, priority=50, in_port=%s, ipv6, "+
				"actions=ct(zone=%d, table=1)", defaultOpenFlowCookie, ofportPhys, config.Default.ConntrackZone))
		if err != nil {
			return fmt.Errorf("failed to add openflow flow to %s, stderr: %q, "+
				"error: %v", gwBridge, stderr, err)
		}
		nFlows++
	}

	// table 1, established and related connections go to pod
	_, stderr, err = exec.RunOVSOfctl("add-flow", gwBridge,
		fmt.Sprintf("cookie=%s, priority=100, table=1, ct_state=+trk+est, "+
			"actions=output:%s", defaultOpenFlowCookie, ofportPatch))
	if err != nil {
		return fmt.Errorf("failed to add openflow flow to %s, stderr: %q, "+
			"error: %v", gwBridge, stderr, err)
	}
	nFlows++

	_, stderr, err = exec.RunOVSOfctl("add-flow", gwBridge,
		fmt.Sprintf("cookie=%s, priority=100, table=1, ct_state=+trk+rel, "+
			"actions=output:%s", defaultOpenFlowCookie, ofportPatch))
	if err != nil {
		return fmt.Errorf("failed to add openflow flow to %s, stderr: %q, "+
			"error: %v", gwBridge, stderr, err)
	}
	nFlows++

	// table 1, all other connections do normal processing
	_, stderr, err = exec.RunOVSOfctl("add-flow", gwBridge,
		fmt.Sprintf("cookie=%s, priority=0, table=1, actions=output:FLOOD", defaultOpenFlowCookie))
	if err != nil {
		return fmt.Errorf("failed to add openflow flow to %s, stderr: %q, "+
			"error: %v", gwBridge, stderr, err)
	}
	nFlows++

	// table 2, return traffic to go to out of the host from nodePort or load balancer access
	_, stderr, err = exec.RunOVSOfctl("add-flow", gwBridge,
		fmt.Sprintf("cookie=%s, priority=0, table=2, actions=output:%s", defaultOpenFlowCookie, ofportPhys))
	if err != nil {
		return fmt.Errorf("failed to add openflow flow to %s, stderr: %q, "+
			"error: %v", gwBridge, stderr, err)
	}
	nFlows++

	// add health check function to check default OpenFlow flows are on the shared gateway bridge
	go checkDefaultConntrackRules(exec, gwBridge, gwIntf, patchPort, ofportPhys, ofportPatch, nFlows, stopChan)
	return nil
}

func (n *OvnNode) initSharedGateway(subnets []*net.IPNet, gwNextHops []net.IP, gwIntf string, nodeAnnotator kube.Annotator) (postWaitFunc, error) {
	var bridgeName string
	var uplinkName string
	var brCreated bool
	var err error

	if bridgeName, _, err = n.exec.RunOVSVsctl("--", "port-to-br", gwIntf); err == nil {
		// This is an OVS bridge's internal port
		uplinkName, err = util.GetNicName(n.exec, bridgeName)
		if err != nil {
			return nil, err
		}
	} else if _, _, err := n.exec.RunOVSVsctl("--", "br-exists", gwIntf); err != nil {
		// This is not a OVS bridge. We need to create a OVS bridge
		// and add cluster.GatewayIntf as a port of that bridge.
		bridgeName, err = util.NicToBridge(n.exec, gwIntf)
		if err != nil {
			return nil, fmt.Errorf("failed to convert %s to OVS bridge: %v",
				gwIntf, err)
		}
		uplinkName = gwIntf
		gwIntf = bridgeName
		brCreated = true
	} else {
		// gateway interface is an OVS bridge
		uplinkName, err = getIntfName(n.exec, gwIntf)
		if err != nil {
			return nil, err
		}
		bridgeName = gwIntf
	}

	// Now, we get IP addresses from OVS bridge. If IP does not exist,
	// error out.
	ips, err := getNetworkInterfaceIPAddresses(gwIntf)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface details for %s (%v)",
			gwIntf, err)
	}
	ifaceID, macAddress, err := bridgedGatewayNodeSetup(n.exec, n.name, bridgeName, gwIntf,
		util.PhysicalNetworkName, brCreated)
	if err != nil {
		return nil, fmt.Errorf("failed to set up shared interface gateway: %v", err)
	}

	err = setupLocalNodeAccessBridge(n.exec, n.name, subnets)
	if err != nil {
		return nil, err
	}
	chassisID, err := util.GetNodeChassisID(n.exec)
	if err != nil {
		return nil, err
	}

	err = util.SetL3GatewayConfig(nodeAnnotator, &util.L3GatewayConfig{
		Mode:           config.GatewayModeShared,
		ChassisID:      chassisID,
		InterfaceID:    ifaceID,
		MACAddress:     macAddress,
		IPAddresses:    ips,
		NextHops:       gwNextHops,
		NodePortEnable: config.Gateway.NodeportEnable,
		VLANID:         &config.Gateway.VLANID,
	})
	if err != nil {
		return nil, err
	}

	return func() error {
		if config.Gateway.NodeportEnable {
			if config.Gateway.Mode == config.GatewayModeLocal {
				if err := addDefaultConntrackRulesLocal(n.exec, n.name, bridgeName, uplinkName, n.stopChan); err != nil {
					return err
				}
			} else {
				// Program cluster.GatewayIntf to let non-pod traffic to go to host
				// stack
				if err := addDefaultConntrackRules(n.exec, n.name, bridgeName, uplinkName, n.stopChan); err != nil {
					return err
				}
				// Program cluster.GatewayIntf to let nodePort traffic to go to pods.
				if err := nodePortWatcher(n.exec, n.name, bridgeName, uplinkName, ips,
					n.watchFactory); err != nil {
					return err
				}
			}
		}
		return nil
	}, nil
}

func cleanupSharedGateway(exec util.ExecHelper) error {
	// NicToBridge() may be created before-hand, only delete the patch port here
	stdout, stderr, err := exec.RunOVSVsctl("--columns=name", "--no-heading", "find", "port",
		"external_ids:ovn-localnet-port!=_")
	if err != nil {
		return fmt.Errorf("failed to get ovn-localnet-port port stderr:%s (%v)", stderr, err)
	}
	ports := strings.Fields(strings.Trim(stdout, "\""))
	for _, port := range ports {
		_, stderr, err := exec.RunOVSVsctl("--if-exists", "del-port", strings.Trim(port, "\""))
		if err != nil {
			return fmt.Errorf("failed to delete port %s stderr:%s (%v)", port, stderr, err)
		}
	}

	// Get the OVS bridge name from ovn-bridge-mappings
	stdout, stderr, err = exec.RunOVSVsctl("--if-exists", "get", "Open_vSwitch", ".",
		"external_ids:ovn-bridge-mappings")
	if err != nil {
		return fmt.Errorf("failed to get ovn-bridge-mappings stderr:%s (%v)", stderr, err)
	}
	// skip the existing mapping setting for the specified physicalNetworkName
	bridgeName := ""
	bridgeMappings := strings.Split(stdout, ",")
	for _, bridgeMapping := range bridgeMappings {
		m := strings.Split(bridgeMapping, ":")
		if network := m[0]; network == util.PhysicalNetworkName {
			bridgeName = m[1]
			break
		}
	}
	if len(bridgeName) == 0 {
		return nil
	}

	_, stderr, err = util.AddFloodActionOFFlow(exec, bridgeName)
	if err != nil {
		return fmt.Errorf("failed to replace-flows on bridge %q stderr:%s (%v)", bridgeName, stderr, err)
	}

	cleanupSharedGatewayIPTChains()
	return nil
}

func svcToCookie(name string, ip net.IP, port int32) (string, error) {
	id := fmt.Sprintf("%s%s%d", name, ip.String(), port)
	h := fnv.New64a()
	_, err := h.Write([]byte(id))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("0x%x", h.Sum64()), nil
}
