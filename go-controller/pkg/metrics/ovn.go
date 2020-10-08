package metrics

import (
	"fmt"
	"k8s.io/klog"
	"strings"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/prometheus/client_golang/prometheus"
)

// ovnController Configuration metrics
var metricRemoteProbeInterval = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemController,
	Name:      "remote_probe_interval",
	Help: "The maximum number of milliseconds of idle time on connection to " +
		"the OVN SB DB before sending an inactivity probe message.",
})

var metricOpenFlowProbeInterval = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemController,
	Name:      "openflow_probe_interval",
	Help: "The maximum number of milliseconds of idle time on OpenFlow connection " +
		"to the OVS bridge before sending an inactivity probe message.",
})

var metricMonitorAll = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemController,
	Name:      "monitor_all",
	Help: "Specifies if ovn-controller should monitor all records of tables in OVN SB DB. " +
		"If set to false, it will conditionally monitor the records that " +
		"is needed in the current chassis. Values are false(0), true(1).",
})

var metricEncapIP = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemController,
	Name:      "encap_ip",
	Help: "A metric with a constant '1' value labeled by ipadress that " +
		"specifies the encapsulation ip address configured on that node.",
},
	[]string{
		"ipaddress",
	},
)

var metricSbConnectionMethod = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemController,
	Name:      "sb_connection_method",
	Help: "A metric with a constant '1' value labeled by connection_method that " +
		"specifies the ovn-remote value configured on that node.",
},
	[]string{
		"connection_method",
	},
)

var metricEncapType = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemController,
	Name:      "encap_type",
	Help: "A metric with a constant '1' value labeled by type that " +
		"specifies the encapsulation type a chassis should use to " +
		"connect to this node.",
},
	[]string{
		"type",
	},
)

var metricBridgeMappings = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemController,
	Name:      "bridge_mappings",
	Help: "A metric with a constant '1' value labeled by mapping that " +
		"specifies list of key-value pairs that map a physical network name " +
		"to a local ovs bridge that provides connectivity to that network.",
},
	[]string{
		"mapping",
	},
)

var (
	ovnControllerVersion       string
	ovnControllerOvsLibVersion string
)

func getOvnControllerVersionInfo(exec util.ExecHelper) {
	stdout, _, err := exec.RunOVNControllerAppCtl("version")
	if err != nil {
		return
	}

	// the output looks something like this:
	// ovn-controller 20.06.0.86f64fc1
	// Open vSwitch Library 2.13.0.f945b5c5
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix("ovn-controller ", line) {
			ovnControllerVersion = strings.Fields(line)[1]
		} else if strings.HasPrefix("Open vSwitch Library ", line) {
			ovnControllerOvsLibVersion = strings.Fields(line)[3]
		}
	}
}

var ovnControllerCoverageShowMetricsMap = map[string]*metricDetails{
	"lflow_run": {
		help: "Number of times ovn-controller has translated " +
			"the Logical_Flow table in the OVN " +
			"SB database into OpenFlow flows.",
	},
	"rconn_sent": {
		help: "Specifies the number of messages " +
			"that have been sent to the underlying virtual " +
			"connection (unix, tcp, or ssl) to OpenFlow devices.",
	},
	"rconn_queued": {
		help: "Specifies the number of messages that have been " +
			"queued because it couldn’t be sent using the " +
			"underlying virtual connection to OpenFlow devices.",
	},
	"rconn_discarded": {
		help: "Specifies the number of messages that " +
			"have been dropped because the send queue " +
			"had to be flushed because of reconnection.",
	},
	"rconn_overflow": {
		help: "Specifies the number of messages that have " +
			"been dropped because of the queue overflow.",
	},
	"vconn_open": {
		help: "Specifies the number of attempts to connect " +
			"to an OpenFlow Device.",
	},
	"vconn_sent": {
		help: "Specifies the number of messages sent " +
			"to the OpenFlow Device.",
	},
	"vconn_received": {
		help: "Specifies the number of messages received " +
			"from the OpenFlow Device.",
	},
	"stream_open": {
		help: "Specifies the number of attempts to connect " +
			"to a remote peer (active connection).",
	},
	"txn_success": {
		help: "Specifies the number of times the OVSDB " +
			"transaction has successfully completed.",
	},
	"txn_error": {
		help: "Specifies the number of times the OVSDB " +
			"transaction has errored out.",
	},
	"txn_uncommitted": {
		help: "Specifies the number of times the OVSDB " +
			"transaction were uncommitted.",
	},
	"txn_unchanged": {
		help: "Specifies the number of times the OVSDB transaction " +
			"resulted in no change to the database.",
	},
	"txn_incomplete": {
		help: "Specifies the number of times the OVSDB transaction " +
			"did not complete and the client had to re-try.",
	},
	"txn_aborted": {
		help: "Specifies the number of times the OVSDB " +
			" transaction has been aborted.",
	},
	"txn_try_again": {
		help: "Specifies the number of times the OVSDB " +
			"transaction failed and the client had to re-try.",
	},
	"netlink_sent": {
		help: "Number of netlink message sent to the kernel.",
	},
	"netlink_received": {
		help: "Number of netlink messages received by the kernel.",
	},
	"netlink_recv_jumbo": {
		help: "Number of netlink messages that were received from" +
			"the kernel were more than the allocated buffer.",
	},
	"netlink_overflow": {
		help: "Netlink messages dropped by the daemon due " +
			"to buffer overflow.",
	},
	"packet_in": {
		srcName: "flow_extract",
		help: "Specifies the number of times ovn-controller has " +
			"handled the packet-ins from ovs-vswitchd.",
	},
	"packet_in_drop": {
		aggregateFrom: []string{
			"pinctrl_drop_put_mac_binding",
			"pinctrl_drop_buffered_packets_map",
			"pinctrl_drop_controller_event",
			"pinctrl_drop_put_vport_binding",
		},
		help: "Specifies the number of times the ovn-controller has dropped the " +
			"packet-ins from ovs-vswitchd due to resource constraints",
	},
}

// setOvnControllerConfigurationMetrics updates ovn-controller configuration
// values (ovn-openflow-probe-interval, ovn-remote-probe-interval, ovn-monitor-all,
// ovn-encap-ip, ovn-encap-type, ovn-remote) through
// "ovs-vsctl list --columns=external_ids Open_vSwitch ."
func setOvnControllerConfigurationMetrics(exec util.ExecHelper) (err error) {
	var stdout, stderr string

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("recovering from panic while parsing the "+
				"Open_vSwitch table's external_ids column - %v", r)
		}
	}()

	stdout, stderr, err = exec.RunOVSVsctl("--no-headings", "--data=bare",
		"--columns=external_ids", "list", "Open_vSwitch", ".")
	if err != nil {
		return fmt.Errorf("failed to get Open_vSwitch table's external_ids column "+
			"stderr(%s) : %v", stderr, err)
	}

	var ovnNodePortValue = 1
	for _, kvPair := range strings.Fields(stdout) {
		elem := strings.Split(kvPair, "=")
		if len(elem) != 2 {
			continue
		}
		fieldType := elem[0]
		fieldValue := elem[1]
		switch fieldType {
		case "ovn-openflow-probe-interval":
			metricValue := parseMetricToFloat(MetricOvnSubsystemController, "ovn-openflow-probe-interval", fieldValue)
			metricOpenFlowProbeInterval.Set(metricValue)
		case "ovn-remote-probe-interval":
			metricValue := parseMetricToFloat(MetricOvnSubsystemController, "ovn-remote-probe-interval", fieldValue)
			metricRemoteProbeInterval.Set(metricValue)
		case "ovn-monitor-all":
			var ovnMonitorValue float64
			if fieldValue == "true" {
				ovnMonitorValue = 1
			}
			metricMonitorAll.Set(ovnMonitorValue)
		case "ovn-encap-ip":
			metricEncapIP.WithLabelValues(fieldValue).Set(1)
		case "ovn-remote":
			metricSbConnectionMethod.WithLabelValues(fieldValue).Set(1)
		case "ovn-encap-type":
			metricEncapType.WithLabelValues(fieldValue).Set(1)
		case "ovn-k8s-node-port":
			if fieldValue == "false" {
				ovnNodePortValue = 0
			}
		case "ovn-bridge-mappings":
			metricBridgeMappings.WithLabelValues(fieldValue).Set(1)
		}
	}
	metricOvnNodePortEnabled.Set(float64(ovnNodePortValue))
	return nil
}

func ovnControllerConfigurationMetricsUpdater(exec util.ExecHelper) {
	for {
		err := setOvnControllerConfigurationMetrics(exec)
		if err != nil {
			klog.Errorf("%s", err.Error())
		}
		time.Sleep(30 * time.Second)
	}
}

func getPortCount(exec util.ExecHelper, portType string) float64 {
	var portCount float64
	stdout, stderr, err := exec.RunOVSVsctl("--no-headings", "--data=bare", "--format=csv",
		"--columns=name", "find", "interface", "type="+portType)
	if err != nil {
		klog.Errorf("Failed to get %s interface count, stderr(%s): (%v)", portType, stderr, err)
		return 0
	}
	portNames := strings.Split(stdout, "\n")
	switch portType {
	case "patch":
		for _, portName := range portNames {
			if strings.Contains(portName, "br-int") {
				portCount++
			}
		}
	default:
		portCount = float64(len(portNames))
	}

	return portCount
}

func RegisterOvnControllerMetrics(exec util.ExecHelper) {
	getOvnControllerVersionInfo(exec)
	ovnRegistry.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Namespace: MetricOvnNamespace,
			Subsystem: MetricOvnSubsystemController,
			Name:      "build_info",
			Help: "A metric with a constant '1' value labeled by version and library " +
				"from which ovn binaries were built",
			ConstLabels: prometheus.Labels{
				"version":         ovnControllerVersion,
				"ovs_lib_version": ovnControllerOvsLibVersion,
			},
		},
		func() float64 { return 1 },
	))

	// ovn-controller metrics
	ovnRegistry.MustRegister(prometheus.NewCounterFunc(
		prometheus.CounterOpts{
			Namespace: MetricOvnNamespace,
			Subsystem: MetricOvnSubsystemController,
			Name:      "integration_bridge_openflow_total",
			Help:      "The total number of OpenFlow flows in the integration bridge.",
		}, func() float64 {
			stdout, stderr, err := exec.RunOVSOfctl("-t", "5", "dump-aggregate", "br-int")
			if err != nil {
				klog.Errorf("Failed to get flow count for br-int, stderr(%s): (%v)",
					stderr, err)
				return 0
			}
			for _, kvPair := range strings.Fields(stdout) {
				if strings.HasPrefix(kvPair, "flow_count=") {
					value := strings.Split(kvPair, "=")[1]
					return parseMetricToFloat(MetricOvnSubsystemController, "integration_bridge_openflow_total",
						value)
				}
			}
			return 0
		}))
	ovnRegistry.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Namespace: MetricOvnNamespace,
			Subsystem: MetricOvnSubsystemController,
			Name:      "integration_bridge_patch_ports_total",
			Help: "Captures the number of patch ports that connect br-int OVS " +
				"bridge to physical OVS bridge and br-local OVS bridge.",
		},
		func() float64 {
			return getPortCount(exec, "patch")
		}))
	ovnRegistry.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Namespace: MetricOvnNamespace,
			Subsystem: MetricOvnSubsystemController,
			Name:      "integration_bridge_geneve_ports_total",
			Help:      "Captures the number of geneve ports that are on br-int OVS bridge.",
		},
		func() float64 {
			return getPortCount(exec, "geneve")
		}))

	// register ovn-controller configuration metrics
	ovnRegistry.MustRegister(metricRemoteProbeInterval)
	ovnRegistry.MustRegister(metricOpenFlowProbeInterval)
	ovnRegistry.MustRegister(metricMonitorAll)
	ovnRegistry.MustRegister(metricEncapIP)
	ovnRegistry.MustRegister(metricSbConnectionMethod)
	ovnRegistry.MustRegister(metricEncapType)
	ovnRegistry.MustRegister(metricBridgeMappings)
	// Register the ovn-controller coverage/show metrics
	componentCoverageShowMetricsMap[ovnController] = ovnControllerCoverageShowMetricsMap
	registerCoverageShowMetrics(ovnController, MetricOvnNamespace, MetricOvnSubsystemController)

	// ovn-controller configuration metrics updater
	go ovnControllerConfigurationMetricsUpdater(exec)
	// ovn-controller coverage show metrics updater
	go coverageShowMetricsUpdater(exec, ovnController)
}
