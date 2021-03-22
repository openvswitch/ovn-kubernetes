package metrics

import (
	"strings"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

var (
	ovnNorthdVersion       string
	ovnNorthdOvsLibVersion string
)

func getOvnNorthdVersionInfo() {
	stdout, _, err := util.RunOVNNorthAppCtl("version")
	if err != nil {
		return
	}

	// the output looks like:
	// ovn-northd 20.06.0.86f64fc1
	// Open vSwitch Library 2.13.0.f945b5c5
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(line, "ovn-northd ") {
			ovnNorthdVersion = strings.Fields(line)[1]
		} else if strings.HasPrefix(line, "Open vSwitch Library ") {
			ovnNorthdOvsLibVersion = strings.Fields(line)[3]
		}
	}
}

var ovnNorthdCoverageShowMetricsMap = map[string]*metricDetails{
	"pstream_open": {
		help: "Specifies the number of time passive connections " +
			"were opened for the remote peer to connect.",
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
}

func RegisterOvnNorthdMetrics(clientset kubernetes.Interface, k8sNodeName string, stopChan chan struct{}) {
	err := wait.PollImmediate(1*time.Second, 300*time.Second, func() (bool, error) {
		return checkPodRunsOnGivenNode(clientset, "name=ovnkube-master", k8sNodeName, true)
	})
	if err != nil {
		if err == wait.ErrWaitTimeout {
			klog.Errorf("Timed out while checking if OVNKube Master Pod runs on this %q K8s Node: %v. "+
				"Not registering OVN North Metrics on this Node", k8sNodeName, err)
		} else {
			klog.Infof("Not registering OVN North Metrics on this Node since ovn-northd is not running on this node.")
		}
		return
	}
	klog.Info("Found OVNKube Master Pod running on this node. Registering OVN North Metrics")

	// ovn-northd metrics
	getOvnNorthdVersionInfo()
	ovnRegistry.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Namespace: MetricOvnNamespace,
			Subsystem: MetricOvnSubsystemNorthd,
			Name:      "build_info",
			Help: "A metric with a constant '1' value labeled by version and library " +
				"from which ovn binaries were built",
			ConstLabels: prometheus.Labels{
				"version":         ovnNorthdVersion,
				"ovs_lib_version": ovnNorthdOvsLibVersion,
			},
		},
		func() float64 { return 1 },
	))
	ovnRegistry.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Namespace: MetricOvnNamespace,
			Subsystem: MetricOvnSubsystemNorthd,
			Name:      "probe_interval",
			Help: "The maximum number of milliseconds of idle time on connection to the OVN SB " +
				"and NB DB before sending an inactivity probe message",
		}, func() float64 {
			stdout, stderr, err := util.RunOVNNbctlWithTimeout(5, "get", "NB_Global", ".",
				"options:northd_probe_interval")
			if err != nil {
				klog.Errorf("Failed to get northd_probe_interval value "+
					"stderr(%s) :(%v)", stderr, err)
				return 0
			}
			return parseMetricToFloat(MetricOvnSubsystemNorthd, "probe_interval", stdout)
		},
	))
	ovnRegistry.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Namespace: MetricOvnNamespace,
			Subsystem: MetricOvnSubsystemNorthd,
			Name:      "status",
			Help:      "Specifies whether this instance of ovn-northd is standby(0) or active(1) or paused(2).",
		}, func() float64 {
			stdout, stderr, err := util.RunOVNNorthAppCtl("status")
			if err != nil {
				klog.Errorf("Failed to get ovn-northd status "+
					"stderr(%s) :(%v)", stderr, err)
				return -1
			}
			northdStatusMap := map[string]float64{
				"standby": 0,
				"active":  1,
				"paused":  2,
			}
			if strings.HasPrefix(stdout, "Status:") {
				output := strings.TrimSpace(strings.Split(stdout, ":")[1])
				if value, ok := northdStatusMap[output]; ok {
					return value
				}
			}
			return -1
		},
	))

	// Register the ovn-northd coverage/show metrics with prometheus
	componentCoverageShowMetricsMap[ovnNorthd] = ovnNorthdCoverageShowMetricsMap
	registerCoverageShowMetrics(ovnNorthd, MetricOvnNamespace, MetricOvnSubsystemNorthd)
	go coverageShowMetricsUpdater(ovnNorthd, config.Default.MetricsScrapeInterval, stopChan)
}
