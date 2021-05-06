package metrics

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

const (
	MetricOvnkubeNamespace       = "ovnkube"
	MetricOvnkubeSubsystemMaster = "master"
	MetricOvnkubeSubsystemNode   = "node"
	MetricOvnNamespace           = "ovn"
	MetricOvnSubsystemDB         = "db"
	MetricOvnSubsystemNorthd     = "northd"
	MetricOvnSubsystemController = "controller"
	MetricOvsNamespace           = "ovs"
	MetricOvsSubsystemVswitchd   = "vswitchd"

	ovnNorthd     = "ovn-northd"
	ovnController = "ovn-controller"
	ovsVswitchd   = "ovs-vswitchd"
)

type metricDetails struct {
	srcName       string
	aggregateFrom []string
	help          string
	metric        prometheus.Gauge
}

// OVN/OVS components, namely ovn-northd, ovn-controller, and ovs-vswitchd provide various
// metrics through the 'coverage/show' command. The following data structure holds all the
// metrics we are interested in that output for a given component. We generalize capturing
// these metrics across all OVN/OVS components.
var componentCoverageShowMetricsMap = map[string]map[string]*metricDetails{}

func parseMetricToFloat(componentName, metricName, value string) float64 {
	f64Value, err := strconv.ParseFloat(value, 64)
	if err != nil {
		klog.Errorf("Failed to parse value %s into float for metric %s_%s :(%v)",
			value, componentName, metricName, err)
		return 0
	}
	return f64Value
}

// registerCoverageShowMetrics registers coverage/show metricss for
// various components(ovn-northd, ovn-controller, and ovs-vswitchd) with prometheus
func registerCoverageShowMetrics(target string, metricNamespace string, metricSubsystem string) {
	coverageShowMetricsMap := componentCoverageShowMetricsMap[target]
	for metricName, metricInfo := range coverageShowMetricsMap {
		metricInfo.metric = prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Subsystem: metricSubsystem,
			Name:      metricName,
			Help:      metricInfo.help,
		})
		prometheus.MustRegister(metricInfo.metric)
	}
}

// getCoverageShowOutputMap obtains the coverage/show metric values for the specified component.
func getCoverageShowOutputMap(component string) (map[string]string, error) {
	var stdout, stderr string
	var err error

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("recovering from a panic while parsing the coverage/show output "+
				"for %s: %v", component, r)
		}
	}()

	if component == ovnController {
		stdout, stderr, err = util.RunOVNControllerAppCtl("coverage/show")
	} else if component == ovnNorthd {
		stdout, stderr, err = util.RunOVNNorthAppCtl("coverage/show")
	} else if component == ovsVswitchd {
		stdout, stderr, err = util.RunOvsVswitchdAppCtl("coverage/show")
	} else {
		return nil, fmt.Errorf("component is unknown, and it isn't %s, %s, or %s",
			ovnNorthd, ovnController, ovsVswitchd)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get coverage/show output for %s "+
			"stderr(%s): (%v)", component, stderr, err)
	}

	coverageShowMetricsMap := make(map[string]string)
	output := strings.Split(stdout, "\n")
	for _, kvPair := range output {
		if strings.Contains(kvPair, "total:") {
			fields := strings.Fields(kvPair)
			coverageShowMetricsMap[fields[0]] = fields[len(fields)-1]
		}
	}
	return coverageShowMetricsMap, nil
}

// coverageShowMetricsUpdater updates the metric
// by obtaining values from getCoverageShowOutputMap for specified component.
func coverageShowMetricsUpdater(component string) {
	for {
		time.Sleep(30 * time.Second)
		coverageShowOutputMap, err := getCoverageShowOutputMap(component)
		if err != nil {
			klog.Errorf("%s", err.Error())
			continue
		}
		coverageShowMetricsMap := componentCoverageShowMetricsMap[component]
		for metricName, metricInfo := range coverageShowMetricsMap {
			var metricValue float64
			if metricInfo.srcName != "" {
				metricName = metricInfo.srcName
			}
			if metricInfo.aggregateFrom != nil {
				for _, aggregateMetricName := range metricInfo.aggregateFrom {
					if value, ok := coverageShowOutputMap[aggregateMetricName]; ok {
						metricValue += parseMetricToFloat(component, aggregateMetricName, value)
					}
				}
			} else {
				if value, ok := coverageShowOutputMap[metricName]; ok {
					metricValue = parseMetricToFloat(component, metricName, value)
				}
			}
			metricInfo.metric.Set(metricValue)
		}
	}
}

// The `keepTrying` boolean when set to true will not return an error if we can't find pods with the given label.
// This is so that the caller can re-try again to see if the pods have appeared in the k8s cluster.
func checkPodRunsOnGivenNode(clientset kubernetes.Interface, label, k8sNodeName string,
	keepTrying bool) (bool, error) {
	pods, err := clientset.CoreV1().Pods(config.Kubernetes.OVNConfigNamespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: label,
	})
	if err != nil {
		klog.V(5).Infof("Failed to list Pods with label %q: %v. Retrying..", label, err)
		return false, nil
	}
	for _, pod := range pods.Items {
		if pod.Spec.NodeName == k8sNodeName {
			return true, nil
		}
	}
	if keepTrying {
		return false, nil
	}
	return false, fmt.Errorf("the Pod matching the label %q doesn't exist on this node %s", label, k8sNodeName)
}

// StartMetricsServer runs the prometheus listener so that OVN K8s metrics can be collected
func StartMetricsServer(bindAddress string, enablePprof bool) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	if enablePprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	go utilwait.Until(func() {
		err := http.ListenAndServe(bindAddress, mux)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("starting metrics server failed: %v", err))
		}
	}, 5*time.Second, utilwait.NeverStop)
}

var ovnRegistry = prometheus.NewRegistry()

// StartOVNMetricsServer runs the prometheus listener so that OVN metrics can be collected
func StartOVNMetricsServer(bindAddress string) {
	handler := promhttp.InstrumentMetricHandler(ovnRegistry,
		promhttp.HandlerFor(ovnRegistry, promhttp.HandlerOpts{}))
	mux := http.NewServeMux()
	mux.Handle("/metrics", handler)

	go utilwait.Until(func() {
		err := http.ListenAndServe(bindAddress, mux)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("starting metrics server failed: %v", err))
		}
	}, 5*time.Second, utilwait.NeverStop)
}

// RegisterOvnMetrics registers OVSDB and Northd metrics if k8sMasterName != "",
// otherwise registers ovn-controller metrics
func RegisterOvnMetrics(clientset kubernetes.Interface, k8sMasterName string) {
	if k8sMasterName != "" {
		klog.V(5).Infof("Registering OVN master metrics")
		go RegisterOvnDBMetrics(clientset, k8sMasterName)
		go RegisterOvnNorthdMetrics(clientset, k8sMasterName)
	} else {
		klog.V(5).Infof("Registering OVN node metrics")
		go RegisterOvnControllerMetrics()
	}
}
