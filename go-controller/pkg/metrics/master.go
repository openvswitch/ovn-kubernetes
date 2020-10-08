package metrics

import (
	"fmt"
	"runtime"
	"sync"
	"time"

	goovn "github.com/ebay/go-ovn"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/prometheus/client_golang/prometheus"

	kapi "k8s.io/api/core/v1"
	"k8s.io/klog"
)

// metricE2ETimestamp is a timestamp value we have persisted to nbdb. We will
// also export a metric with the same column in sbdb. We will also bump this
// every 30 seconds, so we can detect a hung northd.
var metricE2ETimestamp = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: MetricOvnkubeNamespace,
	Subsystem: MetricOvnkubeSubsystemMaster,
	Name:      "nb_e2e_timestamp",
	Help:      "The current e2e-timestamp value as written to the northbound database"})

// metricPodCreationLatency is the time between a pod being scheduled and the
// ovn controller setting the network annotations.
var metricPodCreationLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
	Namespace: MetricOvnkubeNamespace,
	Subsystem: MetricOvnkubeSubsystemMaster,
	Name:      "pod_creation_latency_seconds",
	Help:      "The latency between pod creation and setting the OVN annotations",
	Buckets:   prometheus.ExponentialBuckets(.1, 2, 15),
})

// metricPodCreationLatency is the time between a pod being scheduled and the
// ovn controller setting the network annotations.
var metricOvnCliLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Namespace: MetricOvnkubeNamespace,
	Subsystem: MetricOvnkubeSubsystemMaster,
	Name:      "ovn_cli_latency_seconds",
	Help:      "The latency of various OVN commands. Currently, ovn-nbctl and ovn-sbctl",
	Buckets:   prometheus.ExponentialBuckets(.1, 2, 15)},
	// labels
	[]string{"command"},
)

// MetricResourceUpdateCount is the number of times a particular resource's UpdateFunc has been called.
var MetricResourceUpdateCount = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: MetricOvnkubeNamespace,
	Subsystem: MetricOvnkubeSubsystemMaster,
	Name:      "resource_update_total",
	Help:      "A metric that captures the number of times a particular resource's UpdateFunc has been called"},
	[]string{
		"name",
	},
)

// MetricResourceUpdateLatency is the time taken to complete resource update by an handler.
// This measures the latency for all of the handlers for a given resource.
var MetricResourceUpdateLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Namespace: MetricOvnkubeNamespace,
	Subsystem: MetricOvnkubeSubsystemMaster,
	Name:      "resource_update_latency_seconds",
	Help:      "The latency of various update handlers for a given resource",
	Buckets:   prometheus.ExponentialBuckets(.1, 2, 15)},
	[]string{"name"},
)

var MetricMasterReadyDuration = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: MetricOvnkubeNamespace,
	Subsystem: MetricOvnkubeSubsystemMaster,
	Name:      "ready_duration_seconds",
	Help:      "The duration for the master to get to ready state",
})

// MetricMasterLeader identifies whether this instance of ovnkube-master is a leader or not
var MetricMasterLeader = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: MetricOvnkubeNamespace,
	Subsystem: MetricOvnkubeSubsystemMaster,
	Name:      "leader",
	Help:      "Identifies whether the instance of ovnkube-master is a leader(1) or not(0).",
})

var registerMasterMetricsOnce sync.Once
var startE2ETimeStampUpdaterOnce sync.Once

// RegisterMasterMetrics registers some ovnkube master metrics with the Prometheus
// registry
func RegisterMasterMetrics(exec util.ExecHelper, nbClient, sbClient goovn.Client) {
	registerMasterMetricsOnce.Do(func() {
		// ovnkube-master metrics
		// the updater for this metric is activated
		// after leader election
		prometheus.MustRegister(metricE2ETimestamp)
		prometheus.MustRegister(MetricMasterLeader)
		prometheus.MustRegister(metricPodCreationLatency)

		scrapeOvnTimestamp := func() float64 {
			options, err := sbClient.SBGlobalGetOptions()
			if err != nil {
				klog.Errorf("Failed to get global options for the SB_Global table")
				return 0
			}
			if val, ok := options["e2e_timestamp"]; ok {
				return parseMetricToFloat(MetricOvnkubeSubsystemMaster, "sb_e2e_timestamp", val)
			}
			return 0
		}
		prometheus.MustRegister(prometheus.NewCounterFunc(
			prometheus.CounterOpts{
				Namespace: MetricOvnkubeNamespace,
				Subsystem: MetricOvnkubeSubsystemMaster,
				Name:      "sb_e2e_timestamp",
				Help:      "The current e2e-timestamp value as observed in the southbound database",
			}, scrapeOvnTimestamp))
		prometheus.MustRegister(prometheus.NewCounterFunc(
			prometheus.CounterOpts{
				Namespace: MetricOvnkubeNamespace,
				Subsystem: MetricOvnkubeSubsystemMaster,
				Name:      "skipped_nbctl_daemon_total",
				Help:      "The number of times we skipped using ovn-nbctl daemon and directly interacted with OVN NB DB",
			}, func() float64 {
				return float64(exec.GetSkippedNbctlDaemonCount())
			}))
		prometheus.MustRegister(MetricMasterReadyDuration)
		prometheus.MustRegister(metricOvnCliLatency)
		// this is to not to create circular import between metrics and util package
		util.MetricOvnCliLatency = metricOvnCliLatency
		prometheus.MustRegister(MetricResourceUpdateCount)
		prometheus.MustRegister(MetricResourceUpdateLatency)
		prometheus.MustRegister(prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Namespace: MetricOvnkubeNamespace,
				Subsystem: MetricOvnkubeSubsystemMaster,
				Name:      "build_info",
				Help: "A metric with a constant '1' value labeled by version, revision, branch, " +
					"and go version from which ovnkube was built and when and who built it",
				ConstLabels: prometheus.Labels{
					"version":    "0.0",
					"revision":   config.Commit,
					"branch":     config.Branch,
					"build_user": config.BuildUser,
					"build_date": config.BuildDate,
					"goversion":  runtime.Version(),
				},
			},
			func() float64 { return 1 },
		))
	})
}

// StartE2ETimeStampMetricUpdater adds a goroutine that updates a "timestamp" value in the
// nbdb every 30 seconds. This is so we can determine freshness of the database
func StartE2ETimeStampMetricUpdater(stopChan <-chan struct{}, ovnNBClient goovn.Client) {
	startE2ETimeStampUpdaterOnce.Do(func() {
		go func() {
			tsUpdateTicker := time.NewTicker(30 * time.Second)
			for {
				select {
				case <-tsUpdateTicker.C:
					options, err := ovnNBClient.NBGlobalGetOptions()
					if err != nil {
						klog.Errorf("Can't get existing NB Global Options for updating timestamps")
						continue
					}
					t := time.Now().Unix()
					options["e2e_timestamp"] = fmt.Sprintf("%d", t)
					cmd, err := ovnNBClient.NBGlobalSetOptions(options)
					if err != nil {
						klog.Errorf("Failed to bump timestamp: %v", err)
					} else {
						err = cmd.Execute()
						if err != nil {
							klog.Errorf("Failed to set timestamp: %v", err)
						} else {
							metricE2ETimestamp.Set(float64(t))
						}
					}
				case <-stopChan:
					return
				}
			}
		}()
	})
}

// RecordPodCreated extracts the scheduled timestamp and records how long it took
// us to notice this and set up the pod's scheduling.
func RecordPodCreated(pod *kapi.Pod) {
	t := time.Now()

	// Find the scheduled timestamp
	for _, cond := range pod.Status.Conditions {
		if cond.Type != kapi.PodScheduled {
			continue
		}
		if cond.Status != kapi.ConditionTrue {
			return
		}
		creationLatency := t.Sub(cond.LastTransitionTime.Time).Seconds()
		metricPodCreationLatency.Observe(creationLatency)
		return
	}
}
