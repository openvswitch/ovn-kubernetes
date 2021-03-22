package metrics

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

var metricOVNDBSessions = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "jsonrpc_server_sessions",
	Help:      "Active number of JSON RPC Server sessions to the DB"},
	[]string{
		"db_name",
	},
)

var metricOVNDBMonitor = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "ovsdb_monitors",
	Help:      "Number of OVSDB Monitors on the server"},
	[]string{
		"db_name",
	},
)

var metricDBSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "db_size",
	Help:      "The size of the database file associated with the OVN DB component."},
	[]string{
		"db_name",
	},
)

// ClusterStatus metrics
var metricDBClusterCID = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "cluster_id",
	Help:      "A metric with a constant '1' value labeled by database name and cluster uuid"},
	[]string{
		"db_name",
		"cluster_id",
	},
)

var metricDBClusterSID = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "cluster_server_id",
	Help: "A metric with a constant '1' value labeled by database name, cluster uuid " +
		"and server uuid"},
	[]string{
		"db_name",
		"cluster_id",
		"server_id",
	},
)

var metricDBClusterServerStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "cluster_server_status",
	Help: "A metric with a constant '1' value labeled by database name, cluster uuid, server uuid " +
		"server status"},
	[]string{
		"db_name",
		"cluster_id",
		"server_id",
		"server_status",
	},
)

var metricDBClusterServerRole = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "cluster_server_role",
	Help: "A metric with a constant '1' value labeled by database name, cluster uuid, server uuid " +
		"and server role"},
	[]string{
		"db_name",
		"cluster_id",
		"server_id",
		"server_role",
	},
)

var metricDBClusterTerm = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "cluster_term",
	Help: "A metric that returns the current election term value labeled by database name, cluster uuid, and " +
		"server uuid"},
	[]string{
		"db_name",
		"cluster_id",
		"server_id",
	},
)

var metricDBClusterServerVote = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "cluster_server_vote",
	Help: "A metric with a constant '1' value labeled by database name, cluster uuid, server uuid " +
		"and server vote"},
	[]string{
		"db_name",
		"cluster_id",
		"server_id",
		"server_vote",
	},
)

var metricDBClusterElectionTimer = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "cluster_election_timer",
	Help: "A metric that returns the current election timer value labeled by database name, cluster uuid, " +
		"and server uuid"},
	[]string{
		"db_name",
		"cluster_id",
		"server_id",
	},
)

var metricDBClusterLogIndexStart = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "cluster_log_index_start",
	Help: "A metric that returns the log entry index start value labeled by database name, cluster uuid, " +
		"and server uuid"},
	[]string{
		"db_name",
		"cluster_id",
		"server_id",
	},
)

var metricDBClusterLogIndexNext = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "cluster_log_index_next",
	Help: "A metric that returns the log entry index next value labeled by database name, cluster uuid, " +
		"and server uuid"},
	[]string{
		"db_name",
		"cluster_id",
		"server_id",
	},
)

var metricDBClusterLogNotCommitted = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "cluster_log_not_committed",
	Help: "A metric that returns the number of log entries not committed labeled by database name, cluster uuid, " +
		"and server uuid"},
	[]string{
		"db_name",
		"cluster_id",
		"server_id",
	},
)

var metricDBClusterLogNotApplied = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "cluster_log_not_applied",
	Help: "A metric that returns the number of log entries not applied labeled by database name, cluster uuid, " +
		"and server uuid"},
	[]string{
		"db_name",
		"cluster_id",
		"server_id",
	},
)

var metricDBClusterConnIn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "cluster_inbound_connections_total",
	Help: "A metric that returns the total number of inbound  connections to the server labeled by " +
		"database name, cluster uuid, and server uuid"},
	[]string{
		"db_name",
		"cluster_id",
		"server_id",
	},
)

var metricDBClusterConnOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "cluster_outbound_connections_total",
	Help: "A metric that returns the total number of outbound connections from the server labeled by " +
		"database name, cluster uuid, and server uuid"},
	[]string{
		"db_name",
		"cluster_id",
		"server_id",
	},
)

var metricDBClusterConnInErr = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "cluster_inbound_connections_error_total",
	Help: "A metric that returns the total number of failed inbound connections to the server labeled by " +
		" database name, cluster uuid, and server uuid"},
	[]string{
		"db_name",
		"cluster_id",
		"server_id",
	},
)

var metricDBClusterConnOutErr = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "cluster_outbound_connections_error_total",
	Help: "A metric that returns the total number of failed  outbound connections from the server labeled by " +
		"database name, cluster uuid, and server uuid"},
	[]string{
		"db_name",
		"cluster_id",
		"server_id",
	},
)

var metricDBE2eTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemDB,
	Name:      "e2e_timestamp",
	Help:      "The current e2e-timestamp value as observed in this instance of the database"},
	[]string{
		"db_name",
	},
)

func ovnDBSizeMetricsUpdater(direction, database string) {
	dbFile := fmt.Sprintf("/etc/ovn/ovn%s_db.db", direction)
	fileInfo, err := os.Stat(dbFile)
	if err != nil {
		klog.Errorf("Failed to get the DB size for database %s: %v", database, err)
		return
	}
	metricDBSize.WithLabelValues(database).Set(float64(fileInfo.Size()))
}

func ovnE2eTimeStampUpdater(direction, database string) {
	var stdout, stderr string
	var err error

	if direction == "sb" {
		stdout, stderr, err = util.RunOVNSbctlUnix("--if-exists", "--no-leader-only",
			"get", "SB_Global", ".", "options:e2e_timestamp")
	} else {
		stdout, stderr, err = util.RunOVNNbctlUnix("--if-exists", "--no-leader-only",
			"get", "NB_Global", ".", "options:e2e_timestamp")
	}
	if err != nil {
		klog.Errorf("Failed to scrape timestamp for database %s: "+
			"stderr (%s) (%v)", database, stderr, err)
		return
	}
	if stdout != "" {
		if value, err := strconv.ParseFloat(stdout, 64); err == nil {
			metricDBE2eTimestamp.WithLabelValues(database).Set(value)
		} else {
			klog.Errorf("Failed to parse %s e2e-timestamp value to float64 :(%v)",
				database, err)
		}
	} else {
		metricDBE2eTimestamp.WithLabelValues(database).Set(0)
	}
}

func ovnDBMemoryMetricsUpdater(direction, database string) {
	var stdout, stderr string
	var err error

	if direction == "sb" {
		stdout, stderr, err = util.RunOVNSBAppCtl("--timeout=5", "memory/show")
	} else {
		stdout, stderr, err = util.RunOVNNBAppCtl("--timeout=5", "memory/show")
	}
	if err != nil {
		klog.Errorf("Failed retrieving memory/show output for %q, stderr: %s, err: (%v)",
			strings.ToUpper(database), stderr, err)
		return
	}
	for _, kvPair := range strings.Fields(stdout) {
		if strings.HasPrefix(kvPair, "monitors:") {
			// kvPair will be of the form monitors:2
			fields := strings.Split(kvPair, ":")
			if value, err := strconv.ParseFloat(fields[1], 64); err == nil {
				metricOVNDBMonitor.WithLabelValues(database).Set(value)
			} else {
				klog.Errorf("Failed to parse the monitor's value %s to float64: err(%v)",
					fields[1], err)
			}
		} else if strings.HasPrefix(kvPair, "sessions:") {
			// kvPair will be of the form sessions:2
			fields := strings.Split(kvPair, ":")
			if value, err := strconv.ParseFloat(fields[1], 64); err == nil {
				metricOVNDBSessions.WithLabelValues(database).Set(value)
			} else {
				klog.Errorf("Failed to parse the sessions' value %s to float64: err(%v)",
					fields[1], err)
			}
		}
	}
}

var (
	ovnDbVersion      string
	nbDbSchemaVersion string
	sbDbSchemaVersion string
)

func getOvnDbVersionInfo() {
	stdout, _, err := util.RunOVSDBClient("-V")
	if err == nil && strings.HasPrefix(stdout, "ovsdb-client (Open vSwitch) ") {
		ovnDbVersion = strings.Fields(stdout)[3]
	}
	sockPath := "unix:/var/run/openvswitch/ovnnb_db.sock"
	stdout, _, err = util.RunOVSDBClient("get-schema-version", sockPath, "OVN_Northbound")
	if err == nil {
		nbDbSchemaVersion = strings.TrimSpace(stdout)
	}
	sockPath = "unix:/var/run/openvswitch/ovnsb_db.sock"
	stdout, _, err = util.RunOVSDBClient("get-schema-version", sockPath, "OVN_Southbound")
	if err == nil {
		sbDbSchemaVersion = strings.TrimSpace(stdout)
	}
}

func RegisterOvnDBMetrics(clientset kubernetes.Interface, k8sNodeName string, stopChan chan struct{}) {
	err := wait.PollImmediate(1*time.Second, 300*time.Second, func() (bool, error) {
		return checkPodRunsOnGivenNode(clientset, "ovn-db-pod=true", k8sNodeName, false)
	})
	if err != nil {
		if err == wait.ErrWaitTimeout {
			klog.Errorf("Timed out while checking if OVN DB Pod runs on this %q K8s Node: %v. "+
				"Not registering OVN DB Metrics on this Node.", k8sNodeName, err)
		} else {
			klog.Infof("Not registering OVN DB Metrics on this Node since OVN DBs are not running on this node.")
		}
		return
	}
	klog.Info("Found OVN DB Pod running on this node. Registering OVN DB Metrics")

	// get the ovsdb server version info
	getOvnDbVersionInfo()
	// register metrics that will be served off of /metrics path
	ovnRegistry.MustRegister(metricOVNDBMonitor)
	ovnRegistry.MustRegister(metricOVNDBSessions)
	ovnRegistry.MustRegister(metricDBSize)
	ovnRegistry.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Namespace: MetricOvnNamespace,
			Subsystem: MetricOvnSubsystemDB,
			Name:      "build_info",
			Help: "A metric with a constant '1' value labeled by ovsdb-server version and " +
				"NB and SB schema version",
			ConstLabels: prometheus.Labels{
				"version":           ovnDbVersion,
				"nb_schema_version": nbDbSchemaVersion,
				"sb_schema_version": sbDbSchemaVersion,
			},
		},
		func() float64 { return 1 },
	))
	// check if DB is clustered or not
	dbIsClustered := true
	_, _, err = util.RunOVSDBTool("db-is-standalone", "/etc/openvswitch/ovnsb_db.db")
	if err == nil {
		dbIsClustered = false
	}
	if dbIsClustered {
		ovnRegistry.MustRegister(metricDBClusterCID)
		ovnRegistry.MustRegister(metricDBClusterSID)
		ovnRegistry.MustRegister(metricDBClusterServerStatus)
		ovnRegistry.MustRegister(metricDBClusterTerm)
		ovnRegistry.MustRegister(metricDBClusterServerRole)
		ovnRegistry.MustRegister(metricDBClusterServerVote)
		ovnRegistry.MustRegister(metricDBClusterElectionTimer)
		ovnRegistry.MustRegister(metricDBClusterLogIndexStart)
		ovnRegistry.MustRegister(metricDBClusterLogIndexNext)
		ovnRegistry.MustRegister(metricDBClusterLogNotCommitted)
		ovnRegistry.MustRegister(metricDBClusterLogNotApplied)
		ovnRegistry.MustRegister(metricDBClusterConnIn)
		ovnRegistry.MustRegister(metricDBClusterConnOut)
		ovnRegistry.MustRegister(metricDBClusterConnInErr)
		ovnRegistry.MustRegister(metricDBClusterConnOutErr)
	}
	ovnRegistry.MustRegister(metricDBE2eTimestamp)

	// functions responsible for collecting the values and updating the prometheus metrics
	go func() {
		dirDbMap := map[string]string{
			"nb": "OVN_Northbound",
			"sb": "OVN_Southbound",
		}
		ticker := time.NewTicker(time.Duration(config.Default.MetricsScrapeInterval) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				for direction, database := range dirDbMap {
					if dbIsClustered {
						ovnDBClusterStatusMetricsUpdater(direction, database)
					}
					ovnDBMemoryMetricsUpdater(direction, database)
					ovnDBSizeMetricsUpdater(direction, database)
					ovnE2eTimeStampUpdater(direction, database)
				}
			case <-stopChan:
				return
			}
		}
	}()
}

type OVNDBClusterStatus struct {
	cid             string
	sid             string
	status          string
	role            string
	vote            string
	term            float64
	electionTimer   float64
	logIndexStart   float64
	logIndexNext    float64
	logNotCommitted float64
	logNotApplied   float64
	connIn          float64
	connOut         float64
	connInErr       float64
	connOutErr      float64
}

func getOVNDBClusterStatusInfo(timeout int, direction, database string) (clusterStatus *OVNDBClusterStatus,
	err error) {
	var stdout, stderr string

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("recovering from a panic while parsing the cluster/status output "+
				"for database %q: %v", database, r)
		}
	}()

	if direction == "sb" {
		stdout, stderr, err = util.RunOVNSBAppCtl(fmt.Sprintf("--timeout=%d", timeout),
			"cluster/status", database)
	} else {
		stdout, stderr, err = util.RunOVNNBAppCtl(fmt.Sprintf("--timeout=%d", timeout),
			"cluster/status", database)
	}
	if err != nil {
		klog.Errorf("Failed to retrieve cluster/status info for database %q, stderr: %s, err: (%v)",
			database, stderr, err)
		return nil, err
	}

	clusterStatus = &OVNDBClusterStatus{}
	for _, line := range strings.Split(stdout, "\n") {
		idx := strings.Index(line, ":")
		if idx == -1 {
			continue
		}
		switch line[:idx] {
		case "Cluster ID":
			// the value is of the format `45ef (45ef51b9-9401-46e7-810d-6db0fc344ea2)`
			clusterStatus.cid = strings.Trim(strings.Fields(line[idx+2:])[1], "()")
		case "Server ID":
			clusterStatus.sid = strings.Trim(strings.Fields(line[idx+2:])[1], "()")
		case "Status":
			clusterStatus.status = line[idx+2:]
		case "Role":
			clusterStatus.role = line[idx+2:]
		case "Term":
			if value, err := strconv.ParseFloat(line[idx+2:], 64); err == nil {
				clusterStatus.term = value
			}
		case "Vote":
			clusterStatus.vote = line[idx+2:]
		case "Election timer":
			if value, err := strconv.ParseFloat(line[idx+2:], 64); err == nil {
				clusterStatus.electionTimer = value
			}
		case "Log":
			// the value is of the format [2, 1108]
			values := strings.Split(strings.Trim(line[idx+2:], "[]"), ", ")
			if value, err := strconv.ParseFloat(values[0], 64); err == nil {
				clusterStatus.logIndexStart = value
			}
			if value, err := strconv.ParseFloat(values[1], 64); err == nil {
				clusterStatus.logIndexNext = value
			}
		case "Entries not yet committed":
			if value, err := strconv.ParseFloat(line[idx+2:], 64); err == nil {
				clusterStatus.logNotCommitted = value
			}
		case "Entries not yet applied":
			if value, err := strconv.ParseFloat(line[idx+2:], 64); err == nil {
				clusterStatus.logNotApplied = value
			}
		case "Connections":
			// the value is of the format `->0000 (->56d7) <-46ac <-56d7`
			var connIn, connOut, connInErr, connOutErr float64
			for _, conn := range strings.Fields(line[idx+2:]) {
				if strings.HasPrefix(conn, "->") {
					connOut++
				} else if strings.HasPrefix(conn, "<-") {
					connIn++
				} else if strings.HasPrefix(conn, "(->") {
					connOutErr++
				} else if strings.HasPrefix(conn, "(<-") {
					connInErr++
				}
			}
			clusterStatus.connIn = connIn
			clusterStatus.connOut = connOut
			clusterStatus.connInErr = connInErr
			clusterStatus.connOutErr = connOutErr
		}
	}

	return clusterStatus, nil
}

func ovnDBClusterStatusMetricsUpdater(direction, database string) {
	clusterStatus, err := getOVNDBClusterStatusInfo(5, direction, database)
	if err != nil {
		klog.Errorf(err.Error())
		return
	}
	metricDBClusterCID.WithLabelValues(database, clusterStatus.cid).Set(1)
	metricDBClusterSID.WithLabelValues(database, clusterStatus.cid, clusterStatus.sid).Set(1)
	metricDBClusterServerStatus.WithLabelValues(database, clusterStatus.cid, clusterStatus.sid,
		clusterStatus.status).Set(1)
	metricDBClusterTerm.WithLabelValues(database, clusterStatus.cid, clusterStatus.sid).Set(clusterStatus.term)
	metricDBClusterServerRole.WithLabelValues(database, clusterStatus.cid, clusterStatus.sid,
		clusterStatus.role).Set(1)
	metricDBClusterServerVote.WithLabelValues(database, clusterStatus.cid, clusterStatus.sid,
		clusterStatus.vote).Set(1)
	metricDBClusterElectionTimer.WithLabelValues(database, clusterStatus.cid,
		clusterStatus.sid).Set(clusterStatus.electionTimer)
	metricDBClusterLogIndexStart.WithLabelValues(database, clusterStatus.cid,
		clusterStatus.sid).Set(clusterStatus.logIndexStart)
	metricDBClusterLogIndexNext.WithLabelValues(database, clusterStatus.cid,
		clusterStatus.sid).Set(clusterStatus.logIndexNext)
	metricDBClusterLogNotCommitted.WithLabelValues(database, clusterStatus.cid,
		clusterStatus.sid).Set(clusterStatus.logNotCommitted)
	metricDBClusterLogNotApplied.WithLabelValues(database, clusterStatus.cid,
		clusterStatus.sid).Set(clusterStatus.logNotApplied)
	metricDBClusterConnIn.WithLabelValues(database, clusterStatus.cid,
		clusterStatus.sid).Set(clusterStatus.connIn)
	metricDBClusterConnOut.WithLabelValues(database, clusterStatus.cid,
		clusterStatus.sid).Set(clusterStatus.connOut)
	metricDBClusterConnInErr.WithLabelValues(database, clusterStatus.cid,
		clusterStatus.sid).Set(clusterStatus.connInErr)
	metricDBClusterConnOutErr.WithLabelValues(database, clusterStatus.cid,
		clusterStatus.sid).Set(clusterStatus.connOutErr)
}
