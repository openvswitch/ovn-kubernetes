package ovndbmanager

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// retry counters for cluster statuses
var nbClusterStatusRetryCnt, sbClusterStatusRetryCnt int32

const maxClusterStatusRetry = 10

func RunDBChecker(kclient kube.Interface, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	klog.Info("Starting DB Checker to ensure cluster membership and DB consistency")
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ensureOvnDBState(util.OvnNbdbLocation, kclient, stopCh)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		ensureOvnDBState(util.OvnSbdbLocation, kclient, stopCh)
	}()
	<-stopCh
	klog.Info("Shutting down db checker")
	wg.Wait()
	klog.Info("Shut down db checker")
}

func ensureOvnDBState(db string, kclient kube.Interface, stopCh <-chan struct{}) {
	ticker := time.NewTicker(60 * time.Second)
	klog.Infof("Starting ensure routine for Raft db: %s", db)
	_, _, err := util.RunOVSDBTool("db-is-standalone", db)
	if err == nil {
		klog.Info("The db is running in standalone mode")
		return
	} else {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			klog.Infof("Exit code for the db-is-standalone: %v", ee.ExitCode())
			if ee.ExitCode() != 2 {
				klog.Fatalf("Can't determine if the db is clustered/stand-alone" +
					" restarting the checker")
				os.Exit(1)
			}
		}
	}

	for {
		select {
		case <-ticker.C:
			klog.V(5).Infof("Ensure routines for Raft db: %s kicked off by ticker", db)
			ensureLocalRaftServerID(db)
			ensureClusterRaftMembership(db, kclient)
		case <-stopCh:
			ticker.Stop()
			return
		}
	}
}

// ensureLocalRaftServerID is used to ensure there is no stale member in the Raft cluster with our address
func ensureLocalRaftServerID(db string) {
	var dbName string
	var appCtl func(args ...string) (string, string, error)
	clusterStatusRetryCnt := &nbClusterStatusRetryCnt
	if strings.Contains(db, "ovnnb") {
		dbName = "OVN_Northbound"
		appCtl = util.RunOVNNBAppCtl
	} else {
		dbName = "OVN_Southbound"
		appCtl = util.RunOVNSBAppCtl
		clusterStatusRetryCnt = &sbClusterStatusRetryCnt
	}

	out, stderr, err := util.RunOVSDBTool("db-sid", db)
	if err != nil {
		klog.Warningf("Unable to get db server ID for: %s, stderr: %v, err: %v", db, stderr, err)
		return
	}
	if len(out) < 4 {
		klog.Errorf("Invalid db id found: %s for db: %s", out, db)
		return
	}
	// server ID in raft membership is only first 4 char prefix
	serverID := out[:4]
	out, stderr, err = appCtl("cluster/status", dbName)
	if err != nil {
		klog.Warningf("Unable to get cluster status for: %s, stderr: %v, err: %v", db, stderr, err)
		if atomic.LoadInt32(clusterStatusRetryCnt) > maxClusterStatusRetry {
			//delete the db file and start master
			resetRaftDB(db)
			atomic.StoreInt32(clusterStatusRetryCnt, 0)
		} else {
			atomic.AddInt32(clusterStatusRetryCnt, 1)
			klog.Infof("Failed to get cluster status for: %s, number of retries: %d", db, *clusterStatusRetryCnt)
		}
		return
	}
	// on retrieving cluster/status successfully reset the retry counter.
	atomic.StoreInt32(clusterStatusRetryCnt, 0)

	r, _ := regexp.Compile(`Address: *((ssl|tcp):[?[a-z0-9.:]+]?)`)
	matches := r.FindStringSubmatch(out)
	if len(matches) < 2 {
		klog.Warningf("Unable to parse Address for db: %s, output: %s", db, out)
		return
	}
	addr := matches[1]
	// look for current servers in raft cluster with the same address
	r, _ = regexp.Compile("([a-z0-9]{4}) at " + addr)
	members := r.FindAllStringSubmatch(out, -1)
	for _, member := range members {
		if len(member) < 2 {
			klog.Warningf("Unable to find server id submatch in %s", member)
			return
		}
		if member[1] != serverID {
			// stale entry found for this node with same adddress, need to kick
			klog.Infof("Previous stale member found: %s...kicking", member[1])
			_, stderr, err = appCtl("cluster/kick", dbName, member[1])
			if err != nil {
				klog.Errorf("Error while kicking old Raft member: %s, for address: %s in db: %s,"+
					"stderr: %v, error: %v", member[1], addr, db, stderr, err)
			}
		}
	}
}

// ensureClusterRaftMembership ensures there are no unknown members in the current Raft cluster
func ensureClusterRaftMembership(db string, kclient kube.Interface) {
	var knownMembers, knownServers []string

	var dbName string
	var appCtl func(args ...string) (string, string, error)
	clusterStatusRetryCnt := &nbClusterStatusRetryCnt

	if strings.Contains(db, "ovnnb") {
		dbName = "OVN_Northbound"
		appCtl = util.RunOVNNBAppCtl
		knownMembers = strings.Split(config.OvnNorth.Address, ",")
	} else {
		dbName = "OVN_Southbound"
		appCtl = util.RunOVNSBAppCtl
		knownMembers = strings.Split(config.OvnSouth.Address, ",")
		clusterStatusRetryCnt = &sbClusterStatusRetryCnt
	}
	for _, knownMember := range knownMembers {
		server := strings.Split(knownMember, ":")
		if len(server) < 3 {
			klog.Warningf("Failed to parse known member: %s", knownMember)
			continue
		}
		knownServers = append(knownServers, server[1])
	}
	out, stderr, err := appCtl("cluster/status", dbName)
	if err != nil {
		klog.Warningf("Unable to get cluster status for: %s, stderr: %v, err: %v", db, stderr, err)
		if atomic.LoadInt32(clusterStatusRetryCnt) > maxClusterStatusRetry {
			//delete the db file and start master
			resetRaftDB(db)
			atomic.StoreInt32(clusterStatusRetryCnt, 0)
		} else {
			atomic.AddInt32(clusterStatusRetryCnt, 1)
			klog.Infof("Failed to get cluster status for: %s, number of retries: %d", db, *clusterStatusRetryCnt)
		}
		return
	}
	// on retrieving cluster/status successfully reset the retry counter.
	atomic.StoreInt32(clusterStatusRetryCnt, 0)

	r, _ := regexp.Compile(`([a-z0-9]{4}) at ((ssl|tcp):\[?[a-z0-9.:]+\]?)`)
	members := r.FindAllStringSubmatch(out, -1)
	kickedMembersCount := 0
	dbAppLabel := map[string]string{"ovn-db-pod": "true"}
	dbPods, err := kclient.GetPods(config.Kubernetes.OVNConfigNamespace,
		metav1.LabelSelector{
			MatchLabels: dbAppLabel,
		},
		"")
	if err != nil {
		klog.Warningf("Unable to get db pod list from kubeclient: %v", err)
		return
	}
	for _, member := range members {
		if len(member) < 3 {
			klog.Warningf("Unable to find parse member: %s", member)
			return
		}
		matchedServer := strings.Split(member[2], ":")
		if len(matchedServer) < 3 {
			klog.Warningf("Unable to parse address portion of the member entry: %s", matchedServer)
			return
		}
		memberFound := false
		for _, knownServer := range knownServers {
			if knownServer == matchedServer[1] {
				memberFound = true
				break
			}
		}
		if !memberFound {
			for _, dbPod := range dbPods.Items {
				for _, ip := range dbPod.Status.PodIPs {
					if ip.IP == matchedServer[1] {
						memberFound = true
						break
					}
				}
			}
		}
		if !memberFound && (len(members)-kickedMembersCount) > 3 {
			// unknown member and we have enough members its safe to kick the unknown address
			klog.Infof("Unknown Raft member found: %s, %s...kicking", member[1], member[2])
			_, stderr, err = appCtl("cluster/kick", dbName, member[1])
			if err != nil {
				// warn only: we might fail to kick since other nodes will also be trying to kick the member
				klog.Warningf("Error while kicking old Raft member: %s, for address: %s in db: %s,"+
					"stderr: %v, err: %v", member[1], member[2], db, stderr, err)
				continue
			}
			kickedMembersCount = kickedMembersCount + 1
		}
	}
}

func resetRaftDB(db string) {
	// backup the db by renaming it and then stop the nb/sb ovsdb process.
	dbFile := filepath.Base(db)
	backupFile := strings.TrimSuffix(dbFile, filepath.Ext(dbFile)) +
		time.Now().UTC().Format("2006-01-02_150405") + "db_bak"
	backupDB := filepath.Join(filepath.Dir(db), backupFile)
	err := os.Rename(db, backupDB)
	if err != nil {
		klog.Warningf("Failed to back up the db to backupFile: %s", backupFile)
	} else {
		klog.Infof("Backed up the db to backupFile: %s", backupFile)
		var dbName string
		var appCtl func(args ...string) (string, string, error)
		if strings.Contains(db, "ovnnb") {
			dbName = "OVN_Northbound"
			appCtl = util.RunOVNNBAppCtl
		} else {
			dbName = "OVN_Southbound"
			appCtl = util.RunOVNSBAppCtl
		}
		_, stderr, err := appCtl("exit")
		if err != nil {
			klog.Warningf("Unable to restart the ovn db: %s ,"+
				"stderr: %v, err: %v", dbName, stderr, err)
		}
		klog.Infof("Stopped %s db after backing up the db: %s", dbName, backupFile)
	}
}

// EnableDBMemTrimming enables memory trimming on DB compaction for NBDB and SBDB. Every 10 minutes the DBs are compacted
// and excess memory on the heap is freed. By enabling memory trimming, the freed memory will be returned back to the OS
func EnableDBMemTrimming() error {
	out, stderr, err := util.RunOVNNBAppCtl("list-commands")
	if err != nil {
		return fmt.Errorf("unable to list supported commands for ovn-appctl, stderr: %s, error: %v", stderr, err)
	}
	if !strings.Contains(out, "memory-trim-on-compaction") {
		klog.Warning("memory-trim-on-compaction unsupported in this version of OVN. OVN DBs may experience high " +
			"memory growth")
		return nil
	}
	_, stderr, err = util.RunOVNNBAppCtl("ovsdb-server/memory-trim-on-compaction", "on")
	if err != nil {
		return fmt.Errorf("unable to turn on memory trimming for NB DB, stderr: %s, error: %v", stderr, err)
	}
	_, stderr, err = util.RunOVNSBAppCtl("ovsdb-server/memory-trim-on-compaction", "on")
	if err != nil {
		return fmt.Errorf("unable to turn on memory trimming for SB DB, stderr: %s, error: %v", stderr, err)
	}
	return nil
}
