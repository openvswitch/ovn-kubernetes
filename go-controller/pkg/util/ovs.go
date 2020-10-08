package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/afero"

	"k8s.io/klog"
	kexec "k8s.io/utils/exec"
)

const (
	ovsCommandTimeout  = 15
	ovsVsctlCommand    = "ovs-vsctl"
	ovsOfctlCommand    = "ovs-ofctl"
	ovsDpctlCommand    = "ovs-dpctl"
	ovsAppctlCommand   = "ovs-appctl"
	ovnNbctlCommand    = "ovn-nbctl"
	ovnSbctlCommand    = "ovn-sbctl"
	ovnAppctlCommand   = "ovn-appctl"
	ovsdbClientCommand = "ovsdb-client"
	ovsdbToolCommand   = "ovsdb-tool"
	arpingCommand      = "arping"
	ipCommand          = "ip"
)

const (
	nbdbCtlSock     = "ovnnb_db.ctl"
	sbdbCtlSock     = "ovnsb_db.ctl"
	OvnNbdbLocation = "/etc/ovn/ovnnb_db.db"
	OvnSbdbLocation = "/etc/ovn/ovnsb_db.db"

	ovsRunDir string = "/var/run/openvswitch/"
	ovnRunDir string = "/var/run/ovn/"
)

var ovnCmdRetryCount = 200
var AppFs = afero.NewOsFs()

// this metric is set only for the ovnkube in master mode since 99.9% of
// all the ovn-nbctl/ovn-sbctl calls occur on the master
var MetricOvnCliLatency *prometheus.HistogramVec

type ExecHelper interface {
	RunOVSOfctl(args ...string) (string, string, error)
	RunOVSOfctlWithStdin(stdin *bytes.Buffer, args ...string) (string, string, error)
	RunOVSDpctl(args ...string) (string, string, error)
	RunOVSVsctl(args ...string) (string, string, error)
	RunOVSAppctlWithTimeout(timeout int, args ...string) (string, string, error)
	RunOVSAppctl(args ...string) (string, string, error)
	RunOVNAppctlWithTimeout(timeout int, args ...string) (string, string, error)
	RunOVNNbctlUnix(args ...string) (string, string, error)
	RunOVNNbctlWithTimeout(timeout int, args ...string) (string, string, error)
	RunOVNNbctl(args ...string) (string, string, error)
	RunOVNSbctlUnix(args ...string) (string, string, error)
	RunOVNSbctlWithTimeout(timeout int, args ...string) (string, string, error)
	RunOVSDBClient(args ...string) (string, string, error)
	RunOVSDBTool(args ...string) (string, string, error)
	RunOVSDBClientOVNNB(command string, args ...string) (string, string, error)
	RunOVNSbctl(args ...string) (string, string, error)
	RunOVNNBAppCtl(args ...string) (string, string, error)
	RunOVNSBAppCtl(args ...string) (string, string, error)
	RunOVNNorthAppCtl(args ...string) (string, string, error)
	RunOVNControllerAppCtl(args ...string) (string, string, error)
	RunOvsVswitchdAppCtl(args ...string) (string, string, error)
	RunIP(args ...string) (string, string, error)
	RunArping(args ...string) (string, string, error)
	GetSkippedNbctlDaemonCount() uint64
}

// execHelper runs various OVN and OVS utilities
type execHelper struct {
	exec            kexec.Interface
	ofctlPath       string
	vsctlPath       string
	dpctlPath       string
	appctlPath      string
	ovnappctlPath   string
	nbctlPath       string
	sbctlPath       string
	ovsdbClientPath string
	ovsdbToolPath   string
	ipPath          string
	arpingPath      string

	skippedNbctlDaemonCounter uint64
}

// Ensure execHelper implements Execer
var _ ExecHelper = &execHelper{}

func NewExecHelper(baseExec kexec.Interface) (ExecHelper, error) {
	exec := &execHelper{exec: baseExec}
	if runtime.GOOS == "windows" {
		// Windows has no utilities called via exec
		return exec, nil
	}

	var err error
	exec.ofctlPath, err = baseExec.LookPath(ovsOfctlCommand)
	if err != nil {
		return nil, err
	}
	exec.vsctlPath, err = baseExec.LookPath(ovsVsctlCommand)
	if err != nil {
		return nil, err
	}
	exec.dpctlPath, err = baseExec.LookPath(ovsDpctlCommand)
	if err != nil {
		return nil, err
	}
	exec.appctlPath, err = baseExec.LookPath(ovsAppctlCommand)
	if err != nil {
		return nil, err
	}
	exec.ovnappctlPath, err = baseExec.LookPath(ovnAppctlCommand)
	if err != nil {
		return nil, err
	}
	exec.nbctlPath, err = baseExec.LookPath(ovnNbctlCommand)
	if err != nil {
		return nil, err
	}
	exec.sbctlPath, err = baseExec.LookPath(ovnSbctlCommand)
	if err != nil {
		return nil, err
	}
	exec.ovsdbClientPath, err = baseExec.LookPath(ovsdbClientCommand)
	if err != nil {
		return nil, err
	}
	exec.ovsdbToolPath, err = baseExec.LookPath(ovsdbToolCommand)
	if err != nil {
		return nil, err
	}
	exec.ipPath, err = baseExec.LookPath(ipCommand)
	if err != nil {
		return nil, err
	}
	exec.arpingPath, err = baseExec.LookPath(arpingCommand)
	if err != nil {
		return nil, err
	}

	return exec, nil
}

// SetSpecificExec validates executable paths for selected commands. It also saves the given
// exec interface to be used for running selected commands
func NewOVSVsctlExecHelper(baseExec kexec.Interface) (ExecHelper, error) {
	var err error
	exec := &execHelper{exec: baseExec}
	exec.vsctlPath, err = baseExec.LookPath(ovsVsctlCommand)
	if err != nil {
		return nil, err
	}
	return exec, nil
}

type ExecRunner interface {
	RunCmd(cmd kexec.Cmd, cmdPath string, envVars []string, args ...string) (*bytes.Buffer, *bytes.Buffer, error)
}

// defaultExecRunner implements the methods defined in the ExecRunner interface
type defaultExecRunner struct {
}

// RunCmd invokes the methods of the Cmd interfaces defined in k8s.io/utils/exec to execute commands
// Note: the cmdPath and args parameter are used only for logging and is not processed
func (runsvc *defaultExecRunner) RunCmd(cmd kexec.Cmd, cmdPath string, envVars []string, args ...string) (*bytes.Buffer, *bytes.Buffer, error) {
	if cmd == nil {
		return &bytes.Buffer{}, &bytes.Buffer{}, fmt.Errorf("cmd object cannot be nil")
	}
	if len(envVars) != 0 {
		cmd.SetEnv(envVars)
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	cmd.SetStdout(stdout)
	cmd.SetStderr(stderr)

	counter := atomic.AddUint64(&runCounter, 1)
	logCmd := fmt.Sprintf("%s %s", cmdPath, strings.Join(args, " "))
	klog.V(5).Infof("exec(%d): %s", counter, logCmd)

	err := cmd.Run()
	klog.V(5).Infof("exec(%d): stdout: %q", counter, stdout)
	klog.V(5).Infof("exec(%d): stderr: %q", counter, stderr)
	if err != nil {
		klog.V(5).Infof("exec(%d): err: %v", counter, err)
	}
	return stdout, stderr, err
}

var runCmdExecRunner ExecRunner = &defaultExecRunner{}

var runCounter uint64

func (e *execHelper) runWithStdin(cmdPath string, stdin *bytes.Buffer, args ...string) (*bytes.Buffer, *bytes.Buffer, error) {
	return e.runInternal(cmdPath, nil, stdin, args...)
}

func (e *execHelper) run(cmdPath string, args ...string) (*bytes.Buffer, *bytes.Buffer, error) {
	return e.runInternal(cmdPath, nil, nil, args...)
}

func (e *execHelper) runWithEnvVars(cmdPath string, envVars []string, args ...string) (*bytes.Buffer, *bytes.Buffer, error) {
	return e.runInternal(cmdPath, envVars, nil, args...)
}

func (e *execHelper) runInternal(cmdPath string, envVars []string, stdin *bytes.Buffer, args ...string) (*bytes.Buffer, *bytes.Buffer, error) {
	cmd := e.exec.Command(cmdPath, args...)
	if stdin != nil {
		cmd.SetStdin(stdin)
	}
	return runCmdExecRunner.RunCmd(cmd, cmdPath, envVars, args...)
}

// RunOVSOfctl runs a command via ovs-ofctl.
func (e *execHelper) RunOVSOfctl(args ...string) (string, string, error) {
	stdout, stderr, err := e.run(e.ofctlPath, args...)
	return strings.Trim(stdout.String(), "\" \n"), stderr.String(), err
}

// RunOVSOfctlWithStdin runs a command via ovs-ofctl and pipes stdin to it
func (e *execHelper) RunOVSOfctlWithStdin(stdin *bytes.Buffer, args ...string) (string, string, error) {
	stdout, stderr, err := e.runWithStdin(e.ofctlPath, stdin, args...)
	return strings.Trim(stdout.String(), "\" \n"), stderr.String(), err
}

// RunOVSDpctl runs a command via ovs-dpctl.
func (e *execHelper) RunOVSDpctl(args ...string) (string, string, error) {
	stdout, stderr, err := e.run(e.dpctlPath, args...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVSVsctl runs a command via ovs-vsctl.
func (e *execHelper) RunOVSVsctl(args ...string) (string, string, error) {
	cmdArgs := []string{fmt.Sprintf("--timeout=%d", ovsCommandTimeout)}
	cmdArgs = append(cmdArgs, args...)
	stdout, stderr, err := e.run(e.vsctlPath, cmdArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVSAppctlWithTimeout runs a command via ovs-appctl.
func (e *execHelper) RunOVSAppctlWithTimeout(timeout int, args ...string) (string, string, error) {
	cmdArgs := []string{fmt.Sprintf("--timeout=%d", timeout)}
	cmdArgs = append(cmdArgs, args...)
	stdout, stderr, err := e.run(e.appctlPath, cmdArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVSAppctl runs a command via ovs-appctl.
func (e *execHelper) RunOVSAppctl(args ...string) (string, string, error) {
	return e.RunOVSAppctlWithTimeout(ovsCommandTimeout, args...)
}

// RunOVNAppctlWithTimeout runs a command via ovn-appctl. If ovn-appctl is not present, then it
// falls back to using ovs-appctl.
func (e *execHelper) RunOVNAppctlWithTimeout(timeout int, args ...string) (string, string, error) {
	cmdArgs := []string{fmt.Sprintf("--timeout=%d", timeout)}
	cmdArgs = append(cmdArgs, args...)
	stdout, stderr, err := e.run(e.ovnappctlPath, cmdArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// Run the ovn-ctl command and retry if "Connection refused"
// poll waitng for service to become available
func (e *execHelper) runOVNretry(cmdPath string, envVars []string, args ...string) (*bytes.Buffer, *bytes.Buffer, error) {
	retriesLeft := ovnCmdRetryCount
	for {
		stdout, stderr, err := e.runWithEnvVars(cmdPath, envVars, args...)
		if err == nil {
			return stdout, stderr, err
		}

		// Connection refused
		// Master may not be up so keep trying
		if strings.Contains(stderr.String(), "Connection refused") {
			if retriesLeft == 0 {
				return stdout, stderr, err
			}
			retriesLeft--
			time.Sleep(2 * time.Second)
		} else {
			// Some other problem for caller to handle
			return stdout, stderr, fmt.Errorf("OVN command '%s %s' failed: %s", cmdPath, strings.Join(args, " "), err)
		}
	}
}

func (e *execHelper) GetSkippedNbctlDaemonCount() uint64 {
	return atomic.LoadUint64(&e.skippedNbctlDaemonCounter)
}

// getNbctlSocketPath returns the OVN_NB_DAEMON environment variable to add to
// the ovn-nbctl child process environment, or an error if the nbctl daemon
// control socket cannot be found
func getNbctlSocketPath() (string, error) {
	// Try already-set OVN_NB_DAEMON environment variable
	if nbctlSocketPath := os.Getenv("OVN_NB_DAEMON"); nbctlSocketPath != "" {
		if _, err := AppFs.Stat(nbctlSocketPath); err != nil {
			return "", fmt.Errorf("OVN_NB_DAEMON ovn-nbctl daemon control socket %s missing: %v",
				nbctlSocketPath, err)
		}
		return "OVN_NB_DAEMON=" + nbctlSocketPath, nil
	}

	// OVN 2.13 (by mistake?) didn't switch the default nbctl control socket
	// path from /var/run/openvswitch -> /var/run/ovn. Try both
	dirs := []string{ovnRunDir, ovsRunDir}
	for _, runDir := range dirs {
		// Try autodetecting the socket path based on the nbctl daemon pid
		pidfile := filepath.Join(runDir, "ovn-nbctl.pid")
		if pid, err := afero.ReadFile(AppFs, pidfile); err == nil {
			fname := fmt.Sprintf("ovn-nbctl.%s.ctl", strings.TrimSpace(string(pid)))
			nbctlSocketPath := filepath.Join(runDir, fname)
			if _, err := AppFs.Stat(nbctlSocketPath); err == nil {
				return "OVN_NB_DAEMON=" + nbctlSocketPath, nil
			}
		}
	}

	return "", fmt.Errorf("failed to find ovn-nbctl daemon pidfile/socket in %s", strings.Join(dirs, ","))
}

func (e *execHelper) getNbctlArgsAndEnv(timeout int, args ...string) ([]string, []string) {
	var cmdArgs []string

	if config.NbctlDaemonMode {
		// when ovn-nbctl is running in a "daemon mode", the user first starts
		// ovn-nbctl running in the background and afterward uses the daemon to execute
		// operations. The client needs to use the control socket and set the path to the
		// control socket in environment variable OVN_NB_DAEMON
		envVar, err := getNbctlSocketPath()
		if err == nil {
			envVars := []string{envVar}
			cmdArgs = append(cmdArgs, fmt.Sprintf("--timeout=%d", timeout))
			cmdArgs = append(cmdArgs, args...)
			return cmdArgs, envVars
		}
		klog.Warningf(err.Error() + "; resorting to non-daemon mode")
		atomic.AddUint64(&e.skippedNbctlDaemonCounter, 1)
	}

	if config.OvnNorth.Scheme == config.OvnDBSchemeSSL {
		cmdArgs = append(cmdArgs,
			fmt.Sprintf("--private-key=%s", config.OvnNorth.PrivKey),
			fmt.Sprintf("--certificate=%s", config.OvnNorth.Cert),
			fmt.Sprintf("--bootstrap-ca-cert=%s", config.OvnNorth.CACert),
			fmt.Sprintf("--db=%s", config.OvnNorth.GetURL()))
	} else if config.OvnNorth.Scheme == config.OvnDBSchemeTCP {
		cmdArgs = append(cmdArgs, fmt.Sprintf("--db=%s", config.OvnNorth.GetURL()))
	}
	cmdArgs = append(cmdArgs, fmt.Sprintf("--timeout=%d", timeout))
	cmdArgs = append(cmdArgs, args...)
	return cmdArgs, []string{}
}

func getNbOVSDBArgs(command string, args ...string) []string {
	var cmdArgs []string
	if config.OvnNorth.Scheme == config.OvnDBSchemeSSL {
		cmdArgs = append(cmdArgs,
			fmt.Sprintf("--private-key=%s", config.OvnNorth.PrivKey),
			fmt.Sprintf("--certificate=%s", config.OvnNorth.Cert),
			fmt.Sprintf("--bootstrap-ca-cert=%s", config.OvnNorth.CACert))
	}
	cmdArgs = append(cmdArgs, command)
	cmdArgs = append(cmdArgs, config.OvnNorth.GetURL())
	cmdArgs = append(cmdArgs, args...)
	return cmdArgs
}

// RunOVNNbctlUnix runs command via ovn-nbctl, with ovn-nbctl using the unix
// domain sockets to connect to the ovsdb-server backing the OVN NB database.
func (e *execHelper) RunOVNNbctlUnix(args ...string) (string, string, error) {
	cmdArgs, envVars := e.getNbctlArgsAndEnv(ovsCommandTimeout, args...)
	stdout, stderr, err := e.runOVNretry(e.nbctlPath, envVars, cmdArgs...)
	return strings.Trim(strings.TrimFunc(stdout.String(), unicode.IsSpace), "\""),
		stderr.String(), err
}

// RunOVNNbctlWithTimeout runs command via ovn-nbctl with a specific timeout
func (e *execHelper) RunOVNNbctlWithTimeout(timeout int, args ...string) (string, string, error) {
	cmdArgs, envVars := e.getNbctlArgsAndEnv(timeout, args...)
	start := time.Now()
	stdout, stderr, err := e.runOVNretry(e.nbctlPath, envVars, cmdArgs...)
	if MetricOvnCliLatency != nil {
		MetricOvnCliLatency.WithLabelValues("ovn-nbctl").Observe(time.Since(start).Seconds())
	}
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVNNbctl runs a command via ovn-nbctl.
func (e *execHelper) RunOVNNbctl(args ...string) (string, string, error) {
	return e.RunOVNNbctlWithTimeout(ovsCommandTimeout, args...)
}

// RunOVNSbctlUnix runs command via ovn-sbctl, with ovn-sbctl using the unix
// domain sockets to connect to the ovsdb-server backing the OVN NB database.
func (e *execHelper) RunOVNSbctlUnix(args ...string) (string, string, error) {
	cmdArgs := []string{fmt.Sprintf("--timeout=%d", ovsCommandTimeout)}
	cmdArgs = append(cmdArgs, args...)
	stdout, stderr, err := e.runOVNretry(e.sbctlPath, nil, cmdArgs...)
	return strings.Trim(strings.TrimFunc(stdout.String(), unicode.IsSpace), "\""),
		stderr.String(), err
}

// RunOVNSbctlWithTimeout runs command via ovn-sbctl with a specific timeout
func (e *execHelper) RunOVNSbctlWithTimeout(timeout int, args ...string) (string, string, error) {
	var cmdArgs []string
	if config.OvnSouth.Scheme == config.OvnDBSchemeSSL {
		cmdArgs = []string{
			fmt.Sprintf("--private-key=%s", config.OvnSouth.PrivKey),
			fmt.Sprintf("--certificate=%s", config.OvnSouth.Cert),
			fmt.Sprintf("--bootstrap-ca-cert=%s", config.OvnSouth.CACert),
			fmt.Sprintf("--db=%s", config.OvnSouth.GetURL()),
		}
	} else if config.OvnSouth.Scheme == config.OvnDBSchemeTCP {
		cmdArgs = []string{
			fmt.Sprintf("--db=%s", config.OvnSouth.GetURL()),
		}
	}

	cmdArgs = append(cmdArgs, fmt.Sprintf("--timeout=%d", timeout))
	cmdArgs = append(cmdArgs, args...)
	start := time.Now()
	stdout, stderr, err := e.runOVNretry(e.sbctlPath, nil, cmdArgs...)
	if MetricOvnCliLatency != nil {
		MetricOvnCliLatency.WithLabelValues("ovn-sbctl").Observe(time.Since(start).Seconds())
	}
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVSDBClient runs an 'ovsdb-client [OPTIONS] COMMAND [ARG...] command'.
func (e *execHelper) RunOVSDBClient(args ...string) (string, string, error) {
	stdout, stderr, err := e.runOVNretry(e.ovsdbClientPath, nil, args...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVSDBTool runs an 'ovsdb-tool [OPTIONS] COMMAND [ARG...] command'.
func (e *execHelper) RunOVSDBTool(args ...string) (string, string, error) {
	stdout, stderr, err := e.run(e.ovsdbToolPath, args...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// runOVSDBClientOVNNB runs an 'ovsdb-client [OPTIONS] COMMAND [SERVER] [ARG...] command' against OVN NB database.
func (e *execHelper) RunOVSDBClientOVNNB(command string, args ...string) (string, string, error) {
	cmdArgs := getNbOVSDBArgs(command, args...)
	stdout, stderr, err := e.runOVNretry(e.ovsdbClientPath, nil, cmdArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVNSbctl runs a command via ovn-sbctl.
func (e *execHelper) RunOVNSbctl(args ...string) (string, string, error) {
	return e.RunOVNSbctlWithTimeout(ovsCommandTimeout, args...)
}

// RunOVNNBAppCtl runs an 'ovs-appctl -t nbdbCtlSockPath command'.
func (e *execHelper) RunOVNNBAppCtl(args ...string) (string, string, error) {
	var cmdArgs []string
	cmdArgs = []string{
		"-t",
		ovnRunDir + nbdbCtlSock,
	}
	cmdArgs = append(cmdArgs, args...)
	stdout, stderr, err := e.runOVNretry(e.ovnappctlPath, nil, cmdArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVNSBAppCtl runs an 'ovs-appctl -t sbdbCtlSockPath command'.
func (e *execHelper) RunOVNSBAppCtl(args ...string) (string, string, error) {
	var cmdArgs []string
	cmdArgs = []string{
		"-t",
		ovnRunDir + sbdbCtlSock,
	}
	cmdArgs = append(cmdArgs, args...)
	stdout, stderr, err := e.runOVNretry(e.ovnappctlPath, nil, cmdArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVNNorthAppCtl runs an 'ovs-appctl -t ovn-northd command'.
// TODO: Currently no module is invoking this function, will need to consider adding an unit test when actively used
func (e *execHelper) RunOVNNorthAppCtl(args ...string) (string, string, error) {
	var cmdArgs []string

	pid, err := afero.ReadFile(AppFs, ovnRunDir+"ovn-northd.pid")
	if err != nil {
		return "", "", fmt.Errorf("failed to run the command since failed to get ovn-northd's pid: %v", err)
	}

	cmdArgs = []string{
		"-t",
		ovnRunDir + fmt.Sprintf("ovn-northd.%s.ctl", strings.TrimSpace(string(pid))),
	}
	cmdArgs = append(cmdArgs, args...)
	stdout, stderr, err := e.runOVNretry(e.ovnappctlPath, nil, cmdArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVNControllerAppCtl runs an 'ovn-appctl -t ovn-controller.pid.ctl command'.
func (e *execHelper) RunOVNControllerAppCtl(args ...string) (string, string, error) {
	var cmdArgs []string
	pid, err := afero.ReadFile(AppFs, ovnRunDir+"ovn-controller.pid")
	if err != nil {
		return "", "", fmt.Errorf("failed to get ovn-controller pid : %v", err)
	}
	cmdArgs = []string{
		"-t",
		ovnRunDir + fmt.Sprintf("ovn-controller.%s.ctl", strings.TrimSpace(string(pid))),
	}
	cmdArgs = append(cmdArgs, args...)
	stdout, stderr, err := e.runOVNretry(e.ovnappctlPath, nil, cmdArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOvsVswitchdAppCtl runs an 'ovs-appctl -t /var/run/openvsiwthc/ovs-vswitchd.pid.ctl command'
func (e *execHelper) RunOvsVswitchdAppCtl(args ...string) (string, string, error) {
	var cmdArgs []string
	pid, err := afero.ReadFile(AppFs, ovsRunDir+"ovs-vswitchd.pid")
	if err != nil {
		return "", "", fmt.Errorf("failed to get ovs-vswitch pid : %v", err)
	}
	cmdArgs = []string{
		"-t",
		ovsRunDir + fmt.Sprintf("ovs-vswitchd.%s.ctl", strings.TrimSpace(string(pid))),
	}
	cmdArgs = append(cmdArgs, args...)
	stdout, stderr, err := e.runOVNretry(e.appctlPath, nil, cmdArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunIP runs a command via the iproute2 "ip" utility
func (e *execHelper) RunIP(args ...string) (string, string, error) {
	stdout, stderr, err := e.run(e.ipPath, args...)
	return strings.TrimSpace(stdout.String()), stderr.String(), err
}

// RunArping runs a command via the "arping" utility
func (e *execHelper) RunArping(args ...string) (string, string, error) {
	stdout, stderr, err := e.run(e.arpingPath, args...)
	return strings.TrimSpace(stdout.String()), stderr.String(), err
}

// AddFloodActionOFFlow replaces flows in the bridge with a FLOOD action flow
func AddFloodActionOFFlow(exec ExecHelper, bridgeName string) (string, string, error) {
	stdin := &bytes.Buffer{}
	stdin.Write([]byte("table=0,priority=0,actions=FLOOD\n"))
	args := []string{"-O", "OpenFlow13", "replace-flows", bridgeName, "-"}
	return exec.RunOVSOfctlWithStdin(stdin, args...)
}

// ReplaceOFFlows replaces flows in the bridge with a slice of flows
func ReplaceOFFlows(exec ExecHelper, bridgeName string, flows []string) (string, string, error) {
	stdin := &bytes.Buffer{}
	stdin.Write([]byte(strings.Join(flows, "\n")))
	args := []string{"-O", "OpenFlow13", "--bundle", "replace-flows", bridgeName, "-"}
	return exec.RunOVSOfctlWithStdin(stdin, args...)
}

// ovsdb-server(5) says a clustered database is connected if the server
// is in contact with a majority of its cluster.
type OVNDBServerStatus struct {
	Connected bool
	Leader    bool
	Index     int
}

// Internal structure that holds the un-marshaled json output from the
// ovsdb-client query command. The Index can hold ["set": []] when it is
// not populated yet, so we need to use `interface{}` type. However, we
// don't want our callers to worry about all this and we want them to see the
// Index as an integer and hence we use an exported OVNDBServerStatus for that
type dbRow struct {
	Connected bool        `json:"connected"`
	Leader    bool        `json:"leader"`
	Index     interface{} `json:"index"`
}

type queryResult struct {
	Rows []dbRow `json:"rows"`
}

func GetOVNDBServerInfo(exec ExecHelper, timeout int, direction, database string) (*OVNDBServerStatus, error) {
	sockPath := fmt.Sprintf("unix:/var/run/openvswitch/ovn%s_db.sock", direction)
	transact := fmt.Sprintf(`["_Server", {"op":"select", "table":"Database", "where":[["name", "==", "%s"]], `+
		`"columns": ["connected", "leader", "index"]}]`, database)

	stdout, stderr, err := exec.RunOVSDBClient(fmt.Sprintf("--timeout=%d", timeout), "query", sockPath, transact)
	if err != nil {
		return nil, fmt.Errorf("failed to get %q ovsdb-server status: stderr(%s), err(%v)",
			direction, stderr, err)
	}

	var result []queryResult
	err = json.Unmarshal([]byte(stdout), &result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the json output(%s) from ovsdb-client command for database %q: %v",
			stdout, database, err)
	}
	if len(result) != 1 || len(result[0].Rows) != 1 {
		return nil, fmt.Errorf("parsed json output for %q ovsdb-server has incorrect status information",
			direction)
	}
	serverStatus := &OVNDBServerStatus{}
	serverStatus.Connected = result[0].Rows[0].Connected
	serverStatus.Leader = result[0].Rows[0].Leader
	if index, ok := result[0].Rows[0].Index.(float64); ok {
		serverStatus.Index = int(index)
	} else {
		serverStatus.Index = 0
	}

	return serverStatus, nil
}

// DetectSCTPSupport checks if OVN supports SCTP for load balancer
func DetectSCTPSupport(exec ExecHelper) (bool, error) {
	stdout, stderr, err := exec.RunOVSDBClientOVNNB("list-columns", "--data=bare", "--no-heading",
		"--format=json", "OVN_Northbound", "Load_Balancer")
	if err != nil {
		klog.Errorf("Failed to query OVN NB DB for SCTP support, "+
			"stdout: %q, stderr: %q, error: %v", stdout, stderr, err)
		return false, err
	}
	type OvsdbData struct {
		Data [][]interface{}
	}
	var lbData OvsdbData
	err = json.Unmarshal([]byte(stdout), &lbData)
	if err != nil {
		return false, err
	}
	for _, entry := range lbData.Data {
		if entry[0].(string) == "protocol" && strings.Contains(fmt.Sprintf("%v", entry[1]), "sctp") {
			return true, nil
		}
	}
	return false, nil
}
