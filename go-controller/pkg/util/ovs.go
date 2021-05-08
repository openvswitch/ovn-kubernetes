package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/afero"

	"k8s.io/klog/v2"
	kexec "k8s.io/utils/exec"
)

const (
	// On Windows we need an increased timeout on OVS commands, because
	// adding internal ports on a non Hyper-V enabled host will call
	// external Powershell commandlets.
	// TODO: Decrease the timeout once port adding is improved on Windows
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
	powershellCommand  = "powershell"
	netshCommand       = "netsh"
	routeCommand       = "route"
	osRelease          = "/etc/os-release"
	rhel               = "RHEL"
	ubuntu             = "Ubuntu"
	windowsOS          = "windows"
)

const (
	nbdbCtlSock     = "ovnnb_db.ctl"
	sbdbCtlSock     = "ovnsb_db.ctl"
	OvnNbdbLocation = "/etc/ovn/ovnnb_db.db"
	OvnSbdbLocation = "/etc/ovn/ovnsb_db.db"
	FloodAction     = "FLOOD"
	NormalAction    = "NORMAL"
)

var (
	// These are variables (not constants) so that testcases can modify them
	ovsRunDir string = "/var/run/openvswitch/"
	ovnRunDir string = "/var/run/ovn/"

	savedOVSRunDir = ovsRunDir
	savedOVNRunDir = ovnRunDir
)

var ovnCmdRetryCount = 200
var AppFs = afero.NewOsFs()

// PrepareTestConfig restores default config values. Used by testcases to
// provide a pristine environment between tests.
func PrepareTestConfig() {
	ovsRunDir = savedOVSRunDir
	ovnRunDir = savedOVNRunDir
}

// this metric is set only for the ovnkube in master mode since 99.9% of
// all the ovn-nbctl/ovn-sbctl calls occur on the master
var MetricOvnCliLatency *prometheus.HistogramVec

func runningPlatform() (string, error) {
	if runtime.GOOS == windowsOS {
		return windowsOS, nil
	}
	fileContents, err := afero.ReadFile(AppFs, osRelease)
	if err != nil {
		return "", fmt.Errorf("failed to parse file %s (%v)", osRelease, err)
	}

	var platform string
	ss := strings.Split(string(fileContents), "\n")
	for _, pair := range ss {
		keyValue := strings.Split(pair, "=")
		if len(keyValue) == 2 {
			if keyValue[0] == "Name" || keyValue[0] == "NAME" {
				platform = keyValue[1]
				break
			}
		}
	}

	if platform == "" {
		return "", fmt.Errorf("failed to find the platform name")
	}

	if strings.Contains(platform, "Fedora") ||
		strings.Contains(platform, "Red Hat") || strings.Contains(platform, "CentOS") {
		return rhel, nil
	} else if strings.Contains(platform, "Debian") ||
		strings.Contains(platform, ubuntu) {
		return ubuntu, nil
	} else if strings.Contains(platform, "VMware") {
		return "Photon", nil
	}
	return "", fmt.Errorf("unknown platform")
}

// Exec runs various OVN and OVS utilities
type execHelper struct {
	exec            kexec.Interface
	ofctlPath       string
	vsctlPath       string
	dpctlPath       string
	appctlPath      string
	ovnappctlPath   string
	nbctlPath       string
	sbctlPath       string
	ovnctlPath      string
	ovsdbClientPath string
	ovsdbToolPath   string
	ovnRunDir       string
	ipPath          string
	arpingPath      string
	powershellPath  string
	netshPath       string
	routePath       string
}

var runner *execHelper

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

// SetExec validates executable paths and saves the given exec interface
// to be used for running various OVS and OVN utilites
func SetExec(exec kexec.Interface) error {
	err := SetExecWithoutOVS(exec)
	if err != nil {
		return err
	}

	runner.ofctlPath, err = exec.LookPath(ovsOfctlCommand)
	if err != nil {
		return err
	}
	runner.vsctlPath, err = exec.LookPath(ovsVsctlCommand)
	if err != nil {
		return err
	}
	runner.dpctlPath, err = exec.LookPath(ovsDpctlCommand)
	if err != nil {
		return err
	}
	runner.appctlPath, err = exec.LookPath(ovsAppctlCommand)
	if err != nil {
		return err
	}

	runner.ovnappctlPath, err = exec.LookPath(ovnAppctlCommand)
	if err != nil {
		// If ovn-appctl command is not available then fall back to
		// ovs-appctl. It also means OVN is using the rundir of
		// openvswitch.
		runner.ovnappctlPath = runner.appctlPath
		runner.ovnctlPath = "/usr/share/openvswitch/scripts/ovn-ctl"
		runner.ovnRunDir = ovsRunDir
	} else {
		// If ovn-appctl command is available, it means OVN
		// has its own separate rundir, logdir, sharedir.
		runner.ovnctlPath = "/usr/share/ovn/scripts/ovn-ctl"
		runner.ovnRunDir = ovnRunDir
	}

	runner.nbctlPath, err = exec.LookPath(ovnNbctlCommand)
	if err != nil {
		return err
	}
	runner.sbctlPath, err = exec.LookPath(ovnSbctlCommand)
	if err != nil {
		return err
	}
	runner.ovsdbClientPath, err = exec.LookPath(ovsdbClientCommand)
	if err != nil {
		return err
	}
	runner.ovsdbToolPath, err = exec.LookPath(ovsdbToolCommand)
	if err != nil {
		return err
	}

	return nil
}

// SetExecWithoutOVS validates executable paths excluding OVS/OVN binaries and
// saves the given exec interface to be used for running various utilites
func SetExecWithoutOVS(exec kexec.Interface) error {
	var err error

	runner = &execHelper{exec: exec}
	if runtime.GOOS == windowsOS {
		runner.powershellPath, err = exec.LookPath(powershellCommand)
		if err != nil {
			return err
		}
		runner.netshPath, err = exec.LookPath(netshCommand)
		if err != nil {
			return err
		}
		runner.routePath, err = exec.LookPath(routeCommand)
		if err != nil {
			return err
		}
	} else {
		runner.ipPath, err = exec.LookPath(ipCommand)
		if err != nil {
			return err
		}
		runner.arpingPath, err = exec.LookPath(arpingCommand)
		if err != nil {
			return err
		}
	}
	return nil
}

// SetSpecificExec validates executable paths for selected commands. It also saves the given
// exec interface to be used for running selected commands
func SetSpecificExec(exec kexec.Interface, commands ...string) error {
	var err error

	runner = &execHelper{exec: exec}
	for _, command := range commands {
		switch command {
		case ovsVsctlCommand:
			runner.vsctlPath, err = exec.LookPath(ovsVsctlCommand)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown command: %q", command)
		}
	}
	return nil
}

// GetExec returns the exec interface which can be used for running commands directly.
// Only use for passing an exec interface into pkg/config which cannot call this
// function directly because this module imports pkg/config already.
func GetExec() kexec.Interface {
	return runner.exec
}

// ResetRunner used by unit-tests to reset runner to its initial (un-initialized) value
func ResetRunner() {
	runner = nil
}

var runCounter uint64

func runCmd(cmd kexec.Cmd, cmdPath string, args ...string) (*bytes.Buffer, *bytes.Buffer, error) {
	return runCmdExecRunner.RunCmd(cmd, cmdPath, []string{}, args...)
}

func run(cmdPath string, args ...string) (*bytes.Buffer, *bytes.Buffer, error) {
	cmd := runner.exec.Command(cmdPath, args...)
	return runCmdExecRunner.RunCmd(cmd, cmdPath, []string{}, args...)
}

func runWithEnvVars(cmdPath string, envVars []string, args ...string) (*bytes.Buffer, *bytes.Buffer, error) {
	cmd := runner.exec.Command(cmdPath, args...)
	return runCmdExecRunner.RunCmd(cmd, cmdPath, envVars, args...)
}

// RunOVSOfctl runs a command via ovs-ofctl.
func RunOVSOfctl(args ...string) (string, string, error) {
	stdout, stderr, err := run(runner.ofctlPath, args...)
	return strings.Trim(stdout.String(), "\" \n"), stderr.String(), err
}

// RunOVSDpctl runs a command via ovs-dpctl.
func RunOVSDpctl(args ...string) (string, string, error) {
	stdout, stderr, err := run(runner.dpctlPath, args...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVSVsctl runs a command via ovs-vsctl.
func RunOVSVsctl(args ...string) (string, string, error) {
	cmdArgs := []string{fmt.Sprintf("--timeout=%d", ovsCommandTimeout)}
	cmdArgs = append(cmdArgs, args...)
	stdout, stderr, err := run(runner.vsctlPath, cmdArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVSAppctlWithTimeout runs a command via ovs-appctl.
func RunOVSAppctlWithTimeout(timeout int, args ...string) (string, string, error) {
	cmdArgs := []string{fmt.Sprintf("--timeout=%d", timeout)}
	cmdArgs = append(cmdArgs, args...)
	stdout, stderr, err := run(runner.appctlPath, cmdArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVSAppctl runs a command via ovs-appctl.
func RunOVSAppctl(args ...string) (string, string, error) {
	return RunOVSAppctlWithTimeout(ovsCommandTimeout, args...)
}

// RunOVNAppctlWithTimeout runs a command via ovn-appctl. If ovn-appctl is not present, then it
// falls back to using ovs-appctl.
func RunOVNAppctlWithTimeout(timeout int, args ...string) (string, string, error) {
	cmdArgs := []string{fmt.Sprintf("--timeout=%d", timeout)}
	cmdArgs = append(cmdArgs, args...)
	stdout, stderr, err := run(runner.ovnappctlPath, cmdArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// Run the ovn-ctl command and retry if "Connection refused"
// poll waitng for service to become available
func runOVNretry(cmdPath string, envVars []string, args ...string) (*bytes.Buffer, *bytes.Buffer, error) {

	retriesLeft := ovnCmdRetryCount
	for {
		stdout, stderr, err := runWithEnvVars(cmdPath, envVars, args...)
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

var SkippedNbctlDaemonCounter uint64

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

func getNbctlArgsAndEnv(timeout int, args ...string) ([]string, []string) {
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
		atomic.AddUint64(&SkippedNbctlDaemonCounter, 1)
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
func RunOVNNbctlUnix(args ...string) (string, string, error) {
	cmdArgs, envVars := getNbctlArgsAndEnv(ovsCommandTimeout, args...)
	stdout, stderr, err := runOVNretry(runner.nbctlPath, envVars, cmdArgs...)
	return strings.Trim(strings.TrimFunc(stdout.String(), unicode.IsSpace), "\""),
		stderr.String(), err
}

// RunOVNNbctlWithTimeout runs command via ovn-nbctl with a specific timeout
func RunOVNNbctlWithTimeout(timeout int, args ...string) (string, string, error) {
	cmdArgs, envVars := getNbctlArgsAndEnv(timeout, args...)
	start := time.Now()
	stdout, stderr, err := runOVNretry(runner.nbctlPath, envVars, cmdArgs...)
	if MetricOvnCliLatency != nil {
		MetricOvnCliLatency.WithLabelValues("ovn-nbctl").Observe(time.Since(start).Seconds())
	}
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVNNbctl runs a command via ovn-nbctl.
func RunOVNNbctl(args ...string) (string, string, error) {
	return RunOVNNbctlWithTimeout(ovsCommandTimeout, args...)
}

// RunOVNSbctlUnix runs command via ovn-sbctl, with ovn-sbctl using the unix
// domain sockets to connect to the ovsdb-server backing the OVN SB database.
func RunOVNSbctlUnix(args ...string) (string, string, error) {
	cmdArgs := []string{fmt.Sprintf("--timeout=%d", ovsCommandTimeout)}
	cmdArgs = append(cmdArgs, args...)
	stdout, stderr, err := runOVNretry(runner.sbctlPath, nil, cmdArgs...)
	return strings.Trim(strings.TrimFunc(stdout.String(), unicode.IsSpace), "\""),
		stderr.String(), err
}

// RunOVNSbctlWithTimeout runs command via ovn-sbctl with a specific timeout
func RunOVNSbctlWithTimeout(timeout int, args ...string) (string, string,
	error) {
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
	stdout, stderr, err := runOVNretry(runner.sbctlPath, nil, cmdArgs...)
	if MetricOvnCliLatency != nil {
		MetricOvnCliLatency.WithLabelValues("ovn-sbctl").Observe(time.Since(start).Seconds())
	}
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVSDBClient runs an 'ovsdb-client [OPTIONS] COMMAND [ARG...] command'.
func RunOVSDBClient(args ...string) (string, string, error) {
	stdout, stderr, err := runOVNretry(runner.ovsdbClientPath, nil, args...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVSDBTool runs an 'ovsdb-tool [OPTIONS] COMMAND [ARG...] command'.
func RunOVSDBTool(args ...string) (string, string, error) {
	stdout, stderr, err := run(runner.ovsdbToolPath, args...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVSDBClientOVN runs an 'ovsdb-client [OPTIONS] COMMAND [SERVER] [ARG...] command' against OVN NB database.
func RunOVSDBClientOVNNB(command string, args ...string) (string, string, error) {
	cmdArgs := getNbOVSDBArgs(command, args...)
	stdout, stderr, err := runOVNretry(runner.ovsdbClientPath, nil, cmdArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVNSbctl runs a command via ovn-sbctl.
func RunOVNSbctl(args ...string) (string, string, error) {
	return RunOVNSbctlWithTimeout(ovsCommandTimeout, args...)
}

// RunOVNCtl runs an ovn-ctl command.
func RunOVNCtl(args ...string) (string, string, error) {
	stdout, stderr, err := runOVNretry(runner.ovnctlPath, nil, args...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVNNBAppCtl runs an 'ovs-appctl -t nbdbCtlSockPath command'.
func RunOVNNBAppCtl(args ...string) (string, string, error) {
	var cmdArgs []string
	cmdArgs = []string{
		"-t",
		runner.ovnRunDir + nbdbCtlSock,
	}
	cmdArgs = append(cmdArgs, args...)
	stdout, stderr, err := runOVNretry(runner.ovnappctlPath, nil, cmdArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVNSBAppCtl runs an 'ovs-appctl -t sbdbCtlSockPath command'.
func RunOVNSBAppCtl(args ...string) (string, string, error) {
	var cmdArgs []string
	cmdArgs = []string{
		"-t",
		runner.ovnRunDir + sbdbCtlSock,
	}
	cmdArgs = append(cmdArgs, args...)
	stdout, stderr, err := runOVNretry(runner.ovnappctlPath, nil, cmdArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVNNorthAppCtl runs an 'ovs-appctl -t ovn-northd command'.
// TODO: Currently no module is invoking this function, will need to consider adding an unit test when actively used
func RunOVNNorthAppCtl(args ...string) (string, string, error) {
	var cmdArgs []string

	pid, err := afero.ReadFile(AppFs, runner.ovnRunDir+"ovn-northd.pid")
	if err != nil {
		return "", "", fmt.Errorf("failed to run the command since failed to get ovn-northd's pid: %v", err)
	}

	cmdArgs = []string{
		"-t",
		runner.ovnRunDir + fmt.Sprintf("ovn-northd.%s.ctl", strings.TrimSpace(string(pid))),
	}
	cmdArgs = append(cmdArgs, args...)
	stdout, stderr, err := runOVNretry(runner.ovnappctlPath, nil, cmdArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOVNControllerAppCtl runs an 'ovs-appctl -t ovn-controller.pid.ctl command'.
func RunOVNControllerAppCtl(args ...string) (string, string, error) {
	var cmdArgs []string
	pid, err := afero.ReadFile(AppFs, runner.ovnRunDir+"ovn-controller.pid")
	if err != nil {
		return "", "", fmt.Errorf("failed to get ovn-controller pid : %v", err)
	}
	cmdArgs = []string{
		"-t",
		runner.ovnRunDir + fmt.Sprintf("ovn-controller.%s.ctl", strings.TrimSpace(string(pid))),
	}
	cmdArgs = append(cmdArgs, args...)
	stdout, stderr, err := runOVNretry(runner.ovnappctlPath, nil, cmdArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunOvsVswitchdAppCtl runs an 'ovs-appctl -t /var/run/openvsiwthc/ovs-vswitchd.pid.ctl command'
func RunOvsVswitchdAppCtl(args ...string) (string, string, error) {
	var cmdArgs []string
	pid, err := afero.ReadFile(AppFs, savedOVSRunDir+"ovs-vswitchd.pid")
	if err != nil {
		return "", "", fmt.Errorf("failed to get ovs-vswitch pid : %v", err)
	}
	cmdArgs = []string{
		"-t",
		savedOVSRunDir + fmt.Sprintf("ovs-vswitchd.%s.ctl", strings.TrimSpace(string(pid))),
	}
	cmdArgs = append(cmdArgs, args...)
	stdout, stderr, err := runOVNretry(runner.appctlPath, nil, cmdArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}

// RunIP runs a command via the iproute2 "ip" utility
func RunIP(args ...string) (string, string, error) {
	stdout, stderr, err := run(runner.ipPath, args...)
	return strings.TrimSpace(stdout.String()), stderr.String(), err
}

// RunArping runs a command via the "arping" utility
func RunArping(args ...string) (string, string, error) {
	stdout, stderr, err := run(runner.arpingPath, args...)
	return strings.TrimSpace(stdout.String()), stderr.String(), err
}

// RunPowershell runs a command via the Windows powershell utility
func RunPowershell(args ...string) (string, string, error) {
	stdout, stderr, err := run(runner.powershellPath, args...)
	return strings.TrimSpace(stdout.String()), stderr.String(), err
}

// RunNetsh runs a command via the Windows netsh utility
func RunNetsh(args ...string) (string, string, error) {
	stdout, stderr, err := run(runner.netshPath, args...)
	return strings.TrimSpace(stdout.String()), stderr.String(), err
}

// RunRoute runs a command via the Windows route utility
func RunRoute(args ...string) (string, string, error) {
	stdout, stderr, err := run(runner.routePath, args...)
	return strings.TrimSpace(stdout.String()), stderr.String(), err
}

// AddOFFlowWithSpecificAction replaces flows in the bridge with a FLOOD action flow
func AddOFFlowWithSpecificAction(bridgeName, action string) (string, string, error) {
	args := []string{"-O", "OpenFlow13", "replace-flows", bridgeName, "-"}

	stdin := &bytes.Buffer{}
	stdin.Write([]byte(fmt.Sprintf("table=0,priority=0,actions=%s\n", action)))

	cmd := runner.exec.Command(runner.ofctlPath, args...)
	cmd.SetStdin(stdin)
	stdout, stderr, err := runCmd(cmd, runner.ofctlPath, args...)
	return strings.Trim(stdout.String(), "\" \n"), stderr.String(), err
}

// ReplaceOFFlows replaces flows in the bridge with a slice of flows
func ReplaceOFFlows(bridgeName string, flows []string) (string, string, error) {
	args := []string{"-O", "OpenFlow13", "--bundle", "replace-flows", bridgeName, "-"}
	stdin := &bytes.Buffer{}
	stdin.Write([]byte(strings.Join(flows, "\n")))

	cmd := runner.exec.Command(runner.ofctlPath, args...)
	cmd.SetStdin(stdin)
	stdout, stderr, err := runCmd(cmd, runner.ofctlPath, args...)
	return strings.Trim(stdout.String(), "\" \n"), stderr.String(), err
}

// GetOvnRunDir returns the OVN's rundir.
func GetOvnRunDir() string {
	return runner.ovnRunDir
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

func GetOVNDBServerInfo(timeout int, direction, database string) (*OVNDBServerStatus, error) {
	sockPath := fmt.Sprintf("unix:/var/run/openvswitch/ovn%s_db.sock", direction)
	transact := fmt.Sprintf(`["_Server", {"op":"select", "table":"Database", "where":[["name", "==", "%s"]], `+
		`"columns": ["connected", "leader", "index"]}]`, database)

	stdout, stderr, err := RunOVSDBClient(fmt.Sprintf("--timeout=%d", timeout), "query", sockPath, transact)
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
func DetectSCTPSupport() (bool, error) {
	stdout, stderr, err := RunOVSDBClientOVNNB("list-columns", "--data=bare", "--no-heading",
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

// DetermineOVNTopoVersionFromOVN determines what OVN Topology version is being used
// If "k8s-ovn-topo-version" key in external_ids column does not exist, it is prior to OVN topology versioning
// and therefore set version number to OvnCurrentTopologyVersion
func DetermineOVNTopoVersionFromOVN() (int, error) {
	ver := 0
	stdout, stderr, err := RunOVNNbctl("--data=bare", "--no-headings", "--columns=name", "find", "logical_router",
		fmt.Sprintf("name=%s", types.OVNClusterRouter))
	if err != nil {
		return ver, fmt.Errorf("failed in retrieving %s to determine the current version of OVN logical topology: "+
			"stderr: %q, error: %v", types.OVNClusterRouter, stderr, err)
	}
	if len(stdout) == 0 {
		// no OVNClusterRouter exists, DB is empty, nothing to upgrade
		return math.MaxInt32, nil
	}

	stdout, stderr, err = RunOVNNbctl("--if-exists", "get", "logical_router", types.OVNClusterRouter,
		"external_ids:k8s-ovn-topo-version")
	if err != nil {
		return 0, fmt.Errorf("failed to determine the current version of OVN logical topology: stderr: %q, error: %v",
			stderr, err)
	} else if len(stdout) == 0 {
		klog.Infof("No version string found. The OVN topology is before versioning is introduced. Upgrade needed")
	} else {
		v, err := strconv.Atoi(stdout)
		if err != nil {
			return 0, fmt.Errorf("invalid OVN topology version string for the cluster: %s", stdout)
		} else {
			ver = v
		}
	}
	return ver, nil
}

// NBTxn hold parts of an ovn-nbctl transaction request
type NBTxn struct {
	args    []string
	txnArgs []string
	env     []string
}

// NewNBTxn returns a new ovn-nbctl transaction request object
func NewNBTxn() *NBTxn {
	args, env := getNbctlArgsAndEnv(ovsCommandTimeout, []string{}...)
	return &NBTxn{
		args: args,
		env:  env,
	}
}

// Add adds a new request to the transaction
func (t *NBTxn) Add(args ...string) {
	if len(t.txnArgs) > 0 {
		t.txnArgs = append(t.txnArgs, "--")
	}
	t.txnArgs = append(t.txnArgs, args...)
}

// Commit commits all parts of the transaction and returns output and errors
func (t *NBTxn) Commit() (string, string, error) {
	if len(t.txnArgs) == 0 {
		return "", "", nil
	}
	allArgs := append(t.args, t.txnArgs...)
	stdout, stderr, err := runOVNretry(runner.nbctlPath, t.env, allArgs...)
	return strings.Trim(strings.TrimSpace(stdout.String()), "\""), stderr.String(), err
}
