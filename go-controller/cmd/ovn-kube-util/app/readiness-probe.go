package app

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/urfave/cli/v2"
	kexec "k8s.io/utils/exec"
)

type readinessFunc func(util.ExecHelper, string) error

var callbacks = map[string]readinessFunc{
	"ovn-controller": ovnControllerReadiness,
	"ovnnb-db":       ovnNBDBReadiness,
	"ovnsb-db":       ovnSBDBReadiness,
	"ovn-northd":     ovnNorthdReadiness,
	"ovn-nbctld":     ovnNbCtldReadiness,
	"ovs-daemons":    ovsDaemonsReadiness,
	"ovnkube-node":   ovnNodeReadiness,
	"ovnnb-db-raft":  ovnNBDBRaftReadiness,
	"ovnsb-db-raft":  ovnSBDBRaftReadiness,
}

func ovnControllerReadiness(exec util.ExecHelper, target string) error {
	// Check if ovn-controller is connected to OVN SB
	output, _, err := exec.RunOVSAppctlWithTimeout(5, "-t", target, "connection-status")
	if err != nil {
		return fmt.Errorf("failed getting connection status of %q: (%v)", target, err)
	} else if output != "connected" {
		return fmt.Errorf("%q is not connected to OVN SB database, status: (%s)", target, output)
	}

	// Ensure that the ovs-vswitchd and ovsdb-server processes that ovn-controller
	// dependent on are running and you need to use ovs-appctl via the unix control path
	ovsdbPid, err := ioutil.ReadFile("/var/run/openvswitch/ovsdb-server.pid")
	if err != nil {
		return fmt.Errorf("failed to get pid for osvdb-server process: %v", err)
	}
	ctlFile := fmt.Sprintf("/var/run/openvswitch/ovsdb-server.%s.ctl", strings.Trim(string(ovsdbPid), " \n"))
	_, _, err = exec.RunOVSAppctlWithTimeout(5, "-t", ctlFile, "ovsdb-server/list-dbs")
	if err != nil {
		return fmt.Errorf("failed retrieving list of databases from ovsdb-server: %v", err)
	}

	ovsPid, err := ioutil.ReadFile("/var/run/openvswitch/ovs-vswitchd.pid")
	if err != nil {
		return fmt.Errorf("failed to get pid for ovs-vswitchd process: %v", err)
	}
	ctlFile = fmt.Sprintf("/var/run/openvswitch/ovs-vswitchd.%s.ctl", strings.Trim(string(ovsPid), " \n"))
	_, _, err = exec.RunOVSAppctlWithTimeout(5, "-t", ctlFile, "ofproto/list")
	if err != nil {
		return fmt.Errorf("failed to retrieve ofproto instances from ovs-vswitchd: %v", err)
	}
	return nil
}

func ovnNBDBReadiness(exec util.ExecHelper, target string) error {
	var err error
	var output string

	// 1. Check if the OVN NB process is running.
	// 2. Check if OVN NB process is listening on the port that it is supposed to
	_, _, err = exec.RunOVNNBAppCtl("--timeout=5", "ovsdb-server/list-dbs")
	if err != nil {
		return fmt.Errorf("failed connecting to %q: (%v)", target, err)
	}
	output, _, err = exec.RunOVNNbctlWithTimeout(5, "--data=bare", "--no-heading", "--columns=target",
		"find", "connection", "target!=_")
	if err != nil {
		return fmt.Errorf("%s is not ready: (%v)", target, err)
	}

	if strings.HasPrefix(output, "ptcp") || strings.HasPrefix(output, "pssl") {
		return nil
	}
	return fmt.Errorf("%s is not setup for passive connection: %v", target, output)
}

func ovnSBDBReadiness(exec util.ExecHelper, target string) error {
	var err error
	var output string

	// 1. Check if the OVN SB process is running.
	// 2. Check if OVN SB process is listening on the port that it is supposed to
	_, _, err = exec.RunOVNSBAppCtl("--timeout=5", "ovsdb-server/list-dbs")
	if err != nil {
		return fmt.Errorf("failed connecting to %q: (%v)", target, err)
	}
	output, _, err = exec.RunOVNSbctlWithTimeout(5, "--data=bare", "--no-heading", "--columns=target",
		"find", "connection", "target!=_")
	if err != nil {
		return fmt.Errorf("%s is not ready: (%v)", target, err)
	}

	if strings.HasPrefix(output, "ptcp") || strings.HasPrefix(output, "pssl") {
		return nil
	}
	return fmt.Errorf("%s is not setup for passive connection: %v", target, output)
}

func ovnNorthdReadiness(exec util.ExecHelper, target string) error {
	_, _, err := exec.RunOVNAppctlWithTimeout(5, "-t", target, "version")
	if err != nil {
		return fmt.Errorf("failed to get version from %s: (%v)", target, err)
	}
	return nil
}

func ovnNbCtldReadiness(exec util.ExecHelper, target string) error {
	_, _, err := exec.RunOVNAppctlWithTimeout(5, "-t", "ovn-nbctl", "version")
	if err != nil {
		return fmt.Errorf("failed to get version from %s: (%v)", target, err)
	}
	return nil
}

func ovsDaemonsReadiness(exec util.ExecHelper, target string) error {
	_, _, err := exec.RunOVSAppctlWithTimeout(5, "-t", "ovsdb-server", "ovsdb-server/list-dbs")
	if err != nil {
		return fmt.Errorf("failed retrieving list of databases from ovsdb-server: %v", err)
	}
	_, _, err = exec.RunOVSAppctlWithTimeout(5, "-t", "ovs-vswitchd", "ofproto/list")
	if err != nil {
		return fmt.Errorf("failed to retrieve ofproto instances from ovs-vswitchd: %v", err)
	}
	return nil
}

func ovnNodeReadiness(exec util.ExecHelper, target string) error {
	// Inside the pod we always use `/etc/cni/net.d` folder even if kubelet
	// was started with a different conf directory
	confFile := "/etc/cni/net.d/10-ovn-kubernetes.conf"
	_, err := os.Stat(confFile)
	if os.IsNotExist(err) {
		return fmt.Errorf("OVN Kubernetes config file %q doesn't exist", confFile)
	}
	return nil
}

func ovnNBDBRaftReadiness(exec util.ExecHelper, target string) error {
	status, err := util.GetOVNDBServerInfo(exec, 15, "nb", "OVN_Northbound")
	if err != nil {
		return err
	}
	if !status.Connected {
		return fmt.Errorf("ovsdb-server managing OVN_Northbound is not in contact with a majority of its cluster")
	}
	return nil
}

func ovnSBDBRaftReadiness(exec util.ExecHelper, target string) error {
	status, err := util.GetOVNDBServerInfo(exec, 15, "sb", "OVN_Southbound")
	if err != nil {
		return err
	}
	if !status.Connected {
		return fmt.Errorf("ovsdb-server managing OVN_Southbound is not in contact with a majority of its cluster")
	}
	return nil
}

// ReadinessProbeCommand runs readiness probes against various targets
var ReadinessProbeCommand = cli.Command{
	Name:  "readiness-probe",
	Usage: "check readiness of the specified target daemon",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "target",
			Aliases: []string{"t"},
			Usage:   "target daemon to check for readiness",
		},
	},
	Action: func(ctx *cli.Context) error {
		target := ctx.String("target")

		exec, err := util.NewExecHelper(kexec.New())
		if err != nil {
			return err
		}
		if cbfunc, ok := callbacks[target]; ok {
			return cbfunc(exec, target)
		}
		return fmt.Errorf("incorrect target specified")
	},
}
