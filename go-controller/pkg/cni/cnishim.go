package cni

// contains code for cnishim - one that gets called as the cni Plugin
// This does not do the real cni work. This is just the client to the cniserver
// that does the real work.

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
	"k8s.io/klog/v2"

	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
)

// Plugin is the structure to hold the endpoint information and the corresponding
// functions to use it
type Plugin struct {
	socketPath string
}

// NewCNIPlugin creates the internal Plugin object
func NewCNIPlugin(socketPath string) *Plugin {
	if len(socketPath) == 0 {
		socketPath = serverSocketPath
	}
	return &Plugin{socketPath: socketPath}
}

// Create and fill a Request with this Plugin's environment and stdin which
// contain the CNI variables and configuration
func newCNIRequest(args *skel.CmdArgs) *Request {
	envMap := make(map[string]string)
	for _, item := range os.Environ() {
		idx := strings.Index(item, "=")
		if idx > 0 {
			envMap[strings.TrimSpace(item[:idx])] = item[idx+1:]
		}
	}

	return &Request{
		Env:    envMap,
		Config: args.StdinData,
	}
}

// Send a CNI request to the CNI server via JSON + HTTP over a root-owned unix socket,
// and return the result
func (p *Plugin) doCNI(url string, req interface{}) ([]byte, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CNI request %v: %v", req, err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(proto, addr string) (net.Conn, error) {
				return net.Dial("unix", p.socketPath)
			},
		},
	}

	resp, err := client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to send CNI request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CNI result: %v", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("CNI request failed with status %v: '%s'", resp.StatusCode, string(body))
	}

	return body, nil
}

func setupLogging(conf *ovntypes.NetConf) {
	var err error
	var level klog.Level

	if conf.LogLevel != "" {
		if err = level.Set(conf.LogLevel); err != nil {
			klog.Warningf("Failed to set klog log level to %s: %v", conf.LogLevel, err)
		}
	}
	if conf.LogFile != "" {
		klogFlags := flag.NewFlagSet("klog", flag.ExitOnError)
		klog.InitFlags(klogFlags)
		if err := klogFlags.Set("logtostderr", "false"); err != nil {
			klog.Warningf("Error setting klog logtostderr: %v", err)
		}
		if err := klogFlags.Set("alsologtostderr", "true"); err != nil {
			klog.Warningf("Error setting klog alsologtostderr: %v", err)
		}
		klog.SetOutput(&lumberjack.Logger{
			Filename:   conf.LogFile,
			MaxSize:    conf.LogFileMaxSize, // megabytes
			MaxBackups: conf.LogFileMaxBackups,
			MaxAge:     conf.LogFileMaxAge, // days
			Compress:   true,
		})
	}
}

// report the CNI request processing time to CNI server. This is used for the cni_request_duration_seconds metrics
func (p *Plugin) postMetrics(startTime time.Time, cmd command, err error) {
	elapsedTime := time.Since(startTime).Seconds()
	_, _ = p.doCNI("http://dummy/metrics", &CNIRequestMetrics{
		Command:     cmd,
		ElapsedTime: elapsedTime,
		HasErr:      err != nil,
	})
}

// CmdAdd is the callback for 'add' cni calls from skel
func (p *Plugin) CmdAdd(args *skel.CmdArgs) error {
	var err error

	startTime := time.Now()
	defer func() {
		p.postMetrics(startTime, CNIAdd, err)
	}()

	// read the config stdin args to obtain cniVersion
	conf, errC := config.ReadCNIConfig(args.StdinData)
	if errC != nil {
		err = fmt.Errorf("invalid stdin args %v", errC)
		return err
	}
	setupLogging(conf)

	if conf.NotDefault && conf.NetCidr == "" {
		return fmt.Errorf("netcidr needs to be specified in Network Attachment Definition for non-default network")
	}

	req := newCNIRequest(args)

	body, errB := p.doCNI("http://dummy/", req)
	if errB != nil {
		err = errB
		klog.Error(err.Error())
		return err
	}

	response := &Response{}
	if err = json.Unmarshal(body, response); err != nil {
		err = fmt.Errorf("failed to unmarshal response '%s': %v", string(body), err)
		klog.Error(err.Error())
		return err
	}

	var result *current.Result
	if response.Result != nil {
		result = response.Result
	} else {
		pr, _ := cniRequestToPodRequest(req)
		result, err = pr.getCNIResult(response.PodIFInfo)
		if err != nil {
			err = fmt.Errorf("failed to get CNI Result from pod interface info %v: %v", response.PodIFInfo, err)
			klog.Error(err.Error())
			return err
		}
	}

	return types.PrintResult(result, conf.CNIVersion)
}

// CmdDel is the callback for 'teardown' cni calls from skel
func (p *Plugin) CmdDel(args *skel.CmdArgs) error {
	startTime := time.Now()
	// read the config stdin args
	conf, err := config.ReadCNIConfig(args.StdinData)
	if err == nil {
		setupLogging(conf)
	}

	_, err = p.doCNI("http://dummy/", newCNIRequest(args))
	if err != nil {
		klog.Errorf(err.Error())
	}
	p.postMetrics(startTime, CNIDel, err)
	return err
}

// CmdCheck is the callback for 'checking' container's networking is as expected.
func (p *Plugin) CmdCheck(args *skel.CmdArgs) error {
	var err error

	startTime := time.Now()
	defer func() {
		p.postMetrics(startTime, CNICheck, err)
	}()

	// read the config stdin args
	// Note: in order to validate that RawPrevResult is not nil, we don't use config.ReadCNIConfig(args.StdinData)
	conf := &ovntypes.NetConf{}
	if err = json.Unmarshal(args.StdinData, conf); err != nil {
		return err
	}
	// Parse previous result.
	if conf.RawPrevResult == nil {
		return fmt.Errorf("required prevResult missing")
	}
	if err = version.ParsePrevResult(&conf.NetConf); err != nil {
		return err
	}
	setupLogging(conf)
	defer func() {
		if err != nil {
			klog.Errorf(err.Error())
		}
	}()

	gtet := false
	if gtet, err = version.GreaterThanOrEqualTo(conf.CNIVersion, "0.4.0"); err != nil {
		return types.NewError(types.ErrDecodingFailure, err.Error(), "")
	} else if !gtet {
		err = types.NewError(types.ErrIncompatibleCNIVersion, "config version does not allow CHECK", "")
		return err
	}

	result, errR := current.NewResultFromResult(conf.PrevResult)
	if errR != nil {
		err = errR
		return err
	}
	klog.Infof("PrevResult is %+v", result)

	var intf current.Interface
	for _, inf := range result.Interfaces {
		if args.IfName == inf.Name {
			if args.Netns == inf.Sandbox {
				intf = *inf
				break
			}
		}
	}
	// The namespace must be the same as what was configured
	if args.Netns != intf.Sandbox {
		err = fmt.Errorf("sandbox in prevResult %s doesn't match configured netns: %s",
			intf.Sandbox, args.Netns)
		return err
	}

	netns, errNs := ns.GetNS(args.Netns)
	if errNs != nil {
		err = fmt.Errorf("failed to open netns %q: %v", args.Netns, errNs)
		return err
	}
	defer netns.Close()

	// Check prevResults for ips, routes and dns against values found in the container
	if err = netns.Do(func(_ ns.NetNS) error {

		// Check interface against values found in the container
		err = validateCniContainerInterface(intf)
		if err != nil {
			return err
		}

		err = ip.ValidateExpectedInterfaceIPs(args.IfName, result.IPs)
		if err != nil {
			return err
		}

		err = ip.ValidateExpectedRoute(result.Routes)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	_, err = p.doCNI("http://dummy/", newCNIRequest(args))
	return err
}

func validateCniContainerInterface(intf current.Interface) error {
	var link netlink.Link
	var err error

	if intf.Name == "" {
		return fmt.Errorf("container interface name missing in prevResult: %v", intf.Name)
	}
	link, err = netlink.LinkByName(intf.Name)
	if err != nil {
		return fmt.Errorf("container Interface name in prevResult: %s not found", intf.Name)
	}
	if intf.Sandbox == "" {
		return fmt.Errorf("Error: Container interface %s should not be in host namespace", link.Attrs().Name)
	}

	if intf.Mac != "" {
		if intf.Mac != link.Attrs().HardwareAddr.String() {
			return fmt.Errorf("interface %s Mac %s doesn't match container Mac: %s", intf.Name, intf.Mac, link.Attrs().HardwareAddr)
		}
	}
	return nil
}
