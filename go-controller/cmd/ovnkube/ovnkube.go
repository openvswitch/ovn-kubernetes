package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"text/template"
	"time"

	"k8s.io/klog"

	goovn "github.com/ebay/go-ovn"
	"github.com/urfave/cli/v2"
	"gopkg.in/fsnotify/fsnotify.v1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	ovnnode "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kexec "k8s.io/utils/exec"
)

const (
	// CustomAppHelpTemplate helps in grouping options to ovnkube
	CustomAppHelpTemplate = `NAME:
   {{.Name}} - {{.Usage}}

USAGE:
   {{.HelpName}} [global options]

VERSION:
   {{.Version}}{{if .Description}}

DESCRIPTION:
   {{.Description}}{{end}}

COMMANDS:{{range .VisibleCategories}}{{if .Name}}

   {{.Name}}:{{end}}{{range .VisibleCommands}}
     {{join .Names ", "}}{{"\t"}}{{.Usage}}{{end}}{{end}}

GLOBAL OPTIONS:{{range $title, $category := getFlagsByCategory}}
   {{upper $title}}
   {{range $index, $option := $category}}{{if $index}}
   {{end}}{{$option}}{{end}}
   {{end}}`
)

func getFlagsByCategory() map[string][]cli.Flag {
	m := map[string][]cli.Flag{}
	m["Generic Options"] = config.CommonFlags
	m["CNI Options"] = config.CNIFlags
	m["K8s-related Options"] = config.K8sFlags
	m["OVN Northbound DB Options"] = config.OvnNBFlags
	m["OVN Southbound DB Options"] = config.OvnSBFlags
	m["OVN Gateway Options"] = config.OVNGatewayFlags
	m["Master HA Options"] = config.MasterHAFlags

	return m
}

// borrowed from cli packages' printHelpCustom()
func printOvnKubeHelp(out io.Writer, templ string, data interface{}, customFunc map[string]interface{}) {
	funcMap := template.FuncMap{
		"join":               strings.Join,
		"upper":              strings.ToUpper,
		"getFlagsByCategory": getFlagsByCategory,
	}
	for key, value := range customFunc {
		funcMap[key] = value
	}

	w := tabwriter.NewWriter(out, 1, 8, 2, ' ', 0)
	t := template.Must(template.New("help").Funcs(funcMap).Parse(templ))
	err := t.Execute(w, data)
	if err == nil {
		_ = w.Flush()
	}
}

func main() {
	cli.HelpPrinterCustom = printOvnKubeHelp
	c := cli.NewApp()
	c.Name = "ovnkube"
	c.Usage = "run ovnkube to start master, node, and gateway services"
	c.Version = config.Version
	c.CustomAppHelpTemplate = CustomAppHelpTemplate
	c.Flags = config.GetFlags(nil)

	c.Action = func(c *cli.Context) error {
		return runOvnKube(c)
	}

	ctx := context.Background()

	// trap SIGHUP, SIGINT, SIGTERM, SIGQUIT and
	// cancel the context
	ctx, cancel := context.WithCancel(ctx)
	exitCh := make(chan os.Signal, 1)
	signal.Notify(exitCh,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	defer func() {
		signal.Stop(exitCh)
		cancel()
	}()
	go func() {
		select {
		case s := <-exitCh:
			klog.Infof("Received signal %s. Shutting down", s)
			cancel()
		case <-ctx.Done():
		}
	}()

	if err := c.RunContext(ctx, os.Args); err != nil {
		klog.Exit(err)
	}
}

func delPidfile(pidfile string) {
	if pidfile != "" {
		if _, err := os.Stat(pidfile); err == nil {
			if err := os.Remove(pidfile); err != nil {
				klog.Errorf("%s delete failed: %v", pidfile, err)
			}
		}
	}
}

func setupPIDFile(pidfile string) error {
	// need to test if already there
	_, err := os.Stat(pidfile)

	// Create if it doesn't exist, else exit with error
	if os.IsNotExist(err) {
		if err := ioutil.WriteFile(pidfile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
			klog.Errorf("Failed to write pidfile %s (%v). Ignoring..", pidfile, err)
		}
	} else {
		// get the pid and see if it exists
		pid, err := ioutil.ReadFile(pidfile)
		if err != nil {
			return fmt.Errorf("pidfile %s exists but can't be read: %v", pidfile, err)
		}
		_, err1 := os.Stat("/proc/" + string(pid[:]) + "/cmdline")
		if os.IsNotExist(err1) {
			// Left over pid from dead process
			if err := ioutil.WriteFile(pidfile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
				klog.Errorf("Failed to write pidfile %s (%v). Ignoring..", pidfile, err)
			}
		} else {
			return fmt.Errorf("pidfile %s exists and ovnkube is running", pidfile)
		}
	}

	return nil
}

func runOvnKube(ctx *cli.Context) error {
	pidfile := ctx.String("pidfile")
	if pidfile != "" {
		defer delPidfile(pidfile)
		if err := setupPIDFile(pidfile); err != nil {
			return err
		}
	}

	exec := kexec.New()
	configFile, err := config.InitConfig(ctx, exec, nil)
	if err != nil {
		return err
	}

	if err = util.SetExec(exec); err != nil {
		return fmt.Errorf("failed to initialize exec helper: %v", err)
	}

	clientset, egressIPClientset, egressFirewallClientset, crdClientset, err := util.NewClientsets(&config.Kubernetes)
	if err != nil {
		return err
	}

	// create factory and start the controllers asked for
	factory, err := factory.NewWatchFactory(clientset, egressIPClientset, egressFirewallClientset, crdClientset)
	if err != nil {
		return err
	}

	master := ctx.String("init-master")
	node := ctx.String("init-node")

	cleanupNode := ctx.String("cleanup-node")
	if cleanupNode != "" {
		if master != "" || node != "" {
			return fmt.Errorf("cannot specify cleanup-node together with 'init-node or 'init-master'")
		}

		if err = ovnnode.CleanupClusterNode(cleanupNode); err != nil {
			return err
		}
		return nil
	}

	if master == "" && node == "" {
		return fmt.Errorf("need to run ovnkube in either master and/or node mode")
	}

	// Set up a watch on our config file; if it changes, we exit -
	// (we don't have the ability to dynamically reload config changes).
	if err := watchForChanges(configFile); err != nil {
		return fmt.Errorf("unable to setup configuration watch: %v", err)
	}

	stopChan := make(chan struct{})
	wg := &sync.WaitGroup{}

	if master != "" {
		var ovnNBClient, ovnSBClient goovn.Client
		var err error

		if ovnNBClient, err = util.NewOVNNBClient(); err != nil {
			return fmt.Errorf("error when trying to initialize go-ovn NB client: %v", err)
		}

		if ovnSBClient, err = util.NewOVNSBClient(); err != nil {
			return fmt.Errorf("error when trying to initialize go-ovn SB client: %v", err)
		}

		// register prometheus metrics exported by the master
		// this must be done prior to calling controller start
		// since we capture some metrics in Start()
		metrics.RegisterMasterMetrics(ovnNBClient, ovnSBClient)

		ovnController := ovn.NewOvnController(clientset, egressIPClientset, egressFirewallClientset, factory, stopChan, nil, ovnNBClient, ovnSBClient, util.EventRecorder(clientset))
		if err := ovnController.Start(clientset, master, wg); err != nil {
			return err
		}
	}

	if node != "" {
		if config.Kubernetes.Token == "" {
			return fmt.Errorf("cannot initialize node without service account 'token'. Please provide one with --k8s-token argument")
		}

		smartNic := ctx.Bool("smart-nic")
		// register ovnkube node specific prometheus metrics exported by the node
		metrics.RegisterNodeMetrics()
		start := time.Now()
		n := ovnnode.NewNode(clientset, factory, node, stopChan, util.EventRecorder(clientset), smartNic)
		if err := n.Start(wg); err != nil {
			return err
		}
		end := time.Since(start)
		metrics.MetricNodeReadyDuration.Set(end.Seconds())
	}

	// now that ovnkube master/node are running, lets expose the metrics HTTP endpoint if configured
	// start the prometheus server to serve OVN K8s Metrics (default master port: 9409, node port: 9410)
	if config.Kubernetes.MetricsBindAddress != "" {
		metrics.StartMetricsServer(config.Kubernetes.MetricsBindAddress, config.Kubernetes.MetricsEnablePprof)
	}

	// start the prometheus server to serve OVN Metrics (default port: 9476)
	if config.Kubernetes.OVNMetricsBindAddress != "" {
		metrics.RegisterOvnMetrics(clientset, node)
		metrics.StartOVNMetricsServer(config.Kubernetes.OVNMetricsBindAddress)
	}

	// run until cancelled
	<-ctx.Context.Done()
	close(stopChan)
	factory.Shutdown()
	wg.Wait()
	return nil
}

// watchForChanges exits if the configuration file changed.
func watchForChanges(configPath string) error {
	if configPath == "" {
		return nil
	}
	configPath, err := filepath.Abs(configPath)
	if err != nil {
		return err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					klog.Infof("Configuration file %s changed, exiting...", event.Name)
					os.Exit(0)
					return
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				klog.Errorf("Error watching for changes to configmap: %s, err: %v", configPath, err)
			}
		}
	}()

	// Watch all symlinks for changes
	p := configPath
	maxdepth := 100
	for depth := 0; depth < maxdepth; depth++ {
		if err := watcher.Add(p); err != nil {
			return err
		}
		klog.Infof("Watching config file %s for changes", p)

		stat, err := os.Lstat(p)
		if err != nil {
			return err
		}

		// configmaps are usually symlinks
		if stat.Mode()&os.ModeSymlink > 0 {
			p, err = filepath.EvalSymlinks(p)
			if err != nil {
				return err
			}
		} else {
			break
		}
	}

	return nil
}
