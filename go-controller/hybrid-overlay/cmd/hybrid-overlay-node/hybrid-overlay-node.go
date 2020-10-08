package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/urfave/cli/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/controller"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"k8s.io/client-go/informers"
	"k8s.io/klog"
	kexec "k8s.io/utils/exec"
)

var nodeName string

const windowServiceArgName = "windows-service"
const appName = "hybrid-overlay-node"

func main() {
	c := cli.NewApp()
	c.Name = appName
	c.Usage = "a node controller to integrate disparate networks with VXLAN tunnels"
	c.Version = config.Version
	c.Flags = config.GetFlags([]cli.Flag{
		&cli.StringFlag{
			Name:        "node",
			Usage:       "The name of this node in the Kubernetes cluster.",
			Destination: &nodeName,
		},
		&cli.BoolFlag{
			Name:  windowServiceArgName,
			Usage: "Enables hybrid overlay to run as a Windows service. Ignored on Linux.",
		}})

	ctx := context.Background()

	c.Action = func(c *cli.Context) error {
		if err := initForOS(c, ctx); err != nil {
			klog.Exit(err)
		}

		if err := runHybridOverlay(c); err != nil {
			panic(err.Error())
		}
		return nil
	}

	if err := c.RunContext(ctx, os.Args); err != nil {
		klog.Exit(err)
	}
}

func signalHandler(c context.Context) {
	ctx, cancel := context.WithCancel(c)

	// trap SIGHUP, SIGINT, SIGTERM, SIGQUIT and
	// cancel the context
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
}

func runHybridOverlay(ctx *cli.Context) error {
	baseExec := kexec.New()
	if _, err := config.InitConfig(ctx, baseExec, nil); err != nil {
		return err
	}

	exec, err := util.NewExecHelper(baseExec)
	if err != nil {
		return err
	}

	if nodeName == "" {
		return fmt.Errorf("missing node name; use the 'node' flag to provide one")
	}

	clientset, _, _, _, err := util.NewClientsets(&config.Kubernetes)
	if err != nil {
		return err
	}

	stopChan := make(chan struct{})
	defer close(stopChan)
	f := informers.NewSharedInformerFactory(clientset, informer.DefaultResyncInterval)

	n, err := controller.NewNode(
		&kube.Kube{KClient: clientset},
		exec,
		nodeName,
		f.Core().V1().Nodes().Informer(),
		f.Core().V1().Pods().Informer(),
		informer.NewDefaultEventHandler,
	)
	if err != nil {
		return err
	}

	f.Start(stopChan)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		n.Run(stopChan)
	}()

	// run until cancelled
	<-ctx.Context.Done()
	close(stopChan)
	wg.Wait()
	return nil
}
