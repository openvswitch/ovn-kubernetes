package main

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/urfave/cli/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/controller"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/informer"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"k8s.io/client-go/informers"
	"k8s.io/klog/v2"
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
			klog.Exit(err)
		}
		return nil
	}

	if err := c.RunContext(ctx, os.Args); err != nil {
		klog.Exit(err)
	}
}

func signalHandler(c context.Context) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		util.ContextShutdownHandler(ctx, cancel)
	}()
}

func runHybridOverlay(ctx *cli.Context) error {
	exec := kexec.New()
	if _, err := config.InitConfig(ctx, exec, nil); err != nil {
		return err
	}

	if err := util.SetExecWithoutOVS(exec); err != nil {
		return err
	}

	if nodeName == "" {
		return fmt.Errorf("missing node name; use the 'node' flag to provide one")
	}

	clientset, err := util.NewKubernetesClientset(&config.Kubernetes)
	if err != nil {
		return err
	}

	stopChan := make(chan struct{})
	defer close(stopChan)
	f := informers.NewSharedInformerFactory(clientset, informer.DefaultResyncInterval)

	n, err := controller.NewNode(
		&kube.Kube{KClient: clientset},
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
