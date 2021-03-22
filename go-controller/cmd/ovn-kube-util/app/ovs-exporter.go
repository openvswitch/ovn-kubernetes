package app

import (
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/urfave/cli/v2"
	kexec "k8s.io/utils/exec"
)

var metricsScrapeInterval int
var OvsExporterCommand = cli.Command{
	Name:  "ovs-exporter",
	Usage: "",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "metrics-bind-address",
			Usage: `The IP address and port for the metrics server to serve on (default ":9310")`,
		},
		&cli.IntFlag{
			Name:        "metrics-interval",
			Usage:       "The Interval at which ovs metrics are collected",
			Value:       30,
			Destination: &metricsScrapeInterval,
		},
	},
	Action: func(ctx *cli.Context) error {
		bindAddress := ctx.String("metrics-bind-address")
		if bindAddress == "" {
			bindAddress = "0.0.0.0:9310"
		}

		if err := util.SetExec(kexec.New()); err != nil {
			return err
		}

		stopChan := make(chan struct{})

		// register ovs metrics that will be served off of /metrics path
		metrics.RegisterOvsMetrics(metricsScrapeInterval, stopChan)
		// start the prometheus server to serve OVS Metrics (default port: 9310)
		metrics.StartOVSMetricsServer(bindAddress)

		// run until cancelled
		<-ctx.Context.Done()
		close(stopChan)
		return nil
	},
}
