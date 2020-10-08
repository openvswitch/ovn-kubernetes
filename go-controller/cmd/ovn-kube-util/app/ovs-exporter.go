package app

import (
	"k8s.io/klog"
	"net/http"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/urfave/cli/v2"
	kexec "k8s.io/utils/exec"
)

var OvsExporterCommand = cli.Command{
	Name:  "ovs-exporter",
	Usage: "",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "metrics-bind-address",
			Usage: `The IP address and port for the metrics server to serve on (default ":9310")`,
		},
	},
	Action: func(ctx *cli.Context) error {
		bindAddress := ctx.String("metrics-bind-address")
		if bindAddress == "" {
			bindAddress = "0.0.0.0:9310"
		}

		exec, err := util.NewExecHelper(kexec.New())
		if err != nil {
			return err
		}

		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())

		// register ovs metrics that will be served off of /metrics path
		metrics.RegisterOvsMetrics(exec)

		if err := http.ListenAndServe(bindAddress, mux); err != nil {
			klog.Exitf("Starting metrics server failed: %v", err)
		}
		return nil
	},
}
