package main

import (
	"os"

	"github.com/openvswitch/ovn-kubernetes/go-controller/cmd/ovn-kube-util/app"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func main() {
	c := cli.NewApp()
	c.Name = "ovn-kube-util"
	c.Usage = "Utils for kubernetes ovn"
	c.Version = "0.0.2"

	c.Commands = []cli.Command{
		app.NicsToBridgeCommand,
		app.BridgesToNicCommand,
	}

	if err := c.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}
