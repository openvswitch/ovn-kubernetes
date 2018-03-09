package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/openvswitch/ovn-kubernetes/go-controller/cmd/ovn-k8s-cni-overlay/app"
	"github.com/openvswitch/ovn-kubernetes/go-controller/pkg/config"
	"github.com/openvswitch/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/openvswitch/ovn-kubernetes/go-controller/pkg/util"
)

func argString2Map(args string) (map[string]string, error) {
	argsMap := make(map[string]string)

	pairs := strings.Split(args, ";")
	for _, pair := range pairs {
		kv := strings.Split(pair, "=")
		if len(kv) != 2 {
			return nil, fmt.Errorf("ARGS: invalid pair %q", pair)
		}
		keyString := kv[0]
		valueString := kv[1]
		argsMap[keyString] = valueString
	}

	return argsMap, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	conf := &types.NetConf{}
	if err := json.Unmarshal(args.StdinData, conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	argsMap, err := argString2Map(args.Args)
	if err != nil {
		return err
	}

	namespace := argsMap["K8S_POD_NAMESPACE"]
	podName := argsMap["K8S_POD_NAME"]
	if namespace == "" || podName == "" {
		return fmt.Errorf("required CNI variable missing")
	}

	clientset, err := util.NewClientset(&config.Kubernetes)
	if err != nil {
		return fmt.Errorf("Could not create clientset for kubernetes: %v", err)
	}
	kubecli := &kube.Kube{KClient: clientset}

	// TODO: Remove the following once the Kubernetes will get
	// proper Windows CNI support.
	// NOTE Windows ONLY: there are some cases where we want to return here
	// and not to continue
	stop, fakeResult := app.InitialPlatformCheck(args)
	if stop {
		return types.PrintResult(fakeResult, conf.CNIVersion)
	}

	// Get the IP address and MAC address from the API server.
	// Wait for a maximum of 30 seconds with a retry every 1 second.
	var annotation map[string]string
	for cnt := 0; cnt < 30; cnt++ {
		annotation, err = kubecli.GetAnnotationsOnPod(namespace, podName)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		if _, ok := annotation["ovn"]; ok {
			break
		}
	}

	if annotation == nil {
		return fmt.Errorf("failed to get pod annotation")
	}

	ovnAnnotation, ok := annotation["ovn"]
	if !ok {
		return fmt.Errorf("failed to get annotation of ovn")
	}

	var ovnAnnotatedMap map[string]string
	err = json.Unmarshal([]byte(ovnAnnotation), &ovnAnnotatedMap)
	if err != nil {
		return fmt.Errorf("unmarshal ovn annotation failed")
	}

	ipAddress := ovnAnnotatedMap["ip_address"]
	macAddress := ovnAnnotatedMap["mac_address"]
	gatewayIP := ovnAnnotatedMap["gateway_ip"]

	if ipAddress == "" || macAddress == "" || gatewayIP == "" {
		return fmt.Errorf("failed in pod annotation key extract")
	}

	var interfacesArray []*current.Interface
	interfacesArray, err = app.ConfigureInterface(args, namespace, podName, macAddress, ipAddress, gatewayIP)
	if err != nil {
		return err
	}

	// Build the result structure to pass back to the runtime
	addr, addrNet, err := net.ParseCIDR(ipAddress)
	if err != nil {
		return fmt.Errorf("failed to parse IP address %q: %v", ipAddress, err)
	}
	ipVersion := "6"
	if addr.To4() != nil {
		ipVersion = "4"
	}
	result := &current.Result{
		Interfaces: interfacesArray,
		IPs: []*current.IPConfig{
			{
				Version:   ipVersion,
				Interface: current.Int(1),
				Address:   net.IPNet{IP: addr, Mask: addrNet.Mask},
				Gateway:   net.ParseIP(gatewayIP),
			},
		},
	}

	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	return app.PlatformSpecificCleanup(args)
}

func main() {
	c := cli.NewApp()
	c.Name = "ovn-k8s-cni-overlay"
	c.Usage = "a CNI plugin to set up or tear down a container's network with OVN"
	c.Version = "0.0.1"
	c.Flags = config.Flags
	c.Action = func(ctx *cli.Context) error {
		if err := config.InitConfig(ctx, &config.Defaults{
			K8sAPIServer: true,
			K8sToken:     true,
		}); err != nil {
			return err
		}

		skel.PluginMain(cmdAdd, cmdDel, version.All)
		return nil
	}

	if err := c.Run(os.Args); err != nil {
		// Print the error to stdout in conformance with the CNI spec
		e, ok := err.(*types.Error)
		if !ok {
			e = &types.Error{Code: 100, Msg: err.Error()}
		}
		e.Print()
	}
}
