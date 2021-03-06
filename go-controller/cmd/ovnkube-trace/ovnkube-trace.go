package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	kapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	klog "k8s.io/klog"

	types "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

type AddrInfo struct {
	Family    string `json:"family,omitempty"`
	Local     string `json:"local,omitempty"`
	Prefixlen int    `json:"prefixlen,omitempty"`
}
type IpAddrReq struct {
	IfIndex   int        `json:"ifindex,omitempty"`
	IfName    string     `json:"ifname,omitempty"`
	LinkIndex int        `json:"link_index,omitempty"`
	AInfo     []AddrInfo `json:"addr_info,omitempty"`
}

type SvcInfo struct {
	IP           string
	PodName      string
	PodNamespace string
	PodIP        string
	PodPort      string
}

type PodInfo struct {
	IP                      string
	MAC                     string
	VethName                string
	PortNum                 string
	LocalNum                string
	OVNName                 string
	PodName                 string
	ContainerName           string
	OvnKubeContainerPodName string
	NodeName                string
	StorPort                string
	StorMAC                 string
	HostNetwork             bool
}

func execInPod(coreclient *corev1client.CoreV1Client, restconfig *rest.Config, namespace string, podName string, containerName string, cmd string, in string) (string, string, error) {

	scheme := runtime.NewScheme()
	if err := kapi.AddToScheme(scheme); err != nil {
		fmt.Printf("error adding to scheme: %v", err)
		os.Exit(-1)
	}
	parameterCodec := runtime.NewParameterCodec(scheme)

	useStdin := false
	if in != "" {
		useStdin = true
	}

	// Prepare the API URL used to execute another process within the Pod.
	req := coreclient.RESTClient().
		Post().
		Namespace(namespace).
		Resource("pods").
		Name(podName).
		SubResource("exec").
		VersionedParams(&kapi.PodExecOptions{
			Container: containerName,
			Command:   []string{"bash", "-c", cmd},
			Stdin:     useStdin,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, parameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(restconfig, "POST", req.URL())
	if err != nil {
		return "", "", err
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var stdin io.Reader

	if useStdin {
		stdin = strings.NewReader(in)
	} else {
		stdin = nil
	}

	err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		return stdout.String(), stderr.String(), err
	}

	return stdout.String(), stderr.String(), err
}

func getPodMAC(client *corev1client.CoreV1Client, pod *kapi.Pod) (podMAC string, err error) {

	if pod.Spec.HostNetwork {
		node, err := client.Nodes().Get(context.TODO(), pod.Spec.NodeName, metav1.GetOptions{})
		if err != nil {
			return "", err
		}

		nodeMAC, err := util.ParseNodeManagementPortMACAddress(node)
		if err != nil {
			return "", err
		}
		if nodeMAC != nil {
			podMAC = nodeMAC.String()
		}
	} else {
		podAnnotation, err := util.UnmarshalPodAnnotation(pod.ObjectMeta.Annotations, types.DefaultNetworkName)
		if err != nil {
			return "", err
		}
		if podAnnotation != nil {
			podMAC = podAnnotation.MAC.String()
		}
	}

	return podMAC, nil
}

func getSvcInfo(coreclient *corev1client.CoreV1Client, restconfig *rest.Config, svcName string, ovnNamespace string, namespace string, cmd string) (svcInfo *SvcInfo, err error) {

	// Get service with the name supplied by svcName
	svc, err := coreclient.Services(namespace).Get(context.TODO(), svcName, metav1.GetOptions{})
	if err != nil {
		klog.V(1).Infof("Service %s in namespace %s not found\n", svcName, namespace)
		return nil, err
	}
	klog.V(5).Infof("==>Got service %s in namespace %s\n", svcName, namespace)

	clusterIP := svc.Spec.ClusterIP
	if clusterIP == "" || clusterIP == "None" {
		klog.V(1).Infof("ClusterIP for service %s in namespace %s not available\n", svcName, namespace)
		return nil, err
	}
	klog.V(5).Infof("==>Got service %s ClusterIP is %s\n", svcName, clusterIP)

	svcInfo = &SvcInfo{
		IP: svc.Spec.ClusterIP,
	}

	ep, err := coreclient.Endpoints(namespace).Get(context.TODO(), svcName, metav1.GetOptions{})
	if err != nil {
		klog.V(1).Infof("Endpoints for service %s in namespace %s not found\n", svcName, namespace)
		return nil, err
	}
	klog.V(5).Infof("==>Got Endpoint %v for service %s in namespace %s\n", ep, svcName, namespace)

	addrFound := false
	portFound := false
	for _, subset := range ep.Subsets {
		klog.V(5).Infof("==>Got subset %v for service %s in namespace %s\n", subset, svcName, namespace)
		for _, epAddress := range subset.Addresses {
			klog.V(5).Infof("==>Got Address %v for service %s in namespace %s\n", epAddress, svcName, namespace)
			svcInfo.PodName = epAddress.TargetRef.Name
			svcInfo.PodNamespace = epAddress.TargetRef.Namespace
			svcInfo.PodIP = epAddress.IP
			addrFound = true
			break
		}
		for _, port := range subset.Ports {
			klog.V(5).Infof("==>Got Port %v for service %s in namespace %s\n", port, svcName, namespace)
			svcInfo.PodPort = strconv.Itoa(int(port.Port))
			portFound = true
			break
		}
		if addrFound && portFound {
			break
		}
	}
	if svcInfo.PodName == "" {
		klog.V(0).Infof("Cannot find pods in Endpoints for service %s in namespace %s", svcName, namespace)
		err := fmt.Errorf("cannot find pods in Endpoints for service %s in namespace %s", svcName, namespace)
		return nil, err
	}

	return svcInfo, err
}

func getPodInfo(coreclient *corev1client.CoreV1Client, restconfig *rest.Config, podName string, ovnNamespace string, namespace string, cmd string) (podInfo *PodInfo, err error) {

	var ethName string

	// Get pod with the name supplied by srcPodName
	pod, err := coreclient.Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		klog.V(1).Infof("Pod %s in namespace %s not found\n", podName, namespace)
		return nil, err
	}

	podInfo = &PodInfo{
		IP: pod.Status.PodIP,
	}

	// Get the node on which the pod runs on
	node, err := coreclient.Nodes().Get(context.TODO(), pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		klog.V(1).Infof("Pod %s in namespace %s node not found\n", podName, namespace)
		return nil, err
	}
	klog.V(5).Infof("==>Got pod %s which is running on node %s\n", podName, node.Name)

	podMAC, err := getPodMAC(coreclient, pod)
	if err != nil {
		klog.V(1).Infof("Problem obtaining Ethernet address of Pod %s in namespace %s\n", podName, namespace)
		return nil, err
	}

	podInfo.PodName = pod.Name
	podInfo.MAC = podMAC
	podInfo.ContainerName = pod.Spec.Containers[0].Name

	var tryJSON bool = true
	var linkIndex int

	// The interface name used depends on what network namespasce the pod uses
	if pod.Spec.HostNetwork {
		ethName = util.GetLegacyK8sMgmtIntfName(node.Name)
		podInfo.HostNetwork = true
		linkIndex = 0
	} else {
		ethName = "eth0"
		podInfo.HostNetwork = false

		// Find index used for pod interface

		ipJaddrCmd := "ip -j addr show " + ethName

		klog.V(5).Infof("Ip -j command is %s", ipJaddrCmd)
		ipOutput, ipError, err := execInPod(coreclient, restconfig, namespace, podName, podInfo.ContainerName, ipJaddrCmd, "")
		if err != nil {
			klog.V(1).Infof("Ip -j command error %v stdOut: %s\n stdErr: %s", err, ipOutput, ipError)
			tryJSON = false
		}

		if tryJSON {
			klog.V(5).Infof("==>pod %s: ip addr show: %q", pod.Name, ipOutput)

			var data []IpAddrReq
			ipOutput = strings.Replace(ipOutput, "\n", "", -1)
			klog.V(5).Infof("==> pod %s NOW: %s ", pod.Name, ipOutput)
			err = json.Unmarshal([]byte(ipOutput), &data)
			if err != nil {
				fmt.Printf("JSON ERR: couldn't get stuff from data %v; json parse error: %v\n", data, err)
				return nil, err
			}
			klog.V(5).Infof("Size of IpAddrReq array: %v\n", len(data))
			klog.V(5).Infof("IpAddrReq: %v\n", data)

			for _, addr := range data {
				if addr.IfName == ethName {
					linkIndex = addr.LinkIndex
					klog.V(5).Infof("IfName: %v", addr.IfName)
					break
				}
			}
			klog.V(5).Infof("linkIndex is %d", linkIndex)
		} else {
			awkString := " | awk '{print $2}'"
			iplinkCmd := "ip -o link show dev " + ethName + awkString

			klog.V(5).Infof("The ip -o command is %s", iplinkCmd)
			linkOutput, linkError, err := execInPod(coreclient, restconfig, namespace, podName, podInfo.ContainerName, iplinkCmd, "")
			if err != nil {
				klog.V(1).Infof("The ip -o command error %v stdOut: %s\n stdErr: %s", err, linkOutput, linkError)
				// Give up, pod image doesn't have iproute installed
				return nil, err
			}

			klog.V(5).Infof("AWK string is %s", awkString)
			klog.V(5).Infof("==>pod Old Way %s: ip -o link show: %q", pod.Name, linkOutput)

			linkOutput = strings.Replace(linkOutput, "\n", "", -1)
			klog.V(5).Infof("==> pod Old Way %s NOW: %s ", pod.Name, linkOutput)
			linkOutput = strings.Replace(linkOutput, "eth0@if", "", -1)
			klog.V(5).Infof("==> pod Old Way %s NOW: %s ", pod.Name, linkOutput)
			linkOutput = strings.Replace(linkOutput, ":", "", -1)
			klog.V(5).Infof("==> pod Old Way %s NOW: %s ", pod.Name, linkOutput)

			linkIndex, err = strconv.Atoi(linkOutput)
			if err != nil {
				klog.Error("Error converting string to int", err)
				return nil, err
			}
			klog.V(5).Infof("Using ip -o link show - linkIndex is %d", linkIndex)
		}
	}
	klog.V(5).Infof("Using interface name of %s with MAC of %s", ethName, podMAC)

	if !pod.Spec.HostNetwork && linkIndex == 0 {
		klog.V(0).Infof("Fatal: Pod Network used and linkIndex is zero")
		return nil, err
	}
	if pod.Spec.HostNetwork && linkIndex != 0 {
		klog.V(1).Infof("Fatal: Host Network used and linkIndex is non-zero")
		return nil, err
	}

	// Get pods in the openshift-ovn-kubernetes namespace
	podsOvn, errOvn := coreclient.Pods(ovnNamespace).List(context.TODO(), metav1.ListOptions{})
	if errOvn != nil {
		klog.V(0).Infof("Cannot find pods in %s namespace", ovnNamespace)
		return nil, errOvn
	}

	var ovnkubePod *kapi.Pod
	// Find ovnkube-node-xxx pod running on the same node as Pod
	for _, podOvn := range podsOvn.Items {
		if podOvn.Spec.NodeName == node.Name {
			if !strings.HasPrefix(podOvn.Name, "ovnkube-node-metrics") {
				if strings.HasPrefix(podOvn.Name, "ovnkube-node") {
					klog.V(5).Infof("==> pod %s is running on node %s", podOvn.Name, node.Name)
					ovnkubePod = &podOvn
					break
				}
			}
		}
	}
	if ovnkubePod == nil {
		klog.V(0).Infof("Cannot find ovnkube-node pod on node %s in namespace %s", node.Name, ovnNamespace)
		err := fmt.Errorf("cannot find ovnkube-node pod on node %s in namespace %s", node.Name, ovnNamespace)
		return nil, err
	}

	podInfo.OvnKubeContainerPodName = ovnkubePod.Name
	podInfo.NodeName = ovnkubePod.Spec.NodeName
	podInfo.StorPort = "stor-" + ovnkubePod.Spec.NodeName

	// Find stor MAC
	klog.V(5).Infof("Command is: %s", "ovn-nbctl "+cmd+" lsp-get-addresses "+"stor-"+ovnkubePod.Spec.NodeName)
	lspCmd := "ovn-nbctl " + cmd + " lsp-get-addresses " + "stor-" + ovnkubePod.Spec.NodeName
	ipOutput, ipError, err := execInPod(coreclient, restconfig, ovnNamespace, ovnkubePod.Name, "ovnkube-node", lspCmd, "")
	if err != nil {
		fmt.Printf("execInPod() failed with %s stderr %s stdout %s \n", err, ipError, ipOutput)
		klog.V(5).Infof("execInPod() failed err %s - podInfo %v - ovnkubePod Name %s", err, podInfo, ovnkubePod.Name)
		return nil, err
	}

	podInfo.StorMAC = strings.Replace(ipOutput, "\n", "", -1)

	k8sMgmtIntfName := util.GetLegacyK8sMgmtIntfName(podInfo.NodeName)
	if ethName == k8sMgmtIntfName {
		podInfo.OVNName = types.K8sPrefix + ovnkubePod.Spec.NodeName
		podInfo.VethName = "ovn-k8s-mp0"
		klog.V(5).Infof("hostInterface on host stack OVN name is %s\n", podInfo.OVNName)
	} else {

		// obnkube-node-xxx uses host network.  Find host end of veth matching pod eth0 index

		tryJSON = true
		var hostInterface string

		ipCmd := "ip -j addr show"
		klog.V(5).Infof("Command is: %s", ipCmd)

		hostOutput, hostError, err := execInPod(coreclient, restconfig, ovnNamespace, ovnkubePod.Name, "ovnkube-node", ipCmd, "")
		if err != nil {
			fmt.Printf("execInPod() failed with %s stderr %s stdout %s \n", err, hostError, hostOutput)
			klog.V(5).Infof("execInPod() failed err %s - podInfo %v - ovnkubePod Name %s", err, podInfo, ovnkubePod.Name)
			return nil, err
		}

		if tryJSON {
			klog.V(5).Infof("==>ovnkubePod %s: ip addr show: %q", ovnkubePod.Name, hostOutput)

			var data []IpAddrReq
			hostOutput = strings.Replace(hostOutput, "\n", "", -1)
			klog.V(5).Infof("==> host %s NOW: %s", ovnkubePod.Name, hostOutput)
			err = json.Unmarshal([]byte(hostOutput), &data)
			if err != nil {
				klog.V(1).Infof("JSON ERR: couldn't get stuff from data %v; json parse error: %v", data, err)
				return nil, err
			}
			klog.V(5).Infof("Size of IpAddrReq array: %v", len(data))
			klog.V(5).Infof("IpAddrReq: %v", data)

			for _, addr := range data {
				if addr.IfIndex == linkIndex {
					hostInterface = addr.IfName
					klog.V(5).Infof("ifName: %v\n", addr.IfName)
					break
				}
			}
			klog.V(5).Infof("hostInterface is %s", hostInterface)
		} else {

			ipoCmd := "ip -o addr show"
			klog.V(5).Infof("Command is: %s", ipoCmd)

			hostOutput, hostError, err := execInPod(coreclient, restconfig, ovnNamespace, ovnkubePod.Name, "ovnkube-node", ipoCmd, "")
			if err != nil {
				fmt.Printf("execInPod() failed with %s stderr %s stdout %s \n", err, hostError, hostOutput)
				klog.V(5).Infof("execInPod() failed err %s - podInfo %v - ovnkubePod Name %s", err, podInfo, ovnkubePod.Name)
				return nil, err
			}

			hostOutput = strings.Replace(hostOutput, "\n", "", -1)
			klog.V(5).Infof("==>node %s: ip addr show: %q", node.Name, hostOutput)

			idx := strconv.Itoa(linkIndex) + ": "
			result := strings.Split(hostOutput, idx)
			klog.V(5).Infof("result[0]: %s", result[0])
			klog.V(5).Infof("result[1]: %s", result[1])
			words := strings.Fields(result[1])
			for i, word := range words {
				if i == 0 {
					hostInterface = word
					break
				}
			}
		}
		klog.V(5).Infof("hostInterface name is %s\n", hostInterface)
		podInfo.VethName = hostInterface
	}

	// ovs-vsctl get Interface [vethname] ofport
	portCmd := "ovs-vsctl get Interface " + podInfo.VethName + " ofport"
	klog.V(5).Infof("Command is: %s", portCmd)
	portOutput, portError, err := execInPod(coreclient, restconfig, ovnNamespace, ovnkubePod.Name, "ovnkube-node", portCmd, "")
	if err != nil {
		fmt.Printf("execInPod() failed with %s stderr %s stdout %s \n", err, portError, portOutput)
		klog.V(5).Infof("execInPod() failed err %s - podInfo %v - ovnkubePod Name %s", err, podInfo, ovnkubePod.Name)
		return nil, err
	}
	podInfo.PortNum = strings.Replace(portOutput, "\n", "", -1)

	// ovs-vsctl get Interface ovn-k8s-mp0 ofport
	portCmd = "ovs-vsctl get Interface " + "ovn-k8s-mp0" + " ofport"
	klog.V(5).Infof("Command is: %s", portCmd)
	localOutput, localError, err := execInPod(coreclient, restconfig, ovnNamespace, ovnkubePod.Name, "ovnkube-node", portCmd, "")
	if err != nil {
		fmt.Printf("execInPod() failed with %s stderr %s stdout %s \n", err, localError, localOutput)
		klog.V(5).Infof("execInPod() failed err %s - podInfo %v - ovnkubePod Name %s", err, podInfo, ovnkubePod.Name)
		return nil, err
	}
	podInfo.LocalNum = strings.Replace(localOutput, "\n", "", -1)

	return podInfo, err
}

var (
	level klog.Level
)

func main() {
	var pcfgNamespace *string
	var psrcNamespace *string
	var pdstNamespace *string
	var protocol string
	var ovnNamespace string
	var err error

	pcfgNamespace = flag.String("ovn-config-namespace", "openshift-ovn-kubernetes", "namespace used by ovn-config itself")
	psrcNamespace = flag.String("src-namespace", "default", "k8s namespace of source pod")
	pdstNamespace = flag.String("dst-namespace", "default", "k8s namespace of dest pod")

	cliConfig := flag.String("kubeconfig", "", "absolute path to the kubeconfig file")

	srcPodName := flag.String("src", "", "src: source pod name")
	dstPodName := flag.String("dst", "", "dest: destination pod name")
	dstSvcName := flag.String("service", "", "service: destination service name")
	dstPort := flag.String("dst-port", "80", "dst-port: destination port")
	tcp := flag.Bool("tcp", false, "use tcp transport protocol")
	udp := flag.Bool("udp", false, "use udp transport protocol")
	loglevel := flag.String("loglevel", "0", "loglevel: klog level")

	noSSL := flag.Bool("noSSL", false, "do not use SSL with OVN/OVS")

	flag.Parse()

	klog.InitFlags(nil)
	klog.SetOutput(os.Stderr)
	err = level.Set(*loglevel)
	if err != nil {
		fmt.Printf("fatal: cannot set logging level\n")
		os.Exit(-1)
	}
	klog.V(0).Infof("Log level set to: %s", *loglevel)

	srcNamespace := *psrcNamespace
	dstNamespace := *pdstNamespace

	ovnNamespace = *pcfgNamespace

	if *srcPodName == "" {
		fmt.Printf("Usage: source pod must be specified\n")
		klog.V(1).Infof("Usage: source pod must be specified")
		os.Exit(-1)
	}
	if !*tcp && !*udp {
		fmt.Printf("Usage: either tcp or udp must be specified\n")
		klog.V(1).Infof("Usage: either tcp or udp must be specified")
		os.Exit(-1)
	}
	if *udp && *tcp {
		fmt.Printf("Usage: Both tcp or udp cannot be specified\n")
		klog.V(1).Infof("Usage: Both tcp or udp cannot be specified")
		os.Exit(-1)
	}
	if *tcp {
		if *dstSvcName == "" && *dstPodName == "" {
			fmt.Printf("Usage: destination pod or destination service must be specified for tcp\n")
			klog.V(1).Infof("Usage: destination pod or destination service must be specified for tcp")
			os.Exit(-1)
		} else {
			protocol = "tcp"
		}
	}
	if *udp {
		if *dstPodName == "" {
			fmt.Printf("Usage: destination pod must be specified for udp\n")
			klog.V(1).Infof("Usage: destination pod must be specified for udp")
			os.Exit(-1)
		} else {
			protocol = "udp"
		}
	}

	var restconfig *rest.Config

	// This might work better?  https://godoc.org/sigs.k8s.io/controller-runtime/pkg/client/config

	// When supplied the kubeconfig supplied via cli takes precedence
	if *cliConfig != "" {

		// use the current context in kubeconfig
		restconfig, err = clientcmd.BuildConfigFromFlags("", *cliConfig)
		if err != nil {
			klog.V(1).Infof(" Unexpected error: %v", err)
			os.Exit(-1)
		}
	} else {

		// Instantiate loader for kubeconfig file.
		kubeconfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{},
		)

		// Get a rest.Config from the kubeconfig file.  This will be passed into all
		// the client objects we create.
		restconfig, err = kubeconfig.ClientConfig()
		if err != nil {
			klog.V(1).Infof(" Unexpected error: %v", err)
			os.Exit(-1)
		}
	}

	// Create a Kubernetes core/v1 client.
	coreclient, err := corev1client.NewForConfig(restconfig)
	if err != nil {
		klog.V(1).Infof(" Unexpected error: %v", err)
		os.Exit(-1)
	}

	// List all Nodes.
	nodes, err := coreclient.Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		klog.V(1).Infof(" Unexpected error: %v", err)
		os.Exit(-1)
	}

	masters := make(map[string]string)
	workers := make(map[string]string)

	klog.V(5).Infof(" Nodes: ")
	for _, node := range nodes.Items {

		_, found := node.Labels["node-role.kubernetes.io/master"]
		if found {
			klog.V(5).Infof("  Name: %s is a master", node.Name)
			for _, s := range node.Status.Addresses {
				klog.V(5).Infof("  Address Type: %s - Address: %s", s.Type, s.Address)
				//if s.Type == corev1client.NodeInternalIP {
				if s.Type == "InternalIP" {
					masters[node.Name] = s.Address
				}
			}
		} else {
			klog.V(5).Infof("  Name: %s is a worker", node.Name)
			for _, s := range node.Status.Addresses {
				klog.V(5).Infof("  Address Type: %s - Address: %s", s.Type, s.Address)
				//if s.Type == corev1client.NodeInternalIP {
				if s.Type == "InternalIP" {
					workers[node.Name] = s.Address
				}
			}
		}
	}

	if len(masters) < 3 {
		klog.V(5).Infof("Cluster does not have 3 masters, found %d", len(masters))
	}

	// Common ssl parameters
	var sslCertKeys string
	if *noSSL {
		sslCertKeys = " "
	} else {
		sslCertKeys = "-p /ovn-cert/tls.key -c /ovn-cert/tls.crt -C /ovn-ca/ca-bundle.crt "
	}

	nbUri := ""
	nbCount := 1
	for k, v := range masters {
		klog.V(5).Infof("Master name: %s has IP %s", k, v)
		if *noSSL {
			nbUri += "tcp:" + v + ":6641"
		} else {
			nbUri += "ssl:" + v + ":9641"
		}
		if nbCount == len(masters) {
			nbUri += " "
		} else {
			nbUri += ","
		}
		nbCount++
	}
	nbcmd := sslCertKeys + "--db " + nbUri
	klog.V(5).Infof("The nbcmd is %s", nbcmd)

	sbUri := ""
	sbCount := 1
	for _, v := range masters {
		if *noSSL {
			sbUri += "tcp:" + v + ":6642"
		} else {
			sbUri += "ssl:" + v + ":9642"
		}
		if sbCount == len(masters) {
			sbUri += " "
		} else {
			sbUri += ","
		}
		sbCount++
	}
	sbcmd := sslCertKeys + "--db " + sbUri
	klog.V(5).Infof("The sbcmd is %s", sbcmd)

	// Get info needed for the src Pod
	srcPodInfo, err := getPodInfo(coreclient, restconfig, *srcPodName, ovnNamespace, srcNamespace, nbcmd)
	if err != nil {
		fmt.Printf("Failed to get information from pod %s: %v\n", *srcPodName, err)
		klog.V(1).Infof("Failed to get information from pod %s: %v", *srcPodName, err)
		os.Exit(-1)
	}
	klog.V(5).Infof("srcPodInfo is %v", srcPodInfo)

	var dstSvcInfo *SvcInfo

	// Get destination service if there is one
	if *dstSvcName != "" {
		//Get dst servcie
		dstSvcInfo, err = getSvcInfo(coreclient, restconfig, *dstSvcName, ovnNamespace, dstNamespace, nbcmd)
		if err != nil {
			fmt.Printf("Failed to get information from service %s: %v\n", *dstSvcName, err)
			klog.V(1).Infof("Failed to get information from service %s: %v", *dstSvcName, err)
			os.Exit(-1)
		}

		// ovn-trace from src pod to clusterIP of ther service

		var fromSrc string

		if srcPodInfo.HostNetwork {
			fromSrc = " 'inport==\"" + srcPodInfo.OVNName + "\""
		} else {
			fromSrc = " 'inport==\"" + srcNamespace + "_" + *srcPodName + "\""
		}
		fromSrc += " && eth.dst==" + srcPodInfo.StorMAC
		fromSrc += " && eth.src==" + srcPodInfo.MAC
		fromSrc += " && ip4.dst==" + dstSvcInfo.IP
		fromSrc += " && ip4.src==" + srcPodInfo.IP
		fromSrc += " && ip.ttl==64"
		fromSrc += " && " + protocol + ".dst==" + *dstPort + " && " + protocol + ".src==52888'"
		fromSrc += " --lb-dst " + dstSvcInfo.PodIP + ":" + dstSvcInfo.PodPort

		fromSrcCmd := "ovn-trace " + sbcmd + " " + srcPodInfo.NodeName + " " + "--ct=new " + fromSrc

		klog.V(5).Infof("ovn-trace command from src to service cluserIP is %s", fromSrcCmd)
		ovnSrcDstOut, ovnSrcDstErr, err := execInPod(coreclient, restconfig, ovnNamespace, srcPodInfo.OvnKubeContainerPodName, "ovnkube-node", fromSrcCmd, "")
		if err != nil {
			klog.V(1).Infof("Source to Destination ovn-trace error %v stdOut: %s\n stdErr: %s", err, ovnSrcDstOut, ovnSrcDstErr)
			os.Exit(-1)
		}
		klog.V(2).Infof("Source to service clusterIP  ovn-trace Output: %s\n", ovnSrcDstOut)

		successString := "output to \"" + dstSvcInfo.PodNamespace + "_" + dstSvcInfo.PodName + "\""
		if strings.Contains(ovnSrcDstOut, successString) {
			fmt.Printf("ovn-trace indicates success from %s to %s - matched on %s\n", *srcPodName, *dstSvcName, successString)
			klog.V(0).Infof("ovn-trace indicates success from %s to %s - matched on %s\n", *srcPodName, *dstSvcName, successString)
		} else {
			fmt.Printf("ovn-trace indicates failure from %s to %s - %s not matched\n", *srcPodName, *dstSvcName, successString)
			klog.V(0).Infof("ovn-trace indicates failure from %s to %s - %s not matched\n", *srcPodName, *dstSvcName, successString)
			os.Exit(-1)
		}

		// set dst pod name, we'll use this to run through pod-pod tests as if use supplied this pod
		*dstPodName = dstSvcInfo.PodName
		fmt.Printf("using pod %s in service %s to test against\n", dstSvcInfo.PodName, *dstSvcName)
		klog.V(1).Infof("Using pod %s in service %s to test against\n", dstSvcInfo.PodName, *dstSvcName)
	}

	//Now get info needed for the dst Pod
	dstPodInfo, err := getPodInfo(coreclient, restconfig, *dstPodName, ovnNamespace, dstNamespace, nbcmd)
	if err != nil {
		fmt.Printf("Failed to get information from pod %s: %v\n", *dstPodName, err)
		klog.V(1).Infof("Failed to get information from pod %s: %v", *dstPodName, err)
		os.Exit(-1)
	}
	klog.V(5).Infof("dstPodInfo is %v\n", dstPodInfo)

	podsOnSameNode := false
	if srcPodInfo.NodeName == dstPodInfo.NodeName {
		podsOnSameNode = true
	}

	// At least one pod must not be on the Host Network
	if srcPodInfo.HostNetwork && dstPodInfo.HostNetwork {
		fmt.Printf("Both pods cannot be on Host Network; use ping\n")
		os.Exit(-1)
	}

	// ovn-trace from src pod to dst pod

	var fromSrc string

	if srcPodInfo.HostNetwork {
		fromSrc = " 'inport==\"" + srcPodInfo.OVNName + "\""
	} else {
		fromSrc = " 'inport==\"" + srcNamespace + "_" + *srcPodName + "\""
	}
	fromSrc += " && eth.dst==" + srcPodInfo.StorMAC
	fromSrc += " && eth.src==" + srcPodInfo.MAC
	fromSrc += " && ip4.dst==" + dstPodInfo.IP
	fromSrc += " && ip4.src==" + srcPodInfo.IP
	fromSrc += " && ip.ttl==64"
	fromSrc += " && " + protocol + ".dst==" + *dstPort + " && " + protocol + ".src==52888'"

	fromSrcCmd := "ovn-trace " + sbcmd + " " + srcPodInfo.NodeName + " " + fromSrc

	klog.V(5).Infof("ovn-trace command from src to dst is %s", fromSrcCmd)
	ovnSrcDstOut, ovnSrcDstErr, err := execInPod(coreclient, restconfig, ovnNamespace, srcPodInfo.OvnKubeContainerPodName, "ovnkube-node", fromSrcCmd, "")
	if err != nil {
		klog.V(1).Infof("Source to Destination ovn-trace error %v stdOut: %s\n stdErr: %s", err, ovnSrcDstOut, ovnSrcDstErr)
		os.Exit(-1)
	}
	klog.V(2).Infof("Source to Destination ovn-trace Output: %s\n", ovnSrcDstOut)

	var successString string
	if dstPodInfo.HostNetwork {
		// OVN will get as far as this sending node (the src node)
		successString = "output to \"" + types.K8sPrefix + srcPodInfo.NodeName + "\""
	} else {
		successString = "output to \"" + dstNamespace + "_" + *dstPodName + "\""
	}
	if strings.Contains(ovnSrcDstOut, successString) {
		fmt.Printf("ovn-trace indicates success from %s to %s - matched on %s\n", *srcPodName, *dstPodName, successString)
		klog.V(0).Infof("ovn-trace indicates success from %s to %s - matched on %s\n", *srcPodName, *dstPodName, successString)
	} else {
		fmt.Printf("ovn-trace indicates failure from %s to %s - %s not matched\n", *srcPodName, *dstPodName, successString)
		klog.V(0).Infof("ovn-trace indicates failure from %s to %s - %s not matched\n", *srcPodName, *dstPodName, successString)
		os.Exit(-1)
	}

	// Trace from dst pod to src pod

	var fromDst string

	//fromDst := " 'inport==\"" + namespace + "_" + *dstPodName + "\""
	if dstPodInfo.HostNetwork {
		fromDst = " 'inport==\"" + dstPodInfo.OVNName + "\""
	} else {
		fromDst = " 'inport==\"" + dstNamespace + "_" + *dstPodName + "\""
	}
	fromDst += " && eth.dst==" + dstPodInfo.StorMAC
	fromDst += " && eth.src==" + dstPodInfo.MAC
	fromDst += " && ip4.dst==" + srcPodInfo.IP
	fromDst += " && ip4.src==" + dstPodInfo.IP
	fromDst += " && ip.ttl==64"
	fromDst += " && " + protocol + ".src==" + *dstPort + " && " + protocol + ".dst==52888'"

	fromDstCmd := "ovn-trace " + sbcmd + " " + dstPodInfo.NodeName + " " + fromDst

	klog.V(5).Infof("ovn-trace command from dst to src is %s", fromDstCmd)
	ovnDstSrcOut, ovnDstSrcErr, err := execInPod(coreclient, restconfig, ovnNamespace, srcPodInfo.OvnKubeContainerPodName, "ovnkube-node", fromDstCmd, "")
	if err != nil {
		klog.V(1).Infof("Source to Destination ovn-trace error %v stdOut: %s\n stdErr: %s", err, ovnDstSrcOut, ovnDstSrcErr)
		os.Exit(-1)
	}
	klog.V(2).Infof("Destination to Source ovn-trace Output: %s\n", ovnDstSrcOut)

	if srcPodInfo.HostNetwork {
		// OVN will get as far as this sending node (the dst node)
		successString = "output to \"" + types.K8sPrefix + dstPodInfo.NodeName + "\""
	} else {
		successString = "output to \"" + srcNamespace + "_" + *srcPodName + "\""
	}
	if strings.Contains(ovnDstSrcOut, successString) {
		fmt.Printf("ovn-trace indicates success from %s to %s - matched on %s\n", *dstPodName, *srcPodName, successString)
		klog.V(0).Infof("ovn-trace indicates success from %s to %s - matched on %s\n", *dstPodName, *srcPodName, successString)
	} else {
		fmt.Printf("ovn-trace indicates failure from %s to %s - %s not matched\n", *dstPodName, *srcPodName, successString)
		klog.V(0).Infof("ovn-trace indicates failure from %s to %s - %s not matched\n", *dstPodName, *srcPodName, successString)
		os.Exit(-1)
	}

	// ovs-appctl ofproto/trace: src pod to dst pod

	fromSrc = "ofproto/trace br-int"
	fromSrc += " \"in_port=" + srcPodInfo.VethName + ", " + protocol + ","
	fromSrc += " dl_dst=" + srcPodInfo.StorMAC + ","
	fromSrc += " dl_src=" + srcPodInfo.MAC + ","
	fromSrc += " nw_dst=" + dstPodInfo.IP + ","
	fromSrc += " nw_src=" + srcPodInfo.IP + ","
	fromSrc += " nw_ttl=64" + ","
	fromSrc += " " + protocol + "_dst=" + *dstPort + ","
	fromSrc += " " + protocol + "_src=" + "12345\""

	fromSrcCmd = "ovs-appctl " + fromSrc

	klog.V(5).Infof("ovs-appctl ofproto/trace command from src to dst is %s", fromSrcCmd)
	appSrcDstOut, appSrcDstErr, err := execInPod(coreclient, restconfig, ovnNamespace, srcPodInfo.OvnKubeContainerPodName, "ovnkube-node", fromSrcCmd, "")
	if err != nil {
		klog.V(1).Infof("Source to Destination ovs-appctl error %v stdOut: %s\n stdErr: %s", err, appSrcDstOut, appSrcDstErr)
		os.Exit(-1)
	}
	klog.V(2).Infof("Source to Destination ovs-appctl Output: %s\n", appSrcDstOut)

	if podsOnSameNode {
		klog.V(5).Infof("Pods are on the same node %s", dstPodInfo.NodeName)
		// trace will end at the ovs port number of the dest pod
		successString = "output:" + dstPodInfo.PortNum + "\n\nFinal flow:"
	} else if dstPodInfo.HostNetwork {
		klog.V(5).Infof("Dst pod %s is on host network  %s", dstPodInfo.PodName, dstPodInfo.NodeName)
		// trace will end at the ovs port number of the management port of this sending node
		successString = "output:" + srcPodInfo.LocalNum + "\n\nFinal flow:"
	} else {
		klog.V(5).Infof("Pods are on srcNode: %s and dstNode %s", srcPodInfo.NodeName, dstPodInfo.NodeName)
		successString = "-> output to kernel tunnel"
	}

	if strings.Contains(appSrcDstOut, successString) {
		fmt.Printf("ovs-appctl ofproto/trace indicates success from %s to %s - matched on %s\n", *srcPodName, *dstPodName, successString)
		klog.V(0).Infof("ovs-appctl ofproto/trace indicates success from %s to %s - matched on %s\n", *srcPodName, *dstPodName, successString)
	} else {
		fmt.Printf("ovs-appctl ofproto/trace indicates failure from %s to %s - %s not matched\n", *srcPodName, *dstPodName, successString)
		klog.V(0).Infof("ovs-appctl ofproto/trace indicates failure from %s to %s - %s not matched\n", *srcPodName, *dstPodName, successString)
		os.Exit(-1)
	}

	// ovs-appctl ofproto/trace: dst pod to src pod

	fromDst = "ofproto/trace br-int"
	fromDst += " \"in_port=" + dstPodInfo.VethName + ", " + protocol + ","
	fromDst += " dl_dst=" + dstPodInfo.StorMAC + ","
	fromDst += " dl_src=" + dstPodInfo.MAC + ","
	fromDst += " nw_dst=" + srcPodInfo.IP + ","
	fromDst += " nw_src=" + dstPodInfo.IP + ","
	fromDst += " nw_ttl=64" + ","
	fromDst += " " + protocol + "_src=" + *dstPort + ","
	fromDst += " " + protocol + "_dst=" + "12345\""

	fromDstCmd = "ovs-appctl " + fromDst

	klog.V(5).Infof("ovs-appctl ofproto/trace command from dst to src is %s", fromDstCmd)
	appDstSrcOut, appDstSrcErr, err := execInPod(coreclient, restconfig, ovnNamespace, dstPodInfo.OvnKubeContainerPodName, "ovnkube-node", fromDstCmd, "")
	if err != nil {
		klog.V(1).Infof("Destination to Source ovs-appctl error %v stdOut: %s\n stdErr: %s", err, appDstSrcOut, appDstSrcErr)
		os.Exit(-1)
	}
	klog.V(2).Infof("Destination to Source ovs-appctl Output: %s\n", appDstSrcOut)

	if podsOnSameNode {
		klog.V(5).Infof("Pods are on the same node %s", srcPodInfo.NodeName)
		// trace will end at the ovs port number of the dest pod in this test, which is srcPod
		successString = "output:" + srcPodInfo.PortNum + "\n\nFinal flow:"
	} else if srcPodInfo.HostNetwork {
		klog.V(5).Infof("Src pod %s is on host network  %s", srcPodInfo.PodName, srcPodInfo.NodeName)
		// trace will end at the ovs port number of the management port of the sending node, which is dstPod
		successString = "output:" + dstPodInfo.LocalNum + "\n\nFinal flow:"
	} else {
		klog.V(5).Infof("Pods are on dstNode: %s and srcNode %s", dstPodInfo.NodeName, srcPodInfo.NodeName)
		successString = "-> output to kernel tunnel"
	}

	if strings.Contains(appDstSrcOut, successString) {
		fmt.Printf("ovs-appctl ofproto/trace indicates success from %s to %s - matched on %s\n", *dstPodName, *srcPodName, successString)
		klog.V(0).Infof("ovs-appctl ofproto/trace indicates success from %s to %s - matched on %s\n", *dstPodName, *srcPodName, successString)
	} else {
		fmt.Printf("ovs-appctl ofproto/trace indicates failure from %s to %s - %s not matched\n", *dstPodName, *srcPodName, successString)
		klog.V(0).Infof("ovs-appctl ofproto/trace indicates failure from %s to %s - %s not matched\n", *dstPodName, *srcPodName, successString)
		os.Exit(-1)
	}

	// ovn-detrace TODO - workaround until image supports ovs and pyOpenSSL

	installCmd := "pip3 install ovs pyOpenSSL"
	dtraceInstallOut, dtraceInstallErr, err := execInPod(coreclient, restconfig, ovnNamespace, srcPodInfo.OvnKubeContainerPodName, "ovnkube-node", installCmd, "")
	if err != nil {
		klog.V(0).Infof("ovn-detrace error %v stdOut: %s\n stdErr: %s", err, dtraceInstallOut, dtraceInstallErr)
		os.Exit(-1)
	}
	fmt.Printf("install ovn-detrace Output: %s\n", dtraceInstallOut)

	installCmd2 := "pip3 install ovs pyOpenSSL"
	dtraceInstallOut2, dtraceInstallErr2, err := execInPod(coreclient, restconfig, ovnNamespace, dstPodInfo.OvnKubeContainerPodName, "ovnkube-node", installCmd2, "")
	if err != nil {
		klog.V(0).Infof("ovn-detrace error %v stdOut: %s\n stdErr: %s", err, dtraceInstallOut2, dtraceInstallErr2)
		os.Exit(-1)
	}
	fmt.Printf("install ovn-detrace Output: %s\n", dtraceInstallOut2)

	// ovn-detrace src - dst
	fromSrc = "--ovnnb=" + nbUri + " "
	fromSrc += "--ovnsb=" + sbUri + " "
	fromSrc += sslCertKeys + " "
	//fromSrc += "--ovs --ovsdb=unix:/var/run/openvswitch/db.sock "
	fromSrc += "--ovsdb=unix:/var/run/openvswitch/db.sock "

	fromSrcCmd = "ovn-detrace " + fromSrc

	klog.V(5).Infof("ovn-detrace command from src to dst is %s", fromSrcCmd)
	dtraceSrcDstOut, dtraceSrcDstErr, err := execInPod(coreclient, restconfig, ovnNamespace, srcPodInfo.OvnKubeContainerPodName, "ovnkube-node", fromSrcCmd, appSrcDstOut)
	if err != nil {
		klog.V(1).Infof("Source to Destination ovn-detrace error %v stdOut: %s\n stdErr: %s", err, dtraceSrcDstOut, dtraceSrcDstErr)
		os.Exit(-1)
	}
	klog.V(2).Infof("Source to Destination ovn-detrace Completed - Output: %s\n", dtraceSrcDstOut)

	fromDst = "--ovnnb=" + nbUri + " "
	fromDst += "--ovnsb=" + sbUri + " "
	fromDst += sslCertKeys + " "
	//fromDst += "--ovs --ovsdb=unix:/var/run/openvswitch/db.sock "
	fromDst += "--ovsdb=unix:/var/run/openvswitch/db.sock "

	fromDstCmd = "ovn-detrace " + fromDst

	klog.V(5).Infof("ovn-detrace command from dst to src is %s", fromDstCmd)
	dtraceDstSrcOut, dtraceDstSrcErr, err := execInPod(coreclient, restconfig, ovnNamespace, dstPodInfo.OvnKubeContainerPodName, "ovnkube-node", fromDstCmd, appDstSrcOut)
	if err != nil {
		klog.V(1).Infof("Destination to Source ovn-detrace error %v stdOut: %s\n stdErr: %s", err, dtraceDstSrcOut, dtraceDstSrcErr)
		os.Exit(-1)
	}
	klog.V(2).Infof("Destination to Source detrace Completed - Output: %s\n", appDstSrcOut)

	fmt.Println("ovn-trace command Completed normally")
}
