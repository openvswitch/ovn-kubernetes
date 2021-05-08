package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	"github.com/onsi/gomega"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/kubernetes/test/e2e/framework"
	utilnet "k8s.io/utils/net"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	testutils "k8s.io/kubernetes/test/utils"
)

const (
	vxlanPort            = "4789" // IANA assigned VXLAN UDP port - rfc7348
	podNetworkAnnotation = "k8s.ovn.org/pod-networks"
	retryInterval        = 1 * time.Second  // polling interval timer
	retryTimeout         = 40 * time.Second // polling timeout
	ciNetworkName        = "kind"
	agnhostImage         = "k8s.gcr.io/e2e-test-images/agnhost:2.26"
)

type podCondition = func(pod *v1.Pod) (bool, error)

func checkContinuousConnectivity(f *framework.Framework, nodeName, podName, host string, port, timeout int, podChan chan *v1.Pod, errChan chan error) {
	contName := fmt.Sprintf("%s-container", podName)

	command := []string{
		"bash", "-c",
		"set -xe; for i in {1..10}; do nc -vz -w " + strconv.Itoa(timeout) + " " + host + " " + strconv.Itoa(port) + "; sleep 2; done",
	}

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: podName,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    contName,
					Image:   agnhostImage,
					Command: command,
				},
			},
			NodeName:      nodeName,
			RestartPolicy: v1.RestartPolicyNever,
		},
	}
	podClient := f.ClientSet.CoreV1().Pods(f.Namespace.Name)
	_, err := podClient.Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		errChan <- err
		return
	}

	// Wait for pod network setup to be almost ready
	wait.PollImmediate(1*time.Second, 30*time.Second, func() (bool, error) {
		pod, err := podClient.Get(context.Background(), podName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		_, ok := pod.Annotations[podNetworkAnnotation]
		return ok, nil
	})

	err = e2epod.WaitForPodNotPending(f.ClientSet, f.Namespace.Name, podName)
	if err != nil {
		errChan <- err
		return
	}

	podGet, err := podClient.Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		errChan <- err
		return
	}

	podChan <- podGet

	err = e2epod.WaitForPodSuccessInNamespace(f.ClientSet, podName, f.Namespace.Name)

	if err != nil {
		logs, logErr := e2epod.GetPodLogs(f.ClientSet, f.Namespace.Name, pod.Name, contName)
		if logErr != nil {
			framework.Logf("Warning: Failed to get logs from pod %q: %v", pod.Name, logErr)
		} else {
			framework.Logf("pod %s/%s logs:\n%s", f.Namespace.Name, pod.Name, logs)
		}
	}

	errChan <- err
}

// pingCommand is the type to hold ping command.
type pingCommand string

const (
	// ipv4PingCommand is a ping command for IPv4.
	ipv4PingCommand pingCommand = "ping"
	// ipv6PingCommand is a ping command for IPv6.
	ipv6PingCommand pingCommand = "ping6"
)

// Place the workload on the specified node to test external connectivity
func checkConnectivityPingToHost(f *framework.Framework, nodeName, podName, host string, pingCmd pingCommand, timeout int, exGw bool) error {
	contName := fmt.Sprintf("%s-container", podName)
	// Ping options are:
	// -c sends 3 pings
	// -W wait at most 2 seconds for a reply
	// -w timeout
	command := []string{"/bin/sh", "-c"}
	args := []string{fmt.Sprintf("sleep 20; %s -c 3 -W 2 -w %s %s", string(pingCmd), strconv.Itoa(timeout), host)}

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: podName,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    contName,
					Image:   agnhostImage,
					Command: command,
					Args:    args,
				},
			},
			NodeName:      nodeName,
			RestartPolicy: v1.RestartPolicyNever,
		},
	}
	podClient := f.ClientSet.CoreV1().Pods(f.Namespace.Name)
	_, err := podClient.Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	// Wait for pod network setup to be almost ready
	err = wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
		pod, err := podClient.Get(context.Background(), podName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		_, ok := pod.Annotations[podNetworkAnnotation]
		return ok, nil
	})
	// Fail the test if no pod annotation is retrieved
	if err != nil {
		framework.Failf("Error trying to get the pod annotation")
	}

	err = e2epod.WaitForPodSuccessInNamespace(f.ClientSet, podName, f.Namespace.Name)

	if err != nil {
		logs, logErr := e2epod.GetPodLogs(f.ClientSet, f.Namespace.Name, pod.Name, contName)
		if logErr != nil {
			framework.Logf("Warning: Failed to get logs from pod %q: %v", pod.Name, logErr)
		} else {
			framework.Logf("pod %s/%s logs:\n%s", f.Namespace.Name, pod.Name, logs)
		}
	}

	return err
}

// Place the workload on the specified node and return pod gw route
func getPodGWRoute(f *framework.Framework, nodeName string, podName string) net.IP {
	command := []string{"bash", "-c", "sleep 20000"}
	contName := fmt.Sprintf("%s-container", podName)
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: podName,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    contName,
					Image:   agnhostImage,
					Command: command,
				},
			},
			NodeName:      nodeName,
			RestartPolicy: v1.RestartPolicyNever,
		},
	}
	podClient := f.ClientSet.CoreV1().Pods(f.Namespace.Name)
	_, err := podClient.Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		framework.Failf("Error trying to create pod")
	}

	// Wait for pod network setup to be almost ready
	wait.PollImmediate(1*time.Second, 30*time.Second, func() (bool, error) {
		podGet, err := podClient.Get(context.Background(), podName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		if podGet.Annotations != nil && podGet.Annotations[podNetworkAnnotation] != "" {
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		framework.Failf("Error trying to get the pod annotations")
	}

	podGet, err := podClient.Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		framework.Failf("Error trying to get the pod object")
	}
	annotation, err := unmarshalPodAnnotation(podGet.Annotations)
	if err != nil {
		framework.Failf("Error trying to unmarshal pod annotations")
	}

	return annotation.Gateways[0]
}

// Create a pod on the specified node using the agnostic host image
func createGenericPod(f *framework.Framework, podName, nodeSelector, namespace string, command []string) (*v1.Pod, error) {
	return createPod(f, podName, nodeSelector, namespace, command, nil)
}

// Create a pod on the specified node using the agnostic host image
func createGenericPodWithLabel(f *framework.Framework, podName, nodeSelector, namespace string, command []string, labels map[string]string) (*v1.Pod, error) {
	return createPod(f, podName, nodeSelector, namespace, command, labels)
}

func createClusterExternalContainer(containerName string, containerImage string, dockerArgs []string, entrypointArgs []string) (string, string) {
	args := []string{"docker", "run", "-itd"}
	args = append(args, dockerArgs...)
	args = append(args, []string{"--name", containerName, containerImage}...)
	args = append(args, entrypointArgs...)
	_, err := runCommand(args...)
	if err != nil {
		framework.Failf("failed to start external test container: %v", err)
	}
	ipv4, err := runCommand("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", containerName)
	if err != nil {
		framework.Failf("failed to inspect external test container for its IP: %v", err)
	}
	ipv6, err := runCommand("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}", containerName)
	if err != nil {
		framework.Failf("failed to inspect external test container for its IP (v6): %v", err)
	}
	return strings.Trim(ipv4, "\n"), strings.Trim(ipv6, "\n")
}

func deleteClusterExternalContainer(containerName string) {
	_, err := runCommand("docker", "rm", "-f", containerName)
	if err != nil {
		framework.Failf("failed to delete external test container, err: %v", err)
	}
}

func updateNamespace(f *framework.Framework, namespace *v1.Namespace) {
	_, err := f.ClientSet.CoreV1().Namespaces().Update(context.Background(), namespace, metav1.UpdateOptions{})
	framework.ExpectNoError(err, fmt.Sprintf("unable to update namespace: %s, err: %v", namespace.Name, err))
}

func updatePod(f *framework.Framework, pod *v1.Pod) {
	_, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Update(context.Background(), pod, metav1.UpdateOptions{})
	framework.ExpectNoError(err, fmt.Sprintf("unable to update pod: %s, err: %v", pod.Name, err))
}
func getPod(f *framework.Framework, podName string) *v1.Pod {
	pod, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(context.Background(), podName, metav1.GetOptions{})
	framework.ExpectNoError(err, fmt.Sprintf("unable to get pod: %s, err: %v", podName, err))
	return pod
}

// Create a pod on the specified node using the agnostic host image
func createPod(f *framework.Framework, podName, nodeSelector, namespace string, command []string, labels map[string]string, options ...func(*v1.Pod)) (*v1.Pod, error) {

	contName := fmt.Sprintf("%s-container", podName)

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podName,
			Labels: labels,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    contName,
					Image:   agnhostImage,
					Command: command,
				},
			},
			NodeName:      nodeSelector,
			RestartPolicy: v1.RestartPolicyNever,
		},
	}

	for _, o := range options {
		o(pod)
	}

	podClient := f.ClientSet.CoreV1().Pods(namespace)
	res, err := podClient.Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		framework.Logf("Warning: Failed to create pod %s %v", pod.Name, err)
		return nil, errors.Wrapf(err, "Failed to create pod %s %s", pod.Name, namespace)
	}

	err = e2epod.WaitForPodRunningInNamespace(f.ClientSet, res)

	if err != nil {
		logs, logErr := e2epod.GetPodLogs(f.ClientSet, namespace, pod.Name, contName)
		if logErr != nil {
			framework.Logf("Warning: Failed to get logs from pod %q: %v", pod.Name, logErr)
		} else {
			framework.Logf("pod %s/%s logs:\n%s", namespace, pod.Name, logs)
		}
	}
	// Need to get it again to ensure the ip addresses are filled
	res, err = podClient.Get(context.Background(), pod.Name, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to get pod %s %s", pod.Name, namespace)
	}
	return res, nil
}

// Get the IP address of a pod in the specified namespace
func getPodAddress(podName, namespace string) string {
	podIP, err := framework.RunKubectl(namespace, "get", "pods", podName, "--template={{.status.podIP}}")
	if err != nil {
		framework.Failf("Unable to retrieve the IP for pod %s %v", podName, err)
	}
	return podIP
}

// Get the IP address of the API server
func getApiAddress() string {
	apiServerIP, err := framework.RunKubectl("default", "get", "svc", "kubernetes", "-o", "jsonpath='{.spec.clusterIP}'")
	apiServerIP = strings.Trim(apiServerIP, "'")
	if err != nil {
		framework.Failf("Error: unable to get API-server IP address, err:  %v", err)
	}
	apiServer := net.ParseIP(apiServerIP)
	if apiServer == nil {
		framework.Failf("Error: unable to parse API-server IP address:  %s", apiServerIP)
	}
	return apiServer.String()
}

// runCommand runs the cmd and returns the combined stdout and stderr
func runCommand(cmd ...string) (string, error) {
	output, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to run %q: %s (%s)", strings.Join(cmd, " "), err, output)
	}
	return string(output), nil
}

var _ = ginkgo.Describe("e2e control plane", func() {
	var svcname = "nettest"

	f := framework.NewDefaultFramework(svcname)

	ginkgo.BeforeEach(func() {
		// Assert basic external connectivity.
		// Since this is not really a test of kubernetes in any way, we
		// leave it as a pre-test assertion, rather than a Ginko test.
		ginkgo.By("Executing a successful http request from the external internet")
		resp, err := http.Get("http://google.com")
		if err != nil {
			framework.Failf("Unable to connect/talk to the internet: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			framework.Failf("Unexpected error code, expected 200, got, %v (%v)", resp.StatusCode, resp)
		}
	})

	ginkgo.It("should provide Internet connection continuously when ovn-k8s pod is killed", func() {
		ginkgo.By("Running container which tries to connect to 8.8.8.8 in a loop")

		podChan, errChan := make(chan *v1.Pod), make(chan error)
		go checkContinuousConnectivity(f, "", "connectivity-test-continuous", "8.8.8.8", 53, 30, podChan, errChan)

		testPod := <-podChan
		framework.Logf("Test pod running on %q", testPod.Spec.NodeName)

		time.Sleep(5 * time.Second)

		podClient := f.ClientSet.CoreV1().Pods("ovn-kubernetes")

		podList, _ := podClient.List(context.Background(), metav1.ListOptions{})
		podName := ""
		for _, pod := range podList.Items {
			if strings.HasPrefix(pod.Name, "ovnkube-node") && pod.Spec.NodeName == testPod.Spec.NodeName {
				podName = pod.Name
				break
			}
		}

		err := podClient.Delete(context.Background(), podName, metav1.DeleteOptions{})
		framework.ExpectNoError(err, "should delete ovnkube-node pod")
		framework.Logf("Deleted ovnkube-node %q", podName)

		framework.ExpectNoError(<-errChan)
	})

	ginkgo.It("should provide Internet connection continuously when master is killed", func() {
		ginkgo.By("Running container which tries to connect to 8.8.8.8 in a loop")

		podChan, errChan := make(chan *v1.Pod), make(chan error)
		go checkContinuousConnectivity(f, "", "connectivity-test-continuous", "8.8.8.8", 53, 30, podChan, errChan)

		testPod := <-podChan
		framework.Logf("Test pod running on %q", testPod.Spec.NodeName)

		time.Sleep(5 * time.Second)

		podClient := f.ClientSet.CoreV1().Pods("ovn-kubernetes")

		podList, _ := podClient.List(context.Background(), metav1.ListOptions{})
		podName := ""
		for _, pod := range podList.Items {
			if strings.HasPrefix(pod.Name, "ovnkube-master") {
				podName = pod.Name
				break
			}
		}

		err := podClient.Delete(context.Background(), podName, metav1.DeleteOptions{})
		framework.ExpectNoError(err, "should delete ovnkube-master pod")
		framework.Logf("Deleted ovnkube-master %q", podName)

		framework.ExpectNoError(<-errChan)
	})
	ginkgo.It("should provide connection to external host by DNS name from a pod", func() {
		ginkgo.By("Running container which tries to connect to www.google.com. in a loop")

		podChan, errChan := make(chan *v1.Pod), make(chan error)
		go checkContinuousConnectivity(f, "", "connectivity-test-continuous", "www.google.com.", 443, 30, podChan, errChan)

		testPod := <-podChan
		framework.Logf("Test pod running on %q", testPod.Spec.NodeName)

		time.Sleep(10 * time.Second)

		framework.ExpectNoError(<-errChan)
	})
})

// Test pod connectivity to other host IP addresses
var _ = ginkgo.Describe("test e2e pod connectivity to host addresses", func() {
	const (
		ovnWorkerNode string = "ovn-worker"
		targetIP      string = "123.123.123.123"
		svcname       string = "node-e2e-to-host"
	)

	f := framework.NewDefaultFramework(svcname)

	ginkgo.AfterEach(func() {
		_, _ = runCommand("docker", "exec", ovnWorkerNode, "ip", "a", "del",
			fmt.Sprintf("%s/32", targetIP), "dev", "breth0")
	})

	ginkgo.It("Should validate connectivity from a pod to a non-node host address on same node", func() {
		// Add another IP address to the worker
		_, err := runCommand("docker", "exec", ovnWorkerNode, "ip", "a", "add",
			fmt.Sprintf("%s/32", targetIP), "dev", "breth0")
		framework.ExpectNoError(err, "failed to add IP to %s", ovnWorkerNode)

		// Spin up another pod that attempts to reach the previously started pod on separate nodes
		framework.ExpectNoError(
			checkConnectivityPingToHost(f, ovnWorkerNode, "e2e-src-ping-pod", targetIP, ipv4PingCommand, 30, false))
	})
})

// Test e2e inter-node connectivity over br-int
var _ = ginkgo.Describe("test e2e inter-node connectivity between worker nodes", func() {
	const (
		svcname          string = "inter-node-e2e"
		ovnNs            string = "ovn-kubernetes"
		ovnWorkerNode    string = "ovn-worker"
		ovnWorkerNode2   string = "ovn-worker2"
		ovnHaWorkerNode2 string = "ovn-control-plane2"
		ovnHaWorkerNode3 string = "ovn-control-plane3"
		ovnContainer     string = "ovnkube-node"
		jsonFlag         string = "-o=jsonpath='{.items..metadata.name}'"
		getPodIPRetry    int    = 20
	)

	var (
		haMode    bool
		labelFlag = fmt.Sprintf("name=%s", ovnContainer)
	)

	f := framework.NewDefaultFramework(svcname)

	// Determine which KIND environment is running by querying the running nodes
	ginkgo.BeforeEach(func() {
		fieldSelectorFlag := fmt.Sprintf("--field-selector=spec.nodeName=%s", ovnWorkerNode)
		fieldSelectorHaFlag := fmt.Sprintf("--field-selector=spec.nodeName=%s", ovnHaWorkerNode2)

		// Determine if the kind deployment is in HA mode or non-ha mode based on node naming
		kubectlOut, err := framework.RunKubectl(ovnNs, "get", "pods", "-l", labelFlag, jsonFlag, fieldSelectorFlag)
		if err != nil {
			framework.Failf("Expected container %s running on %s error %v", ovnContainer, ovnWorkerNode, err)
		}
		if kubectlOut == "''" {
			haMode = true
			kubectlOut, err = framework.RunKubectl(ovnNs, "get", "pods", "-l", labelFlag, jsonFlag, fieldSelectorHaFlag)
			if err != nil {
				framework.Failf("Expected container %s running on %s error %v", ovnContainer, ovnHaWorkerNode2, err)
			}
		}
		// Fail the test if no pod is matched within the specified node
		if kubectlOut == "''" {
			framework.Failf("Unable to locate container %s on any known nodes", ovnContainer)
		}
	})

	ginkgo.It("Should validate connectivity within a namespace of pods on separate nodes", func() {
		var validIP net.IP
		var pingTarget string
		var ciWorkerNodeSrc string
		var ciWorkerNodeDst string
		dstPingPodName := "e2e-dst-ping-pod"
		command := []string{"bash", "-c", "sleep 20000"}
		// non-ha ci mode runs a named set of nodes with a prefix of ovn-worker
		ciWorkerNodeSrc = ovnWorkerNode
		ciWorkerNodeDst = ovnWorkerNode2
		// ha ci mode runs a named set of nodes with a prefix of ovn-control-plane
		if haMode {
			framework.Logf("Detected a HA mode KIND environment")
			ciWorkerNodeSrc = ovnHaWorkerNode2
			ciWorkerNodeDst = ovnHaWorkerNode3
		}
		ginkgo.By(fmt.Sprintf("Creating a container on node %s and verifying connectivity to a pod on node %s", ciWorkerNodeSrc, ciWorkerNodeDst))

		// Create the pod that will be used as the destination for the connectivity test
		createGenericPod(f, dstPingPodName, ciWorkerNodeDst, f.Namespace.Name, command)

		// There is a condition somewhere with e2e WaitForPodNotPending that returns ready
		// before calling for the IP address will succeed. This simply adds some retries.
		for i := 1; i < getPodIPRetry; i++ {
			pingTarget = getPodAddress(dstPingPodName, f.Namespace.Name)
			validIP = net.ParseIP(pingTarget)
			if validIP != nil {
				framework.Logf("Destination ping target for %s is %s", dstPingPodName, pingTarget)
				break
			}
			time.Sleep(time.Second * 4)
			framework.Logf("Retry attempt %d to get pod IP from initializing pod %s", i, dstPingPodName)
		}
		// Fail the test if no address is ever retrieved
		if validIP == nil {
			framework.Failf("Warning: Failed to get an IP for target pod %s, test will fail", dstPingPodName)
		}
		// Spin up another pod that attempts to reach the previously started pod on separate nodes
		framework.ExpectNoError(
			checkConnectivityPingToHost(f, ciWorkerNodeSrc, "e2e-src-ping-pod", pingTarget, ipv4PingCommand, 30, false))
	})
})

var _ = ginkgo.Describe("e2e egress IP validation", func() {
	const (
		podHTTPPort          string = "8080"
		svcname              string = "egressip"
		targetNodeName       string = "egressTargetNode-allowed"
		deniedTargetNodeName string = "egressTargetNode-denied"
		egressIPYaml         string = "egressip.yaml"
		egressFirewallYaml   string = "egressfirewall.yaml"
		waitInterval                = 3 * time.Second
	)

	type node struct {
		name   string
		nodeIP string
	}

	podEgressLabel := map[string]string{
		"wants": "egress",
	}

	var (
		egress1Node, egress2Node, pod1Node, pod2Node, targetNode, deniedTargetNode node
		pod1Name                                                                   = "e2e-egressip-pod-1"
		pod2Name                                                                   = "e2e-egressip-pod-2"
	)

	targetPodAndTest := func(namespace, fromName, toName, toIP string) wait.ConditionFunc {
		return func() (bool, error) {
			stdout, err := framework.RunKubectl(namespace, "exec", fromName, "--", "curl", "--connect-timeout", "2", fmt.Sprintf("%s/hostname", net.JoinHostPort(toIP, podHTTPPort)))
			if err != nil || stdout != toName {
				framework.Logf("Error: attempted connection to pod %s found err:  %v", toName, err)
				return false, nil
			}
			return true, nil
		}
	}

	targetAPIServiceAndTest := func(namespace string, podNames []string) wait.ConditionFunc {
		return func() (bool, error) {
			for _, podName := range podNames {
				_, err := framework.RunKubectl(namespace, "exec", podName, "--", "curl", "--connect-timeout", "2", "-k", fmt.Sprintf("https://%s/version", net.JoinHostPort(getApiAddress(), "443")))
				if err != nil {
					framework.Logf("Error: attempted connection to API server found err:  %v", err)
					return false, nil
				}
			}
			return true, nil
		}
	}

	targetExternalContainerAndTest := func(targetNode node, podName, podNamespace string, expectSuccess bool, verifyIPs []string) wait.ConditionFunc {
		return func() (bool, error) {
			_, err := framework.RunKubectl(podNamespace, "exec", podName, "--", "curl", "--connect-timeout", "2", net.JoinHostPort(targetNode.nodeIP, "80"))
			if err != nil {
				if !expectSuccess {
					// curl should timeout with a string containing this error, and this should be the case if we expect a failure
					if !strings.Contains(err.Error(), "Connection timed out") {
						framework.Logf("the test expected netserver container to not be able to connect, but it did with another error, err : %v", err)
						return false, nil
					}
					return true, nil
				}
				return false, nil
			}
			targetNodeLogs, err := runCommand("docker", "logs", targetNode.name)
			if err != nil {
				framework.Logf("failed to inspect logs in test container: %v", err)
				return false, nil
			}
			targetNodeLogs = strings.TrimSuffix(targetNodeLogs, "\n")
			logLines := strings.Split(targetNodeLogs, "\n")
			lastLine := logLines[len(logLines)-1]
			var found bool
			for _, verifyIP := range verifyIPs {
				if strings.Contains(lastLine, verifyIP) {
					found = true
					break
				}
			}
			if !found && expectSuccess {
				framework.Logf("the test external container did not have any trace of the IPs: %v being logged, last logs: %s", verifyIPs, logLines[len(logLines)-1])
				return false, nil
			}
			if !expectSuccess && found {
				framework.Logf("the test external container did have a trace of the IPs: %v being logged, it should not have, last logs: %s", verifyIPs, logLines[len(logLines)-1])
				return false, nil
			}
			return true, nil
		}
	}

	type egressIPStatus struct {
		Node     string `json:"node"`
		EgressIP string `json:"egressIP"`
	}

	type egressIP struct {
		Status struct {
			Items []egressIPStatus `json:"items"`
		} `json:"status"`
	}
	type egressIPs struct {
		Items []egressIP `json:"items"`
	}

	testStatus := func() []egressIPStatus {
		egressIPs := egressIPs{}
		egressIPStdout, err := framework.RunKubectl("default", "get", "eip", "-o", "json")
		if err != nil {
			framework.Logf("Error: failed to get the EgressIP object, err: %v", err)
			return nil
		}
		json.Unmarshal([]byte(egressIPStdout), &egressIPs)
		if len(egressIPs.Items) > 1 {
			framework.Failf("Didn't expect to retrieve more than one egress IP during the execution of this test, saw: %v", len(egressIPs.Items))
		}
		return egressIPs.Items[0].Status.Items
	}

	verifyEgressIPStatusLengthEquals := func(statusLength int) []egressIPStatus {
		var statuses []egressIPStatus
		err := wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
			statuses = testStatus()
			return len(statuses) == statusLength, nil
		})
		if err != nil {
			framework.Failf("Error: expected to have %v egress IP assignment, got: %v", statusLength, len(statuses))
		}
		return statuses
	}

	f := framework.NewDefaultFramework(svcname)

	// Determine what mode the CI is running in and get relevant endpoint information for the tests
	ginkgo.BeforeEach(func() {
		nodes, err := e2enode.GetBoundedReadySchedulableNodes(f.ClientSet, 2)
		framework.ExpectNoError(err)
		if len(nodes.Items) < 2 {
			framework.Failf("Test requires >= 2 Ready nodes, but there are only %v nodes", len(nodes.Items))
		}
		ips := e2enode.CollectAddresses(nodes, v1.NodeInternalIP)
		egress1Node = node{
			name:   nodes.Items[0].Name,
			nodeIP: ips[0],
		}
		egress2Node = node{
			name:   nodes.Items[1].Name,
			nodeIP: ips[1],
		}
		pod1Node = node{
			name:   nodes.Items[0].Name,
			nodeIP: ips[0],
		}
		pod2Node = node{
			name:   nodes.Items[1].Name,
			nodeIP: ips[1],
		}
		targetNode = node{
			name: targetNodeName,
		}
		deniedTargetNode = node{
			name: deniedTargetNodeName,
		}
		if utilnet.IsIPv6String(egress1Node.nodeIP) {
			_, targetNode.nodeIP = createClusterExternalContainer(targetNode.name, "docker.io/httpd", []string{"--network", ciNetworkName, "-P"}, []string{})
			_, deniedTargetNode.nodeIP = createClusterExternalContainer(deniedTargetNode.name, "docker.io/httpd", []string{"--network", ciNetworkName, "-P"}, []string{})
		} else {
			targetNode.nodeIP, _ = createClusterExternalContainer(targetNode.name, "docker.io/httpd", []string{"--network", ciNetworkName, "-P"}, []string{})
			deniedTargetNode.nodeIP, _ = createClusterExternalContainer(deniedTargetNode.name, "docker.io/httpd", []string{"--network", ciNetworkName, "-P"}, []string{})
		}
	})

	ginkgo.AfterEach(func() {
		framework.RunKubectlOrDie("default", "delete", "eip", svcname)
		framework.RunKubectlOrDie("default", "label", "node", egress1Node.name, "k8s.ovn.org/egress-assignable-")
		framework.RunKubectlOrDie("default", "label", "node", egress2Node.name, "k8s.ovn.org/egress-assignable-")
		deleteClusterExternalContainer(targetNode.name)
		deleteClusterExternalContainer(deniedTargetNode.name)
	})

	// Validate the egress IP by creating a httpd container on the kind networking
	// (effectively seen as "outside" the cluster) and curl it from a pod in the cluster
	// which matches the egress IP stanza.

	/* This test does the following:
	   0. Add the "k8s.ovn.org/egress-assignable" label to two nodes
	   1. Create an EgressIP object with two egress IPs defined
	   2. Check that the status is of length two and both are assigned to different nodes
	   3. Create two pods matching the EgressIP: one running on each of the egress nodes
	   4. Check connectivity from both to an external "node" and verify that the IP is one of the two above
	   5. Check connectivity from one pod to the other and verify that the connection is achieved
	   6. Check connectivity from both pods to the api-server (running hostNetwork:true) and verifying that the connection is achieved
	   7. Update one of the pods, unmatching the EgressIP
	   8. Check connectivity from that one to an external "node" and verify that the IP is the node IP.
	   9. Check connectivity from the other one to an external "node" and verify that the IP is one of the egress IPs.
	   10. Remove the node label off one of the egress node
	   11. Check that the status is of length one
	   12. Check connectivity from the remaining pod to an external "node" and verify that the IP is one of the egress IPs.
	   13. Remove the node label off the last egress node
	   14. Check that the status is of length zero
	   15. Check connectivity from the remaining pod to an external "node" and verify that the IP is the node IP.
	   16. Re-add the label to one of the egress nodes
	   17. Check that the status is of length one
	   18. Check connectivity from the remaining pod to an external "node" and verify that the IP is one of the egress IPs.
	*/
	ginkgo.It("Should validate the egress IP functionality against remote hosts", func() {

		command := []string{"/agnhost", "netexec", fmt.Sprintf("--http-port=%s", podHTTPPort)}

		ginkgo.By("0. Add the \"k8s.ovn.org/egress-assignable\" label to two nodes")
		framework.AddOrUpdateLabelOnNode(f.ClientSet, egress1Node.name, "k8s.ovn.org/egress-assignable", "dummy")
		framework.AddOrUpdateLabelOnNode(f.ClientSet, egress2Node.name, "k8s.ovn.org/egress-assignable", "dummy")

		podNamespace := f.Namespace
		podNamespace.Labels = map[string]string{
			"name": f.Namespace.Name,
		}
		updateNamespace(f, podNamespace)

		ginkgo.By("1. Create an EgressIP object with two egress IPs defined")
		dupIP := func(ip net.IP) net.IP {
			dup := make(net.IP, len(ip))
			copy(dup, ip)
			return dup
		}
		// Assign the egress IP without conflicting with any node IP,
		// the kind subnet is /16 or /64 so the following should be fine.
		egressNodeIP := net.ParseIP(egress1Node.nodeIP)
		egressIP1 := dupIP(egressNodeIP)
		egressIP1[len(egressIP1)-2]++
		egressIP2 := dupIP(egressNodeIP)
		egressIP2[len(egressIP2)-2]++
		egressIP2[len(egressIP2)-1]++

		var egressIPConfig = fmt.Sprintf(`apiVersion: k8s.ovn.org/v1
kind: EgressIP
metadata:
    name: ` + svcname + `
spec:
    egressIPs:
    - ` + egressIP1.String() + `
    - ` + egressIP2.String() + `
    podSelector:
        matchLabels:
            wants: egress
    namespaceSelector:
        matchLabels:
            name: ` + f.Namespace.Name + `
`)
		if err := ioutil.WriteFile(egressIPYaml, []byte(egressIPConfig), 0644); err != nil {
			framework.Failf("Unable to write CRD config to disk: %v", err)
		}
		defer func() {
			if err := os.Remove(egressIPYaml); err != nil {
				framework.Logf("Unable to remove the CRD config from disk: %v", err)
			}
		}()

		framework.Logf("Create the EgressIP configuration")
		framework.RunKubectlOrDie("default", "create", "-f", egressIPYaml)

		ginkgo.By("2. Check that the status is of length two and both are assigned to different nodes")
		statuses := verifyEgressIPStatusLengthEquals(2)
		if statuses[0].Node == statuses[1].Node {
			framework.Failf("Step 2. Check that the status is of length two and both are assigned to different nodess, failed, err: both egress IPs have been assigned to the same node")
		}

		ginkgo.By("3. Create two pods matching the EgressIP: one running on each of the egress nodes")
		createGenericPodWithLabel(f, pod1Name, pod1Node.name, f.Namespace.Name, command, podEgressLabel)
		createGenericPodWithLabel(f, pod2Name, pod2Node.name, f.Namespace.Name, command, podEgressLabel)

		err := wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
			for _, podName := range []string{pod1Name, pod2Name} {
				kubectlOut := getPodAddress(podName, f.Namespace.Name)
				srcIP := net.ParseIP(kubectlOut)
				if srcIP == nil {
					return false, nil
				}
			}
			return true, nil
		})
		framework.ExpectNoError(err, "Step 3. Create two pods matching the EgressIP: one running on each of the egress nodes, failed, err: %v", err)

		pod2IP := getPodAddress(pod2Name, f.Namespace.Name)

		ginkgo.By("4. Check connectivity from both to an external \"node\" and verify that the IP is one of the two above")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod1Name, podNamespace.Name, true, []string{egressIP1.String(), egressIP2.String()}))
		framework.ExpectNoError(err, "Step 4. Check connectivity from first to an external \"node\" and verify that the IP is one of the two above, failed: %v", err)
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod2Name, podNamespace.Name, true, []string{egressIP1.String(), egressIP2.String()}))
		framework.ExpectNoError(err, "Step 4. Check connectivity from second to an external \"node\" and verify that the IP is one of the two above, failed: %v", err)

		ginkgo.By("5. Check connectivity from one pod to the other and verify that the connection is achieved")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetPodAndTest(f.Namespace.Name, pod1Name, pod2Name, pod2IP))
		framework.ExpectNoError(err, "Step 5. Check connectivity from one pod to the other and verify that the connection is achieved, failed, err: %v", err)

		ginkgo.By("6. Check connectivity from both pods to the api-server (running hostNetwork:true) and verifying that the connection is achieved")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetAPIServiceAndTest(podNamespace.Name, []string{pod1Name, pod2Name}))
		framework.ExpectNoError(err, "Step 6. Check connectivity from both pods to the api-server (running hostNetwork:true) and verifying that the connection is achieved, failed, err: %v", err)

		ginkgo.By("7. Update one of the pods, unmatching the EgressIP")
		pod2 := getPod(f, pod2Name)
		pod2.Labels = map[string]string{}
		updatePod(f, pod2)

		ginkgo.By("8. Check connectivity from that one to an external \"node\" and verify that the IP is the node IP.")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod2Name, podNamespace.Name, true, []string{pod2Node.nodeIP}))
		framework.ExpectNoError(err, "Step 8. Check connectivity from that one to an external \"node\" and verify that the IP is the node IP, failed, err: %v", err)

		ginkgo.By("9. Check connectivity from the other one to an external \"node\" and verify that the IP is one of the egress IPs.")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod1Name, podNamespace.Name, true, []string{egressIP1.String(), egressIP2.String()}))
		framework.ExpectNoError(err, "Step 9. Check connectivity from the other one to an external \"node\" and verify that the IP is one of the egress IPs, failed, err: %v", err)

		ginkgo.By("10. Remove the node label off one of the egress node")
		framework.RemoveLabelOffNode(f.ClientSet, egress1Node.name, "k8s.ovn.org/egress-assignable")

		ginkgo.By("11. Check that the status is of length one")
		statuses = verifyEgressIPStatusLengthEquals(1)

		ginkgo.By("12. Check connectivity from the remaining pod to an external \"node\" and verify that the IP is one of the egress IPs.")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod1Name, podNamespace.Name, true, []string{statuses[0].EgressIP}))
		framework.ExpectNoError(err, "Step 12. Check connectivity from the remaining pod to an external \"node\" and verify that the IP is one of the egress IPs, failed, err: %v", err)

		ginkgo.By("13. Remove the node label off the last egress node")
		framework.RemoveLabelOffNode(f.ClientSet, egress2Node.name, "k8s.ovn.org/egress-assignable")

		ginkgo.By("14. Check that the status is of length zero")
		statuses = verifyEgressIPStatusLengthEquals(0)

		ginkgo.By("15. Check connectivity from the remaining pod to an external \"node\" and verify that the IP is the node IP.")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod1Name, podNamespace.Name, true, []string{pod1Node.nodeIP}))
		framework.ExpectNoError(err, "Step  15. Check connectivity from the remaining pod to an external \"node\" and verify that the IP is the node IP, failed, err: %v", err)

		ginkgo.By("16. Re-add the label to one of the egress nodes")
		framework.AddOrUpdateLabelOnNode(f.ClientSet, egress2Node.name, "k8s.ovn.org/egress-assignable", "dummy")

		ginkgo.By("17. Check that the status is of length one")
		statuses = verifyEgressIPStatusLengthEquals(1)

		ginkgo.By("18. Check connectivity from the remaining pod to an external \"node\" and verify that the IP is one of the egress IPs.")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod1Name, podNamespace.Name, true, []string{egressIP1.String(), egressIP2.String()}))
		framework.ExpectNoError(err, "Step 18. Check connectivity from the remaining pod to an external \"node\" and verify that the IP is one of the egress IPs, failed, err: %v", err)
	})

	// Validate the egress IP works with egress firewall by creating two httpd
	// containers on the kind networking (effectively seen as "outside" the cluster)
	// and curl them from a pod in the cluster which matches the egress IP stanza.
	// The IP allowed by the egress firewall rule should work, the other not.

	/* This test does the following:
	   0. Add the "k8s.ovn.org/egress-assignable" label to one nodes
	   1. Create an EgressIP object with one egress IP defined
	   2. Create an EgressFirewall object with one allow rule and one "block-all" rule defined
	   3. Create two pods matching both egress firewall and egress IP
	   4. Check connectivity to the blocked IP and verify that it fails
	   5. Check connectivity to the allowed IP and verify it has the egress IP
	   6. Check connectivity to the kubernetes API IP and verify that it works
	   7. Check connectivity to the other pod IP and verify that it works
	*/
	ginkgo.It("Should validate the egress IP functionality against remote hosts with egress firewall applied", func() {

		command := []string{"/agnhost", "netexec", fmt.Sprintf("--http-port=%s", podHTTPPort)}

		ginkgo.By("0. Add the \"k8s.ovn.org/egress-assignable\" label to one nodes")
		framework.AddOrUpdateLabelOnNode(f.ClientSet, egress1Node.name, "k8s.ovn.org/egress-assignable", "dummy")

		podNamespace := f.Namespace
		podNamespace.Labels = map[string]string{
			"name": f.Namespace.Name,
		}
		updateNamespace(f, podNamespace)

		ginkgo.By("1. Create an EgressIP object with one egress IP defined")
		dupIP := func(ip net.IP) net.IP {
			dup := make(net.IP, len(ip))
			copy(dup, ip)
			return dup
		}
		// Assign the egress IP without conflicting with any node IP,
		// the kind subnet is /16 or /64 so the following should be fine.
		egressNodeIP := net.ParseIP(egress1Node.nodeIP)
		egressIP := dupIP(egressNodeIP)
		egressIP[len(egressIP)-2]++

		var egressIPConfig = `apiVersion: k8s.ovn.org/v1
kind: EgressIP
metadata:
    name: ` + svcname + `
spec:
    egressIPs:
    - ` + egressIP.String() + `
    podSelector:
        matchLabels:
            wants: egress
    namespaceSelector:
        matchLabels:
            name: ` + f.Namespace.Name + `
`

		if err := ioutil.WriteFile(egressIPYaml, []byte(egressIPConfig), 0644); err != nil {
			framework.Failf("Unable to write CRD config to disk: %v", err)
		}

		defer func() {
			if err := os.Remove(egressIPYaml); err != nil {
				framework.Logf("Unable to remove the CRD config from disk: %v", err)
			}
		}()

		framework.Logf("Create the EgressIP configuration")
		framework.RunKubectlOrDie("default", "create", "-f", egressIPYaml)

		ginkgo.By("2. Create an EgressFirewall object with one allow rule and one \"block-all\" rule defined")

		var firewallAllowNode, firewallDenyAll string
		if utilnet.IsIPv6String(targetNode.nodeIP) {
			firewallAllowNode = targetNode.nodeIP + "/128"
			firewallDenyAll = "::/0"
		} else {
			firewallAllowNode = targetNode.nodeIP + "/32"
			firewallDenyAll = "0.0.0.0/0"
		}

		var egressFirewallConfig = fmt.Sprintf(`apiVersion: k8s.ovn.org/v1
kind: EgressFirewall
metadata:
  name: default
  namespace: ` + f.Namespace.Name + ` 
spec:
  egress:
  - type: Allow
    to:
      cidrSelector: ` + firewallAllowNode + `
  - type: Deny
    to:
      cidrSelector: ` + firewallDenyAll + `
`)

		if err := ioutil.WriteFile(egressFirewallYaml, []byte(egressFirewallConfig), 0644); err != nil {
			framework.Failf("Unable to write CRD config to disk: %v", err)
		}

		defer func() {
			if err := os.Remove(egressFirewallYaml); err != nil {
				framework.Logf("Unable to remove the CRD config from disk: %v", err)
			}
		}()

		framework.RunKubectlOrDie(f.Namespace.Name, "create", "-f", egressFirewallYaml)

		ginkgo.By("3. Create two pods matching both egress firewall and egress IP")
		createGenericPodWithLabel(f, pod1Name, pod1Node.name, f.Namespace.Name, command, podEgressLabel)
		createGenericPodWithLabel(f, pod2Name, pod2Node.name, f.Namespace.Name, command, podEgressLabel)

		err := wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
			for _, podName := range []string{pod1Name, pod2Name} {
				kubectlOut := getPodAddress(podName, f.Namespace.Name)
				srcIP := net.ParseIP(kubectlOut)
				if srcIP == nil {
					return false, nil
				}
			}
			return true, nil
		})
		framework.ExpectNoError(err, "Step 3. Create two pods matching both egress firewall and egress IP, failed, err: %v", err)

		pod2IP := getPodAddress(pod2Name, f.Namespace.Name)

		ginkgo.By("Checking that the status is of length one")
		verifyEgressIPStatusLengthEquals(1)

		ginkgo.By("4. Check connectivity to the blocked IP and verify that it fails")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(deniedTargetNode, pod1Name, podNamespace.Name, false, []string{egressIP.String()}))
		framework.ExpectNoError(err, "Step:  4. Check connectivity to the blocked IP and verify that it fails, failed, err: %v", err)

		ginkgo.By("5. Check connectivity to the allowed IP and verify it has the egress IP")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetExternalContainerAndTest(targetNode, pod1Name, podNamespace.Name, true, []string{egressIP.String()}))
		framework.ExpectNoError(err, "Step: 5. Check connectivity to the allowed IP and verify it has the egress IP, failed, err: %v", err)

		// TODO: in the future once we only have shared gateway mode: implement egress firewall so that
		// pods that have a "deny all 0.0.0.0/0" rule, still can connect to the Kubernetes API service
		// and re-enable this check

		// ginkgo.By("6. Check connectivity to the kubernetes API IP and verify that it works")
		// err = wait.PollImmediate(retryInterval, retryTimeout, targetAPIServiceAndTest(podNamespace.Name, []string{pod1Name, pod2Name}))
		// framework.ExpectNoError(err, "Step 6. Check connectivity to the kubernetes API IP and verify that it works, failed, err %v", err)

		ginkgo.By("7. Check connectivity to the other pod IP and verify that it works")
		err = wait.PollImmediate(retryInterval, retryTimeout, targetPodAndTest(f.Namespace.Name, pod1Name, pod2Name, pod2IP))
		framework.ExpectNoError(err, "Step 7. Check connectivity to the other pod IP and verify that it works, err: %v", err)
	})
})

// Validate pods can reach a network running in a container's looback address via
// an external gateway running on eth0 of the container without any tunnel encap.
// Next, the test updates the namespace annotation to point to a second container,
// emulating the ext gateway. This test requires shared gateway mode in the job infra.
var _ = ginkgo.Describe("e2e non-vxlan external gateway and update validation", func() {
	const (
		svcname             string = "multiple-novxlan-externalgw"
		exGWRemoteIpAlt1    string = "10.249.3.1"
		exGWRemoteIpAlt2    string = "10.249.4.1"
		ovnNs               string = "ovn-kubernetes"
		ovnWorkerNode       string = "ovn-worker"
		ovnHaWorkerNode     string = "ovn-control-plane2"
		ovnContainer        string = "ovnkube-node"
		gwContainerNameAlt1 string = "gw-novxlan-test-container-alt1"
		gwContainerNameAlt2 string = "gw-novxlan-test-container-alt2"
		ovnControlNode      string = "ovn-control-plane"
	)
	var (
		haMode        bool
		ciNetworkFlag string
	)
	f := framework.NewDefaultFramework(svcname)

	// Determine what mode the CI is running in and get relevant endpoint information for the tests
	ginkgo.BeforeEach(func() {
		labelFlag := fmt.Sprintf("name=%s", ovnContainer)
		jsonFlag := "-o=jsonpath='{.items..metadata.name}'"
		fieldSelectorFlag := fmt.Sprintf("--field-selector=spec.nodeName=%s", ovnWorkerNode)
		fieldSelectorHaFlag := fmt.Sprintf("--field-selector=spec.nodeName=%s", ovnHaWorkerNode)
		ciNetworkFlag = fmt.Sprintf("{{ .NetworkSettings.Networks.%s.IPAddress }}", ciNetworkName)
		fieldSelectorControlFlag := fmt.Sprintf("--field-selector=spec.nodeName=%s", ovnControlNode)
		// retrieve pod names from the running cluster
		kubectlOut, err := framework.RunKubectl(ovnNs, "get", "pods", "-l", labelFlag, jsonFlag, fieldSelectorControlFlag)
		if err != nil {
			framework.Failf("Expected container %s running on %s error %v", ovnContainer, ovnControlNode, err)
		}
		// attempt to retrieve the pod name that will source the test in non-HA mode
		kubectlOut, err = framework.RunKubectl(ovnNs, "get", "pods", "-l", labelFlag, jsonFlag, fieldSelectorFlag)
		if err != nil {
			framework.Failf("Expected container %s running on %s error %v", ovnContainer, ovnWorkerNode, err)
		}
		// attempt to retrieve the pod name that will source the test in HA mode
		if kubectlOut == "''" {
			haMode = true
			kubectlOut, err = framework.RunKubectl(ovnNs, "get", "pods", "-l", labelFlag, jsonFlag, fieldSelectorHaFlag)
			if err != nil {
				framework.Failf("Expected container %s running on %s error %v", ovnContainer, ovnHaWorkerNode, err)
			}
		}
	})

	ginkgo.AfterEach(func() {
		// tear down the containers simulating the gateways
		if cid, _ := runCommand("docker", "ps", "-qaf", fmt.Sprintf("name=%s", gwContainerNameAlt1)); cid != "" {
			if _, err := runCommand("docker", "rm", "-f", gwContainerNameAlt1); err != nil {
				framework.Logf("failed to delete the gateway test container %s %v", gwContainerNameAlt1, err)
			}
		}
		if cid, _ := runCommand("docker", "ps", "-qaf", fmt.Sprintf("name=%s", gwContainerNameAlt2)); cid != "" {
			if _, err := runCommand("docker", "rm", "-f", gwContainerNameAlt2); err != nil {
				framework.Logf("failed to delete the gateway test container %s %v", gwContainerNameAlt2, err)
			}
		}
	})

	ginkgo.It("Should validate connectivity without vxlan before and after updating the namespace annotation to a new external gateway", func() {

		var pingSrc string
		var validIP net.IP
		exGWRemoteCidrAlt1 := fmt.Sprintf("%s/24", exGWRemoteIpAlt1)
		exGWRemoteCidrAlt2 := fmt.Sprintf("%s/24", exGWRemoteIpAlt2)
		srcPingPodName := "e2e-exgw-novxlan-src-ping-pod"
		command := []string{"bash", "-c", "sleep 20000"}
		testContainer := fmt.Sprintf("%s-container", srcPingPodName)
		testContainerFlag := fmt.Sprintf("--container=%s", testContainer)
		// start the container that will act as an external gateway
		_, err := runCommand("docker", "run", "-itd", "--privileged", "--network", ciNetworkName, "--name", gwContainerNameAlt1, "centos")
		if err != nil {
			framework.Failf("failed to start external gateway test container %s: %v", gwContainerNameAlt1, err)
		}
		// retrieve the container ip of the external gateway container
		exGWIpAlt1, err := runCommand("docker", "inspect", "-f", ciNetworkFlag, gwContainerNameAlt1)
		if err != nil {
			framework.Failf("failed to start external gateway test container: %v", err)
		}
		// trim newline from the inspect output
		exGWIpAlt1 = strings.TrimSuffix(exGWIpAlt1, "\n")
		if ip := net.ParseIP(exGWIpAlt1); ip == nil {
			framework.Failf("Unable to retrieve a valid address from container %s with inspect output of %s", gwContainerNameAlt1, exGWIpAlt1)
		}
		// annotate the test namespace
		annotateArgs := []string{
			"annotate",
			"namespace",
			f.Namespace.Name,
			fmt.Sprintf("k8s.ovn.org/routing-external-gws=%s", exGWIpAlt1),
		}
		framework.Logf("Annotating the external gateway test namespace to a container gw: %s ", exGWIpAlt1)
		framework.RunKubectlOrDie(f.Namespace.Name, annotateArgs...)
		// non-ha ci mode runs a set of kind nodes prefixed with ovn-worker
		ciWorkerNodeSrc := ovnWorkerNode
		if haMode {
			// ha ci mode runs a named set of nodes with a prefix of ovn-control-plane
			ciWorkerNodeSrc = ovnHaWorkerNode
		}
		nodeIP, err := runCommand("docker", "inspect", "-f", ciNetworkFlag, ciWorkerNodeSrc)
		if err != nil {
			framework.Failf("failed to get the node ip address from node %s %v", ciWorkerNodeSrc, err)
		}
		nodeIP = strings.TrimSuffix(nodeIP, "\n")
		if ip := net.ParseIP(nodeIP); ip == nil {
			framework.Failf("Unable to retrieve a valid address from container %s with inspect output of %s", ciWorkerNodeSrc, nodeIP)
		}
		framework.Logf("the pod side node is %s and the source node ip is %s", ciWorkerNodeSrc, nodeIP)
		podCIDR, err := getNodePodCIDR(ciWorkerNodeSrc)
		if err != nil {
			framework.Failf("Error retrieving the pod cidr from %s %v", ciWorkerNodeSrc, err)
		}
		framework.Logf("the pod cidr for node %s is %s", ciWorkerNodeSrc, podCIDR)
		// add loopback interface used to validate all traffic is getting drained through the gateway
		_, err = runCommand("docker", "exec", gwContainerNameAlt1, "ip", "address", "add", exGWRemoteCidrAlt1, "dev", "lo")
		if err != nil {
			framework.Failf("failed to add the loopback ip to dev lo on the test container: %v", err)
		}
		// Create the pod that will be used as the source for the connectivity test
		createGenericPod(f, srcPingPodName, ciWorkerNodeSrc, f.Namespace.Name, command)
		// wait for pod setup to return a valid address
		err = wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
			pingSrc = getPodAddress(srcPingPodName, f.Namespace.Name)
			validIP = net.ParseIP(pingSrc)
			if validIP == nil {
				return false, nil
			}
			return true, nil
		})
		// Fail the test if no address is ever retrieved
		if err != nil {
			framework.Failf("Error trying to get the pod IP address")
		}
		// add a host route on the first mock gateway for return traffic to the pod
		_, err = runCommand("docker", "exec", gwContainerNameAlt1, "ip", "route", "add", pingSrc, "via", nodeIP)
		if err != nil {
			framework.Failf("failed to add the pod host route on the test container: %v", err)
		}
		time.Sleep(time.Second * 15)
		// Verify the gateway and remote address is reachable from the initial pod
		ginkgo.By(fmt.Sprintf("Verifying connectivity without vxlan to the updated annotation and initial external gateway %s and remote address %s", exGWIpAlt1, exGWRemoteIpAlt1))
		_, err = framework.RunKubectl(f.Namespace.Name, "exec", srcPingPodName, testContainerFlag, "--", "ping", "-w", "40", exGWRemoteIpAlt1)
		if err != nil {
			framework.Failf("Failed to ping the first gateway network %s from container %s on node %s: %v", exGWRemoteIpAlt1, ovnContainer, ovnWorkerNode, err)
		}
		// start the container that will act as a new external gateway that the tests will be updated to use
		_, err = runCommand("docker", "run", "-itd", "--privileged", "--network", ciNetworkName, "--name", gwContainerNameAlt2, "centos")
		if err != nil {
			framework.Failf("failed to start external gateway test container %s: %v", gwContainerNameAlt2, err)
		}
		// retrieve the container ip of the external gateway container
		exGWIpAlt2, err := runCommand("docker", "inspect", "-f", ciNetworkFlag, gwContainerNameAlt2)
		if err != nil {
			framework.Failf("failed to start external gateway test container: %v", err)
		}
		// trim newline from the inspect output
		exGWIpAlt2 = strings.TrimSuffix(exGWIpAlt2, "\n")
		if ip := net.ParseIP(nodeIP); ip == nil {
			framework.Failf("Unable to retrieve a valid address from container %s with inspect output of %s", gwContainerNameAlt2, nodeIP)
		}
		// override the annotation in the test namespace with the new gateway
		annotateArgs = []string{
			"annotate",
			"namespace",
			f.Namespace.Name,
			fmt.Sprintf("k8s.ovn.org/routing-external-gws=%s", exGWIpAlt2),
			"--overwrite",
		}
		framework.Logf("Annotating the external gateway test namespace to a new container remote IP:%s gw:%s ", exGWIpAlt2, exGWRemoteIpAlt2)
		framework.RunKubectlOrDie(f.Namespace.Name, annotateArgs...)
		// add loopback interface used to validate all traffic is getting drained through the gateway
		_, err = runCommand("docker", "exec", gwContainerNameAlt2, "ip", "address", "add", exGWRemoteCidrAlt2, "dev", "lo")
		if err != nil {
			framework.Failf("failed to add the loopback ip to dev lo on the test container: %v", err)
		}
		// add a host route on the second mock gateway for return traffic to the pod
		_, err = runCommand("docker", "exec", gwContainerNameAlt2, "ip", "route", "add", pingSrc, "via", nodeIP)
		if err != nil {
			framework.Failf("failed to add the pod route on the test container: %v", err)
		}
		// Verify the updated gateway and remote address is reachable from the initial pod
		ginkgo.By(fmt.Sprintf("Verifying connectivity without vxlan to the updated annotation and new external gateway %s and remote IP %s", exGWRemoteIpAlt2, exGWIpAlt2))
		_, err = framework.RunKubectl(f.Namespace.Name, "exec", srcPingPodName, testContainerFlag, "--", "ping", "-w", "40", exGWRemoteIpAlt2)
		if err != nil {
			framework.Failf("Failed to ping the second gateway network %s from container %s on node %s: %v", exGWRemoteIpAlt2, ovnContainer, ovnWorkerNode, err)
		}
	})
})

// Validate the egress firewall policies by applying a policy and verify
// that both explicitly allowed traffic and implicitly denied traffic
// is properly handled as defined in the crd configuration in the test.
var _ = ginkgo.Describe("e2e egress firewall policy validation", func() {
	const (
		svcname                string = "egress-firewall-policy"
		exFWPermitTcpDnsDest   string = "8.8.8.8"
		exFWDenyTcpDnsDest     string = "8.8.4.4"
		exFWPermitTcpWwwDest   string = "1.1.1.1"
		ovnContainer           string = "ovnkube-node"
		egressFirewallYamlFile string = "egress-fw.yml"
		testTimeout            string = "5"
		retryInterval                 = 1 * time.Second
		retryTimeout                  = 30 * time.Second
	)

	type nodeInfo struct {
		name   string
		nodeIP string
	}

	var (
		serverNodeInfo nodeInfo
	)

	f := framework.NewDefaultFramework(svcname)

	// Determine what mode the CI is running in and get relevant endpoint information for the tests
	ginkgo.BeforeEach(func() {
		nodes, err := e2enode.GetBoundedReadySchedulableNodes(f.ClientSet, 2)
		framework.ExpectNoError(err)
		if len(nodes.Items) < 2 {
			framework.Failf(
				"Test requires >= 2 Ready nodes, but there are only %v nodes",
				len(nodes.Items))
		}

		ips := e2enode.CollectAddresses(nodes, v1.NodeInternalIP)

		serverNodeInfo = nodeInfo{
			name:   nodes.Items[1].Name,
			nodeIP: ips[1],
		}
	})

	ginkgo.AfterEach(func() {})

	ginkgo.It("Should validate the egress firewall policy functionality against remote hosts", func() {
		srcPodName := "e2e-egress-fw-src-pod"
		command := []string{"bash", "-c", "sleep 20000"}
		frameworkNsFlag := fmt.Sprintf("--namespace=%s", f.Namespace.Name)
		testContainer := fmt.Sprintf("%s-container", srcPodName)
		testContainerFlag := fmt.Sprintf("--container=%s", testContainer)
		// egress firewall crd yaml configuration
		var egressFirewallConfig = fmt.Sprintf(`kind: EgressFirewall
apiVersion: k8s.ovn.org/v1
metadata:
  name: default
  namespace: %s
spec:
  egress:
  - type: Allow
    to:
      cidrSelector: 8.8.8.8/32
  - type: Allow
    to:
      cidrSelector: 1.1.1.0/24
    ports:
      - protocol: TCP
        port: 80
  - type: Deny
    to:
      cidrSelector: 0.0.0.0/0
`, f.Namespace.Name)
		// write the config to a file for application and defer the removal
		if err := ioutil.WriteFile(egressFirewallYamlFile, []byte(egressFirewallConfig), 0644); err != nil {
			framework.Failf("Unable to write CRD config to disk: %v", err)
		}
		defer func() {
			if err := os.Remove(egressFirewallYamlFile); err != nil {
				framework.Logf("Unable to remove the CRD config from disk: %v", err)
			}
		}()
		// create the CRD config parameters
		applyArgs := []string{
			"apply",
			frameworkNsFlag,
			"-f",
			egressFirewallYamlFile,
		}
		framework.Logf("Applying EgressFirewall configuration: %s ", applyArgs)
		// apply the egress firewall configuration
		framework.RunKubectlOrDie(f.Namespace.Name, applyArgs...)
		// create the pod that will be used as the source for the connectivity test
		createGenericPod(f, srcPodName, serverNodeInfo.name, f.Namespace.Name, command)

		// Wait for pod exgw setup to be almost ready
		err := wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
			kubectlOut := getPodAddress(srcPodName, f.Namespace.Name)
			validIP := net.ParseIP(kubectlOut)
			if validIP == nil {
				return false, nil
			}
			return true, nil
		})
		// Fail the test if no address is ever retrieved
		if err != nil {
			framework.Failf("Error trying to get the pod IP address %v", err)
		}
		// Verify the remote host/port as explicitly allowed by the firewall policy is reachable
		ginkgo.By(fmt.Sprintf("Verifying connectivity to an explicitly allowed host %s is permitted as defined by the external firewall policy", exFWPermitTcpDnsDest))
		_, err = framework.RunKubectl(f.Namespace.Name, "exec", srcPodName, testContainerFlag, "--", "nc", "-vz", "-w", testTimeout, exFWPermitTcpDnsDest, "53")
		if err != nil {
			framework.Failf("Failed to connect to the remote host %s from container %s on node %s: %v", exFWPermitTcpDnsDest, ovnContainer, serverNodeInfo.name, err)
		}
		// Verify the remote host/port as implicitly denied by the firewall policy is not reachable
		ginkgo.By(fmt.Sprintf("Verifying connectivity to an implicitly denied host %s is not permitted as defined by the external firewall policy", exFWDenyTcpDnsDest))
		_, err = framework.RunKubectl(f.Namespace.Name, "exec", srcPodName, testContainerFlag, "--", "nc", "-vz", "-w", testTimeout, exFWDenyTcpDnsDest, "53")
		if err == nil {
			framework.Failf("Succeeded in connecting the implicitly denied remote host %s from container %s on node %s", exFWDenyTcpDnsDest, ovnContainer, serverNodeInfo.name)
		}
		// Verify the the explicitly allowed host/port tcp port 80 rule is functional
		ginkgo.By(fmt.Sprintf("Verifying connectivity to an explicitly allowed host %s is permitted as defined by the external firewall policy", exFWPermitTcpWwwDest))
		_, err = framework.RunKubectl(f.Namespace.Name, "exec", srcPodName, testContainerFlag, "--", "nc", "-vz", "-w", testTimeout, exFWPermitTcpWwwDest, "80")
		if err != nil {
			framework.Failf("Failed to curl the remote host %s from container %s on node %s: %v", exFWPermitTcpWwwDest, ovnContainer, serverNodeInfo.name, err)
		}
		// Verify the remote host/port 443 as implicitly denied by the firewall policy is not reachable
		ginkgo.By(fmt.Sprintf("Verifying connectivity to an implicitly denied port on host %s is not permitted as defined by the external firewall policy", exFWPermitTcpWwwDest))
		_, err = framework.RunKubectl(f.Namespace.Name, "exec", srcPodName, testContainerFlag, "--", "nc", "-vz", "-w", testTimeout, exFWPermitTcpWwwDest, "443")
		if err == nil {
			framework.Failf("Failed to curl the remote host %s from container %s on node %s: %v", exFWPermitTcpWwwDest, ovnContainer, serverNodeInfo.name, err)
		}
	})
	ginkgo.It("Should validate the egress firewall DNS does not deadlock when adding many dnsNames", func() {
		frameworkNsFlag := fmt.Sprintf("--namespace=%s", f.Namespace.Name)
		var egressFirewallConfig = fmt.Sprintf(`kind: EgressFirewall
apiVersion: k8s.ovn.org/v1
metadata:
  name: default
  namespace: %s
spec:
  egress:
  - type: Allow
    to:
      cidrSelector: 8.8.8.8/32
  - type: Allow
    to:
      dnsName: www.test1.com
  - type: Allow
    to:
      dnsName: www.test2.com
  - type: Allow
    to:
      dnsName: www.test3.com
  - type: Allow
    to:
      dnsName: www.test4.com
  - type: Allow
    to:
      dnsName: www.test5.com
  - type: Allow
    to:
      dnsName: www.test6.com
  - type: Allow
    to:
      dnsName: www.test7.com
  - type: Allow
    to:
      dnsName: www.test8.com
  - type: Allow
    to:
      dnsName: www.test9.com
  - type: Allow
    to:
      dnsName: www.test10.com
  - type: Allow
    to:
      dnsName: www.test11.com
  - type: Allow
    to:
      dnsName: www.test12.com
  - type: Allow
    to:
      cidrSelector: 1.1.1.0/24
    ports:
      - protocol: TCP
        port: 80
  - type: Deny
    to:
      cidrSelector: 0.0.0.0/0
`, f.Namespace.Name)
		// write the config to a file for application and defer the removal
		if err := ioutil.WriteFile(egressFirewallYamlFile, []byte(egressFirewallConfig), 0644); err != nil {
			framework.Failf("Unable to write CRD config to disk: %v", err)
		}
		defer func() {
			if err := os.Remove(egressFirewallYamlFile); err != nil {
				framework.Logf("Unable to remove the CRD config from disk: %v", err)
			}
		}()
		// create the CRD config parameters
		applyArgs := []string{
			"apply",
			frameworkNsFlag,
			"-f",
			egressFirewallYamlFile,
		}
		framework.Logf("Applying EgressFirewall configuration: %s ", applyArgs)
		// apply the egress firewall configuration
		framework.RunKubectlOrDie(f.Namespace.Name, applyArgs...)
		gomega.Eventually(func() bool {
			output, err := framework.RunKubectl(f.Namespace.Name, "get", "egressfirewall", "default")
			if err != nil {
				framework.Failf("could not get the egressfirewall default in namespace: %s", f.Namespace.Name)
			}
			return strings.Contains(output, "EgressFirewall Rules applied")
		}, 30*time.Second).Should(gomega.BeTrue())
	})
})

// Validate pods can reach a network running in a container's looback address via
// an external gateway running on eth0 of the container without any tunnel encap.
// The traffic will get proxied through an annotated pod in the default namespace.
var _ = ginkgo.Describe("e2e non-vxlan external gateway through a gateway pod", func() {
	const (
		svcname          string = "externalgw-pod-novxlan"
		dummyMac         string = "01:23:45:67:89:10"
		exGWRemoteIp     string = "10.249.3.1"
		gwContainerName  string = "ex-gw-container"
		ciNetworkFlag    string = "{{ .NetworkSettings.Networks.kind.IPAddress }}"
		ciNetworkName    string = "kind"
		defaultNamespace string = "default"
		routingNetwork   string = "foo"
		srcPingPodName   string = "e2e-exgw-src-ping-pod"
		gatewayPodName   string = "e2e-gateway-pod"
	)

	f := framework.NewDefaultFramework(svcname)

	type nodeInfo struct {
		name   string
		nodeIP string
	}

	var (
		worker1NodeInfo nodeInfo
		worker2NodeInfo nodeInfo
	)

	ginkgo.BeforeEach(func() {

		// retrieve worker node names
		nodes, err := e2enode.GetBoundedReadySchedulableNodes(f.ClientSet, 3)
		framework.ExpectNoError(err)
		if len(nodes.Items) < 3 {
			framework.Failf(
				"Test requires >= 3 Ready nodes, but there are only %v nodes",
				len(nodes.Items))
		}
		ips := e2enode.CollectAddresses(nodes, v1.NodeInternalIP)
		worker1NodeInfo = nodeInfo{
			name:   nodes.Items[1].Name,
			nodeIP: ips[1],
		}
		worker2NodeInfo = nodeInfo{
			name:   nodes.Items[2].Name,
			nodeIP: ips[2],
		}
	})

	ginkgo.AfterEach(func() {
		// tear down the containers simulating the gateways
		if cid, _ := runCommand("docker", "ps", "-qaf", fmt.Sprintf("name=%s", gwContainerName)); cid != "" {
			if _, err := runCommand("docker", "rm", "-f", gwContainerName); err != nil {
				framework.Logf("failed to delete the gateway test container %s %v", gwContainerName, err)
			}
		}
	})

	ginkgo.It("Should validate connectivity to an external gateway's loopback address via a pod with external gateway annotations enabled", func() {

		var (
			pingSrc           string
			exGWRemoteCidr    = fmt.Sprintf("%s/32", exGWRemoteIp)
			command           = []string{"bash", "-c", "sleep 20000"}
			testContainer     = fmt.Sprintf("%s-container", srcPingPodName)
			testContainerFlag = fmt.Sprintf("--container=%s", testContainer)
		)

		// start the container that will act as an external gateway
		_, err := runCommand("docker", "run", "-itd", "--privileged", "--network", ciNetworkName, "--name", gwContainerName, "centos")
		if err != nil {
			framework.Failf("failed to start external gateway test container %s: %v", gwContainerName, err)
		}
		// retrieve the container ip of the external gateway container
		exGWIp, err := runCommand("docker", "inspect", "-f", ciNetworkFlag, gwContainerName)
		if err != nil {
			framework.Failf("failed to start external gateway test container: %v", err)
		}
		// trim newline from the inspect output
		exGWIp = strings.TrimSuffix(exGWIp, "\n")
		if ip := net.ParseIP(exGWIp); ip == nil {
			framework.Failf("Unable to retrieve a valid address from container %s with inspect output of %s", gwContainerName, exGWIp)
		}

		// create the pod that acts as a proxy for egress traffic to the external gateway
		createGenericPod(f, gatewayPodName, worker1NodeInfo.name, defaultNamespace, command)
		// wait for pod setup to return a valid address
		// note: this is polling the default namespace, not the framework naespace
		err = wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
			kubectlOut := getPodAddress(gatewayPodName, defaultNamespace)
			validIP := net.ParseIP(kubectlOut)
			if validIP == nil {
				return false, nil
			}
			return true, nil
		})
		// Fail the test if no address is ever retrieved
		if err != nil {
			framework.Failf("Error trying to get the pod IP address")
		}

		// add the annotations to the pod to enable the gateway forwarding.
		// this fakes out the multus annotation so that the pod IP is
		// actually an IP of an external container for testing purposes
		annotateArgs := []string{
			"annotate",
			"pods",
			gatewayPodName,
			fmt.Sprintf("k8s.v1.cni.cncf.io/network-status=[{\"name\":\"%s\",\"interface\":"+
				"\"net1\",\"ips\":[\"%s\"],\"mac\":\"%s\"}]", routingNetwork, exGWIp, dummyMac),
			fmt.Sprintf("k8s.ovn.org/routing-namespaces=%s", f.Namespace.Name),
			fmt.Sprintf("k8s.ovn.org/routing-network=%s", routingNetwork),
		}
		framework.Logf("Annotating the external gateway pod with annotation %s", annotateArgs)
		framework.RunKubectlOrDie(defaultNamespace, annotateArgs...)

		// create the pod that will source the connectivity test to the external gateway
		createGenericPod(f, srcPingPodName, worker2NodeInfo.name, f.Namespace.Name, command)
		// wait for the pod setup to return a valid address
		err = wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
			pingSrc = getPodAddress(srcPingPodName, f.Namespace.Name)
			validIP := net.ParseIP(pingSrc)
			if validIP == nil {
				return false, nil
			}
			return true, nil
		})
		// Fail the test if no address is ever retrieved
		if err != nil {
			framework.Failf("Error trying to get the pod IP address")
		}

		// add loopback interface used to validate all traffic is getting drained through the gateway
		_, err = runCommand("docker", "exec", gwContainerName, "ip", "address", "add", exGWRemoteCidr, "dev", "lo")
		if err != nil {
			framework.Failf("failed to add the loopback ip to dev lo on the test container: %v", err)
		}
		// add a host route on the mock gateway for return traffic to the proxy pod
		_, err = runCommand("docker", "exec", gwContainerName, "ip", "route", "add", pingSrc, "via", worker1NodeInfo.nodeIP)
		if err != nil {
			framework.Failf("failed to add the pod host route on the test container: %v", err)
		}
		// Verify the external gateway loopback address running on the external container is reachable and
		// that traffic from the source ping pod is proxied through the pod in the default namespace
		ginkgo.By(fmt.Sprintf("Verifying connectivity via the gateway namespace to the gateway %s and remote address %s", exGWIp, exGWRemoteIp))
		_, err = framework.RunKubectl(f.Namespace.Name, "exec", srcPingPodName, testContainerFlag, "--", "ping", "-w", "40", exGWRemoteIp)
		if err != nil {
			framework.Failf("Failed to ping the remote gateway network %s from pod %s: %v", exGWRemoteIp, srcPingPodName, err)
		}
		err = f.ClientSet.CoreV1().Pods(defaultNamespace).Delete(context.Background(), gatewayPodName, metav1.DeleteOptions{})
		if err != nil {
			framework.Logf("Failed to get delete the pod %s in the namespace %s: %v", gatewayPodName, defaultNamespace, err)
		}
	})
})

// Validate pods can reach a network running in multiple container's loopback
// addresses via two external gateways running on eth0 of the container without
// any tunnel encap. This test defines two external gateways and validates ECMP
// functionality to the container loopbacks. To verify traffic reaches the
// gateways, tcpdump is running on the external gateways and will exit successfully
// once an ICMP packet is received from the annotated pod in the k8s cluster.
var _ = ginkgo.Describe("e2e multiple ecmp external gateway validation", func() {
	const (
		svcname            string = "novxlan-externalgw-ecmp"
		exGWRemoteIpPrefix string = "10.249.10."
		gwContainer1       string = "gw-ecmp-test-container1"
		gwContainer2       string = "gw-ecmp-test-container2"
		ciNetworkName      string = "kind"
		testTimeout        string = "20"
		ecmpRetry          int    = 20
	)

	f := framework.NewDefaultFramework(svcname)

	type nodeInfo struct {
		name   string
		nodeIP string
	}

	var (
		workerNodeInfo nodeInfo
	)

	ginkgo.BeforeEach(func() {

		// retrieve worker node names
		nodes, err := e2enode.GetBoundedReadySchedulableNodes(f.ClientSet, 3)
		framework.ExpectNoError(err)
		if len(nodes.Items) < 3 {
			framework.Failf(
				"Test requires >= 3 Ready nodes, but there are only %v nodes",
				len(nodes.Items))
		}
		ips := e2enode.CollectAddresses(nodes, v1.NodeInternalIP)
		workerNodeInfo = nodeInfo{
			name:   nodes.Items[1].Name,
			nodeIP: ips[1],
		}
	})

	ginkgo.AfterEach(func() {
		// tear down the containers simulating the gateways
		if cid, _ := runCommand("docker", "ps", "-qaf", fmt.Sprintf("name=%s", gwContainer1)); cid != "" {
			if _, err := runCommand("docker", "rm", "-f", gwContainer1); err != nil {
				framework.Logf("failed to delete the gateway test container %s %v", gwContainer1, err)
			}
		}
		if cid, _ := runCommand("docker", "ps", "-qaf", fmt.Sprintf("name=%s", gwContainer2)); cid != "" {
			if _, err := runCommand("docker", "rm", "-f", gwContainer2); err != nil {
				framework.Logf("failed to delete the gateway test container %s %v", gwContainer2, err)
			}
		}
	})

	ginkgo.It("Should validate connectivity to multiple external gateways for an ECMP scenario", func() {

		var (
			pingSrc           string
			ciNetworkFlag     = "{{ .NetworkSettings.Networks.kind.IPAddress }}"
			srcPingPodName    = "e2e-exgw-ecmp-src-ping-pod"
			command           = []string{"bash", "-c", "sleep 20000"}
			testContainer     = fmt.Sprintf("%s-container", srcPingPodName)
			testContainerFlag = fmt.Sprintf("--container=%s", testContainer)
		)

		// start the first container that will act as an external gateway
		_, err := runCommand("docker", "run", "-itd", "--privileged", "--network", ciNetworkName, "--name", gwContainer1, "centos/tools")
		if err != nil {
			framework.Failf("failed to start external gateway test container %s: %v", gwContainer1, err)
		}
		// retrieve the container ip of the external gateway container
		exGWIp1, err := runCommand("docker", "inspect", "-f", ciNetworkFlag, gwContainer1)
		if err != nil {
			framework.Failf("failed to start external gateway test container: %v", err)
		}
		// trim newline from the inspect output
		exGWIp1 = strings.TrimSuffix(exGWIp1, "\n")
		if ip := net.ParseIP(exGWIp1); ip == nil {
			framework.Failf("Unable to retrieve a valid address from container %s with inspect output of %s", gwContainer1, exGWIp1)
		}

		// start the second container that will act as an external gateway
		_, err = runCommand("docker", "run", "-itd", "--privileged", "--network", ciNetworkName, "--name", gwContainer2, "centos/tools")
		if err != nil {
			framework.Failf("failed to start external gateway test container %s: %v", gwContainer2, err)
		}
		// retrieve the container ip of the external gateway container
		exGWIp2, err := runCommand("docker", "inspect", "-f", ciNetworkFlag, gwContainer2)
		if err != nil {
			framework.Failf("failed to start external gateway test container: %v", err)
		}
		// trim newline from the inspect output
		exGWIp2 = strings.TrimSuffix(exGWIp2, "\n")
		if ip := net.ParseIP(exGWIp2); ip == nil {
			framework.Failf("Unable to retrieve a valid address from container %s with inspect output of %s", gwContainer2, exGWIp2)
		}

		// annotate the test namespace with multiple gateways defined
		annotateArgs := []string{
			"annotate",
			"namespace",
			f.Namespace.Name,
			fmt.Sprintf("k8s.ovn.org/routing-external-gws=%s,%s", exGWIp1, exGWIp2),
		}
		framework.Logf("Annotating the external gateway test namespace to container gateways: %s, %s", exGWIp1, exGWIp2)
		framework.RunKubectlOrDie(f.Namespace.Name, annotateArgs...)

		nodeIP, err := runCommand("docker", "inspect", "-f", ciNetworkFlag, workerNodeInfo.name)
		if err != nil {
			framework.Failf("failed to get the node ip address from node %s %v", workerNodeInfo.name, err)
		}
		nodeIP = strings.TrimSuffix(nodeIP, "\n")
		if ip := net.ParseIP(nodeIP); ip == nil {
			framework.Failf("Unable to retrieve a valid address from container %s with inspect output of %s", workerNodeInfo.name, nodeIP)
		}
		framework.Logf("the pod side node is %s and the source node ip is %s", workerNodeInfo.name, nodeIP)
		podCIDR, err := getNodePodCIDR(workerNodeInfo.name)
		if err != nil {
			framework.Failf("Error retrieving the pod cidr from %s %v", workerNodeInfo.name, err)
		}
		framework.Logf("the pod cidr for node %s is %s", workerNodeInfo.name, podCIDR)

		// Add loopback addresses used to validate all traffic is getting drained
		// through the gateway. OVN will choose an ECMP route based on a 5-tuple hash,
		// so we need to cycle through multiple dest IPs to be able to hit both gateways
		for _, containerName := range []string{gwContainer1, gwContainer2} {
			for lastOctet := 1; lastOctet <= ecmpRetry; lastOctet++ {
				gwLoPrefix := fmt.Sprintf("%s%d/32", exGWRemoteIpPrefix, lastOctet)
				// add the loopback addresses to the gateway container
				_, err = runCommand("docker", "exec", containerName, "ip", "address", "add", gwLoPrefix, "dev", "lo")
				if err != nil {
					framework.Failf("failed to add the loopback ip to dev lo on the test container %s: %v", containerName, err)
				}
			}
		}

		// Create the pod that will be used as the source for the connectivity test
		createGenericPod(f, srcPingPodName, workerNodeInfo.name, f.Namespace.Name, command)
		// wait for the pod setup to return a valid address
		err = wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
			pingSrc = getPodAddress(srcPingPodName, f.Namespace.Name)
			validIP := net.ParseIP(pingSrc)
			if validIP == nil {
				return false, nil
			}
			return true, nil
		})
		// Fail the test if no address is ever retrieved
		if err != nil {
			framework.Failf("Error trying to get the pod IP address")
		}
		// add a host route on the gateways for return traffic to the pod
		_, err = runCommand("docker", "exec", gwContainer1, "ip", "route", "add", pingSrc, "via", nodeIP)
		if err != nil {
			framework.Failf("failed to add the pod host route on the test container %s: %v", gwContainer1, err)
		}
		_, err = runCommand("docker", "exec", gwContainer2, "ip", "route", "add", pingSrc, "via", nodeIP)
		if err != nil {
			framework.Failf("failed to add the pod host route on the test container %s: %v", gwContainer2, err)
		}

		// Verify the gateways and remote loopback addresses are reachable from the pod.
		// Iterate checking connectivity to the loopbacks on the gateways until tcpdump see
		// the traffic or 20 attempts fail. Odds of a false negative here is ~ (1/2)^20
		ginkgo.By(fmt.Sprintf("Verifying ecmp connectivity to the external gateways by iterating through the prefix %s", exGWRemoteIpPrefix))

		// create a buffered channel that will handle error reporting from the goroutines
		icmpChan := make(chan error, 2)

		// Check for egress traffic to both gateway loopback addresses using tcpdump, since
		// /proc/net/dev counters only record the ingress interface traffic is received on.
		// The test will waits until an ICMP packet is matched on the gateways or fail the
		// test if a packet to the loopback is not received within the timer interval.
		// If an ICMP packet is never detected, return the error via the specified chanel.
		go func() {
			_, err = runCommand("docker", "exec", gwContainer1, "timeout", testTimeout, "tcpdump", "-c", "1", "icmp")
			if err == nil {
				framework.Logf("ICMP packet successfully detected on gateway %s", gwContainer1)
				icmpChan <- err
			}
			icmpChan <- err
		}()
		go func() {
			_, err = runCommand("docker", "exec", gwContainer2, "timeout", testTimeout, "tcpdump", "-c", "1", "icmp")
			if err == nil {
				framework.Logf("ICMP packet successfully detected on gateway %s", gwContainer2)
				icmpChan <- err
			}
			icmpChan <- err
		}()

		// spawn a goroutine to asynchronously (to speed up the test)
		// to ping the gateway loopbacks on both containers via ECMP.
		for lastOctet := 1; lastOctet <= ecmpRetry; lastOctet++ {
			gwLo := fmt.Sprintf("%s%d", exGWRemoteIpPrefix, lastOctet)
			go func() {
				_, err = framework.RunKubectl(f.Namespace.Name, "exec", srcPingPodName, testContainerFlag, "--", "ping", "-c", testTimeout, gwLo)
				if err != nil {
					framework.Logf("error generating a ping from the test pod %s: %v", srcPingPodName, err)
				}
			}()
		}

		// collect any errors and report them in a failure report
		errs := []error{}
		for i := 0; i < 2; i++ {
			if err := <-icmpChan; err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			framework.Failf("failed to reach the mock gateway(s):\n%v", errs)
		}
	})
})

var _ = ginkgo.Describe("e2e ingress traffic validation", func() {
	const (
		endpointHTTPPort    = 80
		endpointUDPPort     = 90
		clusterHTTPPort     = 81
		clusterUDPPort      = 91
		clientContainerName = "npclient"
	)

	f := framework.NewDefaultFramework("nodeport-ingress-test")
	endpointsSelector := map[string]string{"servicebackend": "true"}

	var endPoints []*v1.Pod
	var nodesHostnames sets.String
	maxTries := 0
	var nodes *v1.NodeList

	ginkgo.Context("Validating ingress traffic", func() {
		ginkgo.BeforeEach(func() {
			endPoints = make([]*v1.Pod, 0)
			nodesHostnames = sets.NewString()

			var err error
			nodes, err = e2enode.GetBoundedReadySchedulableNodes(f.ClientSet, 3)
			framework.ExpectNoError(err)

			if len(nodes.Items) < 3 {
				framework.Failf(
					"Test requires >= 3 Ready nodes, but there are only %v nodes",
					len(nodes.Items))
			}

			ginkgo.By("Creating the endpoints pod, one for each worker")
			for _, node := range nodes.Items {
				// this create a udp / http netexec listener which is able to receive the "hostname"
				// command. We use this to validate that each endpoint is received at least once
				args := []string{
					"netexec",
					fmt.Sprintf("--http-port=%d", endpointHTTPPort),
					fmt.Sprintf("--udp-port=%d", endpointUDPPort),
				}
				pod, err := createPod(f, node.Name+"-ep", node.Name, f.Namespace.Name, []string{}, endpointsSelector, func(p *v1.Pod) {
					p.Spec.Containers[0].Args = args
				})
				framework.ExpectNoError(err)
				endPoints = append(endPoints, pod)
				nodesHostnames.Insert(pod.Name)

				// this is arbitrary and mutuated from k8s network e2e tests. We aim to hit all the endpoints at least once
				maxTries = len(endPoints)*len(endPoints) + 30
			}

			ginkgo.By("Creating an external container to send the traffic from")
			// the client uses the netexec command from the agnhost image, which is able to receive commands for poking other
			// addresses.
			createClusterExternalContainer(clientContainerName, agnhostImage, []string{"--network", "kind", "-P"}, []string{"netexec", "--http-port=80"})
		})

		ginkgo.AfterEach(func() {
			deleteClusterExternalContainer(clientContainerName)
		})

		// This test validates ingress traffic to nodeports.
		// It creates a nodeport service on both udp and tcp, and creates a backend pod on each node.
		// The backend pods are using the agnhost - netexec command which replies to commands
		// with different protocols. We use the "hostname" command to have each backend pod to reply
		// with its hostname.
		// We use an external container to poke the service exposed on the node and we iterate until
		// all the hostnames are returned.
		// In case of dual stack enabled cluster, we iterate over all the nodes ips and try to hit the
		// endpoints from both each node's ips.
		ginkgo.It("Should be allowed by nodeport services", func() {
			serviceName := "nodeportsvc"
			ginkgo.By("Creating the nodeport service")
			npSpec := nodePortServiceSpecFrom(serviceName, endpointHTTPPort, endpointUDPPort, clusterHTTPPort, clusterUDPPort, endpointsSelector)
			np, err := f.ClientSet.CoreV1().Services(f.Namespace.Name).Create(context.Background(), npSpec, metav1.CreateOptions{})
			nodeTCPPort, nodeUDPPort := nodePortsFromService(np)
			framework.ExpectNoError(err)

			ginkgo.By("Waiting for the endpoints to pop up")
			err = framework.WaitForServiceEndpointsNum(f.ClientSet, f.Namespace.Name, serviceName, len(endPoints), time.Second, wait.ForeverTestTimeout)
			framework.ExpectNoError(err, "failed to validate endpoints for service %s in namespace: %s", serviceName, f.Namespace.Name)

			for _, protocol := range []string{"http", "udp"} {
				for _, node := range nodes.Items {
					for _, nodeAddress := range node.Status.Addresses {
						// skipping hostnames
						if !addressIsIP(nodeAddress) {
							continue
						}

						responses := sets.NewString()
						valid := false
						nodePort := nodeTCPPort
						if protocol == "udp" {
							nodePort = nodeUDPPort
						}

						ginkgo.By("Hitting the nodeport on " + node.Name + " and reaching all the endpoints " + protocol)
						for i := 0; i < maxTries; i++ {
							epHostname := pokeEndpointHostname(clientContainerName, protocol, nodeAddress.Address, nodePort)
							responses.Insert(epHostname)

							// each endpoint returns its hostname. By doing this, we validate that each ep was reached at least once.
							if responses.Equal(nodesHostnames) {
								framework.Logf("Validated node %s on address %s after %d tries", node.Name, nodeAddress.Address, i)
								valid = true
								break
							}
						}
						framework.ExpectEqual(valid, true, "Validation failed for node", node, responses, nodePort)
					}
				}
			}
		})

		// This test validates ingress traffic to externalservices.
		// It creates a service on both udp and tcp and assignes all the first node's addresses as
		// external addresses. Then, creates a backend pod on each node.
		// The backend pods are using the agnhost - netexec command which replies to commands
		// with different protocols. We use the "hostname" command to have each backend pod to reply
		// with its hostname.
		// We use an external container to poke the service exposed on the node and we iterate until
		// all the hostnames are returned.
		// In case of dual stack enabled cluster, we iterate over all the node's addresses and try to hit the
		// endpoints from both each node's ips.
		ginkgo.It("Should be allowed by externalip services", func() {
			serviceName := "externalipsvc"

			// collecting all the first node's addresses
			addresses := []string{}
			for _, a := range nodes.Items[0].Status.Addresses {
				if addressIsIP(a) {
					addresses = append(addresses, a.Address)
				}
			}

			ginkgo.By("Creating the externalip service")
			externalIPsvcSpec := externalIPServiceSpecFrom(serviceName, endpointHTTPPort, endpointUDPPort, clusterHTTPPort, clusterUDPPort, endpointsSelector, addresses)
			_, err := f.ClientSet.CoreV1().Services(f.Namespace.Name).Create(context.Background(), externalIPsvcSpec, metav1.CreateOptions{})
			framework.ExpectNoError(err)

			ginkgo.By("Waiting for the endpoints to pop up")
			err = framework.WaitForServiceEndpointsNum(f.ClientSet, f.Namespace.Name, serviceName, len(endPoints), time.Second, wait.ForeverTestTimeout)
			framework.ExpectNoError(err, "failed to validate endpoints for service %s in namespace: %s", serviceName, f.Namespace.Name)

			for _, protocol := range []string{"http", "udp"} {
				for _, externalAddress := range addresses {
					responses := sets.NewString()
					valid := false
					externalPort := int32(clusterHTTPPort)
					if protocol == "udp" {
						externalPort = int32(clusterUDPPort)
					}

					ginkgo.By("Hitting the external service on " + externalAddress + " and reaching all the endpoints " + protocol)
					for i := 0; i < maxTries; i++ {
						epHostname := pokeEndpointHostname(clientContainerName, protocol, externalAddress, externalPort)
						responses.Insert(epHostname)

						// each endpoint returns its hostname. By doing this, we validate that each ep was reached at least once.
						if responses.Equal(nodesHostnames) {
							framework.Logf("Validated external address %s after %d tries", externalAddress, i)
							valid = true
							break
						}
					}
					framework.ExpectEqual(valid, true, "Validation failed for external address", externalAddress)
				}
			}
		})
	})
})

// This test validates ingress traffic sourced from a mock external gateway
// running as a container. Add a namespace annotated with the IP of the
// mock external container's eth0 address. Add a loopback address and a
// route pointing to the pod in the test namespace. Validate connectivity
// sourcing from the mock gateway container loopback to the test ns pod.
var _ = ginkgo.Describe("e2e ingress gateway traffic validation", func() {
	const (
		svcname       string = "novxlan-externalgw-ingress"
		gwContainer   string = "gw-ingress-test-container"
		ciNetworkName string = "kind"
	)

	f := framework.NewDefaultFramework(svcname)

	type nodeInfo struct {
		name   string
		nodeIP string
	}

	var (
		workerNodeInfo nodeInfo
	)

	ginkgo.BeforeEach(func() {

		// retrieve worker node names
		nodes, err := e2enode.GetBoundedReadySchedulableNodes(f.ClientSet, 3)
		framework.ExpectNoError(err)
		if len(nodes.Items) < 3 {
			framework.Failf(
				"Test requires >= 3 Ready nodes, but there are only %v nodes",
				len(nodes.Items))
		}
		ips := e2enode.CollectAddresses(nodes, v1.NodeInternalIP)
		workerNodeInfo = nodeInfo{
			name:   nodes.Items[1].Name,
			nodeIP: ips[1],
		}
	})

	ginkgo.AfterEach(func() {
		// tear down the container simulating the gateway
		if cid, _ := runCommand("docker", "ps", "-qaf", fmt.Sprintf("name=%s", gwContainer)); cid != "" {
			if _, err := runCommand("docker", "rm", "-f", gwContainer); err != nil {
				framework.Logf("failed to delete the gateway test container %s %v", gwContainer, err)
			}
		}
	})

	ginkgo.It("Should validate ingress connectivity from an external gateway", func() {

		var (
			pingDstPod     string
			ciNetworkFlag  = "{{ .NetworkSettings.Networks.kind.IPAddress }}"
			dstPingPodName = "e2e-exgw-ingress-ping-pod"
			command        = []string{"bash", "-c", "sleep 20000"}
			exGWLo         = "10.30.1.1"
			exGWLoCidr     = fmt.Sprintf("%s/32", exGWLo)
			pingCount      = "3"
		)

		// start the first container that will act as an external gateway
		_, err := runCommand("docker", "run", "-itd", "--privileged", "--network", ciNetworkName, "--name", gwContainer, "centos/tools")
		if err != nil {
			framework.Failf("failed to start external gateway test container %s: %v", gwContainer, err)
		}
		// retrieve the container ip of the external gateway container
		exGWIp, err := runCommand("docker", "inspect", "-f", ciNetworkFlag, gwContainer)
		if err != nil {
			framework.Failf("failed to start external gateway test container: %v", err)
		}
		// trim newline from the inspect output
		exGWIp = strings.TrimSuffix(exGWIp, "\n")
		if ip := net.ParseIP(exGWIp); ip == nil {
			framework.Failf("Unable to retrieve a valid address from container %s with inspect output of %s", gwContainer, exGWIp)
		}

		// annotate the test namespace with the external gateway address
		annotateArgs := []string{
			"annotate",
			"namespace",
			f.Namespace.Name,
			fmt.Sprintf("k8s.ovn.org/routing-external-gws=%s", exGWIp),
		}
		framework.Logf("Annotating the external gateway test namespace to container gateway: %s", exGWIp)
		framework.RunKubectlOrDie(f.Namespace.Name, annotateArgs...)

		nodeIP, err := runCommand("docker", "inspect", "-f", ciNetworkFlag, workerNodeInfo.name)
		if err != nil {
			framework.Failf("failed to get the node ip address from node %s %v", workerNodeInfo.name, err)
		}
		nodeIP = strings.TrimSuffix(nodeIP, "\n")
		if ip := net.ParseIP(nodeIP); ip == nil {
			framework.Failf("Unable to retrieve a valid address from container %s with inspect output of %s", workerNodeInfo.name, nodeIP)
		}
		framework.Logf("the pod side node is %s and the source node ip is %s", workerNodeInfo.name, nodeIP)
		podCIDR, err := getNodePodCIDR(workerNodeInfo.name)
		if err != nil {
			framework.Failf("Error retrieving the pod cidr from %s %v", workerNodeInfo.name, err)
		}
		framework.Logf("the pod cidr for node %s is %s", workerNodeInfo.name, podCIDR)

		// Create the pod that will be used as the source for the connectivity test
		createGenericPod(f, dstPingPodName, workerNodeInfo.name, f.Namespace.Name, command)
		// wait for the pod setup to return a valid address
		err = wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
			pingDstPod = getPodAddress(dstPingPodName, f.Namespace.Name)
			validIP := net.ParseIP(pingDstPod)
			if validIP == nil {
				return false, nil
			}
			return true, nil
		})
		// fail the test if a pod address is never retrieved
		if err != nil {
			framework.Failf("Error trying to get the pod IP address")
		}
		// add a host route on the gateways for return traffic to the pod
		_, err = runCommand("docker", "exec", gwContainer, "ip", "route", "add", pingDstPod, "via", nodeIP)
		if err != nil {
			framework.Failf("failed to add the pod host route on the test container %s: %v", gwContainer, err)
		}
		// add a loopback address to the mock container that will source the ingress test
		_, err = runCommand("docker", "exec", gwContainer, "ip", "address", "add", exGWLoCidr, "dev", "lo")
		if err != nil {
			framework.Failf("failed to add the loopback ip to dev lo on the test container: %v", err)
		}

		// Validate connectivity from the external gateway loopback to the pod in the test namespace
		ginkgo.By(fmt.Sprintf("Validate ingress traffic from the external gateway %s can reach the pod in the exgw annotated namespace", gwContainer))
		// generate traffic that will verify connectivity from the mock external gateway loopback
		_, err = runCommand("docker", "exec", gwContainer, "ping", "-c", pingCount, "-S", exGWLo, "-I", "eth0", pingDstPod)
		if err != nil {
			framework.Failf("failed to ping the pod address %s from mock container %s: %v", pingDstPod, gwContainer, err)
		}
	})
})

// This test validates OVS exports NetFlow data from br-int to an external collector
var _ = ginkgo.Describe("e2e br-int NetFlow export validation", func() {
	const (
		svcname                   string = "netflow-test"
		ovnNs                     string = "ovn-kubernetes"
		netFlowCollectorContainer string = "netflow-collector"
		ciNetworkName             string = "kind"
	)

	f := framework.NewDefaultFramework(svcname)

	ginkgo.AfterEach(func() {
		// tear down the NetFlow container
		if cid, _ := runCommand("docker", "ps", "-qaf", fmt.Sprintf("name=%s", netFlowCollectorContainer)); cid != "" {
			if _, err := runCommand("docker", "rm", "-f", netFlowCollectorContainer); err != nil {
				framework.Logf("failed to delete the netFlow collector test container %s %v", netFlowCollectorContainer, err)
			}
		}
	})

	ginkgo.It("Should validate NetFlow data of br-int is sent to an external gateway", func() {
		var (
			ciNetworkFlag = "{{ .NetworkSettings.Networks.kind.IPAddress }}"
		)

		// start the NetFlow collector container that will receive data
		_, err := runCommand("docker", "run", "-itd", "--privileged", "--network", ciNetworkName, "--name", netFlowCollectorContainer, "cloudflare/goflow", "-kafka=false")
		if err != nil {
			framework.Failf("failed to start NetFlow collector test container %s: %v", netFlowCollectorContainer, err)
		}
		// retrieve the container ip of the NetFlow collector container
		netFlowCollectorIp, err := runCommand("docker", "inspect", "-f", ciNetworkFlag, netFlowCollectorContainer)
		if err != nil {
			framework.Failf("failed to start NetFlow collector test container: %v", err)
		}
		// trim newline from the inspect output
		netFlowCollectorIp = strings.TrimSuffix(netFlowCollectorIp, "\n")
		if ip := net.ParseIP(netFlowCollectorIp); ip == nil {
			framework.Failf("Unable to retrieve a valid address from container %s with inspect output of %s", netFlowCollectorContainer, netFlowCollectorIp)
		}

		framework.Logf("Setting OVN_NETFLOW_TARGETS environment variable value to NetFlow collector IP %s", netFlowCollectorIp)
		framework.RunKubectlOrDie(ovnNs, "set", "env", "daemonset/ovnkube-node", "-c", "ovnkube-node", "OVN_NETFLOW_TARGETS="+netFlowCollectorIp+":2056")

		// `kubectl set env` causes rollout of ovnkube-node pod, so wait for all of the ovnkube-node Pods
		// to be ready
		err = e2epod.WaitForPodsReady(f.ClientSet, ovnNs, "ovnkube-node", 0)
		if err != nil {
			framework.Failf("ovnkube-node pods are not ready: %v", err)
		}

		netFlowCollectorContainerLogsTest := func() wait.ConditionFunc {
			return func() (bool, error) {
				netFlowCollectorContainerLogs, err := runCommand("docker", "logs", netFlowCollectorContainer)
				if err != nil {
					framework.Logf("failed to inspect logs in test container: %v", err)
					return false, nil
				}
				netFlowCollectorContainerLogs = strings.TrimSuffix(netFlowCollectorContainerLogs, "\n")
				logLines := strings.Split(netFlowCollectorContainerLogs, "\n")
				lastLine := logLines[len(logLines)-1]
				// check that NetFlow traffic has been logged.
				if strings.Contains(lastLine, "NETFLOW_V5") {
					framework.Logf("the NetFlow collector did not receive NetFlow data, last logs: %s", logLines[len(logLines)-1])
					return true, nil
				}
				return false, nil
			}
		}

		err = wait.PollImmediate(retryInterval, retryTimeout, netFlowCollectorContainerLogsTest())
		framework.ExpectNoError(err, "failed to verify that NetFlow collector container received NetFlow data from br-int")
	})
})

func getNodePodCIDR(nodeName string) (string, error) {
	// retrieve the pod cidr for the worker node
	jsonFlag := "jsonpath='{.metadata.annotations.k8s\\.ovn\\.org/node-subnets}'"
	kubectlOut, err := framework.RunKubectl("default", "get", "node", nodeName, "-o", jsonFlag)
	if err != nil {
		return "", err
	}
	// strip the apostrophe from stdout and parse the pod cidr
	annotation := strings.Replace(kubectlOut, "'", "", -1)

	ssSubnets := make(map[string]string)
	if err := json.Unmarshal([]byte(annotation), &ssSubnets); err == nil {
		return ssSubnets["default"], nil
	}
	dsSubnets := make(map[string][]string)
	if err := json.Unmarshal([]byte(annotation), &dsSubnets); err == nil {
		return dsSubnets["default"][0], nil
	}
	return "", fmt.Errorf("could not parse annotation %q", annotation)
}

var _ = ginkgo.Describe("e2e delete databases", func() {
	const (
		svcname                   string = "delete-db"
		ovnNs                     string = "ovn-kubernetes"
		databasePodPrefix         string = "ovnkube-db"
		databasePodNorthContainer string = "nb-ovsdb"
		northDBFileName           string = "ovnnb_db.db"
		southDBFileName           string = "ovnsb_db.db"
		dirDB                     string = "/etc/ovn"
		ovnWorkerNode             string = "ovn-worker"
		ovnWorkerNode2            string = "ovn-worker2"
		haModeMinDb               int    = 0
		haModeMaxDb               int    = 2
	)
	var (
		allDBFiles = []string{path.Join(dirDB, northDBFileName), path.Join(dirDB, southDBFileName)}
	)
	f := framework.NewDefaultFramework(svcname)

	// WaitForPodConditionAllowNotFoundError is a wrapper for WaitForPodCondition that allows at most 6 times for the pod not to be found.
	WaitForPodConditionAllowNotFoundErrors := func(f *framework.Framework, ns, podName, desc string, timeout time.Duration, condition podCondition) error {
		max_tries := 6               // 6 tries to waiting for the pod to restart
		cooldown := 10 * time.Second // 10 sec to cooldown between each try
		for i := 0; i < max_tries; i++ {
			err := e2epod.WaitForPodCondition(f.ClientSet, ns, podName, desc, 5*time.Minute, condition)
			if apierrors.IsNotFound(err) {
				// pod not found,try again after cooldown
				time.Sleep(cooldown)
				continue
			}
			if err != nil {
				return err
			}
			return nil
		}
		return fmt.Errorf("Gave up after waiting %v for pod %q to be %q: pod is not found", timeout, podName, desc)
	}

	// waitForPodToFinishFullRestart waits for a the pod to finish it's reset cycle and returns.
	waitForPodToFinishFullRestart := func(f *framework.Framework, pod *v1.Pod) {
		err := e2epod.WaitForPodCondition(f.ClientSet, pod.Namespace, pod.Name, "not ready", 5*time.Minute, testutils.PodNotReady)
		if err != nil {
			framework.Failf("pod %v is not arrived to not-ready state: %v", pod.Name, err)
		}
		// during this stage on the restarting process we can encounter "pod not found" errors.
		// this type of errors is valid because the pod is during restart so it will have a period that it will not be available.
		// so we will use "WaitForPodConditionAllowNotFoundErrors" in order to handle properly those errors.
		err = WaitForPodConditionAllowNotFoundErrors(f, pod.Namespace, pod.Name, "running and ready", 5*time.Minute, testutils.PodRunningReady)
		if err != nil {
			framework.Failf("pod %v is not arrived to running and ready state: %v", pod.Name, err)
		}
		return
	}
	deletePod := func(f *framework.Framework, namespace string, podName string) {
		podClient := f.ClientSet.CoreV1().Pods(namespace)
		err := podClient.Delete(context.Background(), podName, metav1.DeleteOptions{})
		framework.ExpectNoError(err, "failed to delete ovnkube-node pod")
	}

	fileExistsOnPod := func(f *framework.Framework, namespace string, pod *v1.Pod, file string) bool {
		containerFlag := fmt.Sprintf("-c=%s", pod.Spec.Containers[0].Name)
		_, err := framework.RunKubectl(ovnNs, "exec", pod.Name, containerFlag, "--", "ls", file)
		if err == nil{
				return true
		}
		if strings.Contains(err.Error(), fmt.Sprintf("ls: cannot access '%s': No such file or directory",file)) {
			return false
		}
		framework.Failf("failed to check if file %s exists on pod: %s, err: %v", file, pod.Name, err)
		return false
	}

	allFilesExistsOnPod := func(f *framework.Framework, namespace string, pod *v1.Pod, files []string) bool {
		for _, file := range files {
			if !fileExistsOnPod(f, namespace, pod, file) {
				framework.Logf("file %s not exists", file)
				return false
			}
			framework.Logf("file %s exists", file)
		}
		return true
	}

	deleteFileFromPod := func(f *framework.Framework, namespace string, pod *v1.Pod, file string) {
		containerFlag := fmt.Sprintf("-c=%s", pod.Spec.Containers[0].Name)
		framework.RunKubectl(ovnNs, "exec", pod.Name, containerFlag, "--", "rm", file)
		if fileExistsOnPod(f, namespace, pod, file) {
			framework.Failf("Error: failed to delete file %s", file)
		}
		framework.Logf("file %s deleted ", file)
	}

	singlePodConnectivityTest := func(f *framework.Framework, podName string) {
		framework.Logf("Running container which tries to connect to API server in a loop")
		podChan, errChan := make(chan *v1.Pod), make(chan error)

		go checkContinuousConnectivity(f, "", podName, getApiAddress(), 443, 30, podChan, errChan)
		testPod := <-podChan

		framework.Logf("Test pod running on %q", testPod.Spec.NodeName)
		framework.ExpectNoError(<-errChan)
	}
	twoPodsContinuousConnectivityTest := func(f *framework.Framework,
		node1Name string, node2Name string,
		syncChan chan string, errChan chan error) {
		const (
			pod1Name                  string        = "connectivity-test-pod1"
			pod2Name                  string        = "connectivity-test-pod2"
			port                      string        = "8080"
			timeIntervalBetweenChecks time.Duration = 2 * time.Second
		)

		var (
			command = []string{"/agnhost", "netexec", fmt.Sprintf("--http-port=" + port)}
		)
		createGenericPod(f, pod1Name, node1Name, f.Namespace.Name, command)
		createGenericPod(f, pod2Name, node2Name, f.Namespace.Name, command)

		pod2IP := getPodAddress(pod2Name, f.Namespace.Name)

		ginkgo.By("Checking initial connectivity from one pod to the other and verifying that the connection is achieved")

		stdout, err := framework.RunKubectl(f.Namespace.Name, "exec", pod1Name, "--", "curl", fmt.Sprintf("%s/hostname", net.JoinHostPort(pod2IP, port)))

		if err != nil || stdout != pod2Name {
			framework.Failf("Error: attempted connection to pod %s found err:  %v", pod2Name, err)
		}

		syncChan <- "connectivity test pods are ready"

	L:
		for {
			select {
			case msg := <-syncChan:
				framework.Logf(msg + "finish connectivity test.")
				break L
			default:
				stdout, err := framework.RunKubectl(f.Namespace.Name, "exec", pod1Name, "--", "curl", fmt.Sprintf("%s/hostname", net.JoinHostPort(pod2IP, port)))
				if err != nil || stdout != pod2Name {
					errChan <- err
					framework.Failf("Error: attempted connection to pod %s found err:  %v", pod2Name, err)
				}
				time.Sleep(timeIntervalBetweenChecks)
			}
		}

		errChan <- nil
	}

	table.DescribeTable("recovering from deleting db files while maintain connectivity",
		func(db_pod_num int, DBFileNamesToDelete []string) {
			var (
				db_pod_name = fmt.Sprintf("%s-%d", databasePodPrefix, db_pod_num)
			)
			if db_pod_num < haModeMinDb || db_pod_num > haModeMaxDb {
				framework.Failf("invalid db_pod_num.")
				return
			}

			// Adding db file path
			for i, file := range DBFileNamesToDelete {
				DBFileNamesToDelete[i] = path.Join(dirDB, file)
			}

			framework.Logf("connectivity test before deleting db files")
			framework.Logf("test simple connectivity from new pod to API server,before deleting db files")
			singlePodConnectivityTest(f, "before-delete-db-files")
			framework.Logf("setup two pods for continues connectivity test ")
			syncChan, errChan := make(chan string), make(chan error)
			go twoPodsContinuousConnectivityTest(f, ovnWorkerNode, ovnWorkerNode2, syncChan, errChan)
			// Wait for the connectivity test pods to be ready
			framework.Logf(<-syncChan + "delete and restart db pods.")

			// Start the db disruption - delete the db files and delete the db-pod in order to emulate the cluster/pod restart

			// Retrive the DB pod
			dbPod, err := f.ClientSet.CoreV1().Pods(ovnNs).Get(context.Background(), db_pod_name, metav1.GetOptions{})
			framework.ExpectNoError(err, fmt.Sprintf("unable to get pod: %s, err: %v", db_pod_name, err))

			// Check that all files exists on pod
			framework.Logf("make sure that all the db files are exists on the db pod:%s", dbPod.Name)
			if !allFilesExistsOnPod(f, ovnNs, dbPod, allDBFiles) {
				framework.Failf("Error: db files not found")
			}
			// Delete the db files from the db-pod
			framework.Logf("deleting db files from db pod")
			for _, db_file := range DBFileNamesToDelete {
				deleteFileFromPod(f, ovnNs, dbPod, db_file)
			}
			// Delete the db-pod in order to emulate the cluster/pod restart
			framework.Logf("deleting db pod:%s", dbPod.Name)
			deletePod(f, ovnNs, dbPod.Name)

			framework.Logf("wait for db pod to finish full restart")
			waitForPodToFinishFullRestart(f, dbPod)

			// Check db files existence
			// Check that all files exists on pod
			framework.Logf("make sure that all the db files are exists on the db pod:%s", dbPod.Name)
			if !allFilesExistsOnPod(f, ovnNs, dbPod, allDBFiles) {
				framework.Failf("Error: db files not found")
			}

			// disruption over.
			syncChan <- "disruption over."
			framework.ExpectNoError(<-errChan)

			framework.Logf("test simple connectivity from new pod to API server,after recovery")
			singlePodConnectivityTest(f, "after-delete-db-files")
		},

		// One can choose to delete only specific db file (uncomment the requested lines)

		// db pod 0
		table.Entry("when delete both db files on ovnkube-db-0", 0, []string{northDBFileName, southDBFileName}),
		// table.Entry("when delete north db on ovnkube-db-0", 0, []string{northDBFileName}),
		// table.Entry("when delete south db on ovnkube-db-0", 0, []string{southDBFileName}),

		// db pod 1
		table.Entry("when delete both db files on ovnkube-db-1", 1, []string{northDBFileName, southDBFileName}),
		// table.Entry("when delete north db on ovnkube-db-1", 1, []string{northDBFileName}),
		// table.Entry("when delete south db on ovnkube-db-1", 1, []string{southDBFileName}),

		// db pod 2
		table.Entry("when delete both db files on ovnkube-db-2", 2, []string{northDBFileName, southDBFileName}),
		// table.Entry("when delete north db on ovnkube-db-2", 2, []string{northDBFileName}),
		// table.Entry("when delete south db on ovnkube-db-2", 2, []string{southDBFileName}),
	)

	ginkgo.It("Should validate connectivity before and after deleting all the db-pods at once", func() {
		dbPods, err := e2epod.GetPods(f.ClientSet, ovnNs, map[string]string{"name": databasePodPrefix})
		if err != nil {
			framework.Failf("Error: Failed to get pods, err: %v", err)
		}
		if len(dbPods) == 0 {
			framework.Failf("Error: db pods not found")
		}

		framework.Logf("test simple connectivity from new pod to API server,before deleting db pods")
		singlePodConnectivityTest(f, "before-delete-db-pods")

		framework.Logf("deleting all the db pods")
		for _, dbPod := range dbPods {
			dbPodName := dbPod.Name
			framework.Logf("deleting db pod: %v", dbPodName)
			// Delete the db-pod in order to emulate the pod restart
			dbPod.Status.Message = "check"
			deletePod(f, ovnNs, dbPodName)
		}

		framework.Logf("wait for all the pods to finish full restart")
		var wg sync.WaitGroup
		for _, pod := range dbPods {
			wg.Add(1)
			go func(pod v1.Pod) {
				defer wg.Done()
				waitForPodToFinishFullRestart(f, &pod)
			}(pod)
		}
		wg.Wait()
		framework.Logf("all the pods finish full restart")

		framework.Logf("test simple connectivity from new pod to API server,after recovery")
		singlePodConnectivityTest(f, "after-delete-db-pods")
	})
})
