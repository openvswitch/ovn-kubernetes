package e2e_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/onsi/ginkgo"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/kubernetes/test/e2e/framework"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
)

const (
	vxlanPort            = "4789" // IANA assigned VXLAN UDP port - rfc7348
	podNetworkAnnotation = "k8s.ovn.org/pod-networks"
	exGwAnnotation       = "k8s.ovn.org/hybrid-overlay-external-gw"
	retryInterval        = 1 * time.Second  // polling interval timer
	retryTimeout         = 40 * time.Second // polling timeout
	ciNetworkName        = "kind"
)

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
					Image:   framework.AgnHostImage,
					Command: command,
				},
			},
			NodeName:      nodeName,
			RestartPolicy: v1.RestartPolicyNever,
		},
	}
	podClient := f.ClientSet.CoreV1().Pods(f.Namespace.Name)
	_, err := podClient.Create(pod)
	if err != nil {
		errChan <- err
		return
	}

	// Wait for pod network setup to be almost ready
	wait.PollImmediate(1*time.Second, 30*time.Second, func() (bool, error) {
		pod, err := podClient.Get(podName, metav1.GetOptions{})
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

	podGet, err := podClient.Get(podName, metav1.GetOptions{})
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
					Image:   framework.AgnHostImage,
					Command: command,
					Args:    args,
				},
			},
			NodeName:      nodeName,
			RestartPolicy: v1.RestartPolicyNever,
		},
	}
	podClient := f.ClientSet.CoreV1().Pods(f.Namespace.Name)
	_, err := podClient.Create(pod)
	if err != nil {
		return err
	}

	// Wait for pod network setup to be almost ready
	err = wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
		pod, err := podClient.Get(podName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		if exGw {
			if _, ok := pod.Annotations[exGwAnnotation]; !ok {
				return false, nil
			}
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
					Image:   framework.AgnHostImage,
					Command: command,
				},
			},
			NodeName:      nodeName,
			RestartPolicy: v1.RestartPolicyNever,
		},
	}
	podClient := f.ClientSet.CoreV1().Pods(f.Namespace.Name)
	_, err := podClient.Create(pod)
	if err != nil {
		framework.Failf("Error trying to create pod")
	}

	// Wait for pod network setup to be almost ready
	wait.PollImmediate(1*time.Second, 30*time.Second, func() (bool, error) {
		podGet, err := podClient.Get(podName, metav1.GetOptions{})
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

	podGet, err := podClient.Get(podName, metav1.GetOptions{})
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
func createGenericPod(f *framework.Framework, podName, nodeSelector, namespace string, command []string) {
	createPod(f, podName, nodeSelector, namespace, command, nil)
}

// Create a pod on the specified node using the agnostic host image
func createGenericPodWithLabel(f *framework.Framework, podName, nodeSelector, namespace string, command []string, labels map[string]string) {
	createPod(f, podName, nodeSelector, namespace, command, labels)
}

func createClusterExternalContainer(containerName string, containerImage string, additionalArgs []string) string {
	args := []string{"docker", "run", "-itd"}
	args = append(args, additionalArgs...)
	args = append(args, []string{"--name", containerName, containerImage}...)
	_, err := runCommand(args...)
	if err != nil {
		framework.Failf("failed to start external test container: %v", err)
	}
	ip, err := runCommand("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", containerName)
	if err != nil {
		framework.Failf("failed to inspect external test container for its IP: %v", err)
	}
	return strings.Trim(ip, "\n")
}

func deleteClusterExternalContainer(containerName string) {
	_, err := runCommand("docker", "rm", "-f", containerName)
	if err != nil {
		framework.Failf("failed to delete external test container, err: %v", err)
	}
}

func updateNamespace(f *framework.Framework, namespace *v1.Namespace) {
	_, err := f.ClientSet.CoreV1().Namespaces().Update(namespace)
	framework.ExpectNoError(err, fmt.Sprintf("unable to update namespace: %s, err: %v", namespace.Name, err))
}

func updatePod(f *framework.Framework, pod *v1.Pod) {
	_, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Update(pod)
	framework.ExpectNoError(err, fmt.Sprintf("unable to update pod: %s, err: %v", pod.Name, err))
}
func getPod(f *framework.Framework, podName string) *v1.Pod {
	pod, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(podName, metav1.GetOptions{})
	framework.ExpectNoError(err, fmt.Sprintf("unable to get pod: %s, err: %v", podName, err))
	return pod
}

// Create a pod on the specified node using the agnostic host image
func createPod(f *framework.Framework, podName, nodeSelector, namespace string, command []string, labels map[string]string) {

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
					Image:   framework.AgnHostImage,
					Command: command,
				},
			},
			NodeName:      nodeSelector,
			RestartPolicy: v1.RestartPolicyNever,
		},
	}
	podClient := f.ClientSet.CoreV1().Pods(namespace)
	_, err := podClient.Create(pod)
	if err != nil {
		framework.Logf("Warning: Failed to get logs from pod %q: %v", pod.Name, err)
	}
	err = e2epod.WaitForPodNotPending(f.ClientSet, podName, namespace)
	if err != nil {
		logs, logErr := e2epod.GetPodLogs(f.ClientSet, namespace, pod.Name, contName)
		if logErr != nil {
			framework.Logf("Warning: Failed to get logs from pod %q: %v", pod.Name, logErr)
		} else {
			framework.Logf("pod %s/%s logs:\n%s", namespace, pod.Name, logs)
		}
	}
}

// Get the IP address of a pod in the specified namespace
func getPodAddress(podName, namespace string) string {
	podIP, err := framework.RunKubectl("get", "pods", podName, "--template={{.status.podIP}}", "-n"+namespace)
	if err != nil {
		framework.Failf("Unable to retrieve the IP for pod %s %v", podName, err)
	}
	return podIP
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

		podList, _ := podClient.List(metav1.ListOptions{})
		podName := ""
		for _, pod := range podList.Items {
			if strings.HasPrefix(pod.Name, "ovnkube-node") && pod.Spec.NodeName == testPod.Spec.NodeName {
				podName = pod.Name
				break
			}
		}

		err := podClient.Delete(podName, metav1.NewDeleteOptions(0))
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

		podList, _ := podClient.List(metav1.ListOptions{})
		podName := ""
		for _, pod := range podList.Items {
			if strings.HasPrefix(pod.Name, "ovnkube-master") {
				podName = pod.Name
				break
			}
		}

		err := podClient.Delete(podName, metav1.NewDeleteOptions(0))
		framework.ExpectNoError(err, "should delete ovnkube-master pod")
		framework.Logf("Deleted ovnkube-master %q", podName)

		framework.ExpectNoError(<-errChan)
	})
})

// Test e2e hybrid sdn inter-node connectivity between worker nodes and validate pods do not traverse the external gateway
var _ = ginkgo.Describe("test e2e inter-node connectivity between worker nodes hybrid overlay on separate worker nodes", func() {
	const (
		svcname          string = "internode-hyb-sdn-e2e"
		pingTarget       string = "172.17.0.250"
		ovnNs            string = "ovn-kubernetes"
		ovnWorkerNode    string = "ovn-worker"
		ovnWorkerNode2   string = "ovn-worker2"
		ovnHaWorkerNode2 string = "ovn-control-plane2"
		ovnHaWorkerNode3 string = "ovn-control-plane3"
		ovnContainer     string = "ovnkube-node"
		gwContainerName  string = "gw-test-container-internode"
		jsonFlag         string = "-o=jsonpath='{.items..metadata.name}'"
	)
	var (
		haMode    bool
		ovnNsFlag = fmt.Sprintf("--namespace=%s", ovnNs)
		labelFlag = fmt.Sprintf("name=%s", ovnContainer)
	)

	f := framework.NewDefaultFramework(svcname)

	// Determine what mode the CI is running in and get relevant endpoint information for the tests
	ginkgo.BeforeEach(func() {
		fieldSelectorFlag := fmt.Sprintf("--field-selector=spec.nodeName=%s", ovnWorkerNode)
		fieldSelectorHaFlag := fmt.Sprintf("--field-selector=spec.nodeName=%s", ovnHaWorkerNode2)

		// start the container that will act as an external gateway
		_, err := runCommand("docker", "run", "-itd", "--privileged", "--name", gwContainerName, "centos")
		if err != nil {
			framework.Failf("failed to start external gateway test container: %v", err)
		}
		exVtepIP, err := runCommand("docker", "inspect", "-f", "{{ .NetworkSettings.IPAddress }}", gwContainerName)
		if err != nil {
			framework.Failf("failed to start external gateway test container: %v", err)
		}
		// trim newline from the inspect output >:|
		exVtepIP = strings.TrimSuffix(exVtepIP, "\n")
		framework.Logf("The external gateway IP is %s", exVtepIP)

		annotateArgs := []string{
			"annotate",
			"namespace",
			f.Namespace.Name,
			fmt.Sprintf("k8s.ovn.org/hybrid-overlay-external-gw=%s", pingTarget),
			fmt.Sprintf("k8s.ovn.org/hybrid-overlay-vtep=%s", exVtepIP),
		}
		// Annotate the pods to route pods to hybrid-sdn bridge br-ext
		framework.Logf("Annotating the external gateway test namespace")
		framework.RunKubectlOrDie(annotateArgs...)

		// Attempt to retrieve the pod name that will run the external interface for e2e control-plane non-ha mode
		kubectlOut, err := framework.RunKubectl("get", "pods", ovnNsFlag, "-l", labelFlag, jsonFlag, fieldSelectorFlag)
		if err != nil {
			framework.Failf("Expected container %s running on %s error %v", ovnContainer, ovnWorkerNode, err)
		}
		// Attempt to retrieve the pod name that will run the external interface for e2e control-plane ha mode
		if kubectlOut == "''" {
			haMode = true
			kubectlOut, err = framework.RunKubectl("get", "pods", ovnNsFlag, "-l", labelFlag, jsonFlag, fieldSelectorHaFlag)
			if err != nil {
				framework.Failf("Expected container %s running on %s error %v", ovnContainer, ovnHaWorkerNode2, err)
			}
		}
		// Fail the test if no pod is matched within the specified node
		if kubectlOut == "''" {
			framework.Failf("Unable to locate container %s on any known nodes", ovnContainer)
		}
	})

	ginkgo.AfterEach(func() {
		// tear down the container simulating the gateway
		_, err := runCommand("docker", "rm", "-f", gwContainerName)
		if err != nil {
			framework.Failf("failed to delete the gateway test container %v", err)
		}
	})

	ginkgo.It("Should validate connectivity between pods with hybrid overlay on separate worker nodes and ensure br-ext is not traversed", func() {
		var err error
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

		// Wait for pod exgw setup to be almost ready
		err = wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
			pingTarget = getPodAddress(dstPingPodName, f.Namespace.Name)
			validIP = net.ParseIP(pingTarget)
			if validIP == nil {
				return false, nil
			}
			return true, nil
		})
		// Fail the test if no address is ever retrieved
		if err != nil {
			framework.Failf("Error trying to get the pod IP address")
		}
		// Spin up another pod that attempts to reach the previously started pod on separate nodes
		framework.ExpectNoError(
			checkConnectivityPingToHost(f, ciWorkerNodeSrc, "e2e-src-ping-pod", pingTarget, ipv4PingCommand, 30, true))

		fieldSelectorFlag := fmt.Sprintf("--field-selector=spec.nodeName=%s", ciWorkerNodeSrc)
		kubectlOut, err := framework.RunKubectl("get", "pods", ovnNsFlag, "-l", labelFlag, jsonFlag, fieldSelectorFlag)
		if err != nil {
			framework.Failf("Expected container %s running on %s error %v", ovnContainer, ciWorkerNodeSrc, err)
		}
		ovnPodName := strings.Trim(kubectlOut, "'")
		ovnContainerFlag := fmt.Sprintf("--container=%s", ovnContainer)
		// dump the flowmods from br-ext to verify no counters are hit
		kubectlOut, err = framework.RunKubectl("exec", ovnPodName, ovnNsFlag, ovnContainerFlag, "--", "ovs-ofctl", "dump-flows", "br-ext")
		if err != nil {
			framework.Failf("Expected container %s running on %s error %v", ovnContainer, ovnWorkerNode, err)
		}
		for _, flowmod := range strings.Split(kubectlOut, "\n") {
			// filter out irrelevant lines from ofctl output
			if strings.Contains(flowmod, pingTarget) {
				// verify no flowmod counters were hit in br-ext for the target
				if !strings.Contains(flowmod, "n_packets=0") {
					framework.Failf("Expected packets=0 but found the flow %s", flowmod)
				}
			}
		}
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
		ovnNsFlag = fmt.Sprintf("--namespace=%s", ovnNs)
		labelFlag = fmt.Sprintf("name=%s", ovnContainer)
	)

	f := framework.NewDefaultFramework(svcname)

	// Determine which KIND environment is running by querying the running nodes
	ginkgo.BeforeEach(func() {
		fieldSelectorFlag := fmt.Sprintf("--field-selector=spec.nodeName=%s", ovnWorkerNode)
		fieldSelectorHaFlag := fmt.Sprintf("--field-selector=spec.nodeName=%s", ovnHaWorkerNode2)

		// Determine if the kind deployment is in HA mode or non-ha mode based on node naming
		kubectlOut, err := framework.RunKubectl("get", "pods", ovnNsFlag, "-l", labelFlag, jsonFlag, fieldSelectorFlag)
		if err != nil {
			framework.Failf("Expected container %s running on %s error %v", ovnContainer, ovnWorkerNode, err)
		}
		if kubectlOut == "''" {
			haMode = true
			kubectlOut, err = framework.RunKubectl("get", "pods", ovnNsFlag, "-l", labelFlag, jsonFlag, fieldSelectorHaFlag)
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

// Verify pods in the namespace annotated with an external-gateway traverse the vxlan
// overlay and reach the intended external gateway vtep and gateway end to end
var _ = ginkgo.Describe("e2e external gateway validation", func() {
	const (
		svcname         string = "externalgw"
		ovnNs           string = "ovn-kubernetes"
		extGW           string = "10.249.0.1"
		gwContainerName string = "gw-test-container"
		ovnWorkerNode   string = "ovn-worker"
		ovnHaWorkerNode string = "ovn-control-plane2"
		ovnContainer    string = "ovnkube-node"
	)
	var (
		haMode        bool
		ciNetworkFlag string
		extGWCidr     = fmt.Sprintf("%s/24", extGW)
		ovnNsFlag     = fmt.Sprintf("--namespace=%s", ovnNs)
	)
	f := framework.NewDefaultFramework(svcname)

	// Determine what mode the CI is running in and get relevant endpoint information for the tests
	ginkgo.BeforeEach(func() {
		labelFlag := fmt.Sprintf("name=%s", ovnContainer)
		jsonFlag := "-o=jsonpath='{.items..metadata.name}'"
		fieldSelectorFlag := fmt.Sprintf("--field-selector=spec.nodeName=%s", ovnWorkerNode)
		fieldSelectorHaFlag := fmt.Sprintf("--field-selector=spec.nodeName=%s", ovnHaWorkerNode)
		ciNetworkFlag = fmt.Sprintf("{{ .NetworkSettings.Networks.%s.IPAddress }}", ciNetworkName)
		// start the container that will act as an external gateway
		_, err := runCommand("docker", "run", "-itd", "--privileged", "--network", ciNetworkName, "--name", gwContainerName, "centos")
		if err != nil {
			framework.Failf("failed to start external gateway test container: %v", err)
		}
		// retrieve the container ip of the external gateway container
		exVtepIP, err := runCommand("docker", "inspect", "-f", ciNetworkFlag, gwContainerName)
		if err != nil {
			framework.Failf("failed to start external gateway test container: %v", err)
		}
		// trim newline from the inspect output >:|
		exVtepIP = strings.TrimSuffix(exVtepIP, "\n")
		if ip := net.ParseIP(exVtepIP); ip == nil {
			framework.Failf("Unable to retrieve a valid address from container %s with inspect output of %s", gwContainerName, exVtepIP)
		}
		framework.Logf("The external gateway IP is %s", exVtepIP)
		// annotate the test namespace

		annotateArgs := []string{
			"annotate",
			"namespace",
			f.Namespace.Name,
			fmt.Sprintf("k8s.ovn.org/hybrid-overlay-external-gw=%s", extGW),
			fmt.Sprintf("k8s.ovn.org/hybrid-overlay-vtep=%s", exVtepIP),
		}

		framework.Logf("Annotating the external gateway test namespace")
		framework.RunKubectlOrDie(annotateArgs...)
		// attempt to retrieve the pod name that will source the tunnel test in non-HA mode
		kubectlOut, err := framework.RunKubectl("get", "pods", ovnNsFlag, "-l", labelFlag, jsonFlag, fieldSelectorFlag)
		if err != nil {
			framework.Failf("Expected container %s running on %s error %v", ovnContainer, ovnWorkerNode, err)
		}
		// attempt to retrieve the pod name that will source the tunnel test in HA mode
		if kubectlOut == "''" {
			haMode = true
			kubectlOut, err = framework.RunKubectl("get", "pods", ovnNsFlag, "-l", labelFlag, jsonFlag, fieldSelectorHaFlag)
			if err != nil {
				framework.Failf("Expected container %s running on %s error %v", ovnContainer, ovnHaWorkerNode, err)
			}
		}
	})

	ginkgo.AfterEach(func() {
		// tear down the container simulating the gateway
		if cid, _ := runCommand("docker", "ps", "-qaf", fmt.Sprintf("name=%s", gwContainerName)); cid != "" {
			if _, err := runCommand("docker", "rm", "-f", gwContainerName); err != nil {
				framework.Logf("failed to delete the gateway test container %s %v", gwContainerName, err)
			}
		}
	})

	ginkgo.It("Should validate connectivity to the vxlan interface simulating an external gateway and validate traffic was encapsulated", func() {
		// non-ha ci mode runs a set of kind nodes prefixed with ovn-worker
		ciWorkerNodeSrc := ovnWorkerNode
		if haMode {
			// ha ci mode runs a named set of nodes with a prefix of ovn-control-plane
			ciWorkerNodeSrc = ovnHaWorkerNode
		}
		localVtepIP, err := runCommand("docker", "inspect", "-f", ciNetworkFlag, ciWorkerNodeSrc)
		if err != nil {
			framework.Failf("failed to get the node ip address from node %s %v", ciWorkerNodeSrc, err)
		}
		localVtepIP = strings.TrimSuffix(localVtepIP, "\n")
		if ip := net.ParseIP(localVtepIP); ip == nil {
			framework.Failf("Unable to retrieve a valid address from container %s with inspect output of %s", gwContainerName, localVtepIP)
		}
		framework.Logf("the pod side vtep node is %s and the ip %s", ciWorkerNodeSrc, localVtepIP)
		podCIDR, err := getNodePodCIDR(ciWorkerNodeSrc)
		if err != nil {
			framework.Failf("Error retrieving the pod cidr from %s %v", ciWorkerNodeSrc, err)
		}
		framework.Logf("the pod cidr for node %s is %s", ciWorkerNodeSrc, podCIDR)
		// setup the container to act as an external gateway and vtep
		_, err = runCommand("docker", "exec", gwContainerName, "ip", "link", "add", "vxlan0", "type", "vxlan", "dev",
			"eth0", "id", "4097", "dstport", vxlanPort, "remote", localVtepIP)
		if err != nil {
			framework.Failf("failed to create the vxlan interface on the test container: %v", err)
		}
		_, err = runCommand("docker", "exec", gwContainerName, "ip", "link", "set", "vxlan0", "up")
		if err != nil {
			framework.Failf("failed to enable the vxlan interface on the test container: %v", err)
		}
		_, err = runCommand("docker", "exec", gwContainerName, "ip", "address", "add", extGWCidr, "dev", "lo")
		if err != nil {
			framework.Failf("failed to add the external gateway ip to dev lo on the test container: %v", err)
		}
		_, err = runCommand("docker", "exec", gwContainerName, "ip", "route", "add", podCIDR, "dev", "vxlan0")
		if err != nil {
			framework.Failf("failed to add the pod route on the test container: %v", err)
		}
		// give the container time to come up and stabilize
		time.Sleep(time.Second * 10)
		ginkgo.By(fmt.Sprintf("Creating a container on %s and testing end to end traffic to an external gateway", ciWorkerNodeSrc))
		framework.ExpectNoError(
			// generate traffic that will being encapsulated and sent to the external gateway.
			checkConnectivityPingToHost(f, ciWorkerNodeSrc, "external-gateway-e2e", extGW, ipv4PingCommand, 30, true))
	})

	ginkgo.It("Should add default routes over .3 if hybrid external gw annotation is set", func() {
		// non-ha ci mode runs a set of kind nodes prefixed with ovn-worker
		ciWorkerNodeSrc := ovnWorkerNode
		if haMode {
			// ha ci mode runs a named set of nodes with a prefix of ovn-control-plane
			ciWorkerNodeSrc = ovnHaWorkerNode
		}
		localVtepIP, err := runCommand("docker", "inspect", "-f", ciNetworkFlag, ciWorkerNodeSrc)
		if err != nil {
			framework.Failf("failed to get the node ip address from node %s %v", ciWorkerNodeSrc, err)
		}
		localVtepIP = strings.TrimSuffix(localVtepIP, "\n")
		if ip := net.ParseIP(localVtepIP); ip == nil {
			framework.Failf("Unable to retrieve a valid address from container %s with inspect output of %s", gwContainerName, localVtepIP)
		}
		framework.Logf("the pod side vtep node is %s and the ip %s", ciWorkerNodeSrc, localVtepIP)
		podCIDR, err := getNodePodCIDR(ciWorkerNodeSrc)
		if err != nil {
			framework.Failf("Error retrieving the pod cidr from %s %v", ciWorkerNodeSrc, err)
		}
		framework.Logf("the pod cidr for node %s is %s", ciWorkerNodeSrc, podCIDR)
		ginkgo.By(fmt.Sprintf("Creating a container on %s and check default routes", ciWorkerNodeSrc))
		if getPodGWRoute(f, ciWorkerNodeSrc, "hybrid-external-routing-external-gws-preference-e2e").To4()[3] != 3 {
			framework.Fail("The pod gw route should go thru .3 port when hybrid external gw annotation is used")
		}
	})

	ginkgo.It("routing-external-gws routes to OVN DR should take precedence over hybrid external gw routes to .3", func() {
		// non-ha ci mode runs a set of kind nodes prefixed with ovn-worker
		ciWorkerNodeSrc := ovnWorkerNode
		if haMode {
			// ha ci mode runs a named set of nodes with a prefix of ovn-control-plane
			ciWorkerNodeSrc = ovnHaWorkerNode
		}
		localVtepIP, err := runCommand("docker", "inspect", "-f", ciNetworkFlag, ciWorkerNodeSrc)
		if err != nil {
			framework.Failf("failed to get the node ip address from node %s %v", ciWorkerNodeSrc, err)
		}
		localVtepIP = strings.TrimSuffix(localVtepIP, "\n")
		if ip := net.ParseIP(localVtepIP); ip == nil {
			framework.Failf("Unable to retrieve a valid address from container %s with inspect output of %s", gwContainerName, localVtepIP)
		}
		framework.Logf("the pod side vtep node is %s and the ip %s", ciWorkerNodeSrc, localVtepIP)
		podCIDR, err := getNodePodCIDR(ciWorkerNodeSrc)
		if err != nil {
			framework.Failf("Error retrieving the pod cidr from %s %v", ciWorkerNodeSrc, err)
		}
		framework.Logf("the pod cidr for node %s is %s", ciWorkerNodeSrc, podCIDR)
		annotateArgs := []string{
			"annotate",
			"namespace",
			f.Namespace.Name,
			fmt.Sprintf("k8s.ovn.org/routing-external-gws=%s", "172.17.250.1"),
		}
		framework.Logf("Annotating the external gateway test namespace with routing-external-gws annotation:%s", "172.17.250.1")
		framework.RunKubectlOrDie(annotateArgs...)
		ginkgo.By(fmt.Sprintf("Creating a container on %s and check default routes", ciWorkerNodeSrc))
		if getPodGWRoute(f, ciWorkerNodeSrc, "hybrid-external-routing-external-gws-preference-e2e").To4()[3] != 1 {
			framework.Fail("routing-external-gws annotation not taking precedence over hybrid external as pod gw route is going thru .3 port")
		}
	})
})

// Validate pods can reach the initial gateway and then update the namespace
// annotation to point to a second container also emulating the external gateway
var _ = ginkgo.Describe("e2e multiple external gateway update validation", func() {
	const (
		svcname             string = "multiple-externalgw"
		extGwAlt1           string = "10.249.1.1"
		extGwAlt2           string = "10.249.2.1"
		ovnNs               string = "ovn-kubernetes"
		ovnWorkerNode       string = "ovn-worker"
		ovnHaWorkerNode     string = "ovn-control-plane2"
		ovnContainer        string = "ovnkube-node"
		gwContainerNameAlt1 string = "gw-test-container-alt"
		gwContainerNameAlt2 string = "gw-test-container-alt2"
	)
	var (
		haMode        bool
		ciNetworkFlag string
		ovnNsFlag     = fmt.Sprintf("--namespace=%s", ovnNs)
	)
	f := framework.NewDefaultFramework(svcname)

	// Determine what mode the CI is running in and get relevant endpoint information for the tests
	ginkgo.BeforeEach(func() {
		labelFlag := fmt.Sprintf("name=%s", ovnContainer)
		jsonFlag := "-o=jsonpath='{.items..metadata.name}'"
		fieldSelectorFlag := fmt.Sprintf("--field-selector=spec.nodeName=%s", ovnWorkerNode)
		fieldSelectorHaFlag := fmt.Sprintf("--field-selector=spec.nodeName=%s", ovnHaWorkerNode)
		ciNetworkFlag = fmt.Sprintf("{{ .NetworkSettings.Networks.%s.IPAddress }}", ciNetworkName)
		// attempt to retrieve the pod name that will source the tunnel test in non-HA mode
		kubectlOut, err := framework.RunKubectl("get", "pods", ovnNsFlag, "-l", labelFlag, jsonFlag, fieldSelectorFlag)
		if err != nil {
			framework.Failf("Expected container %s running on %s error %v", ovnContainer, ovnWorkerNode, err)
		}
		// attempt to retrieve the pod name that will source the tunnel test in HA mode
		if kubectlOut == "''" {
			haMode = true
			kubectlOut, err = framework.RunKubectl("get", "pods", ovnNsFlag, "-l", labelFlag, jsonFlag, fieldSelectorHaFlag)
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

	ginkgo.It("Should validate connectivity before and after updating the namespace annotation to a new vtep and external gateway", func() {

		var pingSrc string
		var validIP net.IP
		extGWCidrAlt1 := fmt.Sprintf("%s/24", extGwAlt1)
		extGWCidrAlt2 := fmt.Sprintf("%s/24", extGwAlt2)
		srcPingPodName := "e2e-exgw-src-ping-pod"
		command := []string{"bash", "-c", "sleep 20000"}
		frameworkNsFlag := fmt.Sprintf("--namespace=%s", f.Namespace.Name)
		testContainer := fmt.Sprintf("%s-container", srcPingPodName)
		testContainerFlag := fmt.Sprintf("--container=%s", testContainer)
		// start the container that will act as an external gateway
		_, err := runCommand("docker", "run", "-itd", "--privileged", "--network", ciNetworkName, "--name", gwContainerNameAlt1, "centos")
		if err != nil {
			framework.Failf("failed to start external gateway test container %s: %v", gwContainerNameAlt1, err)
		}
		// retrieve the container ip of the external gateway container
		exVtepIpAlt1, err := runCommand("docker", "inspect", "-f", ciNetworkFlag, gwContainerNameAlt1)
		if err != nil {
			framework.Failf("failed to start external gateway test container: %v", err)
		}
		// trim newline from the inspect output
		exVtepIpAlt1 = strings.TrimSuffix(exVtepIpAlt1, "\n")
		if ip := net.ParseIP(exVtepIpAlt1); ip == nil {
			framework.Failf("Unable to retrieve a valid address from container %s with inspect output of %s", gwContainerNameAlt1, exVtepIpAlt1)
		}
		// annotate the test namespace
		annotateArgs := []string{
			"annotate",
			"namespace",
			f.Namespace.Name,
			fmt.Sprintf("k8s.ovn.org/hybrid-overlay-external-gw=%s", extGwAlt1),
			fmt.Sprintf("k8s.ovn.org/hybrid-overlay-vtep=%s", exVtepIpAlt1),
		}
		framework.Logf("Annotating the external gateway test namespace to a new container vtep:%s gw:%s ", exVtepIpAlt1, extGwAlt1)
		framework.RunKubectlOrDie(annotateArgs...)
		// non-ha ci mode runs a set of kind nodes prefixed with ovn-worker
		ciWorkerNodeSrc := ovnWorkerNode
		if haMode {
			// ha ci mode runs a named set of nodes with a prefix of ovn-control-plane
			ciWorkerNodeSrc = ovnHaWorkerNode
		}
		localVtepIP, err := runCommand("docker", "inspect", "-f", ciNetworkFlag, ciWorkerNodeSrc)
		if err != nil {
			framework.Failf("failed to get the node ip address from node %s %v", ciWorkerNodeSrc, err)
		}
		localVtepIP = strings.TrimSuffix(localVtepIP, "\n")
		if ip := net.ParseIP(localVtepIP); ip == nil {
			framework.Failf("Unable to retrieve a valid address from container %s with inspect output of %s", ciWorkerNodeSrc, localVtepIP)
		}
		framework.Logf("the pod side vtep node is %s and the ip %s", ciWorkerNodeSrc, localVtepIP)
		podCIDR, err := getNodePodCIDR(ciWorkerNodeSrc)
		if err != nil {
			framework.Failf("Error retrieving the pod cidr from %s %v", ciWorkerNodeSrc, err)
		}
		framework.Logf("the pod cidr for node %s is %s", ciWorkerNodeSrc, podCIDR)
		// setup the new container to emulate a gateway with routes, vtep and a loopback interface acting as the gateway
		_, err = runCommand("docker", "exec", gwContainerNameAlt1, "ip", "link", "add", "vxlan0", "type", "vxlan", "dev",
			"eth0", "id", "4097", "dstport", vxlanPort, "remote", localVtepIP)
		if err != nil {
			framework.Failf("failed to create the vxlan interface on the test container: %v", err)
		}
		_, err = runCommand("docker", "exec", gwContainerNameAlt1, "ip", "link", "set", "vxlan0", "up")
		if err != nil {
			framework.Failf("failed to enable the vxlan interface on the test container: %v", err)
		}
		_, err = runCommand("docker", "exec", gwContainerNameAlt1, "ip", "address", "add", extGWCidrAlt1, "dev", "lo")
		if err != nil {
			framework.Failf("failed to add the external gateway ip to dev lo on the test container: %v", err)
		}
		_, err = runCommand("docker", "exec", gwContainerNameAlt1, "ip", "route", "add", podCIDR, "dev", "vxlan0")
		if err != nil {
			framework.Failf("failed to add the pod route on the test container: %v", err)
		}
		// Create the pod that will be used as the source for the connectivity test
		createGenericPod(f, srcPingPodName, ciWorkerNodeSrc, f.Namespace.Name, command)

		// Wait for pod exgw setup to be almost ready
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
		// Verify the initial gateway is reachable from the new pod
		ginkgo.By(fmt.Sprintf("Verifying connectivity to the updated annotation and initial external gateway %s and vtep %s", extGwAlt1, exVtepIpAlt1))
		_, err = framework.RunKubectl("exec", srcPingPodName, frameworkNsFlag, testContainerFlag, "--", "ping", "-w", "40", extGwAlt1)
		if err != nil {
			framework.Failf("Failed to ping the first gateway %s from container %s on node %s: %v", extGwAlt1, ovnContainer, ovnWorkerNode, err)
		}
		// start the container that will act as a new external gateway that the tests will be updated to use
		_, err = runCommand("docker", "run", "-itd", "--privileged", "--network", ciNetworkName, "--name", gwContainerNameAlt2, "centos")
		if err != nil {
			framework.Failf("failed to start external gateway test container %s: %v", gwContainerNameAlt2, err)
		}
		// retrieve the container ip of the external gateway container
		exVtepIpAlt2, err := runCommand("docker", "inspect", "-f", ciNetworkFlag, gwContainerNameAlt2)
		if err != nil {
			framework.Failf("failed to start external gateway test container: %v", err)
		}
		// trim newline from the inspect output
		exVtepIpAlt2 = strings.TrimSuffix(exVtepIpAlt2, "\n")
		if ip := net.ParseIP(localVtepIP); ip == nil {
			framework.Failf("Unable to retrieve a valid address from container %s with inspect output of %s", gwContainerNameAlt2, localVtepIP)
		}
		// override the annotation in the test namespace with the new vtep and gateway
		annotateArgs = []string{
			"annotate",
			"namespace",
			f.Namespace.Name,
			fmt.Sprintf("k8s.ovn.org/hybrid-overlay-external-gw=%s", extGwAlt2),
			fmt.Sprintf("k8s.ovn.org/hybrid-overlay-vtep=%s", exVtepIpAlt2),
			"--overwrite",
		}
		framework.Logf("Annotating the external gateway test namespace to a new container vtep:%s gw:%s ", exVtepIpAlt2, extGwAlt2)
		framework.RunKubectlOrDie(annotateArgs...)
		// setup the new container to emulate a gateway with routes, vtep and a loopback interface acting as the gateway
		_, err = runCommand("docker", "exec", gwContainerNameAlt2, "ip", "link", "add", "vxlan0", "type", "vxlan", "dev",
			"eth0", "id", "4097", "dstport", vxlanPort, "remote", localVtepIP)
		if err != nil {
			framework.Failf("failed to create the vxlan interface on the test container: %v", err)
		}
		_, err = runCommand("docker", "exec", gwContainerNameAlt2, "ip", "link", "set", "vxlan0", "up")
		if err != nil {
			framework.Failf("failed to enable the vxlan interface on the test container: %v", err)
		}
		_, err = runCommand("docker", "exec", gwContainerNameAlt2, "ip", "address", "add", extGWCidrAlt2, "dev", "lo")
		if err != nil {
			framework.Failf("failed to add the external gateway ip to dev lo on the test container: %v", err)
		}
		_, err = runCommand("docker", "exec", gwContainerNameAlt2, "ip", "route", "add", podCIDR, "dev", "vxlan0")
		if err != nil {
			framework.Failf("failed to add the pod route on the test container: %v", err)
		}

		ginkgo.By(fmt.Sprintf("Verifying connectivity to the updated annotation and new external gateway %s and vtep %s", extGwAlt2, exVtepIpAlt2))
		_, err = framework.RunKubectl("exec", srcPingPodName, frameworkNsFlag, testContainerFlag, "--", "ping", "-w", "40", extGwAlt2)
		if err != nil {
			framework.Failf("Failed to ping the second gateway %s from container %s on node %s: %v", extGwAlt2, ovnContainer, ovnWorkerNode, err)
		}
	})
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
14. Check connectivity from the remaining pod to an external "node" and verify that the IP is the node IP.
15. Re-add the label to one of the egress nodes
16. Check connectivity from the remaining pod to an external "node" and verify that the IP is one of the egress IPs.
*/
var _ = ginkgo.Describe("e2e egress IP validation", func() {
	const (
		svcname          string = "egressip"
		egressTargetNode string = "egressTargetNode"
		egressIPYaml     string = "egressip.yml"
		waitInterval            = 3 * time.Second
	)

	type node struct {
		name   string
		nodeIP string
	}

	var (
		egress1Node, egress2Node, pod1Node, pod2Node, targetNode node
	)

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
			name: egressTargetNode,
		}
		targetNode.nodeIP = createClusterExternalContainer(targetNode.name, "docker.io/httpd", []string{"--network", ciNetworkName, "-P"})
	})

	ginkgo.AfterEach(func() {
		deleteClusterExternalContainer(targetNode.name)
	})

	ginkgo.It("Should validate the egress IP functionality against remote hosts", func() {
		podHTTPPort := "8080"
		pod1Name := "e2e-egressip-pod-1"
		pod2Name := "e2e-egressip-pod-2"
		podEgressLabel := map[string]string{
			"wants": "egress",
		}
		command := []string{"/agnhost", "netexec", fmt.Sprintf("--http-port=%s", podHTTPPort)}
		frameworkNsFlag := fmt.Sprintf("--namespace=%s", f.Namespace.Name)

		ginkgo.By("Adding the k8s.ovn.org/egress-assignable label to two nodes")
		framework.AddOrUpdateLabelOnNode(f.ClientSet, egress1Node.name, "k8s.ovn.org/egress-assignable", "dummy")
		framework.AddOrUpdateLabelOnNode(f.ClientSet, egress2Node.name, "k8s.ovn.org/egress-assignable", "dummy")

		podNamespace := f.Namespace
		podNamespace.Labels = map[string]string{
			"name": f.Namespace.Name,
		}
		updateNamespace(f, podNamespace)

		ginkgo.By("Creating one EgressIP with two egress IPs defined")
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
    name: egressip
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

		framework.Logf("Applying the EgressIP configuration")
		framework.RunKubectlOrDie("apply", "-f", egressIPYaml)
		time.Sleep(waitInterval)

		targetExternalContainerAndTest := func(verifyIPType, podName string, verifyIPs []string) {
			framework.RunKubectlOrDie("exec", podName, frameworkNsFlag, "--", "curl", net.JoinHostPort(targetNode.nodeIP, "80"))
			targetNodeLogs, err := runCommand("docker", "logs", targetNode.name)
			if err != nil {
				framework.Failf("failed to inspect logs in test container: %v", err)
			}
			targetNodeLogs = strings.TrimSuffix(targetNodeLogs, "\n")
			logLines := strings.Split(targetNodeLogs, "\n")
			lastLine := logLines[len(logLines)-1]
			var found bool
			for _, verifyIP := range verifyIPs {
				if strings.Contains(lastLine, verifyIP) {
					found = true
				}
			}
			if !found {
				framework.Failf("the test external container did not have any trace of the %s IPs: %s being logged, last logs: %s", verifyIPType, verifyIPs, logLines[len(logLines)-1])
			}
		}

		type status struct {
			node     string
			egressIP string
		}

		testStatus := func() []status {
			nodeStdout, err := framework.RunKubectl("get", "eip", "-o", "jsonpath='{.items[0].status.items[*].node}'")
			if err != nil {
				framework.Failf("Error: failed to get the EgressIP object, err: %v", err)
			}
			egressIPStdout, err := framework.RunKubectl("get", "eip", "-o", "jsonpath='{.items[0].status.items[*].egressIP}'")
			if err != nil {
				framework.Failf("Error: failed to get the EgressIP object, err: %v", err)
			}
			statuses := []status{}
			for _, n := range strings.Split(nodeStdout, " ") {
				statuses = append(statuses, status{
					node: n,
				})
			}
			egressIPStdout = strings.Trim(egressIPStdout, "'")
			for i, e := range strings.Split(egressIPStdout, " ") {
				statuses[i].egressIP = e
			}
			return statuses
		}

		ginkgo.By("Checking that the status is of length two and both are assigned to different nodes")
		statuses := testStatus()
		if len(statuses) != 2 {
			framework.Failf("Error: expected to have two egress IPs assigned, got: %v", len(statuses))
		}
		if eIP := net.ParseIP(statuses[0].egressIP); eIP == nil {
			framework.Failf("Error: expected to have the first egress IP, got something else: %s", statuses[0].egressIP)
		}
		if eIP := net.ParseIP(statuses[1].egressIP); eIP == nil {
			framework.Failf("Error: expected to have the second egress IP, got something else: %s", statuses[1].egressIP)
		}
		if statuses[0].node == statuses[1].node {
			framework.Failf("Error: expected to have egress IP assignment on different nodes")
		}

		ginkgo.By("Creating two pods matching the EgressIP: one running on each of the egress nodes")
		createGenericPodWithLabel(f, pod1Name, pod1Node.name, f.Namespace.Name, command, podEgressLabel)
		createGenericPodWithLabel(f, pod2Name, pod2Node.name, f.Namespace.Name, command, podEgressLabel)

		wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
			for _, podName := range []string{pod1Name, pod2Name} {
				kubectlOut := getPodAddress(podName, f.Namespace.Name)
				srcIP := net.ParseIP(kubectlOut)
				if srcIP == nil {
					return false, nil
				}
			}
			return true, nil
		})

		apiServerIP, err := framework.RunKubectl("get", "svc", "kubernetes", "-n", "default", "-o", "jsonpath='{.spec.clusterIP}'")
		apiServerIP = strings.Trim(apiServerIP, "'")
		if err != nil {
			framework.Failf("Error: unable to get API-server IP address, err:  %v", err)
		}
		apiServer := net.ParseIP(apiServerIP)
		if apiServer == nil {
			framework.Failf("Error: unable to parse API-server IP address:  %s", apiServerIP)
		}

		pod2IP := getPodAddress(pod2Name, f.Namespace.Name)

		ginkgo.By("Checking connectivity from both to an external node and verify that the IP is one of the egress IPs")
		targetExternalContainerAndTest("egress", pod1Name, []string{egressIP1.String(), egressIP2.String()})
		targetExternalContainerAndTest("egress", pod2Name, []string{egressIP1.String(), egressIP2.String()})

		ginkgo.By("Checking connectivity from one pod to the other and verifying that the connection is achieved")
		stdout, err := framework.RunKubectl("exec", pod1Name, frameworkNsFlag, "--", "curl", fmt.Sprintf("%s/hostname", net.JoinHostPort(pod2IP, podHTTPPort)))
		if err != nil || stdout != pod2Name {
			framework.Failf("Error: attempted connection to pod %s found err:  %v", pod2Name, err)
		}

		ginkgo.By("Checking connectivity from both pods to the api-server and verifying that the connection is achieved")
		for _, podName := range []string{pod1Name, pod2Name} {
			_, err := framework.RunKubectl("exec", podName, frameworkNsFlag, "--", "curl", "-k", fmt.Sprintf("https://%s/version", net.JoinHostPort(apiServer.String(), "443")))
			if err != nil {
				framework.Failf("Error: attempted connection to API server found err:  %v", err)
			}
		}

		ginkgo.By("Updating one of the pods, unmatching the EgressIP")
		pod2 := getPod(f, pod2Name)
		pod2.Labels = map[string]string{}
		updatePod(f, pod2)

		ginkgo.By("Checking connectivity from that one to an external node and verify that the IP is the node IP")
		time.Sleep(waitInterval)
		targetExternalContainerAndTest("egress", pod2Name, []string{pod2Node.nodeIP})

		ginkgo.By("Checking connectivity from the other one to an external node and verify that the IP is one of the egress IPs")
		targetExternalContainerAndTest("egress", pod1Name, []string{egressIP1.String(), egressIP2.String()})

		ginkgo.By("Removing the node label off one of the egress node")
		framework.RemoveLabelOffNode(f.ClientSet, egress1Node.name, "k8s.ovn.org/egress-assignable")

		ginkgo.By("Checking that the status is of length one")
		time.Sleep(waitInterval)
		statuses = testStatus()
		if len(statuses) != 1 {
			framework.Failf("Error: expected to have 1 egress IP assignment, got: %v", len(statuses))
		}

		ginkgo.By("Checking connectivity from the remaining pod to an external node and verify that the IP is the remaining egress IP.")
		time.Sleep(waitInterval)
		targetExternalContainerAndTest("egress", pod1Name, []string{statuses[0].egressIP})

		ginkgo.By("Removing the node label off the last egress node")
		framework.RemoveLabelOffNode(f.ClientSet, egress2Node.name, "k8s.ovn.org/egress-assignable")

		ginkgo.By("Checking connectivity from the remaining pod to an external node and verify that the IP is the node IP..")
		time.Sleep(waitInterval)
		targetExternalContainerAndTest("egress", pod1Name, []string{pod1Node.nodeIP})

		ginkgo.By("Re-adding the label to the node")
		framework.AddOrUpdateLabelOnNode(f.ClientSet, egress2Node.name, "k8s.ovn.org/egress-assignable", "dummy")

		ginkgo.By("Checking connectivity from the remaining pod to an external node and verify that the IP is one of the egress IPs.")
		time.Sleep(waitInterval)
		targetExternalContainerAndTest("egress", pod1Name, []string{egressIP1.String(), egressIP2.String()})

		framework.RemoveLabelOffNode(f.ClientSet, egress2Node.name, "k8s.ovn.org/egress-assignable")
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
		ovnNsFlag     = fmt.Sprintf("--namespace=%s", ovnNs)
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
		kubectlOut, err := framework.RunKubectl("get", "pods", ovnNsFlag, "-l", labelFlag, jsonFlag, fieldSelectorControlFlag)
		if err != nil {
			framework.Failf("Expected container %s running on %s error %v", ovnContainer, ovnControlNode, err)
		}
		// attempt to retrieve the pod name that will source the test in non-HA mode
		kubectlOut, err = framework.RunKubectl("get", "pods", ovnNsFlag, "-l", labelFlag, jsonFlag, fieldSelectorFlag)
		if err != nil {
			framework.Failf("Expected container %s running on %s error %v", ovnContainer, ovnWorkerNode, err)
		}
		// attempt to retrieve the pod name that will source the test in HA mode
		if kubectlOut == "''" {
			haMode = true
			kubectlOut, err = framework.RunKubectl("get", "pods", ovnNsFlag, "-l", labelFlag, jsonFlag, fieldSelectorHaFlag)
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
		frameworkNsFlag := fmt.Sprintf("--namespace=%s", f.Namespace.Name)
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
		framework.RunKubectlOrDie(annotateArgs...)
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
		_, err = framework.RunKubectl("exec", srcPingPodName, frameworkNsFlag, testContainerFlag, "--", "ping", "-w", "40", exGWRemoteIpAlt1)
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
		framework.RunKubectlOrDie(annotateArgs...)
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
		_, err = framework.RunKubectl("exec", srcPingPodName, frameworkNsFlag, testContainerFlag, "--", "ping", "-w", "40", exGWRemoteIpAlt2)
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
		framework.RunKubectlOrDie(applyArgs...)
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
		_, err = framework.RunKubectl("exec", srcPodName, frameworkNsFlag, testContainerFlag, "--", "nc", "-vz", "-w", testTimeout, exFWPermitTcpDnsDest, "53")
		if err != nil {
			framework.Failf("Failed to connect to the remote host %s from container %s on node %s: %v", exFWPermitTcpDnsDest, ovnContainer, serverNodeInfo.name, err)
		}
		// Verify the remote host/port as implicitly denied by the firewall policy is not reachable
		ginkgo.By(fmt.Sprintf("Verifying connectivity to an implicitly denied host %s is not permitted as defined by the external firewall policy", exFWDenyTcpDnsDest))
		_, err = framework.RunKubectl("exec", srcPodName, frameworkNsFlag, testContainerFlag, "--", "nc", "-vz", "-w", testTimeout, exFWDenyTcpDnsDest, "53")
		if err == nil {
			framework.Failf("Succeeded in connecting the implicitly denied remote host %s from container %s on node %s", exFWDenyTcpDnsDest, ovnContainer, serverNodeInfo.name)
		}
		// Verify the the explicitly allowed host/port tcp port 80 rule is functional
		ginkgo.By(fmt.Sprintf("Verifying connectivity to an explicitly allowed host %s is permitted as defined by the external firewall policy", exFWPermitTcpWwwDest))
		_, err = framework.RunKubectl("exec", srcPodName, frameworkNsFlag, testContainerFlag, "--", "nc", "-vz", "-w", testTimeout, exFWPermitTcpWwwDest, "80")
		if err != nil {
			framework.Failf("Failed to curl the remote host %s from container %s on node %s: %v", exFWPermitTcpWwwDest, ovnContainer, serverNodeInfo.name, err)
		}
		// Verify the remote host/port 443 as implicitly denied by the firewall policy is not reachable
		ginkgo.By(fmt.Sprintf("Verifying connectivity to an implicitly denied port on host %s is not permitted as defined by the external firewall policy", exFWPermitTcpWwwDest))
		_, err = framework.RunKubectl("exec", srcPodName, frameworkNsFlag, testContainerFlag, "--", "nc", "-vz", "-w", testTimeout, exFWPermitTcpWwwDest, "443")
		if err == nil {
			framework.Failf("Failed to curl the remote host %s from container %s on node %s: %v", exFWPermitTcpWwwDest, ovnContainer, serverNodeInfo.name, err)
		}
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
			frameworkNsFlag   = fmt.Sprintf("--namespace=%s", f.Namespace.Name)
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
		framework.RunKubectlOrDie(annotateArgs...)

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
		_, err = framework.RunKubectl("exec", srcPingPodName, frameworkNsFlag, testContainerFlag, "--", "ping", "-w", "40", exGWRemoteIp)
		if err != nil {
			framework.Failf("Failed to ping the remote gateway network %s from pod %s: %v", exGWRemoteIp, srcPingPodName, err)
		}
		err = f.ClientSet.CoreV1().Pods(defaultNamespace).Delete(gatewayPodName, metav1.NewDeleteOptions(0))
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
			frameworkNsFlag   = fmt.Sprintf("--namespace=%s", f.Namespace.Name)
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
		framework.RunKubectlOrDie(annotateArgs...)

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
				_, err = framework.RunKubectl("exec", srcPingPodName, frameworkNsFlag, testContainerFlag, "--", "ping", "-c", testTimeout, gwLo)
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

// Validate supplying an external gateway address that does not match
// the address family of the pod fails. In this case, an IPv6 address is
// provided as the external gateway address that does not match the
// address family of the pod. The test expects the pod creation to fail.
var _ = ginkgo.Describe("e2e mismatched address family external gateway", func() {
	const (
		svcname string = "external-gw-address-family-mismatch"
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

	ginkgo.AfterEach(func() {})

	ginkgo.It("Should validate failure if an external gateway address does not match the address family of the pod", func() {

		var (
			pingSrc  string
			validIP  net.IP
			podName  = "e2e-mismatched-exgw-addresses"
			command  = []string{"bash", "-c", "sleep 20000"}
			exGWIPv6 = "fd00:10:244:2::6"
		)

		// annotate the test namespace with a v6 address
		annotateArgs := []string{
			"annotate",
			"namespace",
			f.Namespace.Name,
			fmt.Sprintf("k8s.ovn.org/routing-external-gws=%s", exGWIPv6),
		}
		framework.Logf("Annotating the external gateway test namespace to the v6 address: %s ", exGWIPv6)
		framework.RunKubectlOrDie(annotateArgs...)

		ginkgo.By(fmt.Sprintf("Verifying the pod fails to start using mismatched address families between the pod and gateway"))
		createGenericPod(f, podName, workerNodeInfo.name, f.Namespace.Name, command)
		// the pod will fail to create due to mismatched gateway/pod address families
		err := wait.PollImmediate(retryInterval, retryTimeout, func() (bool, error) {
			pingSrc = getPodAddress(podName, f.Namespace.Name)
			validIP = net.ParseIP(pingSrc)
			if validIP == nil {
				return false, nil
			}
			return true, nil
		})
		// Expect the readiness poll to fail since the pod and gateway address families do not match
		framework.ExpectError(err, fmt.Sprintf("Exepcted error using a mismatched address family for the gateway for pod: %s, err: %v",
			podName, err))
	})
})

func getNodePodCIDR(nodeName string) (string, error) {
	// retrieve the pod cidr for the worker node
	jsonFlag := "jsonpath='{.metadata.annotations.k8s\\.ovn\\.org/node-subnets}'"
	kubectlOut, err := framework.RunKubectl("get", "node", nodeName, "-o", jsonFlag)
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
