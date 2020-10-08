package ovn

import (
	"fmt"
	"hash/fnv"
	"strconv"

	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"k8s.io/klog"
)

// hash the provided input to make it a valid addressSet or portGroup name.
func hashForOVN(s string) string {
	h := fnv.New64a()
	_, err := h.Write([]byte(s))
	if err != nil {
		klog.Errorf("Failed to hash %s", s)
	}
	hashString := strconv.FormatUint(h.Sum64(), 10)
	return fmt.Sprintf("a%s", hashString)
}

// hash the provided input to make it a valid portGroup name.
func hashedPortGroup(s string) string {
	return hashForOVN(s)
}

func createPortGroup(exec util.ExecHelper, name string, hashName string) (string, error) {
	klog.V(5).Infof("createPortGroup with %s", name)
	portGroup, stderr, err := exec.RunOVNNbctl("--data=bare",
		"--no-heading", "--columns=_uuid", "find", "port_group",
		fmt.Sprintf("name=%s", hashName))
	if err != nil {
		return "", fmt.Errorf("find failed to get port_group, stderr: %q (%v)",
			stderr, err)
	}

	if portGroup != "" {
		return portGroup, nil
	}

	portGroup, stderr, err = exec.RunOVNNbctl("create", "port_group",
		fmt.Sprintf("name=%s", hashName),
		fmt.Sprintf("external-ids:name=%s", name))
	if err != nil {
		return "", fmt.Errorf("failed to create port_group %s, "+
			"stderr: %q (%v)", name, stderr, err)
	}

	return portGroup, nil
}

func deletePortGroup(exec util.ExecHelper, hashName string) {
	klog.V(5).Infof("deletePortGroup %s", hashName)

	portGroup, stderr, err := exec.RunOVNNbctl("--data=bare",
		"--no-heading", "--columns=_uuid", "find", "port_group",
		fmt.Sprintf("name=%s", hashName))
	if err != nil {
		klog.Errorf("Find failed to get port_group, stderr: %q (%v)",
			stderr, err)
		return
	}

	if portGroup == "" {
		return
	}

	_, stderr, err = exec.RunOVNNbctl("--if-exists", "destroy",
		"port_group", portGroup)
	if err != nil {
		klog.Errorf("Failed to destroy port_group %s, stderr: %q, (%v)",
			hashName, stderr, err)
		return
	}
}

func stringSliceMembership(slice []string, key string) bool {
	for _, val := range slice {
		if val == key {
			return true
		}
	}
	return false
}
