package cni

import (
	"net/http"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"k8s.io/client-go/kubernetes"
)

// serverRunDir is the default directory for CNIServer runtime files
const serverRunDir string = "/var/run/ovn-kubernetes/cni/"

const serverSocketName string = "ovn-cni-server.sock"
const serverSocketPath string = serverRunDir + "/" + serverSocketName

// PodInterfaceInfo consists of interface info result from cni server if cni client configure's interface
type PodInterfaceInfo struct {
	util.PodAnnotation

	MTU        int   `json:"mtu"`
	Ingress    int64 `json:"ingress"`
	Egress     int64 `json:"egress"`
	IsSmartNic bool  `josn:"smartnic"`
}

// Explicit type for CNI commands the server handles
type command string

// CNIAdd is the command representing add operation for a new pod
const CNIAdd command = "ADD"

// CNIUpdate is the command representing update operation for an existing pod
const CNIUpdate command = "UPDATE"

// CNIDel is the command representing delete operation on a pod that is to be torn down
const CNIDel command = "DEL"

// Request sent to the Server by the OVN CNI plugin
type Request struct {
	// CNI environment variables, like CNI_COMMAND and CNI_NETNS
	Env map[string]string `json:"env,omitempty"`
	// CNI configuration passed via stdin to the CNI plugin
	Config []byte `json:"config,omitempty"`
}

// CNIRequestMetrics info to report from CNI shim to CNI server
type CNIRequestMetrics struct {
	Command     command `json:"command"`
	ElapsedTime float64 `json:"elapsedTime"`
	HasErr      bool    `json:"hasErr"`
}

// Response sent to the OVN CNI plugin by the Server
type Response struct {
	Result    *current.Result
	PodIFInfo *PodInterfaceInfo
}

// PodRequest structure built from Request which is passed to the
// handler function given to the Server at creation time
type PodRequest struct {
	// The CNI command of the operation
	Command command
	// kubernetes namespace name
	PodNamespace string
	// kubernetes pod name
	PodName string
	// kubernetes container ID
	SandboxID string
	// kernel network namespace path
	Netns string
	// Interface name to be configured
	IfName string
	// CNI conf obtained from stdin conf
	CNIConf *types.NetConf
}

type cniRequestFunc func(request *PodRequest, kclient kubernetes.Interface) ([]byte, error)

// Server object that listens for JSON-marshaled Request objects
// on a private root-only Unix domain socket.
type Server struct {
	http.Server
	requestFunc cniRequestFunc
	rundir      string
	kclient     kubernetes.Interface
}
