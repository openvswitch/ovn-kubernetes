package cni

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

// serverRunDir is the default directory for CNIServer runtime files
const serverRunDir string = "/var/run/ovn-kubernetes/cni/"

const serverSocketName string = "ovn-cni-server.sock"
const serverSocketPath string = serverRunDir + "/" + serverSocketName

// PodInterfaceInfo consists of interface info result from cni server if cni client configure's interface
type PodInterfaceInfo struct {
	util.PodAnnotation

	MTU         int    `json:"mtu"`
	Ingress     int64  `json:"ingress"`
	Egress      int64  `json:"egress"`
	NetworkName string `json:"network"`
}

// Explicit type for CNI commands the server handles
type command string

// CNIAdd is the command representing add operation for a new pod
const CNIAdd command = "ADD"

// CNIUpdate is the command representing update operation for an existing pod
const CNIUpdate command = "UPDATE"

// CNIDel is the command representing delete operation on a pod that is to be torn down
const CNIDel command = "DEL"

// CNICheck is the command representing check operation on a pod
const CNICheck command = "CHECK"

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
	// Timestamp when the request was started
	timestamp time.Time
	// ctx is a context tracking this request's lifetime
	ctx context.Context
	// cancel should be called to cancel this request
	cancel context.CancelFunc
}

type cniRequestFunc func(request *PodRequest, podLister corev1listers.PodLister) ([]byte, error)

// Server object that listens for JSON-marshaled Request objects
// on a private root-only Unix domain socket.
type Server struct {
	http.Server
	requestFunc cniRequestFunc
	rundir      string
	podLister   corev1listers.PodLister

	// runningSandboxAdds is a map of sandbox ID to PodRequest for any CNIAdd operation
	runningSandboxAddsLock sync.Mutex
	runningSandboxAdds     map[string]*PodRequest
}
