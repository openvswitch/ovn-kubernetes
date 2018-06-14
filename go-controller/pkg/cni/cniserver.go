package cni

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/openvswitch/ovn-kubernetes/go-controller/pkg/config"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
)

// *** The CNIServer is PRIVATE API between OVN components and may be
// changed at any time.  It is in no way a supported interface or API. ***
//
// The CNIServer accepts pod setup/teardown requests from the OVN
// CNI plugin, which is itself called by kubelet when pod networking
// should be set up or torn down.  The OVN CNI plugin gathers up
// the standard CNI environment variables and network configuration provided
// on stdin and forwards them to the CNIServer over a private, root-only
// Unix domain socket, using HTTP as the transport and JSON as the protocol.
//
// The CNIServer interprets standard CNI environment variables as specified
// by the Container Network Interface (CNI) specification available here:
// https://github.com/containernetworking/cni/blob/master/SPEC.md
// While the CNIServer interface is not itself versioned, as the CNI
// specification requires that CNI network configuration is versioned, and
// since the OVN CNI plugin passes that configuration to the
// CNIServer, versioning is ensured in exactly the same way as an executable
// CNI plugin would be versioned.
//
// Security: since the Unix domain socket created by the CNIServer is owned
// by root and inaccessible to any other user, no unprivileged process may
// access the CNIServer.  The Unix domain socket and its parent directory are
// removed and re-created with 0700 permissions each time ovnkube on the node is
// started.

// Create and return a new CNIServer object which will listen on a socket in the given path
func NewCNIServer(rundir string) *CNIServer {
	if len(rundir) == 0 {
		rundir = CNIServerRunDir
	}
	router := mux.NewRouter()

	s := &CNIServer{
		Server: http.Server{
			Handler: router,
		},
		rundir: rundir,
	}
	router.NotFoundHandler = http.HandlerFunc(http.NotFound)
	router.HandleFunc("/", s.handleCNIRequest).Methods("POST")
	return s
}

// Start the CNIServer's local HTTP server on a root-owned Unix domain socket.
// requestFunc will be called to handle pod setup/teardown operations on each
// request to the CNIServer's HTTP server, and should return a PodResult
// when the operation has completed.
func (s *CNIServer) Start(requestFunc cniRequestFunc) error {
	if requestFunc == nil {
		return fmt.Errorf("no pod request handler")
	}
	s.requestFunc = requestFunc

	// Remove and re-create the socket directory with root-only permissions
	if err := os.RemoveAll(s.rundir); err != nil && !os.IsNotExist(err) {
		utilruntime.HandleError(fmt.Errorf("failed to remove old pod info socket: %v", err))
	}
	if err := os.RemoveAll(s.rundir); err != nil && !os.IsNotExist(err) {
		utilruntime.HandleError(fmt.Errorf("failed to remove contents of socket directory: %v", err))
	}
	if err := os.MkdirAll(s.rundir, 0700); err != nil {
		return fmt.Errorf("failed to create pod info socket directory: %v", err)
	}

	// On Linux the socket is created with the permissions of the directory
	// it is in, so as long as the directory is root-only we can avoid
	// racy umask manipulation.
	socketPath := filepath.Join(s.rundir, CNIServerSocketName)
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on pod info socket: %v", err)
	}
	if err := os.Chmod(socketPath, 0600); err != nil {
		l.Close()
		return fmt.Errorf("failed to set pod info socket mode: %v", err)
	}

	s.SetKeepAlivesEnabled(false)
	go utilwait.Forever(func() {
		if err := s.Serve(l); err != nil {
			utilruntime.HandleError(fmt.Errorf("CNI server Serve() failed: %v", err))
		}
	}, 0)
	return nil
}

// Split the "CNI_ARGS" environment variable's value into a map.  CNI_ARGS
// contains arbitrary key/value pairs separated by ';' and is for runtime or
// plugin specific uses.  Kubernetes passes the pod namespace and name in
// CNI_ARGS.
func gatherCNIArgs(env map[string]string) (map[string]string, error) {
	cniArgs, ok := env["CNI_ARGS"]
	if !ok {
		return nil, fmt.Errorf("missing CNI_ARGS: '%s'", env)
	}

	mapArgs := make(map[string]string)
	for _, arg := range strings.Split(cniArgs, ";") {
		parts := strings.Split(arg, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid CNI_ARG '%s'", arg)
		}
		mapArgs[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return mapArgs, nil
}

func cniRequestToPodRequest(r *http.Request) (*PodRequest, error) {
	var cr CNIRequest
	b, _ := ioutil.ReadAll(r.Body)
	if err := json.Unmarshal(b, &cr); err != nil {
		return nil, fmt.Errorf("JSON unmarshal error: %v", err)
	}

	cmd, ok := cr.Env["CNI_COMMAND"]
	if !ok {
		return nil, fmt.Errorf("unexpected or missing CNI_COMMAND")
	}

	req := &PodRequest{
		Command: CNICommand(cmd),
		Result:  make(chan *PodResult),
	}

	req.SandboxID, ok = cr.Env["CNI_CONTAINERID"]
	if !ok {
		return nil, fmt.Errorf("missing CNI_CONTAINERID")
	}
	req.Netns, ok = cr.Env["CNI_NETNS"]
	if !ok {
		return nil, fmt.Errorf("missing CNI_NETNS")
	}

	cniArgs, err := gatherCNIArgs(cr.Env)
	if err != nil {
		return nil, err
	}

	req.PodNamespace, ok = cniArgs["K8S_POD_NAMESPACE"]
	if err != nil {
		return nil, fmt.Errorf("missing K8S_POD_NAMESPACE")
	}

	req.PodName, ok = cniArgs["K8S_POD_NAME"]
	if err != nil {
		return nil, fmt.Errorf("missing K8S_POD_NAME")
	}

	conf, err := config.ReadCNIConfig(cr.Config)
	if err != nil {
		return nil, fmt.Errorf("broken stdin args")
	}
	req.CNIVersion = conf.CNIVersion
	return req, nil
}

// Dispatch a pod request to the request handler and return the result to the
// CNI server client
func (s *CNIServer) handleCNIRequest(w http.ResponseWriter, r *http.Request) {
	req, err := cniRequestToPodRequest(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	logrus.Infof("Waiting for %s result for pod %s/%s", req.Command, req.PodNamespace, req.PodName)
	result, err := s.requestFunc(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("%v", err), http.StatusBadRequest)
	} else {
		// Empty response JSON means success with no body
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(result); err != nil {
			logrus.Warningf("Error writing %s HTTP response: %v", req.Command, err)
		}
	}
}
