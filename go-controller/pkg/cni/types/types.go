package types

import (
	"github.com/containernetworking/cni/pkg/types"
)

// NetConf is CNI NetConf with DeviceID
type NetConf struct {
	types.NetConf
	// PciAddrs in case of using sriov
	DeviceID string `json:"deviceID,omitempty"`
	// Network Cidr
	NetCidr string `json:"net_cidr,omitempty"`
	// Network MTU
	MTU int `json:"mtu,omitempty"`
	// set true if it is default networkattachmentdefintion
	NotDefault bool `json:"not_default,omitempty"`
	// LogFile to log all the messages from cni shim binary to
	LogFile string `json:"logFile,omitempty"`
	// Level is the logging verbosity level
	LogLevel string `json:"logLevel,omitempty"`
	// LogFileMaxSize is the maximum size in bytes of the logfile
	// before it gets rolled.
	LogFileMaxSize int `json:"logfile-maxsize"`
	// LogFileMaxBackups represents the the maximum number of
	// old log files to retain
	LogFileMaxBackups int `json:"logfile-maxbackups"`
	// LogFileMaxAge represents the maximum number
	// of days to retain old log files
	LogFileMaxAge int `json:"logfile-maxage"`
}
