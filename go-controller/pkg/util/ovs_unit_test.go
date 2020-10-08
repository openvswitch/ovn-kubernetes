package util

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"

	mock_k8s_io_utils_exec "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/mocks/k8s.io/utils/exec"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/mocks"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	kexec "k8s.io/utils/exec"
)

type onCallReturnArgsRepetitive struct {
	onCallMethodName                    string
	onCallMethodsArgsStrTypeAppendCount int
	onCallMethodArgType                 []string
	retArgList                          []interface{}
}

type onCallReturnArgs struct {
	onCallMethodName    string
	onCallMethodArgType []string
	retArgList          []interface{}
}

func TestRunOVNretry(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// Below is defined in ovs.go
	ovnCmdRetryCount = 0
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		inpCmdPath              string
		inpEnvVars              []string
		errMatch                error
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "test path when runWithEnvVars returns no error",
			inpCmdPath:              runner.nbctlPath,
			inpEnvVars:              []string{},
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{nil, nil, nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "test path when runWithEnvVars returns  \"Connection refused\" error",
			inpCmdPath:              runner.nbctlPath,
			inpEnvVars:              []string{},
			errMatch:                fmt.Errorf("connection refused"),
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{nil, bytes.NewBuffer([]byte("Connection refused")), fmt.Errorf("connection refused")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "test path when runWithEnvVars returns an error OTHER THAN \"Connection refused\" ",
			inpCmdPath:              runner.nbctlPath,
			inpEnvVars:              []string{},
			errMatch:                fmt.Errorf("OVN command"),
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{nil, nil, fmt.Errorf("mock error")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()
			_, _, e := runner.runOVNretry(tc.inpCmdPath, tc.inpEnvVars)

			if tc.errMatch != nil {
				assert.Contains(t, e.Error(), tc.errMatch.Error())
			} else {
				assert.Nil(t, e)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestGetNbctlSocketPath(t *testing.T) {
	// Below is defined in ovs.go file
	AppFs = afero.NewMemMapFs()

	tests := []struct {
		desc         string
		mockEnvKey   string
		mockEnvVal   string
		errMatch     error
		outExp       string
		dirFileMocks []ovntest.AferoDirMockHelper
	}{
		{
			desc:       "test code path when `os.Getenv() is non empty` and when Stat() returns error",
			mockEnvKey: "OVN_NB_DAEMON",
			mockEnvVal: "/some/blah/path",
			errMatch:   fmt.Errorf("OVN_NB_DAEMON ovn-nbctl daemon control socket"),
			outExp:     "",
		},
		{
			desc:       "test code path when `os.Getenv() is non empty` and when Stat() returns success",
			mockEnvKey: "OVN_NB_DAEMON",
			mockEnvVal: "/some/blah/path",
			dirFileMocks: []ovntest.AferoDirMockHelper{
				{
					DirName:     "/some/blah/",
					Permissions: 0755,
					Files: []ovntest.AferoFileMockHelper{
						{"/some/blah/path", 0755, []byte("blah")},
					},
				},
			},
			outExp: "OVN_NB_DAEMON=/some/blah/path",
		},
		{
			desc: "test code path when ReadFile() returns error",
			dirFileMocks: []ovntest.AferoDirMockHelper{
				{
					DirName:     "/some/blah/",
					Permissions: 0755,
					Files: []ovntest.AferoFileMockHelper{
						{"/some/blah/path", 0755, []byte("blah")},
					},
				},
			},
			errMatch: fmt.Errorf("failed to find ovn-nbctl daemon pidfile/socket in /var/run/ovn/,/var/run/openvswitch/"),
		},
		{
			desc: "test code path when ReadFile() and Stat succeed",
			dirFileMocks: []ovntest.AferoDirMockHelper{
				{
					DirName:     "/var/run/ovn/",
					Permissions: 0755,
					Files: []ovntest.AferoFileMockHelper{
						{"/var/run/ovn/ovn-nbctl.pid", 0755, []byte("pid")},
						{"/var/run/ovn/ovn-nbctl.pid.ctl", 0755, []byte("blah")},
					},
				},
			},
			outExp: "OVN_NB_DAEMON=/var/run/ovn/ovn-nbctl.pid.ctl",
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			if len(tc.mockEnvKey) != 0 && len(tc.mockEnvVal) != 0 {
				prevVal := os.Getenv(tc.mockEnvKey)
				os.Setenv(tc.mockEnvKey, tc.mockEnvVal)
				defer os.Setenv(tc.mockEnvKey, prevVal)
			}
			if len(tc.dirFileMocks) > 0 {
				for _, item := range tc.dirFileMocks {
					AppFs.MkdirAll(item.DirName, item.Permissions)
					defer AppFs.Remove(item.DirName)
					if len(item.Files) != 0 {
						for _, f := range item.Files {
							afero.WriteFile(AppFs, f.FileName, f.Content, f.Permissions)
						}
					}
				}
			}
			out, err := getNbctlSocketPath()
			t.Log(out, err)
			if tc.errMatch != nil {
				assert.Contains(t, err.Error(), tc.errMatch.Error())
				assert.Equal(t, len(out), 0)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tc.outExp, out)
			}
		})
	}
}

func TestGetNbctlArgsAndEnv(t *testing.T) {
	// Below is defined in ovs.go file
	AppFs = afero.NewMemMapFs()

	tests := []struct {
		desc            string
		nbctlDaemonMode bool
		ovnnbscheme     config.OvnDBScheme
		mockEnvKey      string
		mockEnvVal      string
		dirFileMocks    []ovntest.AferoDirMockHelper
		inpTimeout      int
		outCmdArgs      []string
		outEnvArgs      []string
		onRetArgs       *onCallReturnArgs
		fnCallTimes     int
	}{
		{
			desc:            "test success path when confg.NbctlDaemonMode is true",
			nbctlDaemonMode: true,
			mockEnvKey:      "OVN_NB_DAEMON",
			mockEnvVal:      "/some/blah/path",
			dirFileMocks: []ovntest.AferoDirMockHelper{
				{
					DirName:     "/some/blah/",
					Permissions: 0755,
					Files: []ovntest.AferoFileMockHelper{
						{"/some/blah/path", 0755, []byte("blah")},
					},
				},
			},
			inpTimeout:  15,
			outCmdArgs:  []string{"--timeout=15"},
			outEnvArgs:  []string{"OVN_NB_DAEMON=/some/blah/path"},
			onRetArgs:   &onCallReturnArgs{"LookPath", []string{"string"}, []interface{}{"ip", nil, "arping", nil}},
			fnCallTimes: 11,
		},
		{
			desc:            "test error path when config.NbctlDaemonMode is true",
			nbctlDaemonMode: true,
			ovnnbscheme:     config.OvnDBSchemeUnix,
			inpTimeout:      15,
			outCmdArgs:      []string{"--timeout=15"},
			outEnvArgs:      []string{},
			onRetArgs:       &onCallReturnArgs{"LookPath", []string{"string"}, []interface{}{"ip", nil, "arping", nil}},
			fnCallTimes:     11,
		},
		{
			desc:        "test path when config.OvnNorth.Scheme == config.OvnDBSchemeSSL",
			ovnnbscheme: config.OvnDBSchemeSSL,
			inpTimeout:  15,
			// the values for key related to SSL fields are empty as default config do not have those configured
			outCmdArgs:  []string{"--private-key=", "--certificate=", "--bootstrap-ca-cert=", "--db=", "--timeout=15"},
			outEnvArgs:  []string{},
			onRetArgs:   &onCallReturnArgs{"LookPath", []string{"string"}, []interface{}{"ip", nil, "arping", nil}},
			fnCallTimes: 11,
		},
		{
			desc:        "test path when config.OvnNorth.Scheme == config.OvnDBSchemeTCP",
			ovnnbscheme: config.OvnDBSchemeTCP,
			inpTimeout:  15,
			// the values for key related to `db' are empty as as default config do not have those configured
			outCmdArgs:  []string{"--db=", "--timeout=15"},
			outEnvArgs:  []string{},
			onRetArgs:   &onCallReturnArgs{"LookPath", []string{"string"}, []interface{}{"ip", nil, "arping", nil}},
			fnCallTimes: 11,
		},
		{
			desc:        "test default path",
			inpTimeout:  15,
			outCmdArgs:  []string{"--timeout=15"},
			outEnvArgs:  []string{},
			onRetArgs:   &onCallReturnArgs{"LookPath", []string{"string"}, []interface{}{"ip", nil, "arping", nil}},
			fnCallTimes: 11,
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			if len(tc.mockEnvKey) != 0 && len(tc.mockEnvVal) != 0 {
				prevVal := os.Getenv(tc.mockEnvKey)
				os.Setenv(tc.mockEnvKey, tc.mockEnvVal)
				defer os.Setenv(tc.mockEnvKey, prevVal)
			}
			if tc.nbctlDaemonMode {
				preValNbctlDaemonMode := config.NbctlDaemonMode
				config.NbctlDaemonMode = tc.nbctlDaemonMode
				// defining below func to reset daemon mode to the previous value
				resetMode := func(preVal bool) { config.NbctlDaemonMode = preVal }
				// defer is allowed only for functions
				defer resetMode(preValNbctlDaemonMode)
			}
			if len(tc.ovnnbscheme) != 0 {
				preValOvnNBScheme := config.OvnNorth.Scheme
				config.OvnNorth.Scheme = tc.ovnnbscheme
				// defining below func to reset scheme to previous value
				resetScheme := func(preVal config.OvnDBScheme) { config.OvnNorth.Scheme = preValOvnNBScheme }
				// defer is allowed only for functions
				defer resetScheme(preValOvnNBScheme)
			}
			if len(tc.dirFileMocks) > 0 {
				for _, item := range tc.dirFileMocks {
					AppFs.MkdirAll(item.DirName, item.Permissions)
					defer AppFs.Remove(item.DirName)
					if len(item.Files) != 0 {
						for _, f := range item.Files {
							afero.WriteFile(AppFs, f.FileName, f.Content, f.Permissions)
						}
					}
				}
			}
			mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
			call := mockKexecIface.On(tc.onRetArgs.onCallMethodName)
			for _, arg := range tc.onRetArgs.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, elem := range tc.onRetArgs.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, elem)
			}
			call.Times(tc.fnCallTimes)

			execInterface, e := NewExecHelper(mockKexecIface)
			assert.Equal(t, e, nil)
			exec := execInterface.(*execHelper)
			cmdArgs, envVars := exec.getNbctlArgsAndEnv(tc.inpTimeout)
			assert.Equal(t, cmdArgs, tc.outCmdArgs)
			assert.Equal(t, envVars, tc.outEnvArgs)
		})
	}
}

func TestGetNbOVSDBArgs(t *testing.T) {
	tests := []struct {
		desc        string
		inpCmdStr   string
		inpVarArgs  string
		ovnnbscheme config.OvnDBScheme
		outExp      []string
	}{
		{
			desc:        "test code path when command string is EMPTY, NO additional args are provided and config.OvnNorth.Scheme != config.OvnDBSchemeSSL",
			ovnnbscheme: config.OvnDBSchemeUnix,
			outExp:      []string{"", "", ""},
		},
		{
			desc:        "test code path when command string is non-empty, additional args are provided and config.OvnNorth.Scheme == config.OvnDBSchemeSSL",
			inpCmdStr:   "list-columns",
			inpVarArgs:  "blah",
			ovnnbscheme: config.OvnDBSchemeSSL,
			outExp:      []string{"--private-key=", "--certificate=", "--bootstrap-ca-cert=", "list-columns", "", "blah"},
		},
		{
			desc:        "test code path when command string is non-empty, additional args are provided and config.OvnNorth.Scheme != config.OvnDBSchemeSSL",
			inpCmdStr:   "list-columns",
			inpVarArgs:  "blah",
			ovnnbscheme: config.OvnDBSchemeUnix,
			outExp:      []string{"list-columns", "", "blah"},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			if len(tc.ovnnbscheme) != 0 {
				preValOvnNBScheme := config.OvnNorth.Scheme
				config.OvnNorth.Scheme = tc.ovnnbscheme
				// defining below func to reset scheme to previous value
				resetScheme := func(preVal config.OvnDBScheme) { config.OvnNorth.Scheme = preValOvnNBScheme }
				// defer is allowed only for functions
				defer resetScheme(preValOvnNBScheme)
			}
			res := getNbOVSDBArgs(tc.inpCmdStr, tc.inpVarArgs)
			assert.Equal(t, res, tc.outExp)
		})
	}
}

func TestRunOVNNorthAppCtl(t *testing.T) {
	// Below is defined in ovs.go file
	AppFs = afero.NewMemMapFs()
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		inpVarArgs              string
		errMatch                error
		dirFileMocks            []ovntest.AferoDirMockHelper
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:     "test path when ReadFile returns error",
			errMatch: fmt.Errorf("failed to run the command since failed to get ovn-northd's pid:"),
		},
		{
			desc: "test path when runOVNretry succeeds",
			dirFileMocks: []ovntest.AferoDirMockHelper{
				{
					DirName:     "/var/run/ovn/",
					Permissions: 0755,
					Files: []ovntest.AferoFileMockHelper{
						{"/var/run/ovn/ovn-northd.pid", 0755, []byte("pid")},
					},
				},
			},
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			if tc.onRetArgsExecUtilsIface != nil {
				call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
				for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			if tc.onRetArgsKexecIface != nil {
				ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
				for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
					ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range tc.onRetArgsKexecIface.retArgList {
					ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
				}
				ifaceCall.Once()
			}

			if len(tc.dirFileMocks) > 0 {
				for _, item := range tc.dirFileMocks {
					AppFs.MkdirAll(item.DirName, item.Permissions)
					defer AppFs.Remove(item.DirName)
					if len(item.Files) != 0 {
						for _, f := range item.Files {
							afero.WriteFile(AppFs, f.FileName, f.Content, f.Permissions)
						}
					}
				}
			}
			_, _, err := runner.RunOVNNorthAppCtl()
			t.Log(err)
			if tc.errMatch != nil {
				assert.Contains(t, err.Error(), tc.errMatch.Error())
			} else {
				assert.Nil(t, err)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunOVNControllerAppCtl(t *testing.T) {
	// Below is defined in ovs.go file
	AppFs = afero.NewMemMapFs()
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		inpVarArgs              string
		errMatch                error
		dirFileMocks            []ovntest.AferoDirMockHelper
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:     "test path when ReadFile returns error",
			errMatch: fmt.Errorf("failed to get ovn-controller pid"),
		},
		{
			desc: "test path when runOVNretry succeeds",
			dirFileMocks: []ovntest.AferoDirMockHelper{
				{
					DirName:     "/var/run/ovn/",
					Permissions: 0755,
					Files: []ovntest.AferoFileMockHelper{
						{"/var/run/ovn/ovn-controller.pid", 0755, []byte("pid")},
					},
				},
			},
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			if tc.onRetArgsExecUtilsIface != nil {
				call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
				for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			if tc.onRetArgsKexecIface != nil {
				ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
				for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
					ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range tc.onRetArgsKexecIface.retArgList {
					ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
				}
				ifaceCall.Once()
			}

			if len(tc.dirFileMocks) > 0 {
				for _, item := range tc.dirFileMocks {
					AppFs.MkdirAll(item.DirName, item.Permissions)
					defer AppFs.Remove(item.DirName)
					if len(item.Files) != 0 {
						for _, f := range item.Files {
							afero.WriteFile(AppFs, f.FileName, f.Content, f.Permissions)
						}
					}
				}
			}
			_, _, err := runner.RunOVNControllerAppCtl()
			t.Log(err)
			if tc.errMatch != nil {
				assert.Contains(t, err.Error(), tc.errMatch.Error())
			} else {
				assert.Nil(t, err)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunOvsVswitchdAppCtl(t *testing.T) {
	// Below is defined in ovs.go file
	AppFs = afero.NewMemMapFs()
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		inpVarArgs              string
		errMatch                error
		dirFileMocks            []ovntest.AferoDirMockHelper
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:     "test path when ReadFile returns error",
			errMatch: fmt.Errorf("failed to get ovs-vswitch pid"),
		},
		{
			desc: "test path when runOVNretry succeeds",
			dirFileMocks: []ovntest.AferoDirMockHelper{
				{
					DirName:     "/var/run/openvswitch/",
					Permissions: 0755,
					Files: []ovntest.AferoFileMockHelper{
						{"/var/run/openvswitch/ovs-vswitchd.pid", 0755, []byte("pid")},
					},
				},
			},
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			if tc.onRetArgsExecUtilsIface != nil {
				call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
				for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}

			if tc.onRetArgsKexecIface != nil {
				ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
				for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
					ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range tc.onRetArgsKexecIface.retArgList {
					ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
				}
				ifaceCall.Once()
			}

			if len(tc.dirFileMocks) > 0 {
				for _, item := range tc.dirFileMocks {
					AppFs.MkdirAll(item.DirName, item.Permissions)
					defer AppFs.Remove(item.DirName)
					if len(item.Files) != 0 {
						for _, f := range item.Files {
							afero.WriteFile(AppFs, f.FileName, f.Content, f.Permissions)
						}
					}
				}
			}
			_, _, err := runner.RunOvsVswitchdAppCtl()
			t.Log(err)
			if tc.errMatch != nil {
				assert.Contains(t, err.Error(), tc.errMatch.Error())
			} else {
				assert.Nil(t, err)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestDefaultExecRunner_RunCmd(t *testing.T) {
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// tests in other files in the package would set runCmdExecRunner to mocks.ExecRunner,
	// for this test we want to ensure the non-mock instance is used
	runCmdExecRunner = &defaultExecRunner{}

	tests := []struct {
		desc             string
		expectedErr      error
		cmd              kexec.Cmd
		cmdPath          string
		cmdArg           string
		envVars          []string
		onRetArgsCmdList []onCallReturnArgs
	}{
		{
			desc:        "negative: set cmd parameter to be nil",
			expectedErr: fmt.Errorf("cmd object cannot be nil"),
			cmd:         nil,
		},
		{
			desc:        "set envars and ensure cmd.SetEnv is invoked",
			expectedErr: nil,
			cmd:         mockCmd,
			envVars:     []string{"OVN_NB_DAEMON=/some/blah/path"},
			onRetArgsCmdList: []onCallReturnArgs{
				{"Run", []string{}, []interface{}{nil}},
				{"SetStdout", []string{"*bytes.Buffer"}, nil},
				{"SetStderr", []string{"*bytes.Buffer"}, nil},
				{"SetEnv", []string{"[]string"}, nil},
			},
		},
		{
			desc:        "cmd.Run returns error test",
			expectedErr: fmt.Errorf("mock error"),
			cmd:         mockCmd,
			onRetArgsCmdList: []onCallReturnArgs{
				{"Run", []string{}, []interface{}{fmt.Errorf("mock error")}},
				{"SetStdout", []string{"*bytes.Buffer"}, nil},
				{"SetStderr", []string{"*bytes.Buffer"}, nil},
			},
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			if tc.cmd != nil {
				for _, item := range tc.onRetArgsCmdList {
					cmdCall := tc.cmd.(*mock_k8s_io_utils_exec.Cmd).On(item.onCallMethodName)
					for _, arg := range item.onCallMethodArgType {
						cmdCall.Arguments = append(cmdCall.Arguments, mock.AnythingOfType(arg))
					}

					for _, e := range item.retArgList {
						cmdCall.ReturnArguments = append(cmdCall.ReturnArguments, e)
					}
					cmdCall.Once()
				}
			}
			_, _, e := runCmdExecRunner.RunCmd(tc.cmd, tc.cmdPath, tc.envVars, tc.cmdArg)

			assert.Equal(t, e, tc.expectedErr)
			mockCmd.AssertExpectations(t)
		})
	}
}

func TestNewExecHelper(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	tests := []struct {
		desc        string
		expectedErr error
		onRetArgs   *onCallReturnArgs
		fnCallTimes int
	}{
		{
			desc:        "positive, test when 'runner' is nil",
			expectedErr: nil,
			onRetArgs:   &onCallReturnArgs{"LookPath", []string{"string"}, []interface{}{"ip", nil, "arping", nil}},
			fnCallTimes: 11,
		},
		{
			desc:        "positive, test when 'runner' is not nil",
			expectedErr: nil,
			onRetArgs:   &onCallReturnArgs{"LookPath", []string{"string"}, []interface{}{"", nil, "", nil}},
			fnCallTimes: 11,
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockKexecIface.On(tc.onRetArgs.onCallMethodName)
			for _, arg := range tc.onRetArgs.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, elem := range tc.onRetArgs.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, elem)
			}
			call.Times(tc.fnCallTimes)
			_, e := NewExecHelper(mockKexecIface)
			assert.Equal(t, e, tc.expectedErr)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestNewOVSVsctlExecHelper(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	tests := []struct {
		desc        string
		expectedErr error
		onRetArgs   *onCallReturnArgs
		fnCallTimes int
	}{
		{
			desc:        "positive, ip and arping path found",
			expectedErr: nil,
			fnCallTimes: 1,
			onRetArgs:   &onCallReturnArgs{"LookPath", []string{"string"}, []interface{}{"ip", nil, "arping", nil}},
		},
		{
			desc:        "negative, ip path not found",
			expectedErr: fmt.Errorf(`exec: \"ip:\" executable file not found in $PATH`),
			fnCallTimes: 1,
			onRetArgs:   &onCallReturnArgs{"LookPath", []string{"string"}, []interface{}{"", fmt.Errorf(`exec: \"ip:\" executable file not found in $PATH`), "arping", nil}},
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockKexecIface.On(tc.onRetArgs.onCallMethodName)
			for _, arg := range tc.onRetArgs.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, elem := range tc.onRetArgs.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, elem)
			}
			call.Times(tc.fnCallTimes)
			_, e := NewOVSVsctlExecHelper(mockKexecIface)
			assert.Equal(t, e, tc.expectedErr)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunWithEnvVars(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc             string
		expectedErr      error
		cmdPath          string
		cmdArg           string
		envArgs          []string
		onRetArgsIface   *onCallReturnArgs
		onRetArgsCmdList []onCallReturnArgs
	}{
		{
			desc:           "positive: run `ip addr` command with empty envVars",
			expectedErr:    nil,
			cmdPath:        "ip",
			cmdArg:         "a",
			envArgs:        []string{},
			onRetArgsIface: &onCallReturnArgs{"Command", []string{"string"}, []interface{}{mockCmd}},
			onRetArgsCmdList: []onCallReturnArgs{
				{"Run", []string{}, []interface{}{nil}},
				{"SetStdout", []string{"*bytes.Buffer"}, nil},
				{"SetStderr", []string{"*bytes.Buffer"}, nil},
			},
		},
		{
			desc:           "positive: run `ip addr` command with envVars",
			expectedErr:    nil,
			cmdPath:        "ip",
			cmdArg:         "a",
			envArgs:        []string{"OVN_NB_DAEMON=/some/blah/path"},
			onRetArgsIface: &onCallReturnArgs{"Command", []string{"string"}, []interface{}{mockCmd}},
			onRetArgsCmdList: []onCallReturnArgs{
				{"Run", []string{}, []interface{}{nil}},
				{"SetStdout", []string{"*bytes.Buffer"}, nil},
				{"SetStderr", []string{"*bytes.Buffer"}, nil},
				{"SetEnv", []string{"[]string"}, nil},
			},
		},
		{
			desc:           "negative: run `ip addr` command",
			expectedErr:    fmt.Errorf("executable file not found in $PATH"),
			cmdPath:        "ips",
			cmdArg:         "addr",
			envArgs:        nil,
			onRetArgsIface: &onCallReturnArgs{"Command", []string{"string"}, []interface{}{mockCmd}},
			onRetArgsCmdList: []onCallReturnArgs{
				{"Run", []string{}, []interface{}{fmt.Errorf("executable file not found in $PATH")}},
				{"SetStdout", []string{"*bytes.Buffer"}, nil},
				{"SetStderr", []string{"*bytes.Buffer"}, nil},
			},
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {

			for _, item := range tc.onRetArgsCmdList {
				cmdCall := mockCmd.On(item.onCallMethodName)
				for _, arg := range item.onCallMethodArgType {
					cmdCall.Arguments = append(cmdCall.Arguments, mock.AnythingOfType(arg))
				}

				for _, e := range item.retArgList {
					cmdCall.ReturnArguments = append(cmdCall.ReturnArguments, e)
				}
				cmdCall.Once()
			}

			ifaceCall := mockKexecIface.On(tc.onRetArgsIface.onCallMethodName, mock.Anything)
			for _, arg := range tc.onRetArgsIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, item := range tc.onRetArgsIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, item)
			}
			ifaceCall.Once()

			_, _, e := runner.runWithEnvVars(tc.cmdPath, tc.envArgs, tc.cmdArg)

			assert.Equal(t, e, tc.expectedErr)
			mockCmd.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunOVSOfctl(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "negative: run `ovs-ofctl` command",
			expectedErr:             fmt.Errorf("executable file not found in $PATH"),
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{nil, nil, fmt.Errorf("executable file not found in $PATH")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "positive: run `ovs-ofctl` ",
			expectedErr:             nil,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()
			_, _, e := runner.RunOVSOfctl()

			assert.Equal(t, e, tc.expectedErr)
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunOVSDpctl(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "negative: run `ovs-dpctl` command",
			expectedErr:             fmt.Errorf("failed to execute ovs-dpctl command"),
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{nil, nil, fmt.Errorf("failed to execute ovs-dpctl command")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "positive: run `ovs-dpctl` ",
			expectedErr:             nil,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()
			_, _, e := runner.RunOVSDpctl()

			assert.Equal(t, e, tc.expectedErr)
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunOVSVsctl(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "negative: run `ovs-vsctl` command",
			expectedErr:             fmt.Errorf("failed to execute ovs-vsctl command"),
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{nil, nil, fmt.Errorf("failed to execute ovs-vsctl command")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "positive: run `ovs-vsctl` ",
			expectedErr:             nil,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()
			_, _, e := runner.RunOVSVsctl()

			assert.Equal(t, e, tc.expectedErr)
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunOVSAppctlWithTimeout(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		timeout                 int
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "negative: run `ovs-appctl` command with timeout",
			expectedErr:             fmt.Errorf("failed to execute ovs-appctl command"),
			timeout:                 5,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{nil, nil, fmt.Errorf("failed to execute ovs-appctl command")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "positive: run `ovs-appctl` command with timeout",
			expectedErr:             nil,
			timeout:                 5,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()

			_, _, e := runner.RunOVSAppctlWithTimeout(tc.timeout)

			assert.Equal(t, e, tc.expectedErr)
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunOVSAppctl(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "negative: run `ovs-appctl` command",
			expectedErr:             fmt.Errorf("failed to execute ovs-appctl command"),
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{nil, nil, fmt.Errorf("failed to execute ovs-appctl command")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "positive: run `ovs-appctl` command",
			expectedErr:             nil,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()

			_, _, e := runner.RunOVSAppctl()

			assert.Equal(t, e, tc.expectedErr)
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunOVNAppctlWithTimeout(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		timeout                 int
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "negative: run `ovn-appctl` command with timeout",
			expectedErr:             fmt.Errorf("failed to execute ovn-appctl command"),
			timeout:                 5,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{nil, nil, fmt.Errorf("failed to execute ovn-appctl command")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "positive: run `ovn-appctl` command with timeout",
			expectedErr:             nil,
			timeout:                 15,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()
			_, _, e := runner.RunOVNAppctlWithTimeout(tc.timeout)

			assert.Equal(t, e, tc.expectedErr)
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunOVNNbctlUnix(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "negative: run `ovn-nbctl` command with no env vars generated",
			expectedErr:             fmt.Errorf("failed to execute ovn-nbctl command"),
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{nil, nil, fmt.Errorf("failed to execute ovn-nbctl command")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "positive: run `ovn-nbctl` command with no env vars generated",
			expectedErr:             nil,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()
			_, _, e := runner.RunOVNNbctlUnix()

			if tc.expectedErr != nil {
				assert.Error(t, e)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunOVNNbctlWithTimeout(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		timeout                 int
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "negative: run `ovn-nbctl` command with timeout",
			expectedErr:             fmt.Errorf("failed to execute ovn-nbctl command"),
			timeout:                 5,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{nil, nil, fmt.Errorf("failed to execute ovn-nbctl command")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "positive: run `ovn-nbctl` command with timeout",
			expectedErr:             nil,
			timeout:                 15,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()
			_, _, e := runner.RunOVNNbctlWithTimeout(tc.timeout)

			if tc.expectedErr != nil {
				assert.Error(t, e)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunOVNNbctl(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "negative: run `ovn-nbctl` command",
			expectedErr:             fmt.Errorf("failed to execute ovn-nbctl command"),
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{nil, nil, fmt.Errorf("failed to execute ovn-nbctl command")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "positive: run `ovn-nbctl` command",
			expectedErr:             nil,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()
			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()
			_, _, e := runner.RunOVNNbctl()

			if tc.expectedErr != nil {
				assert.Error(t, e)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunOVNSbctlUnix(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "negative: run `ovn-sbctl` command with no env vars generated",
			expectedErr:             fmt.Errorf("failed to execute ovn-sbctl command"),
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{nil, nil, fmt.Errorf("failed to execute ovn-sbctl command")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "positive: run `ovn-sbctl` command with no env vars generated",
			expectedErr:             nil,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()
			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()
			_, _, e := runner.RunOVNSbctlUnix()

			if tc.expectedErr != nil {
				assert.Error(t, e)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunOVNSbctlWithTimeout(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		timeout                 int
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "negative: run `ovn-sbctl` command with timeout",
			expectedErr:             fmt.Errorf("failed to execute ovn-sbctl command"),
			timeout:                 5,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{nil, nil, fmt.Errorf("failed to execute ovn-sbctl command")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "positive: run `ovn-sbctl` command with timeout",
			expectedErr:             nil,
			timeout:                 15,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()
			_, _, e := runner.RunOVNSbctlWithTimeout(tc.timeout)

			if tc.expectedErr != nil {
				assert.Error(t, e)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunOVNSbctl(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "negative: run `ovn-sbctl` command",
			expectedErr:             fmt.Errorf("failed to execute ovn-sbctl command"),
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{nil, nil, fmt.Errorf("failed to execute ovn-sbctl command")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "positive: run `ovn-sbctl` command",
			expectedErr:             nil,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()
			_, _, e := runner.RunOVNSbctl()

			if tc.expectedErr != nil {
				assert.Error(t, e)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunOVSDBClient(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "negative: run `ovsdb-client` command",
			expectedErr:             fmt.Errorf("failed to execute ovsdb-client command"),
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{nil, nil, fmt.Errorf("failed to execute ovsdb-client command")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "positive: run `ovsdb-client` command",
			expectedErr:             nil,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()
			_, _, e := runner.RunOVSDBClient()

			if tc.expectedErr != nil {
				assert.Error(t, e)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunOVSDBClientOVNNB(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "negative: run `ovsdb-client` command against OVN NB database",
			expectedErr:             fmt.Errorf("failed to execute ovsdb-client command against OVN NB database"),
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string"}, []interface{}{nil, nil, fmt.Errorf("failed to execute ovsdb-client command against OVN NB database")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "positive: run `ovsdb-client` command against OVN NB database",
			expectedErr:             nil,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()
			_, _, e := runner.RunOVSDBClientOVNNB("list-dbs")

			if tc.expectedErr != nil {
				assert.Error(t, e)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunOVNNBAppCtl(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "negative: run `ovn-appctl -t nbdbCtlSockPath` command",
			expectedErr:             fmt.Errorf("failed to execute ovn-appctl -t nbdbCtlSockPath command"),
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string"}, []interface{}{nil, nil, fmt.Errorf("failed to execute ovn-appctl -t nbdbCtlSockPath command")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "positive: run `ovn-appctl -t nbdbCtlSockPath` command",
			expectedErr:             nil,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()
			_, _, e := runner.RunOVNNBAppCtl()

			if tc.expectedErr != nil {
				assert.Error(t, e)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunOVNSBAppCtl(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "negative: run `ovn-appctl -t sbdbCtlSockPath` command",
			expectedErr:             fmt.Errorf("failed to execute ovn-appctl -t sbdbCtlSockPath command"),
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string"}, []interface{}{nil, nil, fmt.Errorf("failed to execute ovn-appctl -t sbdbCtlSockPath command")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "positive: run `ovn-appctl -t sbdbCtlSockPath` command",
			expectedErr:             nil,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()
			_, _, e := runner.RunOVNSBAppCtl()

			if tc.expectedErr != nil {
				assert.Error(t, e)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestRunIP(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "positive: run IP ",
			expectedErr:             nil,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()
			_, _, e := runner.RunIP()

			assert.Equal(t, e, tc.expectedErr)
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestAddFloodActionOFFlow(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	mockExecRunner := new(mocks.ExecRunner)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
		onRetArgsCmdList        *onCallReturnArgs
	}{
		{
			desc:                    "negative: run `ovs-ofctl` command",
			expectedErr:             fmt.Errorf("failed to execute ovs-ofctl command"),
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string"}, []interface{}{nil, nil, fmt.Errorf("failed to execute ovs-ofctl command")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
			onRetArgsCmdList:        &onCallReturnArgs{"SetStdin", []string{"*bytes.Buffer"}, nil},
		},
		{
			desc:                    "positive: run `ovs-ofctl` command",
			expectedErr:             nil,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), fmt.Errorf("executable file not found in $PATH")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
			onRetArgsCmdList:        &onCallReturnArgs{"SetStdin", []string{"*bytes.Buffer"}, nil},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()

			mockCall := mockCmd.On(tc.onRetArgsCmdList.onCallMethodName)
			for _, arg := range tc.onRetArgsCmdList.onCallMethodArgType {
				mockCall.Arguments = append(mockCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsCmdList.retArgList {
				mockCall.ReturnArguments = append(mockCall.ReturnArguments, ret)
			}
			mockCall.Once()

			_, _, e := AddFloodActionOFFlow(runner, "somename")

			if tc.expectedErr != nil {
				assert.Error(t, e)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestReplaceOFFlows(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	mockExecRunner := new(mocks.ExecRunner)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             error
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
		onRetArgsCmdList        *onCallReturnArgs
	}{
		{
			desc:                    "negative: run `ovs-ofctl` command",
			expectedErr:             fmt.Errorf("failed to execute ovs-ofctl command"),
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string", "string"}, []interface{}{nil, nil, fmt.Errorf("failed to execute ovs-ofctl command")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
			onRetArgsCmdList:        &onCallReturnArgs{"SetStdin", []string{"*bytes.Buffer"}, nil},
		},
		{
			desc:                    "positive: run `ovs-ofctl` command",
			expectedErr:             nil,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte("testblah")), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
			onRetArgsCmdList:        &onCallReturnArgs{"SetStdin", []string{"*bytes.Buffer"}, nil},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()

			mockCall := mockCmd.On(tc.onRetArgsCmdList.onCallMethodName)
			for _, arg := range tc.onRetArgsCmdList.onCallMethodArgType {
				mockCall.Arguments = append(mockCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsCmdList.retArgList {
				mockCall.ReturnArguments = append(mockCall.ReturnArguments, ret)
			}
			mockCall.Once()

			_, _, e := ReplaceOFFlows(runner, "somename", []string{})

			if tc.expectedErr != nil {
				assert.Error(t, e)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestGetOVNDBServerInfo(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             bool
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "negative: executable not found",
			expectedErr:             true,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string"}, []interface{}{nil, nil, fmt.Errorf("executable file not found in $PATH")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "negative: malformed json output",
			expectedErr:             true,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte(`["rows":[{"connected":true,"index":["set",[]],"leader":true}]}]`)), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "negative: zero rows returned",
			expectedErr:             true,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte(`[{"rows":[]}]`)), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:                    "positive: run `ovsdb-client` command successfully",
			expectedErr:             false,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string"}, []interface{}{bytes.NewBuffer([]byte(`[{"rows":[{"connected":true,"index":["set",[]],"leader":true}]}]`)), bytes.NewBuffer([]byte("")), nil}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()

			_, e := GetOVNDBServerInfo(runner, 15, "nb", "OVN_Northbound")

			if tc.expectedErr {
				assert.Error(t, e)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}

func TestDetectSCTPSupport(t *testing.T) {
	mockKexecIface := new(mock_k8s_io_utils_exec.Interface)
	mockExecRunner := new(mocks.ExecRunner)
	mockCmd := new(mock_k8s_io_utils_exec.Cmd)
	// below is defined in ovs.go
	runCmdExecRunner = mockExecRunner
	// note runner is defined in ovs.go file
	runner := &execHelper{exec: mockKexecIface}

	tests := []struct {
		desc                    string
		expectedErr             bool
		onRetArgsExecUtilsIface *onCallReturnArgs
		onRetArgsKexecIface     *onCallReturnArgs
	}{
		{
			desc:                    "negative: fails to query OVN NB DB for SCTP support",
			expectedErr:             true,
			onRetArgsExecUtilsIface: &onCallReturnArgs{"RunCmd", []string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string", "string", "string"}, []interface{}{nil, nil, fmt.Errorf("fails to query OVN NB DB")}},
			onRetArgsKexecIface:     &onCallReturnArgs{"Command", []string{"string", "string", "string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:        "negative: json unmarshal error",
			expectedErr: true,
			onRetArgsExecUtilsIface: &onCallReturnArgs{
				"RunCmd",
				[]string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string", "string", "string"},
				[]interface{}{ // below three rows are stdout, stderr and error respectively returned by runWithEnvVars method
					bytes.NewBuffer([]byte(`"data":"headings":["Column","Type"]}`)), //stdout value: mocks malformed json returned
					bytes.NewBuffer([]byte("")),
					nil,
				},
			},
			onRetArgsKexecIface: &onCallReturnArgs{"Command", []string{"string", "string", "string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:        "positive: SCTP present in protocol list",
			expectedErr: false,
			onRetArgsExecUtilsIface: &onCallReturnArgs{
				"RunCmd",
				[]string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string", "string", "string"},
				[]interface{}{ // below three rows are stdout, stderr and error respectively returned by runWithEnvVars method
					// below is snippet of valid stdout returned and is truncated for unit testing and readability
					bytes.NewBuffer([]byte(`{"data":[["protocol",{"key":{"enum":["set",["sctp","tcp","udp"]],"type":"string"},"min":0}]],"headings":["Column","Type"]}`)),
					bytes.NewBuffer([]byte("")),
					nil,
				},
			},
			onRetArgsKexecIface: &onCallReturnArgs{"Command", []string{"string", "string", "string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
		},
		{
			desc:        "negative: SCTP not present in protocol list",
			expectedErr: false,
			onRetArgsExecUtilsIface: &onCallReturnArgs{
				"RunCmd",
				[]string{"*mocks.Cmd", "string", "[]string", "string", "string", "string", "string", "string", "string", "string"},
				[]interface{}{ // below three rows are stdout, stderr and error respectively returned by runWithEnvVars method
					// below is snippet of valid stdout returned and is truncated for unit testing and readability
					bytes.NewBuffer([]byte(`{"data":[["protocol",{"key":{"enum":["set",["tcp","udp"]],"type":"string"},"min":0}]],"headings":["Column","Type"]}`)),
					bytes.NewBuffer([]byte("")),
					nil,
				},
			},
			onRetArgsKexecIface: &onCallReturnArgs{"Command", []string{"string", "string", "string", "string", "string", "string", "string", "string"}, []interface{}{mockCmd}},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			call := mockExecRunner.On(tc.onRetArgsExecUtilsIface.onCallMethodName)
			for _, arg := range tc.onRetArgsExecUtilsIface.onCallMethodArgType {
				call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsExecUtilsIface.retArgList {
				call.ReturnArguments = append(call.ReturnArguments, ret)
			}
			call.Once()

			ifaceCall := mockKexecIface.On(tc.onRetArgsKexecIface.onCallMethodName)
			for _, arg := range tc.onRetArgsKexecIface.onCallMethodArgType {
				ifaceCall.Arguments = append(ifaceCall.Arguments, mock.AnythingOfType(arg))
			}
			for _, ret := range tc.onRetArgsKexecIface.retArgList {
				ifaceCall.ReturnArguments = append(ifaceCall.ReturnArguments, ret)
			}
			ifaceCall.Once()

			_, e := DetectSCTPSupport(runner)

			if tc.expectedErr {
				assert.Error(t, e)
			}
			mockExecRunner.AssertExpectations(t)
			mockKexecIface.AssertExpectations(t)
		})
	}
}
