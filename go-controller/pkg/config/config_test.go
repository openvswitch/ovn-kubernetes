package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"
	kexec "k8s.io/utils/exec"

	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

func TestConfig(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Config Suite")
}

func writeConfigFile(cfgFile *os.File, randomOptData bool, args ...string) error {
	// Convert command-line args into sections and options
	sections := make(map[string][]string)
	for _, arg := range args {
		var section string
		switch {
		case strings.HasPrefix(arg, "-k8s-"):
			section = "kubernetes"
			arg = arg[5:]
		case strings.HasPrefix(arg, "-cni-"):
			section = "cni"
			arg = arg[5:]
		case strings.HasPrefix(arg, "-log"):
			section = "logging"
			arg = arg[1:]
		case strings.HasPrefix(arg, "-conntrack-zone"):
			section = "defaults"
			arg = arg[1:]
		case strings.HasPrefix(arg, "-mtu"):
			section = "defaults"
			arg = arg[1:]
		case strings.HasPrefix(arg, "-nb-"):
			section = "ovnnorth"
			arg = arg[4:]
		case strings.HasPrefix(arg, "-sb-"):
			section = "ovnsouth"
			arg = arg[4:]
		default:
			return fmt.Errorf("unexpected argument passed")
		}

		if randomOptData {
			parts := strings.Split(arg, "=")
			gomega.Expect(len(parts)).To(gomega.Equal(2))
			sections[section] = append(sections[section], parts[0]+"=aklsdjfalsdfkjaslfdkjasfdlksa")
		} else {
			sections[section] = append(sections[section], arg)
		}
	}

	// Write sections and options to the file data
	var data string
	for k, array := range sections {
		data += fmt.Sprintf("[%s]\n", k)
		for _, item := range array {
			data += item + "\n"
		}
	}

	_, err := cfgFile.Write([]byte(data))
	return err
}

// runType 1: command-line args only
// runType 2: config file only
// runType 3: command-line args and random config file option data to test CLI override
func runInit(app *cli.App, runType int, cfgFile *os.File, args ...string) error {
	app.Action = func(ctx *cli.Context) error {
		_, err := InitConfig(ctx, kexec.New(), nil)
		return err
	}

	finalArgs := []string{app.Name, "-loglevel=5"}
	switch runType {
	case 1:
		finalArgs = append(finalArgs, args...)
	case 2:
		finalArgs = append(finalArgs, "-config-file="+cfgFile.Name())
		if err := writeConfigFile(cfgFile, false, args...); err != nil {
			return err
		}
	case 3:
		finalArgs = append(finalArgs, "-config-file="+cfgFile.Name())
		finalArgs = append(finalArgs, args...)
		if err := writeConfigFile(cfgFile, true, args...); err != nil {
			return err
		}
	default:
		panic("shouldn't get here")
	}
	return app.Run(finalArgs)
}

var tmpDir string

var _ = ginkgo.AfterSuite(func() {
	err := os.RemoveAll(tmpDir)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
})

func createTempFile(name string) (string, error) {
	fname := filepath.Join(tmpDir, name)
	if err := ioutil.WriteFile(fname, []byte{0x20}, 0644); err != nil {
		return "", err
	}
	return fname, nil
}

func createTempFileContent(name, value string) (string, error) {
	fname := filepath.Join(tmpDir, name)
	if err := ioutil.WriteFile(fname, []byte(value), 0644); err != nil {
		return "", err
	}
	return fname, nil
}

// writeTestConfigFile writes out a config file with well-known options but
// allows specific fields to be overridden by the testcase
func writeTestConfigFile(path string, overrides ...string) error {
	const defaultData string = `[default]
mtu=1500
conntrack-zone=64321
cluster-subnets=10.132.0.0/14/23

[kubernetes]
kubeconfig=/path/to/kubeconfig
apiserver=https://1.2.3.4:6443
token=TG9yZW0gaXBzdW0gZ
cacert=/path/to/kubeca.crt
service-cidrs=172.18.0.0/24
no-hostsubnet-nodes=label=another-test-label

[logging]
loglevel=5
logfile=/var/log/ovnkube.log

[cni]
conf-dir=/etc/cni/net.d22
plugin=ovn-k8s-cni-overlay22

[ovnnorth]
address=ssl:1.2.3.4:6641
client-privkey=/path/to/nb-client-private.key
client-cert=/path/to/nb-client.crt
client-cacert=/path/to/nb-client-ca.crt
cert-common-name=cfg-nbcommonname

[ovnsouth]
address=ssl:1.2.3.4:6642
client-privkey=/path/to/sb-client-private.key
client-cert=/path/to/sb-client.crt
client-cacert=/path/to/sb-client-ca.crt
cert-common-name=cfg-sbcommonname

[gateway]
mode=shared
interface=eth1
next-hop=1.3.4.5
vlan-id=10
nodeport=false

[hybridoverlay]
enabled=true
cluster-subnets=11.132.0.0/14/23
`

	var newData string
	for _, line := range strings.Split(defaultData, "\n") {
		equalsPos := strings.Index(line, "=")
		if equalsPos >= 0 {
			for _, override := range overrides {
				if strings.HasPrefix(override, line[:equalsPos+1]) {
					line = override
					break
				}
			}
		}
		newData += line + "\n"
	}
	return ioutil.WriteFile(path, []byte(newData), 0644)
}

var _ = ginkgo.Describe("Config Operations", func() {
	var app *cli.App
	var cfgFile *os.File

	var tmpErr error
	tmpDir, tmpErr = ioutil.TempDir("", "configtest_certdir")
	if tmpErr != nil {
		ginkgo.GinkgoT().Errorf("failed to create tempdir: %v", tmpErr)
	}
	tmpDir += "/"

	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = Flags

		var err error
		cfgFile, err = ioutil.TempFile("", "conftest-")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.AfterEach(func() {
		os.Remove(cfgFile.Name())
	})

	ginkgo.It("uses expected defaults", func() {
		app.Action = func(ctx *cli.Context) error {
			cfgPath, err := InitConfigSa(ctx, kexec.New(), tmpDir, nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(cfgPath).To(gomega.Equal(cfgFile.Name()))

			gomega.Expect(Default.MTU).To(gomega.Equal(1400))
			gomega.Expect(Default.ConntrackZone).To(gomega.Equal(64000))
			gomega.Expect(Logging.File).To(gomega.Equal(""))
			gomega.Expect(Logging.Level).To(gomega.Equal(4))
			gomega.Expect(CNI.ConfDir).To(gomega.Equal("/etc/cni/net.d"))
			gomega.Expect(CNI.Plugin).To(gomega.Equal("ovn-k8s-cni-overlay"))
			gomega.Expect(Kubernetes.Kubeconfig).To(gomega.Equal(""))
			gomega.Expect(Kubernetes.CACert).To(gomega.Equal(""))
			gomega.Expect(Kubernetes.Token).To(gomega.Equal(""))
			gomega.Expect(Kubernetes.APIServer).To(gomega.Equal(DefaultAPIServer))
			gomega.Expect(Kubernetes.RawServiceCIDRs).To(gomega.Equal("172.16.1.0/24"))
			gomega.Expect(Kubernetes.RawNoHostSubnetNodes).To(gomega.Equal(""))
			gomega.Expect(Default.ClusterSubnets).To(gomega.Equal([]CIDRNetworkEntry{
				{ovntest.MustParseIPNet("10.128.0.0/14"), 23},
			}))
			gomega.Expect(IPv4Mode).To(gomega.Equal(true))
			gomega.Expect(IPv6Mode).To(gomega.Equal(false))
			gomega.Expect(HybridOverlay.Enabled).To(gomega.Equal(false))

			for _, a := range []OvnAuthConfig{OvnNorth, OvnSouth} {
				gomega.Expect(a.Scheme).To(gomega.Equal(OvnDBSchemeUnix))
				gomega.Expect(a.PrivKey).To(gomega.Equal(""))
				gomega.Expect(a.Cert).To(gomega.Equal(""))
				gomega.Expect(a.CACert).To(gomega.Equal(""))
				gomega.Expect(a.Address).To(gomega.Equal(""))
				gomega.Expect(a.CertCommonName).To(gomega.Equal(""))
			}
			return nil
		}
		err := app.Run([]string{app.Name, "-config-file=" + cfgFile.Name()})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("reads defaults from ovs-vsctl external IDs", func() {
		app.Action = func(ctx *cli.Context) error {
			fexec := ovntest.NewFakeExec()

			// k8s-api-server
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovs-vsctl --timeout=15 --if-exists get Open_vSwitch . external_ids:k8s-api-server",
				Output: "https://somewhere.com:8081",
			})

			// k8s-api-token
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovs-vsctl --timeout=15 --if-exists get Open_vSwitch . external_ids:k8s-api-token",
				Output: "asadfasdfasrw3atr3r3rf33fasdaa3233",
			})
			// k8s-ca-certificate
			fname, err := createTempFile("ca.crt")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovs-vsctl --timeout=15 --if-exists get Open_vSwitch . external_ids:k8s-ca-certificate",
				Output: fname,
			})
			// ovn-nb address
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovs-vsctl --timeout=15 --if-exists get Open_vSwitch . external_ids:ovn-nb",
				Output: "tcp:1.1.1.1:6441",
			})

			cfgPath, err := InitConfigSa(ctx, fexec, tmpDir, &Defaults{
				OvnNorthAddress: true,
				K8sAPIServer:    true,
				K8sToken:        true,
				K8sCert:         true,
			})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(cfgPath).To(gomega.Equal(cfgFile.Name()))
			gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)

			gomega.Expect(Kubernetes.APIServer).To(gomega.Equal("https://somewhere.com:8081"))
			gomega.Expect(Kubernetes.CACert).To(gomega.Equal(fname))
			gomega.Expect(Kubernetes.Token).To(gomega.Equal("asadfasdfasrw3atr3r3rf33fasdaa3233"))

			gomega.Expect(OvnNorth.Scheme).To(gomega.Equal(OvnDBSchemeTCP))
			gomega.Expect(OvnNorth.PrivKey).To(gomega.Equal(""))
			gomega.Expect(OvnNorth.Cert).To(gomega.Equal(""))
			gomega.Expect(OvnNorth.CACert).To(gomega.Equal(""))
			gomega.Expect(OvnNorth.Address).To(gomega.Equal("tcp:1.1.1.1:6441"))
			gomega.Expect(OvnNorth.CertCommonName).To(gomega.Equal(""))

			gomega.Expect(OvnSouth.Scheme).To(gomega.Equal(OvnDBSchemeUnix))
			gomega.Expect(OvnSouth.PrivKey).To(gomega.Equal(""))
			gomega.Expect(OvnSouth.Cert).To(gomega.Equal(""))
			gomega.Expect(OvnSouth.CACert).To(gomega.Equal(""))
			gomega.Expect(OvnSouth.Address).To(gomega.Equal(""))
			gomega.Expect(OvnSouth.CertCommonName).To(gomega.Equal(""))

			return nil
		}
		err := app.Run([]string{app.Name, "-config-file=" + cfgFile.Name()})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("reads defaults (multiple master) from ovs-vsctl external IDs", func() {
		app.Action = func(ctx *cli.Context) error {
			fexec := ovntest.NewFakeExec()

			// k8s-api-server
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovs-vsctl --timeout=15 --if-exists get Open_vSwitch . external_ids:k8s-api-server",
				Output: "https://somewhere.com:8081",
			})

			// k8s-api-token
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovs-vsctl --timeout=15 --if-exists get Open_vSwitch . external_ids:k8s-api-token",
				Output: "asadfasdfasrw3atr3r3rf33fasdaa3233",
			})
			// k8s-ca-certificate
			fname, err := createTempFile("kube-cacert.pem")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovs-vsctl --timeout=15 --if-exists get Open_vSwitch . external_ids:k8s-ca-certificate",
				Output: fname,
			})
			// ovn-nb address
			fexec.AddFakeCmd(&ovntest.ExpectedCmd{
				Cmd:    "ovs-vsctl --timeout=15 --if-exists get Open_vSwitch . external_ids:ovn-nb",
				Output: "tcp:1.1.1.1:6441,tcp:1.1.1.2:6641,tcp:1.1.1.3:6641",
			})

			tokenFile, err1 := createTempFileContent("token", "TG9yZW0gaXBzdW0gZ")
			gomega.Expect(err1).NotTo(gomega.HaveOccurred())
			defer os.Remove(tokenFile)

			cfgPath, err := InitConfigSa(ctx, fexec, tmpDir, &Defaults{
				OvnNorthAddress: true,
				K8sAPIServer:    true,
				K8sToken:        true,
				K8sCert:         true,
			})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(cfgPath).To(gomega.Equal(cfgFile.Name()))
			gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)

			gomega.Expect(Kubernetes.APIServer).To(gomega.Equal("https://somewhere.com:8081"))
			gomega.Expect(Kubernetes.CACert).To(gomega.Equal(fname))
			gomega.Expect(Kubernetes.Token).To(gomega.Equal("asadfasdfasrw3atr3r3rf33fasdaa3233"))

			gomega.Expect(OvnNorth.Scheme).To(gomega.Equal(OvnDBSchemeTCP))
			gomega.Expect(OvnNorth.PrivKey).To(gomega.Equal(""))
			gomega.Expect(OvnNorth.Cert).To(gomega.Equal(""))
			gomega.Expect(OvnNorth.CACert).To(gomega.Equal(""))
			gomega.Expect(OvnNorth.Address).To(
				gomega.Equal("tcp:1.1.1.1:6441,tcp:1.1.1.2:6641,tcp:1.1.1.3:6641"))
			gomega.Expect(OvnNorth.CertCommonName).To(gomega.Equal(""))

			gomega.Expect(OvnSouth.Scheme).To(gomega.Equal(OvnDBSchemeUnix))
			gomega.Expect(OvnSouth.PrivKey).To(gomega.Equal(""))
			gomega.Expect(OvnSouth.Cert).To(gomega.Equal(""))
			gomega.Expect(OvnSouth.CACert).To(gomega.Equal(""))
			gomega.Expect(OvnSouth.Address).To(gomega.Equal(""))
			gomega.Expect(OvnSouth.CertCommonName).To(gomega.Equal(""))

			return nil
		}
		err := app.Run([]string{app.Name, "-config-file=" + cfgFile.Name()})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("uses serviceaccount files", func() {
		kubeCAcertFile, err := createTempFile("ca.crt")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		defer os.Remove(kubeCAcertFile)

		tokenFile, err1 := createTempFileContent("token", "TG9yZW0gaXBzdW0gZ")
		gomega.Expect(err1).NotTo(gomega.HaveOccurred())
		defer os.Remove(tokenFile)

		app.Action = func(ctx *cli.Context) error {
			_, err := InitConfigSa(ctx, kexec.New(), tmpDir, nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			gomega.Expect(Kubernetes.CACert).To(gomega.Equal(kubeCAcertFile))
			gomega.Expect(Kubernetes.Token).To(gomega.Equal("TG9yZW0gaXBzdW0gZ"))

			return nil
		}
		err2 := app.Run([]string{app.Name})
		gomega.Expect(err2).NotTo(gomega.HaveOccurred())

	})

	ginkgo.It("uses environment variables", func() {
		kubeconfigEnvFile, err := createTempFile("kubeconfig.env")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		defer os.Remove(kubeconfigEnvFile)
		os.Setenv("KUBECONFIG", kubeconfigEnvFile)
		defer os.Setenv("KUBECONFIG", "")

		os.Setenv("K8S_TOKEN", "this is the  token test")
		defer os.Setenv("K8S_TOKEN", "")

		os.Setenv("K8S_APISERVER", "https://9.2.3.4:6443")
		defer os.Setenv("K8S_APISERVER", "")

		kubeCAFile, err1 := createTempFile("kube-ca.crt")
		gomega.Expect(err1).NotTo(gomega.HaveOccurred())
		defer os.Remove(kubeCAFile)
		os.Setenv("K8S_CACERT", kubeCAFile)
		defer os.Setenv("K8S_CACERT", "")

		app.Action = func(ctx *cli.Context) error {
			var cfgPath string
			cfgPath, err = InitConfigSa(ctx, kexec.New(), tmpDir, nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(cfgPath).To(gomega.Equal(cfgFile.Name()))

			gomega.Expect(Kubernetes.Kubeconfig).To(gomega.Equal(kubeconfigEnvFile))
			gomega.Expect(Kubernetes.CACert).To(gomega.Equal(kubeCAFile))
			gomega.Expect(Kubernetes.Token).To(gomega.Equal("this is the  token test"))
			gomega.Expect(Kubernetes.APIServer).To(gomega.Equal("https://9.2.3.4:6443"))

			return nil
		}
		err = app.Run([]string{app.Name, "-config-file=" + cfgFile.Name()})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

	})

	ginkgo.It("overrides defaults with config file options", func() {
		kubeconfigFile, err := createTempFile("kubeconfig")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		defer os.Remove(kubeconfigFile)

		kubeCAFile, err := createTempFile("kube-ca.crt")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		defer os.Remove(kubeCAFile)

		err = writeTestConfigFile(cfgFile.Name(), "kubeconfig="+kubeconfigFile, "cacert="+kubeCAFile)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		app.Action = func(ctx *cli.Context) error {
			var cfgPath string
			cfgPath, err = InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(cfgPath).To(gomega.Equal(cfgFile.Name()))

			gomega.Expect(Default.MTU).To(gomega.Equal(1500))
			gomega.Expect(Default.ConntrackZone).To(gomega.Equal(64321))
			gomega.Expect(Logging.File).To(gomega.Equal("/var/log/ovnkube.log"))
			gomega.Expect(Logging.Level).To(gomega.Equal(5))
			gomega.Expect(CNI.ConfDir).To(gomega.Equal("/etc/cni/net.d22"))
			gomega.Expect(CNI.Plugin).To(gomega.Equal("ovn-k8s-cni-overlay22"))
			gomega.Expect(Kubernetes.Kubeconfig).To(gomega.Equal(kubeconfigFile))
			gomega.Expect(Kubernetes.CACert).To(gomega.Equal(kubeCAFile))
			gomega.Expect(Kubernetes.Token).To(gomega.Equal("TG9yZW0gaXBzdW0gZ"))
			gomega.Expect(Kubernetes.APIServer).To(gomega.Equal("https://1.2.3.4:6443"))
			gomega.Expect(Kubernetes.RawServiceCIDRs).To(gomega.Equal("172.18.0.0/24"))
			gomega.Expect(Default.ClusterSubnets).To(gomega.Equal([]CIDRNetworkEntry{
				{ovntest.MustParseIPNet("10.132.0.0/14"), 23},
			}))

			gomega.Expect(OvnNorth.Scheme).To(gomega.Equal(OvnDBSchemeSSL))
			gomega.Expect(OvnNorth.PrivKey).To(gomega.Equal("/path/to/nb-client-private.key"))
			gomega.Expect(OvnNorth.Cert).To(gomega.Equal("/path/to/nb-client.crt"))
			gomega.Expect(OvnNorth.CACert).To(gomega.Equal("/path/to/nb-client-ca.crt"))
			gomega.Expect(OvnNorth.Address).To(gomega.Equal("ssl:1.2.3.4:6641"))
			gomega.Expect(OvnNorth.CertCommonName).To(gomega.Equal("cfg-nbcommonname"))

			gomega.Expect(OvnSouth.Scheme).To(gomega.Equal(OvnDBSchemeSSL))
			gomega.Expect(OvnSouth.PrivKey).To(gomega.Equal("/path/to/sb-client-private.key"))
			gomega.Expect(OvnSouth.Cert).To(gomega.Equal("/path/to/sb-client.crt"))
			gomega.Expect(OvnSouth.CACert).To(gomega.Equal("/path/to/sb-client-ca.crt"))
			gomega.Expect(OvnSouth.Address).To(gomega.Equal("ssl:1.2.3.4:6642"))
			gomega.Expect(OvnSouth.CertCommonName).To(gomega.Equal("cfg-sbcommonname"))

			gomega.Expect(Gateway.Mode).To(gomega.Equal(GatewayModeShared))
			gomega.Expect(Gateway.Interface).To(gomega.Equal("eth1"))
			gomega.Expect(Gateway.NextHop).To(gomega.Equal("1.3.4.5"))
			gomega.Expect(Gateway.VLANID).To(gomega.Equal(uint(10)))
			gomega.Expect(Gateway.NodeportEnable).To(gomega.BeFalse())

			gomega.Expect(HybridOverlay.Enabled).To(gomega.BeTrue())
			gomega.Expect(HybridOverlay.ClusterSubnets).To(gomega.Equal([]CIDRNetworkEntry{
				{ovntest.MustParseIPNet("11.132.0.0/14"), 23},
			}))

			return nil
		}
		err = app.Run([]string{app.Name, "-config-file=" + cfgFile.Name()})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("overrides config file and defaults with CLI options", func() {
		kubeconfigFile, err := createTempFile("kubeconfig")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		defer os.Remove(kubeconfigFile)

		kubeCAFile, err := createTempFile("kube-ca.crt")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		defer os.Remove(kubeCAFile)

		err = writeTestConfigFile(cfgFile.Name())
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		app.Action = func(ctx *cli.Context) error {
			var cfgPath string
			cfgPath, err = InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(cfgPath).To(gomega.Equal(cfgFile.Name()))

			gomega.Expect(Default.MTU).To(gomega.Equal(1234))
			gomega.Expect(Default.ConntrackZone).To(gomega.Equal(5555))
			gomega.Expect(Logging.File).To(gomega.Equal("/some/logfile"))
			gomega.Expect(Logging.Level).To(gomega.Equal(3))
			gomega.Expect(CNI.ConfDir).To(gomega.Equal("/some/cni/dir"))
			gomega.Expect(CNI.Plugin).To(gomega.Equal("a-plugin"))
			gomega.Expect(Kubernetes.Kubeconfig).To(gomega.Equal(kubeconfigFile))
			gomega.Expect(Kubernetes.CACert).To(gomega.Equal(kubeCAFile))
			gomega.Expect(Kubernetes.Token).To(gomega.Equal("asdfasdfasdfasfd"))
			gomega.Expect(Kubernetes.APIServer).To(gomega.Equal("https://4.4.3.2:8080"))
			gomega.Expect(Kubernetes.RawServiceCIDRs).To(gomega.Equal("172.15.0.0/24"))
			gomega.Expect(Kubernetes.RawNoHostSubnetNodes).To(gomega.Equal("test=pass"))
			gomega.Expect(Default.ClusterSubnets).To(gomega.Equal([]CIDRNetworkEntry{
				{ovntest.MustParseIPNet("10.130.0.0/15"), 24},
			}))

			gomega.Expect(OvnNorth.Scheme).To(gomega.Equal(OvnDBSchemeSSL))
			gomega.Expect(OvnNorth.PrivKey).To(gomega.Equal("/client/privkey"))
			gomega.Expect(OvnNorth.Cert).To(gomega.Equal("/client/cert"))
			gomega.Expect(OvnNorth.CACert).To(gomega.Equal("/client/cacert"))
			gomega.Expect(OvnNorth.Address).To(gomega.Equal("ssl:6.5.4.3:6651"))
			gomega.Expect(OvnNorth.CertCommonName).To(gomega.Equal("testnbcommonname"))

			gomega.Expect(OvnSouth.Scheme).To(gomega.Equal(OvnDBSchemeSSL))
			gomega.Expect(OvnSouth.PrivKey).To(gomega.Equal("/client/privkey2"))
			gomega.Expect(OvnSouth.Cert).To(gomega.Equal("/client/cert2"))
			gomega.Expect(OvnSouth.CACert).To(gomega.Equal("/client/cacert2"))
			gomega.Expect(OvnSouth.Address).To(gomega.Equal("ssl:6.5.4.1:6652"))
			gomega.Expect(OvnSouth.CertCommonName).To(gomega.Equal("testsbcommonname"))

			gomega.Expect(Gateway.Mode).To(gomega.Equal(GatewayModeShared))
			gomega.Expect(Gateway.NodeportEnable).To(gomega.BeTrue())

			gomega.Expect(HybridOverlay.Enabled).To(gomega.BeTrue())
			gomega.Expect(HybridOverlay.ClusterSubnets).To(gomega.Equal([]CIDRNetworkEntry{
				{ovntest.MustParseIPNet("11.132.0.0/14"), 23},
			}))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-config-file=" + cfgFile.Name(),
			"-mtu=1234",
			"-conntrack-zone=5555",
			"-loglevel=3",
			"-logfile=/some/logfile",
			"-cni-conf-dir=/some/cni/dir",
			"-cni-plugin=a-plugin",
			"-cluster-subnets=10.130.0.0/15/24",
			"-k8s-kubeconfig=" + kubeconfigFile,
			"-k8s-apiserver=https://4.4.3.2:8080",
			"-k8s-cacert=" + kubeCAFile,
			"-k8s-token=asdfasdfasdfasfd",
			"-k8s-service-cidrs=172.15.0.0/24",
			"-nb-address=ssl:6.5.4.3:6651",
			"-no-hostsubnet-nodes=test=pass",
			"-nb-client-privkey=/client/privkey",
			"-nb-client-cert=/client/cert",
			"-nb-client-cacert=/client/cacert",
			"-nb-cert-common-name=testnbcommonname",
			"-sb-address=ssl:6.5.4.1:6652",
			"-sb-client-privkey=/client/privkey2",
			"-sb-client-cert=/client/cert2",
			"-sb-client-cacert=/client/cacert2",
			"-sb-cert-common-name=testsbcommonname",
			"-gateway-mode=shared",
			"-nodeport",
			"-enable-hybrid-overlay",
			"-hybrid-overlay-cluster-subnets=11.132.0.0/14/23",
		}
		err = app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("overrides config file and defaults with CLI legacy service-cluster-ip-range option", func() {
		err := ioutil.WriteFile(cfgFile.Name(), []byte(`[kubernetes]
service-cidrs=172.18.0.0/24
`), 0644)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		app.Action = func(ctx *cli.Context) error {
			var cfgPath string
			cfgPath, err = InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(cfgPath).To(gomega.Equal(cfgFile.Name()))
			gomega.Expect(Kubernetes.RawServiceCIDRs).To(gomega.Equal("172.15.0.0/24"))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-config-file=" + cfgFile.Name(),
			"-service-cluster-ip-range=172.15.0.0/24",
		}
		err = app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("accepts legacy service-cidr config file option", func() {
		err := ioutil.WriteFile(cfgFile.Name(), []byte(`[kubernetes]
service-cidr=172.18.0.0/24
`), 0644)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		app.Action = func(ctx *cli.Context) error {
			var cfgPath string
			cfgPath, err = InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(cfgPath).To(gomega.Equal(cfgFile.Name()))
			gomega.Expect(Kubernetes.RawServiceCIDRs).To(gomega.Equal("172.18.0.0/24"))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-config-file=" + cfgFile.Name(),
		}
		err = app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("returns an error when the k8s-service-cidrs is invalid", func() {
		app.Action = func(ctx *cli.Context) error {
			_, err := InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).To(gomega.MatchError("kubernetes service network CIDR \"adsfasdfaf\" invalid: invalid CIDR address: adsfasdfaf"))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-k8s-service-cidr=adsfasdfaf",
		}
		err := app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("overrides config file and defaults with CLI legacy cluster-subnet option", func() {
		err := ioutil.WriteFile(cfgFile.Name(), []byte(`[default]
cluster-subnets=172.18.0.0/23
`), 0644)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		app.Action = func(ctx *cli.Context) error {
			var cfgPath string
			cfgPath, err = InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(cfgPath).To(gomega.Equal(cfgFile.Name()))
			gomega.Expect(Default.ClusterSubnets).To(gomega.Equal([]CIDRNetworkEntry{
				{ovntest.MustParseIPNet("172.15.0.0/23"), 24},
			}))
			gomega.Expect(IPv4Mode).To(gomega.Equal(true))
			gomega.Expect(IPv6Mode).To(gomega.Equal(false))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-config-file=" + cfgFile.Name(),
			"-cluster-subnet=172.15.0.0/23",
		}
		err = app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("returns an error when the cluster-subnets is invalid", func() {
		app.Action = func(ctx *cli.Context) error {
			_, err := InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).To(gomega.MatchError("cluster subnet invalid: CIDR \"adsfasdfaf\" not properly formatted"))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-cluster-subnets=adsfasdfaf",
		}
		err := app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("returns an error when the hybrid overlay cluster-subnets is invalid", func() {
		app.Action = func(ctx *cli.Context) error {
			_, err := InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).To(gomega.MatchError("hybrid overlay cluster subnet invalid: CIDR \"adsfasdfaf\" not properly formatted"))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-hybrid-overlay-cluster-subnets=adsfasdfaf",
			"-enable-hybrid-overlay",
		}
		err := app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("overrides config file and defaults with CLI legacy --init-gateways option", func() {
		err := ioutil.WriteFile(cfgFile.Name(), []byte(`[gateway]
mode=local
`), 0644)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		app.Action = func(ctx *cli.Context) error {
			var cfgPath string
			cfgPath, err = InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(cfgPath).To(gomega.Equal(cfgFile.Name()))
			gomega.Expect(Gateway.Mode).To(gomega.Equal(GatewayModeShared))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-config-file=" + cfgFile.Name(),
			"-init-gateways",
		}
		err = app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("overrides config file and defaults with CLI legacy --gateway-local option", func() {
		err := ioutil.WriteFile(cfgFile.Name(), []byte(`[gateway]
mode=shared
`), 0644)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		app.Action = func(ctx *cli.Context) error {
			var cfgPath string
			cfgPath, err = InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(cfgPath).To(gomega.Equal(cfgFile.Name()))
			gomega.Expect(Gateway.Mode).To(gomega.Equal(GatewayModeLocal))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-config-file=" + cfgFile.Name(),
			"-init-gateways",
			"-gateway-local",
		}
		err = app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("returns an error when the gateway mode is invalid", func() {
		app.Action = func(ctx *cli.Context) error {
			_, err := InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).To(gomega.MatchError("invalid gateway mode \"adsfasdfaf\": expect one of shared,local"))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-gateway-mode=adsfasdfaf",
		}
		err := app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("returns an error when the vlan-id is specified for mode other than shared gateway mode", func() {
		app.Action = func(ctx *cli.Context) error {
			_, err := InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).To(gomega.MatchError("gateway VLAN ID option: 30 is supported only in shared gateway mode"))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-gateway-mode=local",
			"-gateway-vlanid=30",
		}
		err := app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("overrides config file and defaults with CLI options (multi-master)", func() {
		kubeconfigFile, err := createTempFile("kubeconfig")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		defer os.Remove(kubeconfigFile)

		kubeCAFile, err := createTempFile("kube-ca.crt")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		defer os.Remove(kubeCAFile)

		err = writeTestConfigFile(cfgFile.Name())
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		app.Action = func(ctx *cli.Context) error {
			var cfgPath string
			cfgPath, err = InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(cfgPath).To(gomega.Equal(cfgFile.Name()))

			gomega.Expect(Default.MTU).To(gomega.Equal(1234))
			gomega.Expect(Default.ConntrackZone).To(gomega.Equal(5555))
			gomega.Expect(Logging.File).To(gomega.Equal("/some/logfile"))
			gomega.Expect(Logging.Level).To(gomega.Equal(3))
			gomega.Expect(CNI.ConfDir).To(gomega.Equal("/some/cni/dir"))
			gomega.Expect(CNI.Plugin).To(gomega.Equal("a-plugin"))
			gomega.Expect(Kubernetes.Kubeconfig).To(gomega.Equal(kubeconfigFile))
			gomega.Expect(Kubernetes.CACert).To(gomega.Equal(kubeCAFile))
			gomega.Expect(Kubernetes.Token).To(gomega.Equal("asdfasdfasdfasfd"))
			gomega.Expect(Kubernetes.APIServer).To(gomega.Equal("https://4.4.3.2:8080"))
			gomega.Expect(Kubernetes.RawNoHostSubnetNodes).To(gomega.Equal("label=another-test-label"))
			gomega.Expect(Kubernetes.RawServiceCIDRs).To(gomega.Equal("172.15.0.0/24"))

			gomega.Expect(OvnNorth.Scheme).To(gomega.Equal(OvnDBSchemeSSL))
			gomega.Expect(OvnNorth.PrivKey).To(gomega.Equal("/client/privkey"))
			gomega.Expect(OvnNorth.Cert).To(gomega.Equal("/client/cert"))
			gomega.Expect(OvnNorth.CACert).To(gomega.Equal("/client/cacert"))
			gomega.Expect(OvnNorth.Address).To(
				gomega.Equal("ssl:6.5.4.3:6651,ssl:6.5.4.4:6651,ssl:6.5.4.5:6651"))
			gomega.Expect(OvnNorth.CertCommonName).To(gomega.Equal("testnbcommonname"))

			gomega.Expect(OvnSouth.Scheme).To(gomega.Equal(OvnDBSchemeSSL))
			gomega.Expect(OvnSouth.PrivKey).To(gomega.Equal("/client/privkey2"))
			gomega.Expect(OvnSouth.Cert).To(gomega.Equal("/client/cert2"))
			gomega.Expect(OvnSouth.CACert).To(gomega.Equal("/client/cacert2"))
			gomega.Expect(OvnSouth.Address).To(
				gomega.Equal("ssl:6.5.4.1:6652,ssl:6.5.4.2:6652,ssl:6.5.4.3:6652"))
			gomega.Expect(OvnSouth.CertCommonName).To(gomega.Equal("testsbcommonname"))

			return nil
		}
		cliArgs := []string{
			app.Name,
			"-config-file=" + cfgFile.Name(),
			"-mtu=1234",
			"-conntrack-zone=5555",
			"-loglevel=3",
			"-logfile=/some/logfile",
			"-cni-conf-dir=/some/cni/dir",
			"-cni-plugin=a-plugin",
			"-k8s-kubeconfig=" + kubeconfigFile,
			"-k8s-apiserver=https://4.4.3.2:8080",
			"-k8s-cacert=" + kubeCAFile,
			"-k8s-token=asdfasdfasdfasfd",
			"-k8s-service-cidr=172.15.0.0/24",
			"-nb-address=ssl:6.5.4.3:6651,ssl:6.5.4.4:6651,ssl:6.5.4.5:6651",
			"-nb-client-privkey=/client/privkey",
			"-nb-client-cert=/client/cert",
			"-nb-client-cacert=/client/cacert",
			"-nb-cert-common-name=testnbcommonname",
			"-sb-address=ssl:6.5.4.1:6652,ssl:6.5.4.2:6652,ssl:6.5.4.3:6652",
			"-sb-client-privkey=/client/privkey2",
			"-sb-client-cert=/client/cert2",
			"-sb-client-cacert=/client/cacert2",
			"-sb-cert-common-name=testsbcommonname",
		}
		err = app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("does not override config file settings with default cli options", func() {
		kubeconfigFile, err := createTempFile("kubeconfig")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		defer os.Remove(kubeconfigFile)

		kubeCAFile, err := createTempFile("kube-ca.crt")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		defer os.Remove(kubeCAFile)

		err = writeTestConfigFile(cfgFile.Name())
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		app.Action = func(ctx *cli.Context) error {
			var cfgPath string
			cfgPath, err = InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(cfgPath).To(gomega.Equal(cfgFile.Name()))

			gomega.Expect(Default.MTU).To(gomega.Equal(1500))
			gomega.Expect(Default.ConntrackZone).To(gomega.Equal(64321))
			gomega.Expect(Default.RawClusterSubnets).To(gomega.Equal("10.132.0.0/14/23"))
			gomega.Expect(Default.ClusterSubnets).To(gomega.Equal([]CIDRNetworkEntry{
				{ovntest.MustParseIPNet("10.132.0.0/14"), 23},
			}))
			gomega.Expect(Logging.File).To(gomega.Equal("/var/log/ovnkube.log"))
			gomega.Expect(Logging.Level).To(gomega.Equal(5))
			gomega.Expect(CNI.ConfDir).To(gomega.Equal("/etc/cni/net.d22"))
			gomega.Expect(CNI.Plugin).To(gomega.Equal("ovn-k8s-cni-overlay22"))
			gomega.Expect(Kubernetes.Kubeconfig).To(gomega.Equal(kubeconfigFile))
			gomega.Expect(Kubernetes.CACert).To(gomega.Equal(kubeCAFile))
			gomega.Expect(Kubernetes.Token).To(gomega.Equal("TG9yZW0gaXBzdW0gZ"))
			gomega.Expect(Kubernetes.RawServiceCIDRs).To(gomega.Equal("172.18.0.0/24"))

			return nil
		}

		cliArgs := []string{
			app.Name,
			"-config-file=" + cfgFile.Name(),
			"-k8s-kubeconfig=" + kubeconfigFile,
			"-k8s-cacert=" + kubeCAFile,
		}
		err = app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("allows configuring a single-stack IPv6 cluster", func() {
		app.Action = func(ctx *cli.Context) error {
			_, err := InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(IPv4Mode).To(gomega.Equal(false))
			gomega.Expect(IPv6Mode).To(gomega.Equal(true))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-cluster-subnets=fd01::/48/64",
			"-k8s-service-cidrs=fd02::/112",
		}
		err := app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("allows configuring a dual-stack cluster", func() {
		app.Action = func(ctx *cli.Context) error {
			_, err := InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(IPv4Mode).To(gomega.Equal(true))
			gomega.Expect(IPv6Mode).To(gomega.Equal(true))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-cluster-subnets=10.0.0.0/16/24,fd01::/48/64",
			"-k8s-service-cidrs=172.30.0.0/16,fd02::/112",
		}
		err := app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("allows configuring a dual-stack cluster with multiple IPv4 cluster subnet ranges", func() {
		app.Action = func(ctx *cli.Context) error {
			_, err := InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(IPv4Mode).To(gomega.Equal(true))
			gomega.Expect(IPv6Mode).To(gomega.Equal(true))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-cluster-subnets=10.0.0.0/16/24,10.2.0.0/16/24,fd01::/48/64",
			"-k8s-service-cidrs=172.30.0.0/16,fd02::/112",
		}
		err := app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("rejects a cluster with IPv4 pods and IPv6 services", func() {
		app.Action = func(ctx *cli.Context) error {
			_, err := InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).To(gomega.MatchError("illegal network configuration: IPv4 cluster subnet, IPv6 service subnet"))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-cluster-subnets=10.0.0.0/16/24",
			"-k8s-service-cidrs=fd02::/112",
		}
		err := app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("rejects a cluster with IPv6 pods and IPv4 services", func() {
		app.Action = func(ctx *cli.Context) error {
			_, err := InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).To(gomega.MatchError("illegal network configuration: IPv6 cluster subnet, IPv4 service subnet"))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-cluster-subnets=fd01::/48/64",
			"-k8s-service-cidrs=172.30.0.0/16",
		}
		err := app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("rejects a cluster with dual-stack pods and single-stack services", func() {
		app.Action = func(ctx *cli.Context) error {
			_, err := InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).To(gomega.MatchError("illegal network configuration: dual-stack cluster subnet, IPv4 service subnet"))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-cluster-subnets=10.0.0.0/16/24,fd01::/48/64",
			"-k8s-service-cidrs=172.30.0.0/16",
		}
		err := app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("rejects a cluster with single-stack pods and dual-stack services", func() {
		app.Action = func(ctx *cli.Context) error {
			_, err := InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).To(gomega.MatchError("illegal network configuration: IPv6 cluster subnet, dual-stack service subnet"))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-cluster-subnets=fd01::/48/64",
			"-k8s-service-cidrs=172.30.0.0/16,fd02::/112",
		}
		err := app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("rejects a cluster with multiple single-stack service CIDRs", func() {
		app.Action = func(ctx *cli.Context) error {
			_, err := InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).To(gomega.MatchError("kubernetes service-cidrs must contain either a single CIDR or else an IPv4/IPv6 pair"))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-cluster-subnets=10.0.0.0/16/24",
			"-k8s-service-cidrs=172.30.0.0/16,172.31.0.0/16",
		}
		err := app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("rejects a cluster with dual-stack cluster subnets and single-stack hybrid overlap subnets", func() {
		app.Action = func(ctx *cli.Context) error {
			_, err := InitConfig(ctx, kexec.New(), nil)
			gomega.Expect(err).To(gomega.MatchError("illegal network configuration: dual-stack cluster subnet, dual-stack service subnet, IPv4 hybrid overlay subnet"))
			return nil
		}
		cliArgs := []string{
			app.Name,
			"-cluster-subnets=10.0.0.0/16/24,fd01::/48/64",
			"-k8s-service-cidrs=172.30.0.0/16,fd02::/112",
			"-enable-hybrid-overlay",
			"-hybrid-overlay-cluster-subnets=10.132.0.0/14/23",
		}
		err := app.Run(cliArgs)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.Describe("OvnDBAuth operations", func() {
		var certFile, keyFile, caFile string

		ginkgo.BeforeEach(func() {
			var err error
			certFile, err = createTempFile("cert.crt")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			keyFile, err = createTempFile("priv.key")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			caFile = filepath.Join(tmpDir, "ca.crt")
		})

		ginkgo.AfterEach(func() {
			err := os.Remove(certFile)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			err = os.Remove(keyFile)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			os.Remove(caFile)
		})

		const (
			nbURL             string = "ssl:1.2.3.4:6641"
			sbURL             string = "ssl:1.2.3.4:6642"
			nbDummyCommonName        = "cfg-nbcommonname"
			sbDummyCommonName        = "cfg-sbcommonname"
		)

		ginkgo.It("configures client northbound SSL correctly", func() {
			fexec := ovntest.NewFakeExec()
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --db=" + nbURL + " --timeout=5 --private-key=" + keyFile + " --certificate=" + certFile + " --bootstrap-ca-cert=" + caFile + " list nb_global",
				"ovs-vsctl --timeout=15 set Open_vSwitch . external_ids:ovn-nb=\"" + nbURL + "\"",
			})

			cliConfig := &OvnAuthConfig{
				Address:        nbURL,
				PrivKey:        keyFile,
				Cert:           certFile,
				CACert:         caFile,
				CertCommonName: nbDummyCommonName,
			}
			a, err := buildOvnAuth(fexec, true, cliConfig, &OvnAuthConfig{}, true)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(a.Scheme).To(gomega.Equal(OvnDBSchemeSSL))
			gomega.Expect(a.PrivKey).To(gomega.Equal(keyFile))
			gomega.Expect(a.Cert).To(gomega.Equal(certFile))
			gomega.Expect(a.CACert).To(gomega.Equal(caFile))
			gomega.Expect(a.Address).To(gomega.Equal(nbURL))
			gomega.Expect(a.CertCommonName).To(gomega.Equal(nbDummyCommonName))
			gomega.Expect(a.northbound).To(gomega.BeTrue())
			gomega.Expect(a.externalID).To(gomega.Equal("ovn-nb"))

			gomega.Expect(a.GetURL()).To(gomega.Equal(nbURL))
			err = a.SetDBAuth()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)
		})

		ginkgo.It("configures client southbound SSL correctly", func() {
			fexec := ovntest.NewFakeExec()
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovn-nbctl --db=" + sbURL + " --timeout=5 --private-key=" + keyFile + " --certificate=" + certFile + " --bootstrap-ca-cert=" + caFile + " list nb_global",
				"ovs-vsctl --timeout=15 del-ssl",
				"ovs-vsctl --timeout=15 set-ssl " + keyFile + " " + certFile + " " + caFile,
				"ovs-vsctl --timeout=15 set Open_vSwitch . external_ids:ovn-remote=\"" + sbURL + "\"",
			})

			cliConfig := &OvnAuthConfig{
				Address:        sbURL,
				PrivKey:        keyFile,
				Cert:           certFile,
				CACert:         caFile,
				CertCommonName: sbDummyCommonName,
			}
			a, err := buildOvnAuth(fexec, false, cliConfig, &OvnAuthConfig{}, false)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(a.Scheme).To(gomega.Equal(OvnDBSchemeSSL))
			gomega.Expect(a.PrivKey).To(gomega.Equal(keyFile))
			gomega.Expect(a.Cert).To(gomega.Equal(certFile))
			gomega.Expect(a.CACert).To(gomega.Equal(caFile))
			gomega.Expect(a.Address).To(gomega.Equal(sbURL))
			gomega.Expect(a.CertCommonName).To(gomega.Equal(sbDummyCommonName))
			gomega.Expect(a.northbound).To(gomega.BeFalse())
			gomega.Expect(a.externalID).To(gomega.Equal("ovn-remote"))

			gomega.Expect(a.GetURL()).To(gomega.Equal(sbURL))
			err = a.SetDBAuth()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)
		})

		const (
			nbURLLegacy    string = "tcp://1.2.3.4:6641"
			nbURLConverted string = "tcp:1.2.3.4:6641"
			sbURLLegacy    string = "tcp://1.2.3.4:6642"
			sbURLConverted string = "tcp:1.2.3.4:6642"
		)

		ginkgo.It("configures client northbound TCP legacy address correctly", func() {
			fexec := ovntest.NewFakeExec()
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovs-vsctl --timeout=15 set Open_vSwitch . external_ids:ovn-nb=\"" + nbURLConverted + "\"",
			})

			cliConfig := &OvnAuthConfig{Address: nbURLLegacy}
			a, err := buildOvnAuth(fexec, true, cliConfig, &OvnAuthConfig{}, true)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(a.Scheme).To(gomega.Equal(OvnDBSchemeTCP))
			// Config should convert :// to : in addresses
			gomega.Expect(a.Address).To(gomega.Equal(nbURLConverted))
			gomega.Expect(a.northbound).To(gomega.BeTrue())
			gomega.Expect(a.externalID).To(gomega.Equal("ovn-nb"))

			gomega.Expect(a.GetURL()).To(gomega.Equal(nbURLConverted))
			err = a.SetDBAuth()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)
		})

		ginkgo.It("configures client southbound TCP legacy address correctly", func() {
			fexec := ovntest.NewFakeExec()
			fexec.AddFakeCmdsNoOutputNoError([]string{
				"ovs-vsctl --timeout=15 set Open_vSwitch . external_ids:ovn-nb=\"" + nbURLConverted + "\"",
			})

			cliConfig := &OvnAuthConfig{Address: nbURLLegacy}
			a, err := buildOvnAuth(fexec, true, cliConfig, &OvnAuthConfig{}, true)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(a.Scheme).To(gomega.Equal(OvnDBSchemeTCP))
			// Config should convert :// to : in addresses
			gomega.Expect(a.Address).To(gomega.Equal(nbURLConverted))
			gomega.Expect(a.northbound).To(gomega.BeTrue())
			gomega.Expect(a.externalID).To(gomega.Equal("ovn-nb"))

			gomega.Expect(a.GetURL()).To(gomega.Equal(nbURLConverted))
			err = a.SetDBAuth()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(fexec.CalledMatchesExpected()).To(gomega.BeTrue(), fexec.ErrorDesc)
		})
	})

	// This testcase factory function exists only to ensure that 'runType'
	// and 'dir' are evaluated when this factory function is called (and
	// the It() is created), but that the CLI arguments are evaluated only
	// when the test function is actually executed.
	createOneTest := func(runType int, dir, match string, getArgs func() []string) func() {
		return func() {
			args := getArgs()
			finalArgs := make([]string, len(args))
			if dir == "" {
				finalArgs = args
			} else {
				// Update args for OVN NB/SB database options
				for i, a := range args {
					finalArgs[i] = fmt.Sprintf("-%s-%s", dir, a)
				}
			}
			err := runInit(app, runType, cfgFile, finalArgs...)
			if match != "" {
				gomega.Expect(err.Error()).To(gomega.ContainSubstring(match))
			} else {
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			}
		}
	}

	// Generates multiple runType and direction It() tests for a given description, match, and args
	generateTests := func(desc, match string, getArgs func() []string) {
		for _, dir := range []string{"nb", "sb"} {
			for runType := 1; runType <= 3; runType++ {
				realDesc := fmt.Sprintf("(%d/%s) %s", runType, dir, desc)
				ginkgo.It(realDesc, createOneTest(runType, dir, match, getArgs))
			}
		}
	}

	// Generates multiple runType It() tests for a given description, match, and args
	generateTestsSimple := func(desc, match string, args ...string) {
		for runType := 1; runType <= 3; runType++ {
			realDesc := fmt.Sprintf("(%d) %s", runType, desc)
			ginkgo.It(realDesc, createOneTest(runType, "", match, func() []string {
				return args
			}))
		}
	}

	// Run once without config file, once with
	ginkgo.Describe("Kubernetes config options", func() {
		ginkgo.Context("returns an error when the", func() {
			generateTestsSimple("CA cert does not exist",
				"kubernetes CA certificate file \"/foo/bar/baz.cert\" not found",
				"-k8s-apiserver=https://localhost:8443", "-k8s-cacert=/foo/bar/baz.cert")

			generateTestsSimple("apiserver URL scheme is invalid",
				"kubernetes API server URL scheme \"gggggg\" invalid",
				"-k8s-apiserver=gggggg://localhost:8443")

			generateTestsSimple("apiserver URL is invalid",
				"invalid character \" \" in host name",
				"-k8s-apiserver=http://a b.com/")

			generateTestsSimple("kubeconfig file does not exist",
				"kubernetes kubeconfig file \"/foo/bar/baz\" not found",
				"-k8s-kubeconfig=/foo/bar/baz")
		})
	})

	ginkgo.Describe("OVN API config options", func() {
		var certFile, keyFile, caFile string

		ginkgo.BeforeEach(func() {
			var err error
			certFile, err = createTempFile("cert.crt")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			keyFile, err = createTempFile("priv.key")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			caFile, err = createTempFile("ca.crt")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.AfterEach(func() {
			os.Remove(certFile)
			os.Remove(keyFile)
			os.Remove(caFile)
		})

		ginkgo.Context("returns an error when", func() {
			generateTests("the scheme is not empty/tcp/ssl",
				"unknown OVN DB scheme \"blah\"",
				func() []string {
					return []string{"address=blah:1.2.3.4:5555"}
				})

			generateTests("the address is unix socket and certs are given",
				"certificate or key given; perhaps you mean to use the 'ssl' scheme?",
				func() []string {
					return []string{
						"client-privkey=/bar/baz/foo",
						"client-cert=/bar/baz/foo",
						"client-cacert=/var/baz/foo",
					}
				})

			generateTests("the OVN URL has no port",
				"failed to parse OVN DB host/port \"4.3.2.1\": address 4.3.2.1: missing port in address",
				func() []string {
					return []string{
						"address=tcp:4.3.2.1",
					}
				})

			generateTests("certs are provided for the TCP scheme",
				"certificate or key given; perhaps you mean to use the 'ssl' scheme?",
				func() []string {
					return []string{
						"address=tcp:1.2.3.4:444",
						"client-privkey=/bar/baz/foo",
					}
				})
		})

		ginkgo.Context("does not return an error when", func() {
			generateTests("the SSL scheme is missing a client CA cert", "",
				func() []string {
					return []string{
						"address=ssl:1.2.3.4:444",
						"client-privkey=" + keyFile,
						"client-cert=" + certFile,
						"cert-common-name=foobar",
						"client-cacert=/foo/bar/baz",
					}
				})

			generateTests("the SSL scheme is missing a private key file", "",
				func() []string {
					return []string{
						"address=ssl:1.2.3.4:444",
						"client-privkey=/foo/bar/baz",
						"client-cert=" + certFile,
						"client-cacert=" + caFile,
						"cert-common-name=foobar",
					}
				})

			generateTests("the SSL scheme is missing a client cert file", "",
				func() []string {
					return []string{
						"address=ssl:1.2.3.4:444",
						"client-privkey=" + keyFile,
						"client-cert=/foo/bar/baz",
						"client-cacert=" + caFile,
						"cert-common-name=foobar",
					}
				})
		})
	})
})
