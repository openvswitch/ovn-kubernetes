package egressfirewalldns

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	//addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	//mocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set/mocks"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	util_mocks "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/mocks"
	"github.com/stretchr/testify/assert"
	mock "github.com/stretchr/testify/mock"

	"k8s.io/client-go/kubernetes/fake"

	egressfirewallfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressfirewall/v1/apis/clientset/versioned/fake"
	egressipfake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/egressip/v1/apis/clientset/versioned/fake"
	nodednsinfofake "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/nodednsinfo/v1/apis/clientset/versioned/fake"
	apiextensionsfake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"github.com/miekg/dns"
	utilnet "k8s.io/utils/net"
)

func TestNewEgressDNS(t *testing.T) {
	testCh := make(chan struct{})
	nodeName := "Node1"
	mockDnsOps := new(util_mocks.DNSOps)
	util.SetDNSLibOpsMockInst(mockDnsOps)
	fakeClient := &util.OVNClientset{
		KubeClient:           fake.NewSimpleClientset(),
		EgressIPClient:       egressipfake.NewSimpleClientset(),
		EgressFirewallClient: egressfirewallfake.NewSimpleClientset(),
		NodeDNSInfoClient:    nodednsinfofake.NewSimpleClientset(),
		APIExtensionsClient:  apiextensionsfake.NewSimpleClientset(),
	}
	factory, _ := factory.NewNodeWatchFactory(fakeClient, nodeName)
	tests := []struct {
		desc             string
		errExp           bool
		dnsOpsMockHelper []ovntest.TestifyMockHelper
	}{
		{
			desc:   "fails to read the /etc/resolv.conf file",
			errExp: true,
			dnsOpsMockHelper: []ovntest.TestifyMockHelper{
				{"ClientConfigFromFile", []string{"string"}, []interface{}{nil, fmt.Errorf("mock error")}, 0, 1},
			},
		},
		{
			desc: "positive tests case",
			dnsOpsMockHelper: []ovntest.TestifyMockHelper{
				{"ClientConfigFromFile", []string{"string"}, []interface{}{&dns.ClientConfig{}, nil}, 0, 1},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			for _, item := range tc.dnsOpsMockHelper {
				call := mockDnsOps.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			_, err := NewEgressDNS(nodeName, factory, &kube.Kube{KClient: fakeClient.KubeClient, NodeDNSInfoClient: fakeClient.NodeDNSInfoClient}, testCh)
			//t.Log(res, err)
			if tc.errExp {
				assert.Error(t, err)
			} else {
				assert.Nil(t, err)
			}
			mockDnsOps.AssertExpectations(t)
		})
	}
}

func generateRR(dnsName, ip, nextQueryTime string) dns.RR {
	var rr dns.RR
	if utilnet.IsIPv6(net.ParseIP(ip)) {
		rr, _ = dns.NewRR(dnsName + ".        " + nextQueryTime + "     IN      AAAA       " + ip)
	} else {
		rr, _ = dns.NewRR(dnsName + ".        " + nextQueryTime + "     IN      A       " + ip)
	}
	return rr
}

func TestAdd(t *testing.T) {
	mockDnsOps := new(util_mocks.DNSOps)
	util.SetDNSLibOpsMockInst(mockDnsOps)
	nodeName := "Node1"
	fakeClient := &util.OVNClientset{
		KubeClient:           fake.NewSimpleClientset(),
		EgressIPClient:       egressipfake.NewSimpleClientset(),
		EgressFirewallClient: egressfirewallfake.NewSimpleClientset(),
		NodeDNSInfoClient:    nodednsinfofake.NewSimpleClientset(),
		APIExtensionsClient:  apiextensionsfake.NewSimpleClientset(),
	}

	factory, _ := factory.NewNodeWatchFactory(fakeClient, nodeName)
	factory.InitializeEgressFirewallWatchFactory()
	test1DNSName := "www.test.com"
	test1IPv4 := "2.2.2.2"
	test1IPv4Update := "3.3.3.3"
	test1IPv6 := "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	tests := []struct {
		desc                     string
		errExp                   bool
		dnsName                  string
		configIPv4               bool
		configIPv6               bool
		testingUpdateOnQueryTime bool
		syncTime                 time.Duration
		waitForSyncLoop          bool
		dnsOpsMockHelper         []ovntest.TestifyMockHelper
	}{
		{
			desc:       "EgressFirewall Add(dnsName) succeeds IPv4 only",
			errExp:     false,
			syncTime:   5 * time.Minute,
			dnsName:    test1DNSName,
			configIPv4: true,
			configIPv6: false,

			dnsOpsMockHelper: []ovntest.TestifyMockHelper{
				{"ClientConfigFromFile", []string{"string"}, []interface{}{&dns.ClientConfig{
					Servers: []string{"1.1.1.1"},
					Port:    "1234"}, nil}, 0, 1},
				{"Fqdn", []string{"string"}, []interface{}{test1DNSName}, 0, 1},

				{"SetQuestion", []string{"*dns.Msg", "string", "uint16"}, []interface{}{&dns.Msg{}}, 0, 1},
				{"Exchange", []string{"*dns.Client", "*dns.Msg", "string"}, []interface{}{&dns.Msg{Answer: []dns.RR{generateRR(test1DNSName, test1IPv4, "300")}}, 500 * time.Second, nil}, 0, 1},
			},
		},

		{
			desc:                     "EgressFirewall Add(dnsName) succeeds dual stack",
			errExp:                   false,
			syncTime:                 5 * time.Minute,
			dnsName:                  test1DNSName,
			testingUpdateOnQueryTime: false,
			configIPv4:               true,
			configIPv6:               true,

			dnsOpsMockHelper: []ovntest.TestifyMockHelper{
				{"ClientConfigFromFile", []string{"string"}, []interface{}{&dns.ClientConfig{
					Servers: []string{"1.1.1.1"},
					Port:    "1234"}, nil}, 0, 1},
				{"Fqdn", []string{"string"}, []interface{}{test1DNSName}, 0, 1},
				{"Fqdn", []string{"string"}, []interface{}{test1DNSName}, 0, 1},
				{"SetQuestion", []string{"*dns.Msg", "string", "uint16"}, []interface{}{&dns.Msg{}}, 0, 1},
				{"SetQuestion", []string{"*dns.Msg", "string", "uint16"}, []interface{}{&dns.Msg{}}, 0, 1},
				{"Exchange", []string{"*dns.Client", "*dns.Msg", "string"}, []interface{}{&dns.Msg{Answer: []dns.RR{generateRR(test1DNSName, test1IPv4, "300")}}, 500 * time.Second, nil}, 0, 1},
				{"Exchange", []string{"*dns.Client", "*dns.Msg", "string"}, []interface{}{&dns.Msg{Answer: []dns.RR{generateRR(test1DNSName, test1IPv6, "300")}}, 500 * time.Second, nil}, 0, 1},
			},
		},
		{
			desc:                     "EgressFirewall DNS Run Runs update after the ttl returned from the DNS server expires",
			errExp:                   false,
			dnsName:                  test1DNSName,
			testingUpdateOnQueryTime: true,
			syncTime:                 5 * time.Minute,
			configIPv4:               true,
			configIPv6:               false,

			dnsOpsMockHelper: []ovntest.TestifyMockHelper{
				{"ClientConfigFromFile", []string{"string"}, []interface{}{&dns.ClientConfig{
					Servers: []string{"1.1.1.1"},
					Port:    "1234"}, nil}, 0, 1},
				{"Fqdn", []string{"string"}, []interface{}{test1DNSName}, 0, 1},

				{"SetQuestion", []string{"*dns.Msg", "string", "uint16"}, []interface{}{&dns.Msg{}}, 0, 1},
				// return a very low ttl so that the update based on ttl timeout occurs
				{"Exchange", []string{"*dns.Client", "*dns.Msg", "string"}, []interface{}{&dns.Msg{Answer: []dns.RR{generateRR(test1DNSName, test1IPv4, "2")}}, 1 * time.Second, nil}, 0, 1},
				{"Fqdn", []string{"string"}, []interface{}{test1DNSName}, 0, 1},

				{"SetQuestion", []string{"*dns.Msg", "string", "uint16"}, []interface{}{&dns.Msg{}}, 0, 1},
				{"Exchange", []string{"*dns.Client", "*dns.Msg", "string"}, []interface{}{&dns.Msg{Answer: []dns.RR{generateRR(test1DNSName, test1IPv4Update, "300")}}, 1 * time.Second, nil}, 0, 1},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			testCh := make(chan struct{})
			config.IPv4Mode = tc.configIPv4
			config.IPv6Mode = tc.configIPv6

			for _, item := range tc.dnsOpsMockHelper {
				call := mockDnsOps.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			res, err := NewEgressDNS(nodeName, factory, &kube.Kube{KClient: fakeClient.KubeClient, NodeDNSInfoClient: fakeClient.NodeDNSInfoClient}, testCh)

			t.Log(res, err)
			err = res.Add([]string{test1DNSName}, "addNamespace")
			if tc.errExp {
				assert.Error(t, err)
			} else {
				res.Run(tc.syncTime)
				assert.Nil(t, err)
				for stay, timeout := true, time.After(10*time.Second); stay; {
					_, dnsResolves := res.getDNSEntry(tc.dnsName)
					if dnsResolves != nil {
						break
					}
					select {
					case <-timeout:
						stay = false
						t.Errorf("timeout: it is taking too long for the goroutine to complete")
					default:
					}

				}
			}
			if tc.testingUpdateOnQueryTime {
				for stay, timeout := true, time.After(10*time.Second); stay; {
					_, dnsResolves := res.getDNSEntry(tc.dnsName)
					if dnsResolves != nil {
						if len(dnsResolves) == 1 && dnsResolves[0].String() == test1IPv4Update {
							break
						}
					}
					select {
					case <-timeout:
						stay = false
						t.Errorf("timeout waiting for update based on ttl to fire or process")
					default:
					}

				}
			}

			close(testCh)
			mockDnsOps.AssertExpectations(t)
		})
	}
}

func TestDelete(t *testing.T) {
	mockDnsOps := new(util_mocks.DNSOps)
	util.SetDNSLibOpsMockInst(mockDnsOps)
	nodeName := "Node1"
	fakeClient := &util.OVNClientset{
		KubeClient:           fake.NewSimpleClientset(),
		EgressIPClient:       egressipfake.NewSimpleClientset(),
		EgressFirewallClient: egressfirewallfake.NewSimpleClientset(),
		NodeDNSInfoClient:    nodednsinfofake.NewSimpleClientset(),
		APIExtensionsClient:  apiextensionsfake.NewSimpleClientset(),
	}

	factory, _ := factory.NewNodeWatchFactory(fakeClient, nodeName)
	factory.InitializeEgressFirewallWatchFactory()
	test1DNSName := "www.test.com"
	test1IPv4 := "2.2.2.2"
	test1IPv6 := "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	tests := []struct {
		desc                     string
		errExp                   bool
		dnsName                  string
		configIPv4               bool
		configIPv6               bool
		testingUpdateOnQueryTime bool
		syncTime                 time.Duration
		waitForSyncLoop          bool
		dnsOpsMockHelper         []ovntest.TestifyMockHelper
	}{
		{
			desc:                     "EgressFirewall Delete functions",
			errExp:                   false,
			syncTime:                 5 * time.Minute,
			dnsName:                  test1DNSName,
			testingUpdateOnQueryTime: false,
			configIPv4:               true,
			configIPv6:               true,

			dnsOpsMockHelper: []ovntest.TestifyMockHelper{
				{"ClientConfigFromFile", []string{"string"}, []interface{}{&dns.ClientConfig{
					Servers: []string{"1.1.1.1"},
					Port:    "1234"}, nil}, 0, 1},
				{"Fqdn", []string{"string"}, []interface{}{test1DNSName}, 0, 1},
				{"Fqdn", []string{"string"}, []interface{}{test1DNSName}, 0, 1},
				{"SetQuestion", []string{"*dns.Msg", "string", "uint16"}, []interface{}{&dns.Msg{}}, 0, 1},
				{"SetQuestion", []string{"*dns.Msg", "string", "uint16"}, []interface{}{&dns.Msg{}}, 0, 1},
				{"Exchange", []string{"*dns.Client", "*dns.Msg", "string"}, []interface{}{&dns.Msg{Answer: []dns.RR{generateRR(test1DNSName, test1IPv4, "300")}}, 500 * time.Second, nil}, 0, 1},
				{"Exchange", []string{"*dns.Client", "*dns.Msg", "string"}, []interface{}{&dns.Msg{Answer: []dns.RR{generateRR(test1DNSName, test1IPv6, "300")}}, 500 * time.Second, nil}, 0, 1},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			testCh := make(chan struct{})
			config.IPv4Mode = tc.configIPv4
			config.IPv6Mode = tc.configIPv6

			for _, item := range tc.dnsOpsMockHelper {
				call := mockDnsOps.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			res, err := NewEgressDNS(nodeName, factory, &kube.Kube{KClient: fakeClient.KubeClient, NodeDNSInfoClient: fakeClient.NodeDNSInfoClient}, testCh)

			t.Log(res, err)
			err = res.Add([]string{test1DNSName}, "addNamespace")
			if tc.errExp {
				assert.Error(t, err)
			} else {
				res.Run(tc.syncTime)
				assert.Nil(t, err)
				for stay, timeout := true, time.After(10*time.Second); stay; {
					_, dnsResolves := res.getDNSEntry(tc.dnsName)
					if dnsResolves != nil {
						break
					}
					select {
					case <-timeout:
						stay = false
						t.Errorf("timeout: it is taking too long for the goroutine to complete")
					default:
					}

				}
			}
			res.Remove([]string{test1DNSName}, "addNamespace")
			for stay, timeout := true, time.After(10*time.Second); stay; {
				if _, exists := res.dnsEntries[test1DNSName]; !exists {
					break
				}
				select {
				case <-timeout:
					stay = false
					t.Errorf("timeout: dns is taking to long for the goroutine to update the dns object")
				default:
				}
			}

			assert.Equal(t, len(res.dnsEntries), 0)

			close(testCh)
			mockDnsOps.AssertExpectations(t)
		})
	}
}

// test what happens when the last dns name is deleted from the EgressFirewall
// discovered while manually testing that a segfault could happen if the entry that is
// the next to refresh is deleted before the refresh occurs
func TestDeleteWithDNSRefresh(t *testing.T) {
	mockDnsOps := new(util_mocks.DNSOps)
	util.SetDNSLibOpsMockInst(mockDnsOps)
	nodeName := "Node1"
	fakeClient := &util.OVNClientset{
		KubeClient:           fake.NewSimpleClientset(),
		EgressIPClient:       egressipfake.NewSimpleClientset(),
		EgressFirewallClient: egressfirewallfake.NewSimpleClientset(),
		NodeDNSInfoClient:    nodednsinfofake.NewSimpleClientset(),
		APIExtensionsClient:  apiextensionsfake.NewSimpleClientset(),
	}

	factory, _ := factory.NewNodeWatchFactory(fakeClient, nodeName)
	factory.InitializeEgressFirewallWatchFactory()
	test1DNSName := "www.test.com"
	test1IPv4 := "2.2.2.2"
	//test1IPv6 := "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	tests := []struct {
		desc                     string
		errExp                   bool
		dnsName                  string
		configIPv4               bool
		configIPv6               bool
		testingUpdateOnQueryTime bool
		syncTime                 time.Duration
		waitForSyncLoop          bool
		dnsOpsMockHelper         []ovntest.TestifyMockHelper
	}{
		{
			desc:                     "EgressFirewall Delete functions, avoids segfault when deleting dns names",
			errExp:                   false,
			syncTime:                 5 * time.Minute,
			dnsName:                  test1DNSName,
			testingUpdateOnQueryTime: false,
			configIPv4:               true,
			configIPv6:               false,

			dnsOpsMockHelper: []ovntest.TestifyMockHelper{
				{"ClientConfigFromFile", []string{"string"}, []interface{}{&dns.ClientConfig{
					Servers: []string{"1.1.1.1"},
					Port:    "1234"}, nil}, 0, 1},
				{"Fqdn", []string{"string"}, []interface{}{test1DNSName}, 0, 1},
				{"SetQuestion", []string{"*dns.Msg", "string", "uint16"}, []interface{}{&dns.Msg{}}, 0, 1},
				{"Exchange", []string{"*dns.Client", "*dns.Msg", "string"}, []interface{}{&dns.Msg{Answer: []dns.RR{generateRR(test1DNSName, test1IPv4, "1")}}, 1 * time.Second, nil}, 0, 1},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			testCh := make(chan struct{})
			config.IPv4Mode = tc.configIPv4
			config.IPv6Mode = tc.configIPv6

			for _, item := range tc.dnsOpsMockHelper {
				call := mockDnsOps.On(item.OnCallMethodName)
				for _, arg := range item.OnCallMethodArgType {
					call.Arguments = append(call.Arguments, mock.AnythingOfType(arg))
				}
				for _, ret := range item.RetArgList {
					call.ReturnArguments = append(call.ReturnArguments, ret)
				}
				call.Once()
			}
			res, err := NewEgressDNS(nodeName, factory, &kube.Kube{KClient: fakeClient.KubeClient, NodeDNSInfoClient: fakeClient.NodeDNSInfoClient}, testCh)

			t.Log(res, err)
			err = res.Add([]string{test1DNSName}, "addNamespace")
			if tc.errExp {
				assert.Error(t, err)
			} else {
				res.Run(tc.syncTime)
				assert.Nil(t, err)
				for stay, timeout := true, time.After(10*time.Second); stay; {
					_, dnsResolves := res.getDNSEntry(tc.dnsName)
					if dnsResolves != nil {
						break
					}
					select {
					case <-timeout:
						stay = false
						t.Errorf("timeout: it is taking too long for the goroutine to complete")
					default:
					}

				}
			}
			res.Remove([]string{test1DNSName}, "addNamespace")
			for stay, timeout := true, time.After(10*time.Second); stay; {
				if _, exists := res.dnsEntries[test1DNSName]; !exists {
					break
				}
				select {
				case <-timeout:
					stay = false
					t.Errorf("timeout: dns is taking to long for the goroutine to update the dns object")
				default:
				}
			}

			assert.Equal(t, len(res.dnsEntries), 0)
			//the segfault would occur before the below timeout
			time.Sleep(2 * time.Second)

			close(testCh)
			mockDnsOps.AssertExpectations(t)
		})
	}
}

func (e *EgressDNS) getDNSEntry(dnsName string) (map[string]struct{}, []net.IP) {
	e.lock.Lock()
	defer e.lock.Unlock()
	if dnsEntry, exists := e.dnsEntries[dnsName]; exists {
		return dnsEntry.namespaces, dnsEntry.dnsResolves
	}

	return nil, nil
}
