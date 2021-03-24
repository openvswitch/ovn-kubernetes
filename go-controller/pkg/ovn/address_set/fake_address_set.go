package addressset

import (
	"net"
	"strings"
	"sync"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"

	"k8s.io/apimachinery/pkg/util/sets"
	utilnet "k8s.io/utils/net"

	"github.com/onsi/gomega"
)

func NewFakeAddressSetFactory() *FakeAddressSetFactory {
	return &FakeAddressSetFactory{
		sets: make(map[string]*fakeAddressSet),
	}
}

type FakeAddressSetFactory struct {
	sync.RWMutex
	// maps address set name to object
	sets map[string]*fakeAddressSet
}

// fakeFactory implements the AddressSetFactory interface
var _ AddressSetFactory = &FakeAddressSetFactory{}

// NewAddressSet returns a new address set object
func (f *FakeAddressSetFactory) NewAddressSet(name string, ips []net.IP) (AddressSet, error) {
	f.Lock()
	defer f.Unlock()
	_, ok := f.sets[name]
	gomega.Expect(ok).To(gomega.BeFalse())
	set, err := newFakeAddressSets(name, ips, f.removeAddressSet)
	if err != nil {
		return nil, err
	}
	ip4ASName, ip6ASName := MakeAddressSetName(name)
	if set.ipv4 != nil {
		f.sets[ip4ASName] = set.ipv4
	}
	if set.ipv6 != nil {
		f.sets[ip6ASName] = set.ipv6
	}
	return set, nil
}

func (f *FakeAddressSetFactory) ForEachAddressSet(iteratorFn AddressSetIterFunc) error {
	asNames := sets.String{}
	for _, set := range f.sets {
		asName := truncateSuffixFromAddressSet(set.getName())
		if asNames.Has(asName) {
			continue
		}
		asNames.Insert(asName)
		parts := strings.Split(asName, ".")
		addrSetNamespace := parts[0]
		nameSuffix := ""
		if len(parts) >= 2 {
			nameSuffix = parts[1]
		}
		iteratorFn(asName, addrSetNamespace, nameSuffix)
	}
	return nil
}

func (f *FakeAddressSetFactory) DestroyAddressSetInBackingStore(name string) error {
	if _, ok := f.sets[name]; ok {
		f.removeAddressSet(name)
		return nil
	}
	ip4ASName, ip6ASName := MakeAddressSetName(name)
	if config.IPv4Mode {
		f.removeAddressSet(ip4ASName)
	}
	if config.IPv6Mode {
		f.removeAddressSet(ip6ASName)
	}
	return nil
}

func (f *FakeAddressSetFactory) getAddressSet(name string) *fakeAddressSet {
	f.RLock()
	defer f.RUnlock()
	if as, ok := f.sets[name]; ok {
		as.Lock()
		return as
	}
	return nil
}

// removeAddressSet removes the address set from the factory
func (f *FakeAddressSetFactory) removeAddressSet(name string) {
	f.Lock()
	defer f.Unlock()
	delete(f.sets, name)
}

// ExpectNoAddressSet ensures the named address set does not exist
func (f *FakeAddressSetFactory) ExpectNoAddressSet(name string) {
	_, ok := f.sets[name]
	gomega.ExpectWithOffset(1, ok).To(gomega.BeFalse())
}

// ExpectAddressSetWithIPs ensures the named address set exists with the given set of IPs
func (f *FakeAddressSetFactory) ExpectAddressSetWithIPs(name string, ips []string) {
	var lenAddressSet int
	name4, name6 := MakeAddressSetName(name)
	as4 := f.getAddressSet(name4)
	if as4 != nil {
		defer as4.Unlock()
		lenAddressSet = lenAddressSet + len(as4.ips)
	}
	as6 := f.getAddressSet(name6)
	if as6 != nil {
		defer as6.Unlock()
		lenAddressSet = lenAddressSet + len(as6.ips)
	}

	for _, ip := range ips {
		if utilnet.IsIPv6(net.ParseIP(ip)) {
			gomega.ExpectWithOffset(1, as6).NotTo(gomega.BeNil(), "address set "+as6.name)
			gomega.ExpectWithOffset(1, as6.ips).To(gomega.HaveKey(ip), "address set "+as6.name)
		} else {
			gomega.ExpectWithOffset(1, as4).NotTo(gomega.BeNil(), "address set "+as4.name)
			gomega.ExpectWithOffset(1, as4.ips).To(gomega.HaveKey(ip), "address set "+as4.name)
		}
	}

	gomega.ExpectWithOffset(1, lenAddressSet).To(gomega.Equal(len(ips)))
}

// ExpectEmptyAddressSet ensures the named address set exists with no IPs
func (f *FakeAddressSetFactory) ExpectEmptyAddressSet(name string) {
	var lenAddressSet int
	name4, name6 := MakeAddressSetName(name)
	as4 := f.getAddressSet(name4)
	if as4 != nil {
		defer as4.Unlock()
		lenAddressSet = lenAddressSet + len(as4.ips)
	}
	as6 := f.getAddressSet(name6)
	if as6 != nil {
		defer as6.Unlock()
		lenAddressSet = lenAddressSet + len(as6.ips)
	}

	gomega.ExpectWithOffset(1, lenAddressSet).To(gomega.Equal(0))
}

// EventuallyExpectEmptyAddressSet ensures the named address set eventually exists with no IPs
func (f *FakeAddressSetFactory) EventuallyExpectEmptyAddressSet(name string) {
	// TODO ipv6
	name4, _ := MakeAddressSetName(name)
	gomega.EventuallyWithOffset(1, func() bool {
		as := f.getAddressSet(name4)
		if as == nil {
			return false
		}
		defer as.Unlock()
		return len(as.ips) == 0
	}).Should(gomega.BeTrue())
}

// EventuallyExpectNoAddressSet ensures the named address set eventually does not exist
func (f *FakeAddressSetFactory) EventuallyExpectNoAddressSet(name string) {
	gomega.Eventually(func() bool {
		f.RLock()
		defer f.RUnlock()
		_, ok := f.sets[name]
		return ok
	}).Should(gomega.BeFalse())
}

type removeFunc func(string)

type fakeAddressSet struct {
	sync.Mutex
	name      string
	hashName  string
	ips       map[string]net.IP
	destroyed bool
	removeFn  removeFunc
}

// fakeAddressSets implements the AddressSet interface
var _ AddressSet = &fakeAddressSets{}

type fakeAddressSets struct {
	sync.Mutex
	name string
	ipv4 *fakeAddressSet
	ipv6 *fakeAddressSet
}

func newFakeAddressSets(name string, ips []net.IP, removeFn removeFunc) (*fakeAddressSets, error) {
	var v4set, v6set *fakeAddressSet
	v4Ips := make([]net.IP, 0)
	v6Ips := make([]net.IP, 0)
	for _, ip := range ips {
		if utilnet.IsIPv6(ip) {
			v6Ips = append(v6Ips, ip)
		} else {
			v4Ips = append(v4Ips, ip)
		}
	}
	ip4ASName, ip6ASName := MakeAddressSetName(name)
	if config.IPv4Mode {
		v4set = newFakeAddressSet(ip4ASName, v4Ips, removeFn)
	}
	if config.IPv6Mode {
		v6set = newFakeAddressSet(ip6ASName, v6Ips, removeFn)
	}
	return &fakeAddressSets{name: name, ipv4: v4set, ipv6: v6set}, nil
}

func newFakeAddressSet(name string, ips []net.IP, removeFn removeFunc) *fakeAddressSet {
	as := &fakeAddressSet{
		name:     name,
		hashName: hashedAddressSet(name),
		ips:      make(map[string]net.IP),
		removeFn: removeFn,
	}
	for _, ip := range ips {
		as.ips[ip.String()] = ip
	}
	return as
}

func (as *fakeAddressSets) GetASHashNames() (string, string) {
	var ipv4AS string
	var ipv6AS string
	if as.ipv4 != nil {
		ipv4AS = as.ipv4.getHashName()
	}
	if as.ipv6 != nil {
		ipv6AS = as.ipv6.getHashName()
	}
	return ipv4AS, ipv6AS
}

func (as *fakeAddressSets) GetName() string {
	return as.name
}

func (as *fakeAddressSets) AddIPs(ips []net.IP) error {
	var err error
	as.Lock()
	defer as.Unlock()

	for _, ip := range ips {
		if utilnet.IsIPv6(ip) {
			err = as.ipv6.addIP(ip)
		} else {
			err = as.ipv4.addIP(ip)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (as *fakeAddressSets) SetIPs(ips []net.IP) error {
	as.Lock()
	defer as.Unlock()

	v4, v6 := splitIPsByFamily(ips)
	if as.ipv4 != nil {
		as.ipv4.setIPs(v4)
	}

	if as.ipv6 != nil {
		as.ipv6.setIPs(v6)
	}
	return nil
}

func (as *fakeAddressSets) DeleteIPs(ips []net.IP) error {
	var err error
	as.Lock()
	defer as.Unlock()

	for _, ip := range ips {
		if utilnet.IsIPv6(ip) {
			err = as.ipv6.deleteIP(ip)
		} else {
			err = as.ipv4.deleteIP(ip)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (as *fakeAddressSets) Destroy() error {
	as.Lock()
	defer as.Unlock()

	if as.ipv4 != nil {
		err := as.ipv4.destroy()
		if err != nil {
			return err
		}
	}
	if as.ipv6 != nil {
		return as.ipv6.destroy()
	}
	return nil
}

func (as *fakeAddressSet) getHashName() string {
	gomega.Expect(as.destroyed).To(gomega.BeFalse())
	return as.hashName
}

func (as *fakeAddressSet) getName() string {
	gomega.Expect(as.destroyed).To(gomega.BeFalse())
	return as.name
}

func (as *fakeAddressSet) addIP(ip net.IP) error {
	gomega.Expect(as.destroyed).To(gomega.BeFalse())
	ipStr := ip.String()
	if _, ok := as.ips[ipStr]; !ok {
		as.ips[ip.String()] = ip
	}
	return nil
}

func (as *fakeAddressSet) setIPs(ips []net.IP) {
	as.Lock()
	defer as.Unlock()
	gomega.Expect(as.destroyed).To(gomega.BeFalse())
	as.ips = make(map[string]net.IP, len(ips))
	for _, ip := range ips {
		as.ips[ip.String()] = ip
	}
}

func (as *fakeAddressSet) deleteIP(ip net.IP) error {
	as.Lock()
	defer as.Unlock()
	gomega.Expect(as.destroyed).To(gomega.BeFalse())
	delete(as.ips, ip.String())
	return nil
}

func (as *fakeAddressSet) destroyInternal() {
	gomega.Expect(as.destroyed).To(gomega.BeFalse())
	as.destroyed = true
	as.removeFn(as.name)
}

func (as *fakeAddressSet) destroy() error {
	gomega.Expect(as.destroyed).To(gomega.BeFalse())
	as.destroyInternal()
	return nil
}
