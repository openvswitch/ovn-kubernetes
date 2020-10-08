package ovn

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"
	utilnet "k8s.io/utils/net"
)

const (
	ipv4AddressSetSuffix = "_v4"
	ipv6AddressSetSuffix = "_v6"
)

type AddressSetIterFunc func(hashedName, namespace, suffix string)
type AddressSetDoFunc func(as AddressSet) error

// AddressSetFactory is an interface for managing address set objects
type AddressSetFactory interface {
	// NewAddressSet returns a new object that implements AddressSet
	// and contains the given IPs, or an error. Internally it creates
	// an address set for IPv4 and IPv6 each.
	NewAddressSet(name string, ips []net.IP) (AddressSet, error)
	// ForEachAddressSet calls the given function for each address set
	// known to the factory
	ForEachAddressSet(iteratorFn AddressSetIterFunc) error
	// DestroyAddressSetInBackingStore deletes the named address set from the
	// factory's backing store. SHOULD NOT BE CALLED for any address set
	// for which an AddressSet object has been created.
	DestroyAddressSetInBackingStore(name string) error
}

// AddressSet is an interface for address set objects
type AddressSet interface {
	// GetIPv4HashName returns the hashed name for v4 address set
	GetIPv4HashName() string
	// GetIPv6HashName returns the hashed name for v4 address set
	GetIPv6HashName() string
	// GetName returns the descriptive name of the address set
	GetName() string
	AddIPs(ip []net.IP) error
	DeleteIPs(ip []net.IP) error
	Destroy() error
}

type ovnAddressSetFactory struct {
	exec util.ExecHelper
}

// NewOvnAddressSetFactory creates a new AddressSetFactory backed by
// address set objects that execute OVN commands
func NewOvnAddressSetFactory(exec util.ExecHelper) AddressSetFactory {
	return &ovnAddressSetFactory{exec: exec}
}

// ovnAddressSetFactory implements the AddressSetFactory interface
var _ AddressSetFactory = &ovnAddressSetFactory{}

// NewAddressSet returns a new address set object
func (asf *ovnAddressSetFactory) NewAddressSet(name string, ips []net.IP) (AddressSet, error) {
	return newOvnAddressSets(asf.exec, name, ips)
}

// ForEachAddressSet will pass the unhashed address set name, namespace name
// and the first suffix in the name to the 'iteratorFn' for every address_set in
// OVN. (Unhashed address set names are of the form namespaceName[.suffix1.suffix2. .suffixN])
func (asf *ovnAddressSetFactory) ForEachAddressSet(iteratorFn AddressSetIterFunc) error {
	output, stderr, err := asf.exec.RunOVNNbctl("--format=csv", "--data=bare", "--no-heading",
		"--columns=external_ids", "find", "address_set")
	if err != nil {
		return fmt.Errorf("error reading address sets: "+
			"stdout: %q, stderr: %q err: %v", output, stderr, err)
	}

	processedAddressSets := sets.String{}
	for _, line := range strings.Split(output, "\n") {
		parts := strings.Split(line, ",")
		if len(parts) != 2 {
			continue
		}
		for _, externalID := range strings.Fields(parts[1]) {
			if !strings.HasPrefix(externalID, "name=") {
				continue
			}
			// Remove the suffix from the address set name and normalize
			addrSetName := truncateSuffixFromAddressSet(externalID[5:])
			if processedAddressSets.Has(addrSetName) {
				// We have already processed the address set. In case of dual stack we will have _v4 and _v6
				// suffixes for address sets. Since we are normalizing these two address sets through this API
				// we will process only one normalized address set name.
				break
			}
			processedAddressSets.Insert(addrSetName)
			names := strings.Split(addrSetName, ".")
			addrSetNamespace := names[0]
			nameSuffix := ""
			if len(names) >= 2 {
				nameSuffix = names[1]
			}
			iteratorFn(addrSetName, addrSetNamespace, nameSuffix)
			break
		}
	}
	return nil
}

func truncateSuffixFromAddressSet(asName string) string {
	// Legacy address set names will not have v4 or v6 suffixes.
	// truncate them for the new ones
	if strings.HasSuffix(asName, ipv4AddressSetSuffix) {
		return strings.TrimSuffix(asName, ipv4AddressSetSuffix)
	}
	if strings.HasSuffix(asName, ipv6AddressSetSuffix) {
		return strings.TrimSuffix(asName, ipv6AddressSetSuffix)
	}
	return asName
}

func (asf *ovnAddressSetFactory) DestroyAddressSetInBackingStore(name string) error {
	// We need to handle both legacy and new address sets in this method. Legacy names
	// will not have v4 and v6 suffix as they were same as namespace name. Hence we will always try to destroy
	// the address set with raw name(namespace name), v4 name and v6 name.  The method destroyAddressSet uses
	// --if-exists parameter which will take care of deleting the address set only if it exists.
	err := destroyAddressSet(asf.exec, name)
	if err != nil {
		return err
	}
	err = destroyAddressSet(asf.exec, getIPv4ASName(name))
	if err != nil {
		return err
	}
	err = destroyAddressSet(asf.exec, getIPv6ASName(name))
	return err
}

func destroyAddressSet(exec util.ExecHelper, name string) error {
	hashName := hashedAddressSet(name)
	_, stderr, err := exec.RunOVNNbctl("--if-exists", "destroy", "address_set", hashName)
	if err != nil {
		return fmt.Errorf("failed to destroy address set %q, stderr: %q, (%v)",
			hashName, stderr, err)
	}
	return nil
}

type ovnAddressSet struct {
	name     string
	exec     util.ExecHelper
	hashName string
	uuid     string
	ips      map[string]net.IP
}

type ovnAddressSets struct {
	sync.RWMutex
	name string
	ipv4 *ovnAddressSet
	ipv6 *ovnAddressSet
}

// ovnAddressSets implements the AddressSet interface
var _ AddressSet = &ovnAddressSets{}

// hash the provided input to make it a valid ovnAddressSet name.
func hashedAddressSet(s string) string {
	return hashForOVN(s)
}

func asDetail(as *ovnAddressSet) string {
	return fmt.Sprintf("%s/%s/%s", as.uuid, as.name, as.hashName)
}

func newOvnAddressSets(exec util.ExecHelper, name string, ips []net.IP) (*ovnAddressSets, error) {
	var (
		v4set, v6set *ovnAddressSet
		err          error
	)
	v4IPs := make([]net.IP, 0)
	v6IPs := make([]net.IP, 0)

	for _, ip := range ips {
		if utilnet.IsIPv6(ip) {
			v6IPs = append(v6IPs, ip)
		} else {
			v4IPs = append(v4IPs, ip)
		}
	}
	if config.IPv4Mode {
		v4set, err = newOvnAddressSet(exec, getIPv4ASName(name), v4IPs)
		if err != nil {
			return nil, err
		}
	}
	if config.IPv6Mode {
		v6set, err = newOvnAddressSet(exec, getIPv6ASName(name), v6IPs)
		if err != nil {
			return nil, err
		}
	}
	return &ovnAddressSets{name: name, ipv4: v4set, ipv6: v6set}, nil
}

func newOvnAddressSet(exec util.ExecHelper, name string, ips []net.IP) (*ovnAddressSet, error) {
	as := &ovnAddressSet{
		name:     name,
		exec:     exec,
		hashName: hashedAddressSet(name),
		ips:      make(map[string]net.IP),
	}
	for _, ip := range ips {
		as.ips[ip.String()] = ip
	}

	uuid, stderr, err := exec.RunOVNNbctl("--data=bare",
		"--no-heading", "--columns=_uuid", "find", "address_set",
		"name="+as.hashName)
	if err != nil {
		return nil, fmt.Errorf("find failed to get address set %q, stderr: %q (%v)",
			as.name, stderr, err)
	}
	as.uuid = uuid

	if uuid != "" {
		klog.V(5).Infof("New(%s) already exists; updating IPs", asDetail(as))
		// ovnAddressSet already exists in the database; just update IPs
		if err := as.setOrClear(); err != nil {
			return nil, err
		}
	} else {
		// ovnAddressSet has not been created yet. Create it.
		args := []string{
			"create",
			"address_set",
			"name=" + as.hashName,
			"external-ids:name=" + as.name,
		}
		joinedIPs := as.joinIPs()
		if len(joinedIPs) > 0 {
			args = append(args, "addresses="+joinedIPs)
		}
		as.uuid, stderr, err = exec.RunOVNNbctl(args...)
		if err != nil {
			return nil, fmt.Errorf("failed to create address set %q, stderr: %q (%v)",
				asDetail(as), stderr, err)
		}
	}

	klog.V(5).Infof("New(%s) with %v", asDetail(as), ips)

	return as, nil
}

func (as *ovnAddressSets) GetIPv4HashName() string {
	if as.ipv4 != nil {
		return as.ipv4.hashName
	}
	return ""
}

func (as *ovnAddressSets) GetIPv6HashName() string {
	if as.ipv6 != nil {
		return as.ipv6.hashName
	}
	return ""
}

func (as *ovnAddressSets) GetName() string {
	return as.name
}

func (as *ovnAddressSets) AddIPs(ips []net.IP) error {
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

func (as *ovnAddressSets) DeleteIPs(ips []net.IP) error {
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

func (as *ovnAddressSets) Destroy() error {
	as.Lock()
	defer as.Unlock()

	if as.ipv4 != nil {
		err := as.ipv4.destroy()
		if err != nil {
			return err
		}
	}
	if as.ipv6 != nil {
		err := as.ipv6.destroy()
		if err != nil {
			return err
		}
	}
	return nil
}

func (as *ovnAddressSet) joinIPs() string {
	list := make([]string, 0, len(as.ips))
	for ipStr := range as.ips {
		list = append(list, `"`+ipStr+`"`)
	}
	sort.Strings(list)
	return strings.Join(list, " ")
}

// setOrClear updates the OVN database with the address set's addresses or
// clears the address set if there are no addresses in the address set
func (as *ovnAddressSet) setOrClear() error {
	joinedIPs := as.joinIPs()
	if len(joinedIPs) > 0 {
		_, stderr, err := as.exec.RunOVNNbctl("set", "address_set", as.uuid, "addresses="+joinedIPs)
		if err != nil {
			return fmt.Errorf("failed to set address set %q, stderr: %q (%v)",
				asDetail(as), stderr, err)
		}
	} else {
		_, stderr, err := as.exec.RunOVNNbctl("clear", "address_set", as.uuid, "addresses")
		if err != nil {
			return fmt.Errorf("failed to clear address set %q, stderr: %q (%v)",
				asDetail(as), stderr, err)
		}
	}
	return nil
}

func (as *ovnAddressSet) addIP(ip net.IP) error {
	ipStr := ip.String()
	if _, ok := as.ips[ipStr]; ok {
		return nil
	}

	klog.V(5).Infof("(%s) adding IP %s to address set", asDetail(as), ipStr)

	_, stderr, err := as.exec.RunOVNNbctl("add", "address_set", as.uuid, "addresses", `"`+ipStr+`"`)
	if err != nil {
		return fmt.Errorf("failed to add IP %q to address set %q, stderr: %q (%v)",
			ip, asDetail(as), stderr, err)
	}

	as.ips[ip.String()] = ip
	return nil
}

func (as *ovnAddressSet) deleteIP(ip net.IP) error {
	ipStr := ip.String()
	if _, ok := as.ips[ipStr]; !ok {
		return nil
	}

	klog.V(5).Infof("(%s) deleting IP %s from address set", asDetail(as), ipStr)

	_, stderr, err := as.exec.RunOVNNbctl("remove", "address_set", as.uuid, "addresses", `"`+ipStr+`"`)
	if err != nil {
		return fmt.Errorf("failed to remove IP %q from address set %q, stderr: %q (%v)",
			ip, asDetail(as), stderr, err)
	}

	delete(as.ips, ipStr)
	return nil
}

func (as *ovnAddressSet) destroy() error {
	klog.V(5).Infof("destroy(%s)", asDetail(as))
	_, stderr, err := as.exec.RunOVNNbctl("--if-exists", "destroy", "address_set", as.uuid)
	if err != nil {
		return fmt.Errorf("failed to destroy address set %q, stderr: %q, (%v)",
			asDetail(as), stderr, err)
	}
	as.ips = nil
	return nil
}

func getIPv4ASName(name string) string {
	return name + ipv4AddressSetSuffix
}

func getIPv6ASName(name string) string {
	return name + ipv6AddressSetSuffix
}

func getIPv4ASHashedName(name string) string {
	return hashedAddressSet(name + ipv4AddressSetSuffix)
}

func getIPv6ASHashedName(name string) string {
	return hashedAddressSet(name + ipv6AddressSetSuffix)
}
