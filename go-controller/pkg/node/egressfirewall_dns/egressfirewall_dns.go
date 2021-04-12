package egressfirewalldns

import (
	"fmt"
	"net"
	"sync"
	"time"

	factory "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	nodednsinfo "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/nodednsinfo/v1"
	nodednsinfoapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/nodednsinfo/v1"

	errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
)

// holds the source of truth for EgressFirewall DNS names on a node
type EgressDNS struct {
	lock sync.Mutex
	// holds DNS entries globally
	dns *util.DNS
	// name of the node
	nodeName string
	// this map holds dnsNames to the dnsEntries
	dnsEntries map[string]*dnsEntry
	// allows to get object using the informer cache
	wf factory.NodeWatchFactory
	k  kube.Interface

	added          chan string
	addFinished    chan struct{}
	stopChan       chan struct{}
	controllerStop <-chan struct{}
}

type dnsEntry struct {
	// the current IP addresses the dnsName resolves to
	dnsResolves []net.IP
	namespaces  map[string]struct{} //the namespaces that this DNSName applies to
}

func NewEgressDNS(nodeName string, watchFactory factory.NodeWatchFactory, k kube.Interface, controllerStop <-chan struct{}) (*EgressDNS, error) {
	dnsInfo, err := util.NewDNS("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}

	egressDNS := &EgressDNS{
		dns:        dnsInfo,
		nodeName:   nodeName,
		dnsEntries: make(map[string]*dnsEntry),
		wf:         watchFactory,
		k:          k,

		added:          make(chan string, 1),
		addFinished:    make(chan struct{}, 1),
		stopChan:       make(chan struct{}),
		controllerStop: controllerStop,
	}

	return egressDNS, nil
}

func (e *EgressDNS) Add(dnsNames []string, namespace string) error {
	e.lock.Lock()
	defer e.lock.Unlock()
	for _, dnsName := range dnsNames {
		if _, exists := e.dnsEntries[dnsName]; !exists {
			e.dnsEntries[dnsName] = &dnsEntry{
				namespaces: map[string]struct{}{
					namespace: {},
				},
			}
			e.signalAdded(dnsName)
		} else {
			// only need to add the namespace to the struct
			e.dnsEntries[dnsName].namespaces[namespace] = struct{}{}
		}
	}
	return nil

}

//updateEntryForName takes a dnsName and creates/updates the EgressDNS's
// dnsEntries map for the given dnsName assumes that you have locked the EgressDNS object
// before calling this function
func (e *EgressDNS) updateEntryForName(dnsName string) error {
	ips := e.dns.GetIPs(dnsName)
	//TODO: if the old and new resolutions are the same should not update the nodeDNSInfo
	e.dnsEntries[dnsName].dnsResolves = ips

	resultErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		//update the nodeDNSInfo object so the master can coordinate all the nodes ip addresses
		// if the node has not reported any DNS addresses before create the nodeDNSObject
		nodeDNSInfo, err := e.wf.GetNodeDNSInfo(e.nodeName)

		existed := true
		if errors.IsNotFound(err) {
			// the object *MOST LIKELY* has not been created yet, so start making it
			nodeDNSInfo = &nodednsinfoapi.NodeDNSInfo{
				ObjectMeta: metav1.ObjectMeta{Name: e.nodeName},
			}
			existed = false
		} else if err != nil {
			return err
		}
		newNodeDNSInfo := nodeDNSInfo.DeepCopy()
		var ipStrings []string
		for _, ip := range e.dnsEntries[dnsName].dnsResolves {
			ipStrings = append(ipStrings, ip.String())
		}

		if newNodeDNSInfo.Status.DNSEntries == nil {
			newNodeDNSInfo.Status.DNSEntries = make(map[string]nodednsinfo.DNSEntry)
		}

		dnsEntry := newNodeDNSInfo.Status.DNSEntries[dnsName]
		dnsEntry.IPAddresses = ipStrings
		newNodeDNSInfo.Status.DNSEntries[dnsName] = dnsEntry

		//create or update NodeDNSInfo
		if existed {
			return e.k.UpdateNodeDNSInfo(newNodeDNSInfo)
		} else {
			_, err = e.k.CreateNodeDNSInfo(newNodeDNSInfo)
		}
		if err != nil {
			return err
		}
		return nil
	})
	if resultErr != nil {
		klog.Errorf("Error updating NodeDNSInfo %v", resultErr)
	}

	return nil
}

//Update wraps the dnsUpdate so that the functions can be mocked for testing
// make a call to the backend DNS implementation to Update the resolved IPs
// and and TTL for that address
func (e *EgressDNS) Update(dns string) (bool, error) {
	return e.dns.Update(dns)
}

// Run() spawns go-routines that handles add/update/delete of dns entries for dnsNames used in
// EgressFirewalls.
func (e *EgressDNS) Run(defaultInterval time.Duration) {
	go e.addDNSNames()
	go e.updateDNSRecord(defaultInterval)

}

// go-routine that handles adding new DNS names to the resolver, it is signaled by Add()
// which is in turn is triggered by the addition of an egressFirewall with DNS names.
// Signals the updateDNSRecord go-routine when it is finished adding a DNS so the
// durationTillNextQuery can be updated if needed
func (e *EgressDNS) addDNSNames() {
	for {
		select {
		case dnsName := <-e.added:
			func() {
				e.lock.Lock()
				defer e.lock.Unlock()
				if err := e.dns.Add(dnsName); err != nil {
					utilruntime.HandleError(err)
				}
				if err := e.updateEntryForName(dnsName); err != nil {
					utilruntime.HandleError(err)
				}
				e.signalAddFinished()
			}()
		case <-e.stopChan:
			return
		case <-e.controllerStop:
			return
		}
	}
}

// go-routine that handles periodic requiering of the dnsResolver to update
// the IP addresses that dnsNames resolve to.
// at least 1 DNS record gets updated every 30 min in the case that there is no
// TTL less then 30 minutes. Everytime an update occurs only one DNS record is
// updated. This go-routine is signaled to recompute the next query time after an
// add operation is completed.
func (e *EgressDNS) updateDNSRecord(defaultInterval time.Duration) {
	// initially set the next DNS Query to happen at the default interval
	durationTillNextQuery := defaultInterval
	var ttl time.Time
	var timeSet bool
	var dnsName string
	for {
		select {
		case <-time.After(durationTillNextQuery):
			func() {
				e.lock.Lock()
				defer e.lock.Unlock()
				if len(dnsName) > 0 && e.dnsEntries[dnsName] != nil {
					if _, err := e.Update(dnsName); err != nil {
						utilruntime.HandleError(err)
					}
					if err := e.updateEntryForName(dnsName); err != nil {
						utilruntime.HandleError(err)
					}
				}
			}()
		case <-e.addFinished:
			// after a dnsName gets added this go-routine needs to recompute how long
			// to wait before waking again
		case <-e.stopChan:
			return
		case <-e.controllerStop:
			return
		}

		// before waiting on the signals get the next time this go-routine  needs to wake up
		ttl, dnsName, timeSet = e.dns.GetNextQueryTime()
		if time.Until(ttl) > defaultInterval || !timeSet {
			durationTillNextQuery = defaultInterval
		} else {
			durationTillNextQuery = time.Until(ttl)
		}

	}
}

func (e *EgressDNS) Remove(dnsNames []string, namespace string) error {
	e.lock.Lock()
	defer e.lock.Unlock()

	resultErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// preemptivly get the NodeDNSInfo so that all the Removes can be processed at once
		nodeDNSInfo, err := e.wf.GetNodeDNSInfo(e.nodeName)
		for _, dnsName := range dnsNames {
			delete(e.dnsEntries[dnsName].namespaces, namespace)
			if len(e.dnsEntries[dnsName].namespaces) == 0 {
				delete(e.dnsEntries, dnsName)
				e.dns.Delete(dnsName)
				if err != nil {
					return err
				}
				delete(nodeDNSInfo.Status.DNSEntries, dnsName)
			}
		}
		if len(nodeDNSInfo.Status.DNSEntries) == 0 {
			klog.Infof("Deleteing NodeDNSInfo %s from the cluster", nodeDNSInfo.Name)
			return e.k.DeleteNodeDNSInfo(nodeDNSInfo.Name)
		} else {
			return e.k.UpdateNodeDNSInfo(nodeDNSInfo)
		}
	})
	if resultErr != nil {
		return fmt.Errorf("error Removing DNS names from NodeDNSInfo: %v", resultErr)
	}
	return nil

}

func (e *EgressDNS) Shutdown() {
	close(e.stopChan)
}

func (e *EgressDNS) signalAdded(dnsName string) {
	e.added <- dnsName
}

func (e *EgressDNS) signalAddFinished() {
	e.addFinished <- struct{}{}
}

// *** Functions below are used for testing purposes only ***

// returns the fields of a dnsEntry for a given name
func (e *EgressDNS) GetDNSEntry(dnsName string) ([]net.IP, []string, bool) {
	//e.lock.Lock()
	//defer e.lock.Unlock()
	var namespaces []string
	if dnsEntry, exists := e.dnsEntries[dnsName]; exists {
		for namespace := range dnsEntry.namespaces {
			namespaces = append(namespaces, namespace)
		}

		return dnsEntry.dnsResolves, namespaces, true
	}
	return nil, nil, false

}

func (e *EgressDNS) LockEgressDNS() {
	e.lock.Lock()
}

func (e *EgressDNS) UnlockEgressDNS() {
	e.lock.Unlock()
}
