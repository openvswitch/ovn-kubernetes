package podset

import (
	"fmt"
	"net"
	"sync"

	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
)

// PodSet represents a union of 1 or more pod + namespace selectors, applied to an
// AddressSet in OVN.
type PodSet struct {
	sync.Mutex

	// synced is true if we've ever applied this PodSet to nbdb and thus can
	// apply deltas. Otherwise, we need to re-compute and apply.
	synced bool

	name string // internal; used for keying

	// addressSet is the destination address set for the pod
	addressSet addressset.AddressSet

	// cache of ips->pods. need this for two reasons: want to avoid
	// unnecessary ovn updates, as well as handling the case where
	// somehow two pods have the same ip.
	podIPs map[string]sets.String

	// list of pods already synced to this set; used for deletion
	pods sets.String

	// namepaces is the set of namespace names that we currently understand to match this set
	// used for making pod selection more efficient as well as identifying PodSets that need
	// to be resynced when a namespace is deleted.
	namespaces sets.String

	// Selectors are the list of desired pods in this PodSet
	selectors []Selector
}

type Selector struct {
	// NamespaceName selects a namespace by name directly
	NamespaceName string

	// NamespaceSelector and PodSelector are AND'd together - a pod must match both.
	// If no PodSelector is supplied, it is defaulted to "any".
	NamespaceSelector labels.Selector
	PodSelector       labels.Selector

	// pre-compute the list of namespaces this applies to, so we can efficiently determine
	// pod membership
	namespaces sets.String
}

// matchesPod evaluates if this pod mactches a given selector
func (s *Selector) matchesPod(pod *v1.Pod) bool {
	return s.namespaces.Has(pod.Namespace) && s.PodSelector.Matches(
		labels.Set(pod.Labels))
}

// matches checks to see if a given pod matches this pod / pod + namespace selector
func (ps *PodSet) matchesPod(pod *v1.Pod) bool {
	ps.Lock()
	defer ps.Unlock()

	// shortcut - don't bother to evaluate selectors if the namespace is excluded
	if !ps.namespaces.Has(pod.Namespace) {
		return false
	}

	for _, sel := range ps.selectors {
		if sel.matchesPod(pod) {
			return true
		}
	}
	return false
}

// hasPod returns true if a given pod has already been added to the PodSet
func (ps *PodSet) hasPod(namespace, name string) bool {
	ps.Lock()
	defer ps.Unlock()
	return ps.pods.Has(types.NamespacedName{Namespace: namespace, Name: name}.String())
}

// hasNamespace returns true if a given ns has already been added to the PodSet
func (ps *PodSet) hasNamespace(nsName string) bool {
	ps.Lock()
	defer ps.Unlock()
	return ps.namespaces.Has(nsName)
}

// setsForPod finds all PodSets that match a given pod.
// TODO: this is somewhat inefficient. Lots of ways to make this faster.
// - hash podsets by namespaces, so we can do direct lookups
// - consider selector memoization
//
// Note: callers should already hold at least the read lock.
func (psc *PodSetController) setsForPod(pod *v1.Pod) (sets.String, error) {
	out := sets.String{}

	for name, ps := range psc.podSets {
		if ps.matchesPod(pod) {
			out.Insert(name)
		}
	}

	return out, nil
}

// setsForNamespace returns any podsets that match a given namespace
// note: callers should already hold the read lock
func (psc *PodSetController) setsForNamespace(ns *v1.Namespace) sets.String {
	out := sets.String{}

	for name, ps := range psc.podSets {
		ps.Lock()
		for _, selector := range ps.selectors {
			// don't need to lock here, since these values are never written after
			// initialization
			if selector.NamespaceName == ns.Name {
				out.Insert(name)
				break
			}
			if selector.NamespaceName == "" && selector.NamespaceSelector.Matches(labels.Set(ns.Labels)) {
				out.Insert(name)
				break
			}
		}
		ps.Unlock()
	}

	return out
}

// syncPodSet computes the list of pods that apply to a specific PodSet and applies
// it down to the address set.
func (psc *PodSetController) syncPodSet(ps *PodSet) error {
	ps.Lock()
	defer ps.Unlock()

	// Build list of namespaces in the podset
	// Either the name or the label-selector must be set
	ps.namespaces = sets.String{}
	for i := range ps.selectors {
		ps.selectors[i].namespaces = sets.String{}
		selector := ps.selectors[i]

		if selector.NamespaceName != "" {
			selector.namespaces.Insert(selector.NamespaceName)
		} else {
			namespaces, err := psc.namespaceLister.List(selector.NamespaceSelector)
			if err != nil {
				return fmt.Errorf("failed to list podset %s namespaces: %w", ps.name, err)
			}

			for _, namespace := range namespaces {
				selector.namespaces.Insert(namespace.Name)
			}
		}

		ps.namespaces.Insert(selector.namespaces.UnsortedList()...)
	}

	// Find all pods that are in the set
	pods := []*v1.Pod{}

	for _, selector := range ps.selectors {
		for _, ns := range selector.namespaces.List() {
			p, err := psc.podLister.Pods(ns).List(selector.PodSelector)
			if err != nil {
				return fmt.Errorf("failed to list podset %s pods: %w", ps.name, err)
			}
			pods = append(pods, p...)
		}
	}

	// find all IPs for the pods
	podIPs := make([]net.IP, 0, len(pods))
	for _, pod := range pods {
		ips, err := util.GetAllPodIPs(pod)
		if err != nil {
			return err
		}
		podIPs = append(podIPs, ips...)

	}

	// apply IPs to OVN
	klog.V(5).Infof("Setting PodSet %s with %d IPs %v", ps.name, len(podIPs), podIPs)
	if err := ps.addressSet.SetIPs(podIPs); err != nil {
		return fmt.Errorf("failed to sync PodSet %s: %w", ps.name, err)
	}

	// build ip -> pod(s) registration
	ps.podIPs = map[string]sets.String{}
	ps.pods = sets.String{}
	for _, pod := range pods {
		ps.pods.Insert(podKey(pod))

		ips, _ := util.GetAllPodIPs(pod)
		for _, ip := range ips {
			if set := ps.podIPs[ip.String()]; set != nil {
				set.Insert(podKey(pod))
			} else {
				ps.podIPs[ip.String()] = sets.NewString(podKey(pod))
			}
		}
	}

	ps.synced = true

	return nil
}

// updatePod adds or updates a pod in the PodSet.
// If the pod's IPs have changed, it will compute the delta.
//
// If the list of IPs is already known (e.g. while a pod is being added),
// ipsOverride can be passed. Otherwise, the IPs are taken from the Pod object.
func (ps *PodSet) updatePod(pod *v1.Pod, ipsOverride []net.IP) error {
	ps.Lock()
	defer ps.Unlock()

	// if we haven't synced, then don't even do anything
	if !ps.synced {
		return nil
	}

	podIPs := ipsOverride
	if len(ipsOverride) == 0 {
		var err error
		podIPs, err = util.GetAllPodIPs(pod)
		if err != nil {
			return err
		}
	}

	// compute the delta: find new ips for this pod, as well as any old ips
	// this pod no longer has.

	// ips that are new to the **podset and the pod**
	ipsToAdd := make([]net.IP, 0, len(podIPs))
	for _, ip := range podIPs {
		if _, ok := ps.podIPs[ip.String()]; !ok {
			ipsToAdd = append(ipsToAdd, ip)
		}
	}

	// stale ips
	oldPodIPs := []string{}
	for ip, set := range ps.podIPs {
		if set.Has(podKey(pod)) {
			// check to see if pod stil has ips
			found := false
			for _, podIP := range podIPs {
				if podIP.String() == ip {
					found = true
					break
				}
			}

			if !found { // not in list of new ips
				oldPodIPs = append(oldPodIPs, ip)
			}
		}
	}

	// if we have new IPs, add them to OVN.
	if len(ipsToAdd) > 0 {
		if err := ps.addressSet.AddIPs(ipsToAdd); err != nil {
			return err
		}
	}

	ps.pods.Insert(podKey(pod))

	// associate all pod IPS with this pod
	for _, ip := range podIPs {
		if set := ps.podIPs[ip.String()]; set != nil {
			set.Insert(podKey(pod))
		} else {
			ps.podIPs[ip.String()] = sets.NewString(podKey(pod))
		}
	}

	// remove this pod from any old ips, deleting from OVN any now-orphaned IPs
	ipsToDelete := []net.IP{}
	for _, oldIP := range oldPodIPs {
		set := ps.podIPs[oldIP]
		set.Delete(podKey(pod))
		if set.Len() == 0 {
			delete(ps.podIPs, oldIP)
			ipsToDelete = append(ipsToDelete, net.ParseIP(oldIP))
		}
	}

	if err := ps.addressSet.DeleteIPs(ipsToDelete); err != nil {
		return fmt.Errorf("failed to delete stale pod IPs: %w", err)
	}

	return nil
}

// removePod removes a given pod from an ovn address set
func (ps *PodSet) removePod(namespace, name string) error {
	ps.Lock()
	defer ps.Unlock()

	if !ps.synced {
		return nil
	}

	key := types.NamespacedName{Namespace: namespace, Name: name}.String()

	// find ips that contain this pod, and ips that contain
	// only this pod
	ipsToDelete := []net.IP{}
	ipsToUnset := []string{}
	for ip, set := range ps.podIPs {
		if set.Has(key) {
			ipsToUnset = append(ipsToUnset, ip)
			if set.Len() == 1 {
				ipsToDelete = append(ipsToDelete, net.ParseIP(ip))
			}
		}
	}

	// delete ips that are now no longer in the set
	if err := ps.addressSet.DeleteIPs(ipsToDelete); err != nil {
		return err
	}

	// bookkeeping: clear this pod from ip sets, removing any ips
	// that are no longer associated with any pods
	for _, ip := range ipsToUnset {
		set := ps.podIPs[ip]
		set.Delete(key)
		if set.Len() == 0 {
			delete(ps.podIPs, ip)
		}
	}

	ps.pods.Delete(key)

	return nil
}

func podKey(pod *v1.Pod) string {
	return types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}.String()
}
