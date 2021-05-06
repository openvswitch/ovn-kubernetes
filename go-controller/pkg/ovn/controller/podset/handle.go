package podset

import (
	"net"

	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
)

// functions that actually process changes.

// handleNamespaceUpdate re-syncs any PodSets that are newly selected or de-selected
// by the namespace changing labels (or coming in to existence)
func (psc *PodSetController) handleNamespaceUpdate(ns *v1.Namespace) error {
	psc.podSetsLock.RLock()
	defer psc.podSetsLock.RUnlock()

	newPodSets := psc.setsForNamespace(ns)

	oldPodSets := sets.String{}
	for psName, ps := range psc.podSets {
		if ps.hasNamespace(ns.Name) {
			oldPodSets.Insert(psName)
		}
	}

	addPodSets := newPodSets.Difference(oldPodSets)
	removePodSets := oldPodSets.Difference(newPodSets)

	errs := []error{}

	klog.V(5).Infof("Syncing namespace %s - adding to %d and removing from %d PodSets",
		ns.Name, addPodSets.Len(), removePodSets.Len())

	// sync any actually-new and actually-stale podsets
	for psName := range addPodSets {
		if err := psc.syncPodSet(psc.podSets[psName]); err != nil {
			errs = append(errs, err)
		}
	}
	for psName := range removePodSets {
		if err := psc.syncPodSet(psc.podSets[psName]); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.NewAggregate(errs)
	}
	return nil
}

// handleNamespaceDelete sync any PodSets that previously selected a namespace
func (psc *PodSetController) handleNamespaceDelete(nsName string) error {
	psc.podSetsLock.RLock()
	defer psc.podSetsLock.RUnlock()

	oldPodSets := sets.String{}
	for psName, ps := range psc.podSets {
		if ps.hasNamespace(nsName) {
			oldPodSets.Insert(psName)
		}
	}

	klog.V(5).Infof("Deleting namespace %s from %d PodSets", nsName, oldPodSets.Len())
	errs := []error{}
	for psName := range oldPodSets {
		if err := psc.syncPodSet(psc.podSets[psName]); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.NewAggregate(errs)
	}
	return nil
}

// AddPod is called by the Pod controller, so we can pre-add a pod before
// the apiserver gets to it
func (psc *PodSetController) AddPodDirectly(pod *v1.Pod, ips []net.IP) error {
	psc.podSetsLock.RLock()
	defer psc.podSetsLock.RUnlock()

	podSetNames, err := psc.setsForPod(pod)
	if err != nil {
		return err
	}

	errs := []error{}

	klog.V(5).Infof("Adding pod %s/%s directly to %d PodSets", pod.Namespace, pod.Name, podSetNames.Len())

	for psName := range podSetNames {
		ps := psc.podSets[psName]
		if err := ps.updatePod(pod, ips); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.NewAggregate(errs)
	}

	return nil
}

// handlePodUpdate applies any changes to pods:
// - any podSets that no longer contain a pod will have it removed
// - any podSets that now contain a pod will have it added
// - if IP addresses change, that change will be applied
func (psc *PodSetController) handlePodUpdate(pod *v1.Pod) error {
	psc.podSetsLock.RLock()
	defer psc.podSetsLock.RUnlock()

	oldPodSets := sets.String{}
	// find all podsets this pod is in
	for name, ps := range psc.podSets {
		if ps.hasPod(pod.Namespace, pod.Name) {
			oldPodSets.Insert(name)
		}
	}

	newPodSets, err := psc.setsForPod(pod)
	if err != nil {
		return err
	}

	// remove pod from old - new
	removePodSets := oldPodSets.Difference(newPodSets)

	klog.V(5).Infof("Syncing pod %s/%s to %d new/existing and %d stale PodSets",
		pod.Namespace, pod.Name, newPodSets.Len(), removePodSets.Len())

	errs := []error{}

	for psName := range removePodSets {
		ps := psc.podSets[psName]
		if err := ps.removePod(pod.Namespace, pod.Name); err != nil {
			errs = append(errs, err)
		}
	}

	// add pod to all containing PodSets, even if they didn't change
	// just in case IPs changed (though unlikely)
	for psName := range newPodSets {
		ps := psc.podSets[psName]
		if err := ps.updatePod(pod, nil); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.NewAggregate(errs)
	}

	return nil
}

// handlePodDelete deletes a pod from any sets that already contain it.
func (psc *PodSetController) handlePodDelete(namespace, name string) error {
	klog.V(5).Infof("PodSetController: handlePodDelete %s %s", namespace, name)

	psc.podSetsLock.RLock()
	defer psc.podSetsLock.RUnlock()

	oldPodSets := sets.String{}
	// find all podsets this pod is in
	for psName, ps := range psc.podSets {
		if ps.hasPod(namespace, name) {
			oldPodSets.Insert(psName)
		}
	}

	klog.V(5).Infof("PodSetController: Deleting pod %s/%s from %d podSets", namespace, name, oldPodSets.Len())
	errs := []error{}

	for psName := range oldPodSets {
		ps := psc.podSets[psName]
		if err := ps.removePod(namespace, name); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.NewAggregate(errs)
	}

	return nil
}
