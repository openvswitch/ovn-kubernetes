#!/usr/bin/env bash

# always exit on errors
set -ex


export KUBECONFIG=${HOME}/admin.conf
export OVN_IMAGE=${OVN_IMAGE:-ovn-daemonset-f:pr}

kubectl_wait_pods() {
  # Check that everything is fine and running. IPv6 cluster seems to take a little
  # longer to come up, so extend the wait time.
  OVN_TIMEOUT=900s
  if [ "$KIND_IPV6_SUPPORT" == true ]; then
    OVN_TIMEOUT=1400s
  fi
  if ! kubectl wait -n ovn-kubernetes --for=condition=ready pods --all --timeout=${OVN_TIMEOUT} ; then
    echo "some pods in OVN Kubernetes are not running"
    kubectl get pods -A -o wide || true
    kubectl describe po -n ovn-kubernetes
    exit 1
  fi
  if ! kubectl wait -n kube-system --for=condition=ready pods --all --timeout=300s ; then
    echo "some pods in the system are not running"
    kubectl get pods -A -o wide || true
    kubectl describe po -A
    exit 1
  fi
}


run_kubectl() {
  local retries=0
  local attempts=10
  while true; do
    if kubectl "$@"; then
      break
    fi

    ((retries += 1))
    if [[ "${retries}" -gt ${attempts} ]]; then
      echo "error: 'kubectl $*' did not succeed, failing"
      exit 1
    fi
    echo "info: waiting for 'kubectl $*' to succeed..."
    sleep 1
  done
}


install_ovn_image() {
  kind load docker-image "${OVN_IMAGE}" --name "${KIND_CLUSTER_NAME}"
}

kubectl_wait_for_upgrade(){
    # waits until new image is updated into all relevant pods
    count=0
    while [ $count -lt 4 ];
    do
        echo "waiting for ovnkube-master and ovnkube-node to have new image, ${OVN_IMAGE}, sleeping 30 seconds"
        # sleep 30
        count=$(run_kubectl  get pods --all-namespaces -o=jsonpath='{range .items[*]}{"\n"}{.metadata.name}{":\t"}{range .spec.containers[*]}{.image}{", "}{end}{end}'|grep -c ${OVN_IMAGE})
        echo "Currently count is $count, expected 4"
    done;

}

## This script is responsible to upgrade ovn daemonsets to run new pods with image built from a PR
install_ovn_image
run_kubectl set image daemonsets.apps ovnkube-node ovnkube-node="${OVN_IMAGE}" ovs-metrics-exporter="${OVN_IMAGE}"  ovn-controller="${OVN_IMAGE}" -n ovn-kubernetes

kubectl_wait_pods

run_kubectl set image deploy  ovnkube-master ovn-northd="${OVN_IMAGE}" nbctl-daemon="${OVN_IMAGE}" ovnkube-master="${OVN_IMAGE}" -n ovn-kubernetes

kubectl_wait_pods

kubectl_wait_for_upgrade

run_kubectl describe ds ovnkube-node -n ovn-kubernetes

run_kubectl describe deployments.apps ovnkube-master -n ovn-kubernetes
