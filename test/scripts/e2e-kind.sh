#!/usr/bin/env bash

set -ex

SHARD=$1

groomTestList() {
	echo $(echo "${1}" | sed -e '/^\($\|#\)/d' -e 's/ /\\s/g' | tr '\n' '|' | sed -e 's/|$//')
}

SKIPPED_TESTS="
# PERFORMANCE, DISRUPTIVE, OR UNRELATED TESTS: NOT WANTED FOR CI
Networking IPerf IPv[46]
\[Feature:PerformanceDNS\]
Disruptive
DisruptionController
\[sig-apps\] CronJob
\[sig-storage\]

# FEATURES NOT AVAILABLE IN OUR CI ENVIRONMENT
\[Feature:Federation\]
should have ipv4 and ipv6 internal node ip
should have ipv4 and ipv6 node podCIDRs

# TESTS THAT ASSUME KUBE-PROXY
kube-proxy
should set TCP CLOSE_WAIT timeout

# TO BE IMPLEMENTED: https://github.com/ovn-org/ovn-kubernetes/issues/819
Services.+session affinity

# NOT IMPLEMENTED; SEE DISCUSSION IN https://github.com/ovn-org/ovn-kubernetes/pull/1225
named port.+\[Feature:NetworkPolicy\]

# TO BE FIXED BY https://github.com/kubernetes/kubernetes/pull/93119
GCE

# Clean up SCTP tests https://github.com/kubernetes/kubernetes/issues/96717
\[Feature:SCTP\]

# https://github.com/ovn-org/ovn-kubernetes/issues/1907
service.kubernetes.io/headless

# TO BE FIXED BY https://github.com/kubernetes/kubernetes/pull/95351
should resolve connection reset issue #74839

# Broken in shared gw mode
service endpoints using hostNetwork

# api flakes
sig-api-machinery

# ???
\[Feature:NoSNAT\]
Services.+(ESIPP|cleanup finalizer)
configMap nameserver
ClusterDns \[Feature:Example\]
should set default value on new IngressClass
"

IPV4_ONLY_TESTS="
# Limit the IPv4 related test to IPv4 only deployments
#  See: https://github.com/leblancd/kube-v6-test
\[Feature:Networking-IPv4\]

# The following tests currently fail for IPv6 only, but should be passing.
# They will be removed as they are resolved.

# See: https://github.com/ovn-org/ovn-kubernetes/issues/1683
IPBlock.CIDR and IPBlock.Except

# shard-n Tests
#  See: https://github.com/kubernetes/kubernetes/pull/94136
Network.+should resolve connection reset issue

# shard-np Tests
#  See: https://github.com/ovn-org/ovn-kubernetes/issues/1517
NetworkPolicy.+should allow egress access to server in CIDR block
"
IPV6_ONLY_TESTS="
# Limit the IPv6 related tests to IPv6 only deployments
#  See: https://github.com/leblancd/kube-v6-test
\[Feature:Networking-IPv6\]
"

DUALSTACK_ONLY_TESTS="
\[Feature:.*DualStack.*\]
"

# Github CI doesn´t offer IPv6 connectivity, so always skip IPv6 only tests.
#  See: https://github.com/ovn-org/ovn-kubernetes/issues/1522
SKIPPED_TESTS=$SKIPPED_TESTS$IPV6_ONLY_TESTS

# IPv6 Only, skip any IPv4 Only Tests
if [ "$KIND_IPV4_SUPPORT" == false ] && [ "$KIND_IPV6_SUPPORT" == true ]; then
	echo "IPv6 Only"
	SKIPPED_TESTS=$SKIPPED_TESTS$IPV4_ONLY_TESTS
fi

# If not DualStack, skip DualStack tests
if [ "$KIND_IPV4_SUPPORT" == false ] || [ "$KIND_IPV6_SUPPORT" == false ]; then
	SKIPPED_TESTS=$SKIPPED_TESTS$DUALSTACK_ONLY_TESTS
fi

SKIPPED_TESTS="$(groomTestList "${SKIPPED_TESTS}")"

# if we set PARALLEL=true, skip serial test
if [ "${PARALLEL:-false}" = "true" ]; then
  export GINKGO_PARALLEL=y
  export GINKGO_PARALLEL_NODES=20
  SKIPPED_TESTS="${SKIPPED_TESTS}|\\[Serial\\]"
fi

case "$SHARD" in
	shard-network)
		FOCUS="\\[sig-network\\]"
		;;
	shard-conformance)
		FOCUS="\\[Conformance\\]|\\[sig-network\\]"
		;;
	shard-test)
		FOCUS=$(echo ${@:2} | sed 's/ /\\s/g')
		;;
	*)
		echo "unknown shard"
		exit 1
	;;
esac

# setting this env prevents ginkgo e2e from trying to run provider setup
export KUBERNETES_CONFORMANCE_TEST='y'
# setting these is required to make RuntimeClass tests work ... :/
export KUBE_CONTAINER_RUNTIME=remote
export KUBE_CONTAINER_RUNTIME_ENDPOINT=unix:///run/containerd/containerd.sock
export KUBE_CONTAINER_RUNTIME_NAME=containerd
# FIXME we should not tolerate flakes
# but until then, we retry the test in the same job
# to stop PR retriggers for totally broken code
export FLAKE_ATTEMPTS=5
export NUM_NODES=20
# Kind clusters are three node clusters
export NUM_WORKER_NODES=3
ginkgo --nodes=${NUM_NODES} \
	--focus=${FOCUS} \
	--skip=${SKIPPED_TESTS} \
	--flakeAttempts=${FLAKE_ATTEMPTS} \
	/usr/local/bin/e2e.test \
	-- \
	--kubeconfig=${HOME}/admin.conf \
	--provider=local \
	--dump-logs-on-failure=false \
	--report-dir=${E2E_REPORT_DIR}	\
	--disable-log-dump=true \
	--num-nodes=${NUM_WORKER_NODES}
