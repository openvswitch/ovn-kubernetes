#!/usr/bin/env bash

set -ex

pushd e2e
go mod download
popd

export KUBERNETES_CONFORMANCE_TEST=y
export KUBECONFIG=${HOME}/admin.conf
export MASTER_NAME=${KIND_CLUSTER_NAME}-control-plane
export NODE_NAMES=${MASTER_NAME}
export KIND_INSTALL_INGRESS=${KIND_INSTALL_INGRESS}

sed -E -i 's/"\$\{ginkgo\}" "\$\{ginkgo_args\[\@\]\:\+\$\{ginkgo_args\[\@\]\}\}" "\$\{e2e_test\}"/pushd \$GITHUB_WORKSPACE\/test\/e2e\nGO111MODULE=on "\$\{ginkgo\}" "\$\{ginkgo_args\[\@\]\:\+\$\{ginkgo_args\[\@\]\}\}"/' ${GOPATH}/src/k8s.io/kubernetes/hack/ginkgo-e2e.sh

pushd ${GOPATH}/src/k8s.io/kubernetes
kubetest --provider=local --deployment=kind --kind-cluster-name=kind-ovn --test --test_args='--disable-log-dump=false'
popd
