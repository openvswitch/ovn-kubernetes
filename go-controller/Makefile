OUT_DIR = _output
export OUT_DIR
PREFIX ?= ${DESTDIR}/usr
BINDIR ?= ${PREFIX}/bin
CNIBINDIR ?= ${DESTDIR}/opt/cni/bin
GCFLAGS ?=
export GCFLAGS
PKGS ?=
GOPATH ?= $(shell go env GOPATH)
TEST_REPORT_DIR?=$(CURDIR)/_artifacts
export TEST_REPORT_DIR

.PHONY: all build check test

# Example:
#   make
#   make all
#   make all GCFLAGS="-N -l"
#       (disables compiler optimization and inlining to aid source debugging tools
#        like delve)


all build:
	hack/build-go.sh cmd/ovnkube cmd/ovn-k8s-cni-overlay cmd/ovn-kube-util cmd/ovn-k8s-cni-smart-nic hybrid-overlay/cmd/hybrid-overlay-node

windows:
	WINDOWS_BUILD="yes" hack/build-go.sh hybrid-overlay/cmd/hybrid-overlay-node

check test:
	hack/test-go.sh ${PKGS}

codegen:
	hack/update-codegen.sh

install:
	install -D -m 755 ${OUT_DIR}/go/bin/ovnkube ${BINDIR}/
	install -D -m 755 ${OUT_DIR}/go/bin/ovn-kube-util ${BINDIR}/
	install -D -m 755 ${OUT_DIR}/go/bin/ovn-k8s-cni-overlay -t ${CNIBINDIR}/
	install -D -m 755 ${OUT_DIR}/go/bin/ovn-k8s-cni-smart-nic -t ${CNIBINDIR}/

clean:
	rm -rf ${OUT_DIR}
	rm -rf ${TEST_REPORT_DIR}

.PHONY: install.tools lint gofmt

install.tools:
	curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | bash -s -- -b ${GOPATH}/bin

lint:
	@GOPATH=${GOPATH} ./hack/lint.sh

gofmt:
	@./hack/verify-gofmt.sh
