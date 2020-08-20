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
GO_DOCKER_IMG = quay.io/giantswarm/golang:1.15.7
# CONTAINER_RUNNABLE determines if the tests can be run inside a container. It checks to see if
# podman/docker is installed on the system.
PODMAN ?= $(shell podman -v > /dev/null 2>&1; echo $$?)
ifeq ($(PODMAN), 0)
CONTAINER_RUNTIME=podman
else
CONTAINER_RUNTIME=docker
endif
CONTAINER_RUNNABLE ?= $(shell $(CONTAINER_RUNTIME) -v > /dev/null 2>&1; echo $$?)

.PHONY: all build check test

# Example:
#   make
#   make all
#   make all GCFLAGS="-N -l"
#       (disables compiler optimization and inlining to aid source debugging tools
#        like delve)

all build:
	hack/build-go.sh  cmd/ovnkube-admission-controller cmd/ovnkube cmd/ovn-k8s-cni-overlay cmd/ovn-kube-util hybrid-overlay/cmd/hybrid-overlay-node cmd/ovndbchecker cmd/ovnkube-trace

windows:
	WINDOWS_BUILD="yes" hack/build-go.sh hybrid-overlay/cmd/hybrid-overlay-node

# Note: `--security-opt label=disable` option is required on systems where SELinux is enabled for `podman` to successfully run the
# tests in a container. Refer: https://www.projectatomic.io/blog/2016/03/dwalsh_selinux_containers/ for additional context
check test:
ifeq ($(CONTAINER_RUNNABLE), 0)
	$(CONTAINER_RUNTIME) run -it --rm --security-opt label=disable --cap-add=NET_ADMIN --cap-add=SYS_ADMIN -v $(shell dirname $(PWD)):/go/src/github.com/ovn-org/ovn-kubernetes -w /go/src/github.com/ovn-org/ovn-kubernetes/go-controller -e COVERALLS=${COVERALLS} -e GINKGO_FOCUS="${GINKGO_FOCUS}" $(GO_DOCKER_IMG) sh -c "RACE=1 DOCKER_TEST=1 COVERALLS=${COVERALLS} hack/test-go.sh focus \"${GINKGO_FOCUS}\" ${PKGS}"
else
	RACE=1 hack/test-go.sh ${PKGS}
endif

codegen:
	hack/update-codegen.sh

install:
	install -D -m 755 ${OUT_DIR}/go/bin/ovnkube ${BINDIR}/
	install -D -m 755 ${OUT_DIR}/go/bin/ovn-kube-util ${BINDIR}/
	install -D -m 755 ${OUT_DIR}/go/bin/ovn-k8s-cni-overlay -t ${CNIBINDIR}/
	install -D -m 755 ${OUT_DIR}/go/bin/ovndbchecker ${BINDIR}/

clean:
	rm -rf ${OUT_DIR}
	rm -rf ${TEST_REPORT_DIR}

.PHONY: install.tools lint gofmt

install.tools:
	curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | bash -s -- -b ${GOPATH}/bin

lint:
ifeq ($(CONTAINER_RUNNABLE), 0)
	@GOPATH=${GOPATH} ./hack/lint.sh $(CONTAINER_RUNTIME)
else
	echo "linter can only be run within a container since it needs a specific golangci-lint version"
endif

gofmt:
ifeq ($(CONTAINER_RUNNABLE), 0)
	$(CONTAINER_RUNTIME) run -it --rm --security-opt label=disable -v $(shell dirname $(PWD)):/go/src/github.com/ovn-org/ovn-kubernetes -w /go/src/github.com/ovn-org/ovn-kubernetes/go-controller $(GO_DOCKER_IMG) hack/verify-gofmt.sh
else
	@./hack/verify-gofmt.sh
endif
