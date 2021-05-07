# Package related
PACKAGE=sriovnet
ORG_PATH=github.com/Mellanox
REPO_PATH=$(ORG_PATH)/$(PACKAGE)
GOPATH=$(CURDIR)/.gopath
GOBIN =$(CURDIR)/bin
BASE=$(GOPATH)/src/$(REPO_PATH)
GOFILES=$(shell find . -name "*.go" | grep -vE "(\/vendor\/)|(_test.go)")
PKGS=$(or $(PKG),$(shell cd $(BASE) && env GOPATH=$(GOPATH) $(GO) list ./... | grep -v "^$(PACKAGE)/vendor/"))
TESTPKGS = $(shell env GOPATH=$(GOPATH) $(GO) list -f '{{ if or .TestGoFiles .XTestGoFiles }}{{ .ImportPath }}{{ end }}' $(PKGS))

export GOPATH

# Go tools
GO      = go
GOLANGCI_LINT = $(GOBIN)/golangci-lint
# golangci-lint version should be updated periodically
# we keep it fixed to avoid it from unexpectedly failing on the project
# in case of a version bump
GOLANGCI_LINT_VER = v1.39.0
TIMEOUT = 15
Q = $(if $(filter 1,$V),,@)

.PHONY: all
all: lint test build

$(GOBIN):
	@mkdir -p $@

$(BASE): ; $(info  setting GOPATH...)
	@mkdir -p $(dir $@)
	@ln -sf $(CURDIR) $@

build: $(GOFILES) 
	@CGO_ENABLED=0 $(GO) build -v

# Tools

$(GOLANGCI_LINT): ; $(info  building golangci-lint...)
	$Q curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOBIN) $(GOLANGCI_LINT_VER)

GOVERALLS = $(GOBIN)/goveralls
$(GOBIN)/goveralls:  $(BASE)  $(GOBIN) ; $(info  building goveralls...)
	$Q go get github.com/mattn/goveralls

# Tests

.PHONY: lint
lint: $(BASE) $(GOLANGCI_LINT) ; $(info  running golangci-lint...) @ ## Run golangci-lint
	$Q mkdir -p $(BASE)/test
	$Q cd $(BASE) && ret=0 && \
		test -z "$$($(GOLANGCI_LINT) run | tee $(BASE)/test/lint.out)" || ret=1 ; \
		cat $(BASE)/test/lint.out ; rm -rf $(BASE)/test ; \
	 exit $$ret


.PHONY: test tests
test: $(BASE) ; $(info  running unit tests...) @ ## Run unit tests
	$Q cd $(BASE) && $(GO) test -timeout $(TIMEOUT)s $(ARGS) ./...

tests: test lint ;

COVERAGE_MODE = count
.PHONY: test-coverage test-coverage-tools
test-coverage-tools: $(GOVERALLS)
test-coverage: COVERAGE_DIR := $(CURDIR)/test
test-coverage: test-coverage-tools $(BASE) ; $(info  running coverage tests...) @ ## Run coverage tests
	$Q cd $(BASE); $(GO) test -covermode=$(COVERAGE_MODE) -coverprofile=sriovnet.cover ./...

# Misc

.PHONY: clean
clean: ; $(info  Cleaning...)	 @ ## Cleanup everything
	@rm -rf $(GOPATH)
	@rm -rf  test

.PHONY: help
help: ## Show this message
	@grep -E '^[ a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
