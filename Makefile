MODULES=$(shell find . -mindepth 1 -maxdepth 4 -type f -name 'go.mod' | cut -c 3- | sed 's|/[^/]*$$||' | sort -u | tr / :)
root_dir=$(shell git rev-parse --show-toplevel)

PKG?=$*
GO_TEST_ARGS ?= -race

# Architecture to use envtest with
ENVTEST_ARCH ?= amd64

# Kubernetes versions to use envtest with
ENVTEST_KUBERNETES_VERSION?=1.26

# Use $GOBIN from the environment if set, otherwise use ./bin
ifeq (,$(shell go env GOBIN))
GOBIN=$(root_dir)/bin
else
GOBIN=$(shell go env GOBIN)
endif

all: tidy generate fmt vet

tidy:
	$(MAKE) $(addprefix tidy-, $(MODULES))

tidy-%:
	cd $(subst :,/,$*); go mod tidy -compat=1.19

fmt:
	$(MAKE) $(addprefix fmt-, $(MODULES))

fmt-%:
	cd $(subst :,/,$*); go fmt ./...

vet:
	$(MAKE) $(addprefix vet-, $(MODULES))

vet-%:
	cd $(subst :,/,$*); go vet ./... ;\

# Run tests for all modules
test:
	$(MAKE) $(addprefix test-, $(MODULES))

test-%: tidy-% generate-% fmt-% vet-% install-envtest
	cd $(subst :,/,$*); go test ./... $(GO_TEST_ARGS) -coverprofile cover.out ;\


ENVTEST_ASSETS_DIR=$(shell pwd)/testbin
install-envtest: setup-envtest
	mkdir -p ${ENVTEST_ASSETS_DIR}
	$(ENVTEST) use $(ENVTEST_KUBERNETES_VERSION) --arch=$(ENVTEST_ARCH) --bin-dir=$(ENVTEST_ASSETS_DIR)

ENVTEST = $(GOBIN)/setup-envtest
.PHONY: envtest
setup-envtest: ## Download envtest-setup locally if necessary.
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest@latest)

# go-install-tool will 'go install' any package $2 and install it to $1.
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-install-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
GOBIN=$(PROJECT_DIR)/bin go install $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef