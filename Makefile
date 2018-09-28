# ============================================================================ #
#                                                                              #
#                    Auth Config Operator - Build and Test                     #
#                    -------------------------------------                     #
#                                                                              #
# ============================================================================ #

SHELL := /bin/bash
PKG   := github.com/openshift/auth-config-operator
CMDS  := $(addprefix bin/, $(shell go list ./cmd/... | xargs -I{} basename {}))
IMAGE_REPO := quay.io/openshift/auth-config-operator
IMAGE_TAG ?= "dev"

.PHONY: build test run clean vendor vendor-update coverage coverage-html

all: test build

test: cover.out

unit:
	go test -v -race ./pkg/...

cover.out:
	go test -v -race -coverprofile=cover.out -covermode=atomic \
		-coverpkg ./pkg/controller/... ./pkg/...

coverage: cover.out
	go tool cover -func=cover.out

coverage-html: cover.out
	go tool cover -html=cover.out

build: $(CMDS)
	# docker build -t $(IMAGE_REPO):$(IMAGE_TAG) . # TODO

$(CMDS):
	CGO_ENABLED=0 go build -o $@ $(PKG)/cmd/$(shell basename $@)

DEP := $(GOPATH)/bin/dep
$(DEP):
	go get -u github.com/golang/dep/cmd/dep

vendor: $(DEP)
	$(DEP) ensure -v -vendor-only

vendor-update: $(DEP)
	$(DEP) ensure -v

clean:
	rm -rf bin

CODEGEN := ./vendor/k8s.io/code-generator/generate-groups.sh

KUBE_RELEASE=1.11
$(CODEGEN):
	# dep doesn't currently support downloading dependencies that don't have go
	# in the top-level dir.
	# Move to dep when merged: https://github.com/golang/dep/pull/1545
	mkdir -p vendor/k8s.io/code-generator
	git clone --branch release-$(KUBE_RELEASE) \
		https://github.com/kubernetes/code-generator.git vendor/k8s.io/code-generator

codegen: $(CODEGEN)
	$(CODEGEN) all $(PKG)/pkg/client $(PKG)/pkg/apis "auth:v1alpha1"


counterfeiter := $(GOBIN)/counterfeiter
$(counterfeiter):
	go install github.com/maxbrunsfeld/counterfeiter

mockgen := $(GOBIN)/mockgen
$(mockgen):
	go install github.com/golang/mock/mockgen

.PHONY: generate-mock-client
generate-mock-client: $(counterfeiter)
	go generate ./...

gen-all: codegen generate-mock-client
