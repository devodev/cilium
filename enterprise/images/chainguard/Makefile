# Copyright (C) Isovalent, Inc. - All Rights Reserved.
# SPDX-License-Identifier: LicenseRef-Isovalent-Enterprise

# Local build for chainguard based cilium images

REGISTRY  ?= artifactory.devhub-cloud.cisco.com/isovalent-eng-docker
TAG       ?= $(shell git -C "$(ROOT_DIR)" rev-parse --short HEAD 2>/dev/null || echo dev)
SUFFIX    ?= -dev

# Explicit platforms, e.g. linux/amd64,linux/arm64. Empty = host platform only.
PLATFORMS ?=
# FIPS build toggle — set to "true" to use go-fips toolchain via --build-arg
FIPS      ?= false
# Operator cloud-provider variant (e.g. generic, aws, azure, alibabacloud)
OPERATOR_VARIANT ?= generic

ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../../..)

# FIPS base images (only used when FIPS=true)
GOLANG_IMAGE_FIPS ?= artifactory.devhub-cloud.cisco.com/sto-cg-docker/go-fips:v1.26.2.1-dev-2026.04.22 
APK_IMAGE_FIPS    ?= artifactory.devhub-cloud.cisco.com/sto-cg-docker/chainguard-base-fips:v20230214-2026.03.24
BASE_IMAGE_FIPS   ?= artifactory.devhub-cloud.cisco.com/sto-cg-docker/glibc-openssl-fips:15.2.0

PLATFORM_FLAG :=
ifneq ($(PLATFORMS),)
PLATFORM_FLAG := --platform $(PLATFORMS)
endif

FIPS_SUFFIX :=
FIPS_BUILD_ARGS :=
ifeq ($(FIPS),true)
FIPS_SUFFIX := -fips
FIPS_BUILD_ARGS := \
  --build-arg GOLANG_IMAGE=$(GOLANG_IMAGE_FIPS) \
  --build-arg APK_IMAGE=$(APK_IMAGE_FIPS) \
  --build-arg BASE_IMAGE=$(BASE_IMAGE_FIPS) \
  --build-arg GOEXPERIMENT=systemcrypto \
  --build-arg "EXTRA_GOTAGS=-tags=requirefips" \
  --build-arg "MODIFIERS=CGO_ENABLED=1"
endif

IMAGE_NAME  = $(REGISTRY)/$(1)-cg$(FIPS_SUFFIX)$(SUFFIX):$(TAG)

DOCKER_BUILD_FLAGS ?=

define buildx
	docker buildx build \
	  --file $(ROOT_DIR)/enterprise/images/chainguard/$(1)/Dockerfile \
	  --tag $(call IMAGE_NAME,$(1)) \
	  --output type=image \
	  $(PLATFORM_FLAG) \
	  $(DOCKER_BUILD_FLAGS) \
	  $(FIPS_BUILD_ARGS) \
	  $(2) \
	  $(ROOT_DIR)
endef

.PHONY: all cilium operator hubble-relay clustermesh-apiserver \
        standalone-dns-proxy cilium-cli cilium-dnsproxy

all: cilium operator hubble-relay clustermesh-apiserver \
     standalone-dns-proxy cilium-cli cilium-dnsproxy

cilium:
	$(call buildx,cilium,)

operator:
	$(call buildx,operator,--build-arg OPERATOR_VARIANT=$(OPERATOR_VARIANT))

hubble-relay:
	$(call buildx,hubble-relay,)

clustermesh-apiserver:
	$(call buildx,clustermesh-apiserver,)

standalone-dns-proxy:
	$(call buildx,standalone-dns-proxy,)

cilium-cli:
	$(call buildx,cilium-cli,)

cilium-dnsproxy:
	$(call buildx,cilium-dnsproxy,)
