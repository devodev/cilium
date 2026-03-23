# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../../../../Makefile.defs

CILIUM_BUILDER_IMAGE=$(shell cat $(ROOT_DIR)/images/cilium/Dockerfile | grep "ARG CILIUM_BUILDER_IMAGE=" | cut -d"=" -f2)

.PHONY: proto
proto:
	$(QUIET)$(CONTAINER_ENGINE) container run --rm \
		--volume $(ROOT_DIR):/src \
		--user "$(shell id -u):$(shell id -g)" \
		$(CILIUM_BUILDER_IMAGE) \
		make -C /src/enterprise/pkg/lb/t2servicehealth/api -f Makefile.protoc
