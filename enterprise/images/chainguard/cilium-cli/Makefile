# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

MAKEFILE_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
CILIUM_CLI_DIR := $(MAKEFILE_DIR)../../../../cilium-cli

.DEFAULT_GOAL := all

all:
	$(MAKE) -C $(CILIUM_CLI_DIR) $(if $(TARGET),TARGET=$(TARGET))

install:
	$(MAKE) -C $(CILIUM_CLI_DIR) install $(if $(TARGET),TARGET=$(TARGET))

clean:
	$(MAKE) -C $(CILIUM_CLI_DIR) clean

.PHONY: all install clean
