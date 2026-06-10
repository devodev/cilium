#!/usr/bin/env bash

# Copyright (C) Isovalent, Inc. - All Rights Reserved.

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

packages=(
  # Bash completion for Cilium
  bash-completion
  # Additional misc runtime dependencies
  iproute # RHEL calls iproute the package for the upstream project iproute2
  ipset
  iptables
  kmod
  jq
  util-linux # nsenter required
  glibc
  findutils
  libstdc++
  libatomic # required by cilium-envoy
)

# tzdata is one of the dependencies and a timezone must be set
# to avoid interactive prompt when it is being installed
# ln -fs /usr/share/zoneinfo/UTC /etc/localtime

microdnf install -y --nodocs "${packages[@]}"

microdnf clean all

