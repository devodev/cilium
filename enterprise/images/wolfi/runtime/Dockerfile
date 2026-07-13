#  Copyright (C) Isovalent, Inc. - All Rights Reserved. 
# 
#  NOTICE: All information contained herein is, and remains the property of 
#  Isovalent Inc and its suppliers, if any. The intellectual and technical 
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers 
#  and may be covered by U.S. and Foreign Patents, patents in process, and are 
#  protected by trade secret or copyright law.  Dissemination of this information 
#  or reproduction of this material is strictly forbidden unless prior written 
#  permission is obtained from Isovalent Inc.

ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:1732033893-de666b6@sha256:ee005bd47b20f78a727c06fdf2275861848be7acd242603c82f86ca8faaeda90
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:5a9c4852a21287686009bfe1cdc1fed6e7aabdea@sha256:188e398ee30456373530698d0d29de66dda0c4428068ea430027ceb7e9c15b7c
ARG CILIUM_RUNTIME_BASE_IMAGE=quay.io/isovalent-dev/cilium-runtime-base-wfi:31b55db67f5425b72ec07fd87c9fd30df0aa69a6@sha256:72f944800d667b24903c5da5915d91203bccf2f23ebe833e8097cac371b316d5
ARG CILIUM_IPTABLES_IMAGE=quay.io/cilium/iptables:1331e9b1b03f70c9d8b08626d9a7126963f86478@sha256:d761d967243aced2729adde1e332a9c9def6baeb61f5f6cde5758b04e9a79355
ARG GOLANG_IMAGE=docker.io/library/golang:1.26.5@sha256:63f132d58c1f589f0dcda584933a9bb44bfda1150f1506377f5a902f34d86033

FROM ${CILIUM_LLVM_IMAGE} AS llvm-dist
FROM ${CILIUM_BPFTOOL_IMAGE} AS bpftool-dist
FROM ${CILIUM_IPTABLES_IMAGE} AS iptables-dist

RUN apt-get update
RUN apt-get -y install wget
RUN wget https://www.netfilter.org/projects/iptables/files/iptables-1.8.8.tar.bz2 && \
    wget https://www.netfilter.org/projects/iptables/files/iptables-1.8.8.tar.bz2.sha256sum && \
    sha256sum --check iptables-1.8.8.tar.bz2.sha256sum

FROM ${GOLANG_IMAGE} AS go-builder

WORKDIR /go/src/github.com/cilium/cilium/images/runtime
ARG TARGETARCH
RUN --mount=type=bind,readwrite,source=./images/runtime,target=. \
    --mount=target=/root/.cache,type=cache \
    --mount=target=/go/pkg/mod,type=cache \
    ./build-iptables-wrapper.sh

FROM ${CILIUM_RUNTIME_BASE_IMAGE}

WORKDIR /go/src/github.com/cilium/cilium/enterprise/images/wolfi/runtime

COPY --from=iptables-dist /iptables/iptables-1.8.8.tar.bz2 /iptables/iptables-1.8.8.tar.bz2
# Needed for iptables configure script to use gcc with no issue 
RUN ln -s /usr/bin/gcc-14 /usr/bin/gcc
# Installation of iptables v1.8.8
RUN cd /iptables && tar -xvf iptables-1.8.8.tar.bz2 
RUN cd /iptables/iptables-1.8.8 && ./configure --sbindir=/sbin && make && make install

# Copy the pre-built iptables-wrapper binary and let it install the symlinks.
# On its first invocation the wrapper detects whether the host is using the
# legacy or nft iptables backend and re-points these symlinks at the matching
# backend before re-execing the original command.
COPY --from=go-builder /out/usr/sbin/iptables-wrapper /usr/sbin/iptables-wrapper
RUN /usr/sbin/iptables-wrapper install
RUN ln -s /run /var/run #TODO: move to apk package
RUN mkdir /cni
RUN ln -s /bin/loopback /cni/loopback

COPY --from=llvm-dist /usr/local/bin/clang /usr/local/bin/llc /usr/local/bin/
COPY --from=bpftool-dist /usr/local /usr/local
