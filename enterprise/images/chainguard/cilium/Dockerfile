# Copyright (C) Isovalent, Inc. - All Rights Reserved.
# SPDX-License-Identifier: LicenseRef-Isovalent-Enterprise

# check=error=true

# renovate: datasource=docker depName=artifactory.devhub-cloud.cisco.com/isovalent-eng-docker/cilium-envoy-chainguard
ARG CILIUM_ENVOY_IMAGE=artifactory.devhub-cloud.cisco.com/isovalent-eng-docker/cilium-envoy-chainguard:v1.36.6-1776083692-8fb1248202fd04d910b7d53b5269d0320e795f62
# renovate: datasource=docker depName=artifactory.devhub-cloud.cisco.com/isovalent-eng-docker/cilium-llvm-chainguard
ARG CILIUM_LLVM_IMAGE=artifactory.devhub-cloud.cisco.com/isovalent-eng-docker/cilium-llvm-chainguard:1776863332-e71595f
# renovate: datasource=docker depName=artifactory.devhub-cloud.cisco.com/sto-cg-docker/go
ARG GOLANG_IMAGE=artifactory.devhub-cloud.cisco.com/sto-cg-docker/go:v1.26.4-dev@sha256:9f3ca2566ae24eb5b4bb06d69ac361f191acf93d8682db26c642cf9e2f4273f6
# renovate: datasource=docker depName=artifactory.devhub-cloud.cisco.com/sto-cg-docker/chainguard-base
ARG APK_IMAGE=artifactory.devhub-cloud.cisco.com/sto-cg-docker/chainguard-base:latest@sha256:b55e0043be0b2e564f560d855038367234a5639bd72af102ae01144b7328daa5
# renovate: datasource=docker depName=artifactory.devhub-cloud.cisco.com/sto-cg-docker/static
ARG BASE_IMAGE=artifactory.devhub-cloud.cisco.com/sto-cg-docker/static:latest@sha256:4124a7da5f2ce1cb2d67afc3d8779c86ead71bd431caa530cfbd2da8017882cd

# FIPS vars (overridden via --build-arg for FIPS builds)
ARG GOEXPERIMENT=
ARG EXTRA_GOTAGS=

FROM ${CILIUM_ENVOY_IMAGE} AS cilium-envoy
FROM ${CILIUM_LLVM_IMAGE} AS llvm-dist

# Stage 1: Build gops from source
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} AS gops-builder

ARG MODIFIERS
ARG GOEXPERIMENT
ARG EXTRA_GOTAGS

RUN apk add --no-cache git

# legit:ignore
RUN git clone --depth 1 https://github.com/google/gops.git /build/gops && \
    cd /build/gops && \
    export $(echo $MODIFIERS | tr -d '"') && \
    GOEXPERIMENT=${GOEXPERIMENT} \
    go build -buildmode=pie -ldflags "-s -w" ${EXTRA_GOTAGS} -o /out/gops .

# Stage 2: Build all Cilium Go binaries
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} AS builder

ARG TARGETOS
ARG TARGETARCH
ARG MODIFIERS
ARG GOEXPERIMENT
ARG EXTRA_GOTAGS
# Re-declare so it is available to override CILIUM_ENVOY_REF, which derives requiredEnvoyVersionSHA
ARG CILIUM_ENVOY_IMAGE

WORKDIR /go/src/github.com/cilium/cilium

# -buildmode=pie is incompatible with -race on linux/amd64.
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    MODS="$(echo $MODIFIERS | tr -d '\"')"; \
    case " $MODS " in \
      *" RACE=1 "*) PIE_FLAG="" ;; \
      *)            PIE_FLAG="-buildmode=pie" ;; \
    esac; \
    GOEXPERIMENT=${GOEXPERIMENT} \
    make GOARCH=${TARGETARCH} \
         DESTDIR=/out/${TARGETOS}/${TARGETARCH} \
         PKG_BUILD=1 \
         CILIUM_ENVOY_REF=${CILIUM_ENVOY_IMAGE} \
         EXTRA_GO_BUILD_LDFLAGS="-s -w" \
         EXTRA_GO_BUILD_FLAGS="$PIE_FLAG ${EXTRA_GOTAGS}" \
         $MODS \
         build-container install-container-binary

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${BUILDARCH} \
         DESTDIR=/out/${TARGETOS}/${TARGETARCH} \
         PKG_BUILD=1 \
         $(echo $MODIFIERS | tr -d '"') \
         install-bash-completion licenses-all && \
    mv LICENSE.all /out/${TARGETOS}/${TARGETARCH}/LICENSE.all

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    cp images/cilium/init-container.sh \
       plugins/cilium-cni/install-plugin.sh \
       plugins/cilium-cni/cni-uninstall.sh \
       /out/${TARGETOS}/${TARGETARCH}/

# Stage 3: runtime deps in chainguard-base builder
FROM ${BASE_IMAGE} AS static-base
FROM ${APK_IMAGE} AS deps-builder

COPY --from=static-base / /rootfs
RUN apk add --no-cache --no-commit-hooks --root /rootfs \
    # static-pie cannot be used with cilium otherwise cilium-cni panic on core-dns pod creation with FIPS enabled
    ld-linux \
    # networking tools
    iproute2 \
    ipset \
    kmod \
    # BPF / eBPF toolchain
    bpftool \
    # CNI loopback plugin
    cni-plugins-loopback \
    # diag
    jq \
    grep \
    # needed by mount-bpf-fs init container
    mount \
    util-linux-misc \
    # provides /bin/kill (used by graceful-shutdown chaos test and ops tooling)
    procps \
    # needed for groupadd (used during node init)
    shadow \
    # needed for embedded envoy
    libatomic \
    ca-certificates \
    # temp: prometheus metrics retrieval in CI
    curl \
    # used by K8sAgentHubbleTest "Test TLS certificate" (openssl s_client -> test/k8s/hubble.go:185-189)
    openssl \
    bash \
    # /bin/sh symlink (needed by RUN instructions in final stage)
    bash-binsh \
    coreutils

    # needed by iptables build
RUN apk add --no-cache \
    gcc-15 \
    libmnl-dev \
    libnftnl-dev \
    pkgconf \
    make \
    curl && \
    ln -sf /usr/bin/gcc-15 /usr/local/bin/gcc

ARG IPTABLES_VERSION=1.8.8

WORKDIR /build
RUN curl -fsSLO "https://www.netfilter.org/projects/iptables/files/iptables-${IPTABLES_VERSION}.tar.bz2" && \
    curl -fsSLO "https://www.netfilter.org/projects/iptables/files/iptables-${IPTABLES_VERSION}.tar.bz2.sha256sum" && \
    sha256sum -c iptables-${IPTABLES_VERSION}.tar.bz2.sha256sum && \
    tar -xjf "iptables-${IPTABLES_VERSION}.tar.bz2"

WORKDIR /build/iptables-${IPTABLES_VERSION}
RUN ./configure --prefix=/usr/local --sbindir=/sbin --libdir=/usr/local/lib \
        || { echo 'iptables configure log : '; cat config.log; exit 1; }
RUN make && \
    make DESTDIR=/rootfs install && \
    # copy matching libmnl and libnftnl from the build env (must match what iptables was linked against)
    cp -a /usr/lib/libmnl.so* /rootfs/usr/local/lib/ 2>/dev/null || true && \
    cp -a /usr/lib/libnftnl.so* /rootfs/usr/local/lib/ 2>/dev/null || true && \
    # ensure dynamic linker finds iptables libs in /usr/local/lib
    mkdir -p /rootfs/etc/ld.so.conf.d && \
    echo "/usr/local/lib" > /rootfs/etc/ld.so.conf.d/iptables.conf && \
    ldconfig -r /rootfs

RUN grep -E "^root:" /etc/passwd >> /rootfs/etc/passwd && \
    grep -E "^root:" /etc/group >> /rootfs/etc/group && \
    mkdir /rootfs/home/cilium

    # cleanup apk remnants
RUN rm -f /rootfs/etc/apko.json && \
    rm -rf /rootfs/etc/apk /rootfs/var/cache/apk

# Stage 4: Build image under scratch base
FROM scratch AS release

ARG TARGETOS
ARG TARGETARCH

LABEL maintainer="support@isovalent.com" \
      org.opencontainers.image.vendor="Isovalent, part of Cisco" \
      org.opencontainers.image.title="Isovalent Networking for Kubernetes — Cilium agent" \
      org.opencontainers.image.description="Cilium agent image built on Cisco Chainguard static base"

COPY --from=deps-builder /rootfs /
COPY --from=llvm-dist /usr/local/bin/clang /usr/local/bin/llc /usr/local/bin/
COPY --from=gops-builder /out/gops /usr/local/bin/gops
COPY --from=cilium-envoy /usr/bin/cilium-envoy /usr/bin/cilium-envoy-starter /usr/bin/
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/ /

USER root

    # Fix broken symlink created by install-container-binary with absolute DESTDIR path
RUN rm -f /usr/bin/cilium /bin/cilium && \
    ln -sfn cilium-dbg /usr/bin/cilium && \
    # compatibility symlinks
    mkdir -p /usr/local/bin && \
    ln -sf /usr/bin/bpftool /usr/local/bin/bpftool && \
    # /var/run → /run (Wolfi uses /run)
    mkdir -p /var && \
    ln -sfn /run /var/run && \
    # CNI loopback compatibility path
    mkdir -p /cni /usr/lib/cni && \
    ln -sf /usr/bin/loopback /cni/loopback && \
    ln -sf /usr/bin/loopback /usr/lib/cni/loopback && \
    # cilium-cli sysdump expects gops at /bin/gops
    ln -sf /usr/local/bin/gops /bin/gops

RUN --mount=type=bind,readwrite,target=/src \
    /src/images/runtime/iptables-wrapper-installer.sh --no-sanity-check

WORKDIR /home/cilium
ENV HUBBLE_SERVER=unix:///var/run/cilium/hubble.sock
ENV INITSYSTEM=SYSTEMD
CMD ["/usr/bin/cilium-dbg"]
