# Copyright (C) Isovalent, Inc. - All Rights Reserved.
# SPDX-License-Identifier: LicenseRef-Isovalent-Enterprise

# check=error=true

# renovate: datasource=docker depName=artifactory.devhub-cloud.cisco.com/sto-cg-docker/go
ARG GOLANG_IMAGE=artifactory.devhub-cloud.cisco.com/sto-cg-docker/go:v1.26.4-dev@sha256:9f3ca2566ae24eb5b4bb06d69ac361f191acf93d8682db26c642cf9e2f4273f6
# renovate: datasource=docker depName=artifactory.devhub-cloud.cisco.com/sto-cg-docker/chainguard-base
ARG APK_IMAGE=artifactory.devhub-cloud.cisco.com/sto-cg-docker/chainguard-base:v20230214-2026.03.24
# renovate: datasource=docker depName=artifactory.devhub-cloud.cisco.com/sto-cg-docker/static
ARG BASE_IMAGE=artifactory.devhub-cloud.cisco.com/sto-cg-docker/static:latest@sha256:4124a7da5f2ce1cb2d67afc3d8779c86ead71bd431caa530cfbd2da8017882cd

# FIPS vars (overridden via --build-arg for FIPS builds)
ARG GOEXPERIMENT=
ARG EXTRA_GOTAGS=

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
    go build -buildmode=pie -ldflags "-s -w -extldflags '--static-pie'" ${EXTRA_GOTAGS} -o /out/gops .

# Stage 2: Build clustermesh-apiserver binary
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} AS builder

ARG TARGETOS
ARG TARGETARCH
ARG MODIFIERS
ARG GOEXPERIMENT
ARG EXTRA_GOTAGS

WORKDIR /go/src/github.com/cilium/cilium

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    mkdir -p /tmp/install && \
    cp clustermesh-apiserver/etcd-config.yaml /tmp/install/etcd-config.yaml

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    # pie mode and -race are incompatible
    MODS="$(echo $MODIFIERS | tr -d '\"')"; \
    case " $MODS " in \
      *" RACE=1 "*) PIE_FLAG="" ; PIE_LDFLAGS="" ; CGO="1" ;; \
      *)            PIE_FLAG="-buildmode=pie" ; PIE_LDFLAGS="-extldflags '--static-pie'" ; CGO="0" ;; \
    esac; \
    GOEXPERIMENT=${GOEXPERIMENT} \
    make GOARCH=${TARGETARCH} \
         DESTDIR=/out/${TARGETOS}/${TARGETARCH} \
         EXTRA_GO_BUILD_LDFLAGS="-s -w $PIE_LDFLAGS" \
         EXTRA_GO_BUILD_FLAGS="$PIE_FLAG ${EXTRA_GOTAGS}" \
         CGO_ENABLED=$CGO \
         $MODS \
         build-container-clustermesh-apiserver install-container-binary-clustermesh-apiserver

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${BUILDARCH} licenses-all && \
    mv LICENSE.all /tmp/install/LICENSE.all

# Stage 3: Install APK runtime deps in an intermediate builder
FROM ${BASE_IMAGE} AS base-image
FROM ${APK_IMAGE} AS deps-builder

COPY --from=base-image / /rootfs
RUN apk add --no-cache --no-commit-hooks --root /rootfs etcd ld-linux

RUN mkdir -p /rootfs/run/cilium && chmod 0777 /rootfs/run/cilium && \
    mkdir -p /rootfs/var && ln -sfn /run /rootfs/var/run && \
    grep -E "^root:" /etc/passwd >> /rootfs/etc/passwd && \
    grep -E "^root:" /etc/group >> /rootfs/etc/group

    # cleanup apk remnants
RUN rm -f /rootfs/etc/apko.json && \
    rm -rf /rootfs/etc/apk /rootfs/var/cache/apk

# Stage 4: Build image under scratch base
FROM scratch AS release

ARG TARGETOS
ARG TARGETARCH

LABEL maintainer="support@isovalent.com" \
      org.opencontainers.image.vendor="Isovalent, part of Cisco" \
      org.opencontainers.image.title="Isovalent Networking for Kubernetes — Clustermesh API Server (Cisco Chainguard)" \
      org.opencontainers.image.description="Clustermesh API server image built on Cisco Chainguard static base"

COPY --from=deps-builder /rootfs/ /
COPY --from=gops-builder /out/gops /usr/local/bin/gops
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/clustermesh-apiserver /usr/bin/clustermesh-apiserver
COPY --from=builder /tmp/install/etcd-config.yaml /var/lib/cilium/etcd-config.yaml
COPY --from=builder /tmp/install/LICENSE.all /LICENSE.all

ENV GOPS_CONFIG_DIR=/tmp/gops

USER root
ENTRYPOINT ["/usr/bin/clustermesh-apiserver"]
