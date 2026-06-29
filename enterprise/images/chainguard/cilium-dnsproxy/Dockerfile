# Copyright (C) Isovalent, Inc. - All Rights Reserved.
# SPDX-License-Identifier: LicenseRef-Isovalent-Enterprise

# check=error=true

# renovate: datasource=docker depName=artifactory.devhub-cloud.cisco.com/sto-cg-docker/go
ARG GOLANG_IMAGE=artifactory.devhub-cloud.cisco.com/sto-cg-docker/go:v1.26.4-dev@sha256:9f3ca2566ae24eb5b4bb06d69ac361f191acf93d8682db26c642cf9e2f4273f6
# renovate: datasource=docker depName=artifactory.devhub-cloud.cisco.com/sto-cg-docker/static
ARG BASE_IMAGE=artifactory.devhub-cloud.cisco.com/sto-cg-docker/static:latest@sha256:a0081f4e329e8e5b97801299043f90454d6a44d5b4b5a1dd51638528a9c58345
# renovate: datasource=docker depName=artifactory.devhub-cloud.cisco.com/sto-cg-docker/chainguard-base
ARG APK_IMAGE=artifactory.devhub-cloud.cisco.com/sto-cg-docker/chainguard-base:v20230214-2026.03.24

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

# Stage 2: Build dnsproxy binary from enterprise/fqdn-proxy
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
    # pie mode and -race are incompatible
    MODS="$(echo $MODIFIERS | tr -d '\"')"; \
    case " $MODS " in \
      *" RACE=1 "*) PIE_FLAG="" ; PIE_LDFLAGS="" ;; \
      *)            PIE_FLAG="-buildmode=pie" ; PIE_LDFLAGS="-extldflags '--static-pie'" ;; \
    esac; \
    GOEXPERIMENT=${GOEXPERIMENT} \
    make GOARCH=${TARGETARCH} \
         DESTDIR=/out/${TARGETOS}/${TARGETARCH} \
         EXTRA_GO_BUILD_LDFLAGS="-s -w $PIE_LDFLAGS" \
         EXTRA_GO_BUILD_FLAGS="$PIE_FLAG ${EXTRA_GOTAGS}" \
         $MODS \
         -C enterprise/fqdn-proxy all install

# Stage 3: Install APK runtime deps in an intermediate builder
FROM ${BASE_IMAGE} AS base-image
FROM ${APK_IMAGE} AS deps-builder

COPY --from=base-image / /rootfs
RUN apk add --no-cache --no-commit-hooks --root /rootfs ld-linux

RUN mkdir -p /rootfs/run/cilium && chmod 0777 /rootfs/run/cilium && \
    mkdir -p /rootfs/var && ln -sfn /run /rootfs/var/run
RUN grep -E "^root:" /etc/passwd >> /rootfs/etc/passwd && \
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
      org.opencontainers.image.title="Isovalent Networking for Kubernetes — DNS Proxy (Cisco Chainguard)" \
      org.opencontainers.image.description="Enterprise DNS proxy image built on Cisco Chainguard static base"

COPY --from=deps-builder /rootfs/ /
COPY --from=gops-builder /out/gops /bin/gops
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/dnsproxy /usr/bin/dnsproxy

USER root
ENV HOME=/tmp
WORKDIR /
CMD ["/usr/bin/dnsproxy"]
