# Copyright (C) Isovalent, Inc. - All Rights Reserved.
# SPDX-License-Identifier: LicenseRef-Isovalent-Enterprise

# check=error=true

# renovate: datasource=docker depName=artifactory.devhub-cloud.cisco.com/sto-cg-docker/static
ARG BASE_IMAGE=artifactory.devhub-cloud.cisco.com/sto-cg-docker/static:latest@sha256:4124a7da5f2ce1cb2d67afc3d8779c86ead71bd431caa530cfbd2da8017882cd
# renovate: datasource=docker depName=artifactory.devhub-cloud.cisco.com/sto-cg-docker/go
ARG GOLANG_IMAGE=artifactory.devhub-cloud.cisco.com/sto-cg-docker/go:v1.26.4-dev@sha256:cb3386a6695d33b1ece1d6395418dbace625d103cead6a1329c85eae2613d7b1
# renovate: datasource=docker depName=artifactory.devhub-cloud.cisco.com/sto-cg-docker/chainguard-base
ARG APK_IMAGE=artifactory.devhub-cloud.cisco.com/sto-cg-docker/chainguard-base:latest@sha256:b55e0043be0b2e564f560d855038367234a5639bd72af102ae01144b7328daa5

# FIPS vars (overridden via --build-arg for FIPS builds)
ARG GOEXPERIMENT=
ARG EXTRA_GOTAGS=

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} AS builder

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
# MODIFIERS are extra arguments to be passed to make at build time.
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
    make GOARCH=${TARGETARCH} DESTDIR=/out/${TARGETOS}/${TARGETARCH} \
    EXTRA_GO_BUILD_LDFLAGS="-s -w $PIE_LDFLAGS" \
    EXTRA_GO_BUILD_FLAGS="$PIE_FLAG ${EXTRA_GOTAGS}" \
    $MODS \
    build-container-standalone-dns-proxy install-container-binary-standalone-dns-proxy

FROM ${BASE_IMAGE} AS base-image
FROM ${APK_IMAGE} AS deps-builder

COPY --from=base-image / /rootfs
RUN apk add --no-cache --no-commit-hooks --root /rootfs ld-linux

RUN mkdir -p /rootfs/run/cilium && chmod 0777 /rootfs/run/cilium && \
    mkdir -p /rootfs/var && ln -sfn /run /rootfs/var/run

    # cleanup apk remnants
RUN rm -f /rootfs/etc/apko.json && \
    rm -rf /rootfs/etc/apk /rootfs/var/cache/apk

FROM scratch AS release
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH

LABEL maintainer="support@isovalent.com" \
      org.opencontainers.image.vendor="Isovalent, part of Cisco" \
      org.opencontainers.image.title="Isovalent Networking for Kubernetes — Standalone DNS Proxy (Cisco Chainguard)" \
      org.opencontainers.image.description="Standalone DNS proxy image built on Cisco Chainguard base"

COPY --from=deps-builder /rootfs/ /
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/standalone-dns-proxy /usr/bin/standalone-dns-proxy
ENV HOME=/tmp
USER 65532:65532
ENTRYPOINT [ "/usr/bin/standalone-dns-proxy" ]
