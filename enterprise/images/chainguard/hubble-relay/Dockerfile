# Copyright (C) Isovalent, Inc. - All Rights Reserved.
# SPDX-License-Identifier: LicenseRef-Isovalent-Enterprise

# check=error=true

# renovate: datasource=docker depName=artifactory.devhub-cloud.cisco.com/sto-cg-docker/go
ARG GOLANG_IMAGE=artifactory.devhub-cloud.cisco.com/sto-cg-docker/go:1.26.1-dev@sha256:362ae70fb5415c038fe6938f5abfbdb32bd2ea7275a36b02bc02b0187ee979cf
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


# Stage 2: Build hubble-relay binary
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
         build-container-hubble-relay install-container-binary-hubble-relay

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${BUILDARCH} licenses-all && \
    mkdir -p /tmp/install && \
    mv LICENSE.all /tmp/install/LICENSE.all

# Stage 3: Install APK runtime deps in an intermediate builder
FROM ${BASE_IMAGE} AS base-image
FROM ${APK_IMAGE} AS deps-builder

COPY --from=base-image / /rootfs
RUN apk add --no-cache --no-commit-hooks --root /rootfs ca-certificates

RUN mkdir -p /rootfs/run/cilium && chmod 0777 /rootfs/run/cilium && \
    mkdir -p /rootfs/var && ln -sfn /run /rootfs/var/run

    # cleanup apk remnants
RUN rm -f /rootfs/etc/apko.json && \
    rm -rf /rootfs/etc/apk /rootfs/var/cache/apk

# Stage 4: Build image under scratch base
FROM scratch AS release

ARG TARGETOS
ARG TARGETARCH

LABEL maintainer="support@isovalent.com" \
      org.opencontainers.image.vendor="Isovalent, part of Cisco" \
      org.opencontainers.image.title="Isovalent Networking for Kubernetes — Hubble Relay (Cisco Chainguard)" \
      org.opencontainers.image.description="Hubble Relay image built on Cisco Chainguard static base"

COPY --from=deps-builder /rootfs/ /
COPY --from=gops-builder /out/gops /usr/local/bin/gops
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/hubble-relay /usr/bin/hubble-relay
COPY --from=builder /tmp/install/LICENSE.all /LICENSE.all

# gops temp dir — avoid permission issues for non-root UIDs
ENV GOPS_CONFIG_DIR=/tmp

WORKDIR /tmp
# uid:gid for nonroot user, compatible with runAsNonRoot
USER 65532:65532
ENTRYPOINT ["/usr/bin/hubble-relay"]
CMD ["serve"]
