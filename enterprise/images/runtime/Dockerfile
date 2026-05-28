# Copyright (C) Isovalent, Inc. - All Rights Reserved.

ARG TESTER_IMAGE=quay.io/cilium/image-tester:1755027438-ef4e849@sha256:ff0eb08901053e72afcfadc58e9d1736c6d1b257ffdf0779966d44e4872bfae5
ARG UBI_MINI_IMAGE=registry.redhat.io/ubi9/ubi-minimal:9.8@sha256:5b74fce9d6e629942a0c6dc0f546c193e70d7f974d999a48c948c53dd3d36362
ARG GOLANG_IMAGE=docker.io/library/golang:1.26.3@sha256:2d6c80227255c3112a4d08e67ba98e58efd3846daf15d9d7d4c389565d881b1a
ARG CILIUM_LLVM_IMAGE=quay.io/isovalent-dev/cilium-llvm-ubi:1773727319-1c694cf@sha256:04f1764c41706e9a285f90d2ab1eb85242333ca2d966ed0d1885607d84a2544d
ARG CILIUM_BPFTOOL_IMAGE=quay.io/isovalent-dev/cilium-bpftool-ubi:1773727319-1c694cf@sha256:c08fae92a12088b73d769d83246d68ce30d0e6a53810e39c6b132fce65beeb39
ARG COMPILERS_IMAGE=quay.io/isovalent-dev/image-compilers-ubi:1773656974-2c62f04@sha256:5f74cfe5e037ba86cf50c5c570009bab11ceb608cc0096ca6e0a1d806130ec52

ARG VERSION=0.0.0-dev
ARG REVISION=000000

FROM ${CILIUM_LLVM_IMAGE} AS llvm-dist
FROM ${CILIUM_BPFTOOL_IMAGE} AS bpftool-dist
FROM ${COMPILERS_IMAGE} AS compilers

FROM ${GOLANG_IMAGE} AS go-builder

WORKDIR /go/src/github.com/isovalent/cilium/images/runtime
RUN --mount=type=bind,readwrite,source=./images/runtime,target=. \
    --mount=target=/root/.cache,type=cache \
    --mount=target=/go/pkg/mod,type=cache \
    ./build-gops.sh

ARG TARGETARCH
RUN --mount=type=bind,readwrite,source=./images/runtime,target=. \
    --mount=target=/root/.cache,type=cache \
    --mount=target=/go/pkg/mod,type=cache \
    ./download-cni.sh

FROM ${UBI_MINI_IMAGE} AS release

LABEL name="Isovalent UBI runtime image" \
      maintainer="support@isovalent.com" \
      vendor="Isovalent" \
      release="1" \
      summary="Isovalent runtime image based on Red Hat Universal Base Image" \
      description="This image extends Red Hat UBI image with generic tooling used by Isovalent images" \
      org.opencontainers.image.authors="Isovalent" \
      org.opencontainers.image.url="https://isovalent.com" \
      org.opencontainers.image.documentation="https://isovalent.com/product" \
      org.opencontainers.image.vendor="Isovalent, part of Cisco" \
      org.opencontainers.image.title="Isovalent UBI runtime image" \
      org.opencontainers.image.description="This image extends Red Hat UBI image with generic tooling used by Isovalent images"

WORKDIR /go/src/github.com/isovalent/cilium/enterprise/images/runtime
RUN --mount=type=bind,readwrite,source=./enterprise/images/runtime,target=. ./install-runtime-deps.sh
COPY ./enterprise/images/runtime/LICENSE /usr/share/licenses/isovalent/
RUN ln -s /usr/share/licenses /licenses

WORKDIR /go/src/github.com/isovalent/cilium/images/runtime
RUN --mount=type=bind,readwrite,source=./images/runtime,target=. ./iptables-wrapper-installer.sh --no-sanity-check

COPY --from=llvm-dist /usr/local/bin/clang /usr/local/bin/llc /usr/local/bin/

COPY --from=bpftool-dist /usr/local/bin/bpftool /usr/local/bin/bpftool

COPY --from=go-builder /out /

LABEL version="${VERSION}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

FROM ${TESTER_IMAGE} AS test

COPY --from=release / /

COPY --from=llvm-dist /test /test
COPY --from=llvm-dist /test /test
COPY --from=bpftool-dist /test /test
COPY --from=compilers /usr/bin/which /usr/bin/

RUN /test/bin/cst -C /test/llvm
RUN /test/bin/cst -C /test/bpftool
