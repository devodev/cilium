# Copyright (C) Isovalent, Inc. - All Rights Reserved.

ARG TESTER_IMAGE=quay.io/cilium/image-tester:1755027438-ef4e849@sha256:ff0eb08901053e72afcfadc58e9d1736c6d1b257ffdf0779966d44e4872bfae5
ARG UBI_MINI_IMAGE=registry.redhat.io/ubi9/ubi-minimal:9.6@sha256:34880b64c07f28f64d95737f82f891516de9a3b43583f39970f7bf8e4cfa48b7
ARG GOLANG_IMAGE=docker.io/library/golang:1.26.0@sha256:9edf71320ef8a791c4c33ec79f90496d641f306a91fb112d3d060d5c1cee4e20
ARG CILIUM_LLVM_IMAGE=quay.io/isovalent-dev/cilium-llvm-ubi:1754712783-48bbfc6@sha256:b673ca26acfc574d815c231814707ffa6e39e039450ce95bf296a436f4ff22e9
ARG CILIUM_BPFTOOL_IMAGE=quay.io/isovalent-dev/cilium-bpftool-ubi:1754712783-48bbfc6@sha256:e4401c2a3bbbacbf6a061ce8294165d03779ae9a904e7902303d4d0b8c9f9360
ARG COMPILERS_IMAGE=quay.io/isovalent-dev/image-compilers-ubi:1754570895-16e2939@sha256:731c9cebd0d6bd5846faa6cf76d0e7841f700df745a9f814273e77c5ae43121a

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
