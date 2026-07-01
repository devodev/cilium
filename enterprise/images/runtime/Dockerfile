# Copyright (C) Isovalent, Inc. - All Rights Reserved.

ARG TESTER_IMAGE=quay.io/cilium/image-tester:1755027438-ef4e849@sha256:ff0eb08901053e72afcfadc58e9d1736c6d1b257ffdf0779966d44e4872bfae5
ARG UBI_MINI_IMAGE=registry.redhat.io/ubi9/ubi-minimal:9.8@sha256:850143255ee0d1915f09aaa09f6ed31f24086ba605c323badfbefa95b8c52b0e
ARG GOLANG_IMAGE=docker.io/library/golang:1.26.4@sha256:68cb6d68bed024785b69195b89af7ac7a444f27791435f98647edff595aa0479
ARG CILIUM_LLVM_IMAGE=artifactory.devhub-cloud.cisco.com/isovalent-eng-docker/cilium-llvm-ubi:1782199947-07a03f9@sha256:e44d0f71c3b7d200a374059ea42e726d67240507dec7260c3a2cec0e8e280047
ARG CILIUM_BPFTOOL_IMAGE=artifactory.devhub-cloud.cisco.com/isovalent-eng-docker/cilium-bpftool-ubi:1782199947-07a03f9@sha256:07a75813555b1e3922fc9d90fcf64a1dbe15dba3460927548b50b22466273942
ARG COMPILERS_IMAGE=artifactory.devhub-cloud.cisco.com/isovalent-eng-docker/image-compilers-ubi:1782199947-07a03f9@sha256:fb9d3e0106977928c0d1f7f9399ab520f28c7961542c3943ffac754624f96b90

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
    ./build-cni.sh

FROM ${UBI_MINI_IMAGE} AS release

ARG VERSION=0.0.0-dev
ARG REVISION=000000

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
