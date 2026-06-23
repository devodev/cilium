ARG BASE_IMAGE=quay.io/isovalent-dev/cilium-runtime-ubi:cd74ebc98d21b15e6fa66d02e7b73cccb75f5566@sha256:6d8d88e05a96cfe72ae28f71e762761e2f3d4234f465dc69c9cb1881f1f846cd
ARG GOLANG_IMAGE=docker.io/library/golang:1.26.4@sha256:68cb6d68bed024785b69195b89af7ac7a444f27791435f98647edff595aa0479

FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} AS builder

ARG TARGETOS
ARG TARGETARCH
ARG BUILDARCH
ARG MODIFIERS

WORKDIR /go/src/github.com/cilium/cilium
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOOS=${TARGETOS} GOARCH=${TARGETARCH} DESTDIR=/out/${TARGETOS}/${TARGETARCH} $(echo $MODIFIERS | tr -d '"') -C enterprise/gateway-api-controlplane install

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${BUILDARCH} licenses-all && mv LICENSE.all /out/${TARGETOS}/${TARGETARCH}

FROM ${BASE_IMAGE} AS release

LABEL name="Gateway API controlplane component of Isovalent Networking for Kubernetes" \
      maintainer="support@isovalent.com" \
      vendor="Isovalent" \
      release="1" \
      summary="Gateway API controlplane component of Isovalent Networking for Kubernetes" \
      description="Image of the Gateway API controlplane component of Isovalent Networking for Kubernetes" \
      org.opencontainers.image.authors="Isovalent" \
      org.opencontainers.image.url="https://isovalent.com" \
      org.opencontainers.image.documentation="https://isovalent.com/product" \
      org.opencontainers.image.vendor="Isovalent, part of Cisco" \
      org.opencontainers.image.title="Isovalent Networking for Kubernetes Gateway API controlplane image" \
      org.opencontainers.image.description="Image of the Gateway API controlplane component of Isovalent Networking for Kubernetes" \
      io.k8s.description="Image of the Gateway API controlplane component of Isovalent Networking for Kubernetes" \
      io.k8s.display-name="Gateway API controlplane component of Isovalent Networking for Kubernetes"

ARG TARGETOS
ARG TARGETARCH
ARG BUILD_DATE
LABEL org.opencontainers.image.created="${BUILD_DATE}"
ARG VERSION=0.0.0
LABEL version=${VERSION}

COPY enterprise/images/gateway-api-controlplane/LICENSE /usr/share/licenses/isovalent/
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/gateway-api-controlplane /usr/bin/gateway-api-controlplane
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/LICENSE.all /LICENSE.all
RUN mv /LICENSE.all /usr/share/licenses/isovalent/LICENSE.dependencies && ln -s /usr/share/licenses /licenses

USER 65532:65532
ENV GOPS_CONFIG_DIR=/tmp/gops
ENTRYPOINT ["/usr/bin/gateway-api-controlplane"]
