# Build the manager binary
FROM docker.io/library/golang:1.26@sha256:68cb6d68bed024785b69195b89af7ac7a444f27791435f98647edff595aa0479 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/main.go cmd/main.go
COPY api/ api/
COPY manager/ manager/
COPY controller/ controller/
COPY helm/ helm/

# Build
# the GOARCH has not a default value to allow the binary be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o clife-manager cmd/main.go

# Use distroless as minimal base image to package the manager binary
FROM registry.redhat.io/ubi9/ubi-micro:9.7-1771346390@sha256:093a704be0eaef9bb52d9bc0219c67ee9db13c2e797da400ddb5d5ae6849fa10

LABEL name="CLife, Cilium lifecycle operator of Isovalent Networking for Kubernetes" \
      maintainer="support@isovalent.com" \
      vendor="Isovalent" \
      release="1" \
      summary="CLife, Cilium lifecycle operator of Isovalent Networking for Kubernetes" \
      description="Image of CLife, Cilium lifecycle operator of Isovalent Networking for Kubernetes built on top of Red Hat Universal Base Image" \
      org.opencontainers.image.authors="Isovalent" \
      org.opencontainers.image.url="https://isovalent.com" \
      org.opencontainers.image.documentation="https://isovalent.com/product" \
      org.opencontainers.image.vendor="Isovalent, part of Cisco" \
      org.opencontainers.image.title="Isovalent Networking for Kubernetes CLife image" \
      org.opencontainers.image.description="Image of the Cilium lifecycle operator of Isovalent Networking for Kubernetes built on top of Red Hat Universal Base Image" \
      io.k8s.description="Image of the Cilium lifecycle operator of Isovalent Networking for Kubernetes built on top of Red Hat Universal Base Image" \
      io.k8s.display-name="CLife, Cilium lifecycle operator of Isovalent Networking for Kubernetes"
ARG BUILD_DATE
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL build-date="${BUILD_DATE}"
ARG VERSION=0.0.0
LABEL version=${VERSION}

WORKDIR /
COPY LICENSE /usr/share/licenses/isovalent/
COPY LICENSE.all /usr/share/licenses/isovalent/LICENSE.dependencies
RUN ln -s /usr/share/licenses /licenses
COPY --from=builder /workspace/clife-manager .
COPY manifests/ manifests/
USER 65532:65532

ENTRYPOINT ["/clife-manager"]
