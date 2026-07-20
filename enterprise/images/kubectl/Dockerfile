ARG BASE_IMAGE=debian:13.6-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd

FROM debian:13.6-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd AS downloader

# renovate: datasource=github-releases depName=kubernetes/kubernetes
ARG KUBECTL_VERSION=v1.34.2
ARG TARGETARCH

# Download kubectl for the target architecture.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates;
RUN set -euo pipefail; \
    curl -L -o /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl";

FROM ${BASE_IMAGE} AS release

LABEL name="Kubectl for Isovalent Networking for Kubernetes" \
      maintainer="support@isovalent.com" \
      vendor="Isovalent" \
      release="1" \
      summary="Kubectl for Isovalent Networking for Kubernetes" \
      description="Image of the Kubectl for Isovalent Networking for Kubernetes built on top of a minimal Linux base image" \
      org.opencontainers.image.authors="Isovalent" \
      org.opencontainers.image.url="https://isovalent.com" \
      org.opencontainers.image.documentation="https://isovalent.com/product" \
      org.opencontainers.image.vendor="Isovalent, part of Cisco" \
      org.opencontainers.image.title="Isovalent Networking for Kubernetes Kubectl" \
      org.opencontainers.image.description="Image of the Kubectl for Isovalent Networking for Kubernetes" \
      io.k8s.description="Image of the Kubectl for Isovalent Networking for Kubernetes" \
      io.k8s.display-name="Kubectl for Isovalent Networking for Kubernetes"

LABEL org.opencontainers.image.created="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
ARG VERSION=0.0.0
LABEL version=${VERSION}

# Install kubectl for the target architecture.
COPY --from=downloader /usr/local/bin/kubectl /usr/local/bin/kubectl
RUN chmod +x /usr/local/bin/kubectl

COPY LICENSE /usr/share/licenses/isovalent/
RUN ln -s /usr/share/licenses /licenses
# use uid:gid for the nonroot user for compatibility with runAsNonRoot
USER 65532:65532

CMD ["kubectl"]
