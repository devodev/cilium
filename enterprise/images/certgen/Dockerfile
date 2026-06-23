# Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Isovalent Inc and its suppliers, if any. The intellectual and technical
# concepts contained herein are proprietary to Isovalent Inc and its suppliers
# and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.  Dissemination of this information
# or reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Isovalent Inc.

ARG BASE_IMAGE=registry.redhat.io/ubi9/ubi-minimal:9.8@sha256:ae09ecc3d754bc1726cbda3e2599cc7839e09fe1cc547ce173cf669b645be3cc
ARG UPSTREAM_IMAGE=quay.io/cilium/certgen:v0.4.5@sha256:f107522ed4dcea62f918b8eb836142875a9b3e3cb2b2d728dc680f76cdbde6cf

FROM ${UPSTREAM_IMAGE} AS upstream

FROM ${BASE_IMAGE}

LABEL name="Isovalent UBI certgen image" \
    maintainer="support@isovalent.com" \
    vendor="Isovalent" \
    release="1" \
    summary="Isovalent certgen image based on Red Hat Universal Base Image" \
    description="This image extends Red Hat UBI image with tooling for generating certificates" \
    org.opencontainers.image.authors="Isovalent" \
    org.opencontainers.image.url="https://isovalent.com" \
    org.opencontainers.image.documentation="https://isovalent.com/product" \
    org.opencontainers.image.vendor="Isovalent, part of Cisco" \
    org.opencontainers.image.title="Isovalent UBI cergen image" \
    org.opencontainers.image.description="This image extends Red Hat UBI image with tooling for generating certificates"
ARG VERSION=0.0.0
LABEL version=${VERSION}

COPY LICENSE /usr/share/licenses/isovalent/
RUN ln -s /usr/share/licenses /licenses
COPY --from=upstream /usr/bin/cilium-certgen /usr/bin/cilium-certgen
ENTRYPOINT ["/usr/bin/cilium-certgen"]
