# Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Isovalent Inc and its suppliers, if any. The intellectual and technical
# concepts contained herein are proprietary to Isovalent Inc and its suppliers
# and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law. Dissemination of this information
# or reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Isovalent Inc.

FROM vmware/vcsim:v0.54.0@sha256:5aea60be9fd57e7096f55bfecab49dca0ba95cd3faf013ebe0edf07a8d4d00a6 AS vcsim

FROM vmware/govc:v0.54.0@sha256:e8942979db4ba548ee767a2f6544f4466fd1e387a315b2684e9d7abe10f2f840 AS govc

FROM docker.io/library/alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
COPY --from=vcsim /vcsim /usr/bin/vcsim
COPY --from=govc /govc /usr/bin/govc
