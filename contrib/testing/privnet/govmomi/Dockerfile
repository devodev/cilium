# Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Isovalent Inc and its suppliers, if any. The intellectual and technical
# concepts contained herein are proprietary to Isovalent Inc and its suppliers
# and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law. Dissemination of this information
# or reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Isovalent Inc.

FROM vmware/vcsim:v0.53.1@sha256:c99de0dceae5a41176eb7badea7d61774dd19775aaabb94fa4b3d00eff0f63dd AS vcsim

FROM vmware/govc:v0.53.1@sha256:f3494a3f4086a202972430716c0dc829fc244802e382e78c229f0fb303061963 AS govc

FROM docker.io/library/alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
COPY --from=vcsim /vcsim /usr/bin/vcsim
COPY --from=govc /govc /usr/bin/govc
