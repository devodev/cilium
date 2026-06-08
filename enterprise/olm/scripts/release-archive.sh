#!/usr/bin/env bash

# Copyright (C) Isovalent, Inc. - All Rights Reserved.

# This script generates an archive and its checksum with the manifests used for deploying
# Isovalent Networking for Kubernetes using CLife.

set -o errexit
set -o pipefail
set -o nounset

olm_dir=$(git rev-parse --show-toplevel)/enterprise/olm

if [ -z "${CL_TAG+x}" ] ; then
  echo "CL_TAG, containing the release version number, must be provided"
  exit 1
fi
version=$(echo "$CL_TAG" | cut -d \- -f -1 | cut -d \+ -f -1)
echo "version: ${version}"
channel=$(echo "$version" | cut -d \. -f -2)
channel=${channel#v}

# renovate: datasource=docker depName=mikefarah/yq
yq_version=4.53.3

mkdir -p ${olm_dir}/.docs
cp ${olm_dir}/config/samples/cilium.io_v1alpha1_ciliumconfig.yaml ${olm_dir}/dist/manifests/ciliumconfig.yaml
cp ${olm_dir}/config/samples/operatorgroup.yaml ${olm_dir}/dist/manifests/
cp ${olm_dir}/config/samples/subscription.yaml ${olm_dir}/dist/manifests/
docker run --rm -v "${olm_dir}":/workdir --user "$(id -u):$(id -g)" mikefarah/yq:${yq_version} e -i ".spec.channel = \"${channel}\"" /workdir/dist/manifests/subscription.yaml
tar -czvf ${olm_dir}/.docs/clife-${version}.tar.gz -C ${olm_dir}/dist/manifests .
pushd ${olm_dir}/.docs
sha256sum clife-${version}.tar.gz > ${olm_dir}/.docs/clife-${version}.tar.gz.sha256
popd
