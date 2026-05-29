#!/usr/bin/env bash

# Copyright (C) Isovalent, Inc. - All Rights Reserved.

# This script generates the bundle manifests and populates the Red Hat certified operators repository with them
# CL_TAG: the tag use ford the release version
# CL_RH_REPO: the location of the Red Hat repository

set -o errexit
set -o pipefail
set -o nounset

if [ -z "${CL_TAG+x}" ] ; then
  echo "CL_TAG, containing the release version number, must be provided"
  exit 1
fi
tag="${CL_TAG}"
echo "tag: ${tag}"
rh_repo="${CL_RH_REPO}"
echo "Red Hat certified operators repo: ${rh_repo}"
root_dir=$(git rev-parse --show-toplevel)

# Generate manifests
export CL_IS_CI=false
export CL_TAG=$tag
export CL_REGISTRY=containers.isovalent.com
export IMG=${CL_REGISTRY}/clife:${tag}
export USE_IMAGE_DIGESTS=true
export VERSION=${tag#v}
make manifests
make set-images
make bundle

mkdir -p "${rh_repo}/operators/isovalent-networking/${tag#v}"
cp -R ${root_dir}/enterprise/olm/bundle/manifests "${rh_repo}/operators/isovalent-networking/${tag#v}/"
cp -R ${root_dir}/enterprise/olm/bundle/metadata "${rh_repo}/operators/isovalent-networking/${tag#v}/"
echo "  # Red Hat annotations"  >> "${rh_repo}/operators/isovalent-networking/${tag#v}/metadata/annotations.yaml"
echo "  com.redhat.openshift.versions: \"v4.14\"" >> "${rh_repo}/operators/isovalent-networking/${tag#v}/metadata/annotations.yaml"

echo "Bundle manifests and metadata added"

