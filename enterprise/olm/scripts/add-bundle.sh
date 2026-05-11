#!/usr/bin/env bash

# Copyright (C) Isovalent, Inc. - All Rights Reserved.

# This script populates a catalog with a newly created bundle.
# It is meant for CI or local development where keeping the history of previous catalog configurations is not needed.
# For production catalog manifests shoud get versioned in GitHub.

set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=docker depName=mikefarah/yq
yq_version=4.45.1
# renovate: datasource=github-releases depName=operator-framework/operator-registry
opm_version=v1.67.0

root_dir="$(git rev-parse --show-toplevel)"
olm_dir="${root_dir}/enterprise/olm"
tag="$(git rev-parse --short HEAD)"
bundle_version="${BUNDLE_VERSION:-${tag}}"
default_channel="${DEFAULT_CHANNEL:-main-ce}"
channel="${CHANNEL:-main-ce}"
repo_base_name="${IMAGE_TAG_BASE:-quay.io/isovalent-dev/clife-ci}"
catalog_tag="${CATALOG_TAG:-latest}"

mkdir -p catalog-dev
if docker manifest inspect ${repo_base_name}-catalog:${catalog_tag}; then
  docker run --rm -v "${olm_dir}":/workdir quay.io/operator-framework/opm:${opm_version} render ${repo_base_name}-catalog:${catalog_tag} -o yaml > "${olm_dir}/catalog-dev/index.yaml"
else
  # Used for bootstrapping
  # TODO: check that the reinitilization of the catalog is not triggered by a connectivity or quay issue
  docker run --rm -v "${olm_dir}":/workdir quay.io/operator-framework/opm:${opm_version} init clife --default-channel="${default_channel}" --description=/workdir/catalog-README.md --icon=/workdir/isovalent.svg --output yaml > "${olm_dir}/catalog-dev/index.yaml"
fi
bundle=$(docker run --rm -v "${olm_dir}":/workdir mikefarah/yq:${yq_version} ".name | select(. == \"clife.v${bundle_version}\")" /workdir/catalog-dev/index.yaml)
if [ -n "$bundle" ]; then
  printf "Bundle clife.%s already present in catalog index\n" "${bundle_version}"
else
  printf "Adding the bundle clife.%s to the catalog\n" "${bundle_version}"
  docker run --rm -v "${olm_dir}":/workdir quay.io/operator-framework/opm:${opm_version} render ${repo_base_name}-bundle:v${bundle_version} --output=yaml >> "${olm_dir}/catalog-dev/index.yaml"
fi

# Add the channel if it does not exist
channel_snippet="---\nschema: olm.channel\npackage: clife\nname: \"${channel}\"\nentries:"
channel_yaml=$(docker run --rm -v "${olm_dir}":/workdir mikefarah/yq:${yq_version} ". | select (.schema == \"olm.channel\" and .name == \"${channel}\")" /workdir/catalog-dev/index.yaml)
if [ -z "$channel_yaml" ]; then
  printf "Adding the channel %s to the catalog\n" "${channel}"
  sed -i "/schema: olm.package/a ${channel_snippet}" "${olm_dir}/catalog-dev/index.yaml"
fi
# Get the channel entries
channel_entries=$(docker run --rm -v "${olm_dir}":/workdir mikefarah/yq:${yq_version} ". | select (.schema == \"olm.channel\" and .name == \"${channel}\") | .entries[]" /workdir/catalog-dev/index.yaml)

# Add the bundle to the channel if not already there
if [[ ! "${channel_entries}" =~ clife.v"${bundle_version}" ]]; then
  printf "Adding the bundle clife.%s to the channel ${channel}\n" "${bundle_version}"
  if [ -z "${channel_entries}" ]; then
    docker run --rm -v "${olm_dir}":/workdir --user "$(id -u):$(id -g)" mikefarah/yq:${yq_version} e -i "select (.schema == \"olm.channel\" and .name == \"${channel}\").entries = [{\"name\": \"clife.v${bundle_version}\"}]" /workdir/catalog-dev/index.yaml
  else
    # Retrieve the name of the last bundle in the channel
    readarray channel_entries < <(docker run --rm -v "${olm_dir}":/workdir mikefarah/yq:${yq_version} -o=j -I=0 ". | select (.schema == \"olm.channel\" and .name == \"${channel}\") | .entries[]" /workdir/catalog-dev/index.yaml)
    printf "channel entries:\n"
    printf "%s" "${channel_entries[@]}"
    nb_entries=${#channel_entries[@]}
    printf "number of entries %s\n" "${nb_entries}"
    printf "entry getting replaced %s\n" "${channel_entries[$((nb_entries-1))]}"
    last_name=$(echo "${channel_entries[$((nb_entries-1))]}" | jq .name -r)
    docker run --rm -v "${olm_dir}":/workdir --user "$(id -u):$(id -g)" mikefarah/yq:${yq_version} e -i "select (.schema == \"olm.channel\" and .name == \"${channel}\").entries = .entries + {\"name\": \"clife.v${bundle_version}\", \"replaces\": \"${last_name}\"}" /workdir/catalog-dev/index.yaml
  fi
else
  printf "Bundle clife.%s already part of the channel %s\n" "${bundle_version}" "${channel}"
fi
docker run --rm -v "${olm_dir}":/workdir quay.io/operator-framework/opm:${opm_version} validate /workdir/catalog-dev
