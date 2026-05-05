#!/usr/bin/env bash

# Copyright (C) Isovalent, Inc. - All Rights Reserved.

# This script generates the release-config.yaml file for the Red Hat certified operators repository.
# Based on this file a newly published bundle gets added to the defined channels and Red Hat catalogs
# automatically updated accordingly.
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

# renovate: datasource=docker depName=mikefarah/yq
yq_version=4.46.1

bundle_major=$(echo "$CL_TAG" | cut -d \. -f 1)
bundle_major=${bundle_major#v}
bundle_minor=$(echo "$CL_TAG" | cut -d \. -f 2)
release_file=release-config.yaml
template_file=template.yaml

# Retrieve existing channel entries for the current minor
channel_name="${bundle_major}.${bundle_minor}"
entries=$(docker run --rm -v "${rh_repo}/operators/isovalent-networking/catalog-templates":/workdir mikefarah/yq:${yq_version} ".entries[] | select (.schema == \"olm.channel\" and .name == \"${channel_name}\") | .entries[].name" /workdir/${template_file})

replaces_entry=""
skip_from=""

if [ -z "${entries}" ]; then
  # This is a new minor release channel.
  echo "Creating new minor release channel: ${channel_name}"
  previous_minor=$(( bundle_minor - 1 ))
  previous_channel_name="${bundle_major}.${previous_minor}"
  previous_entries=$(docker run --rm -v "${rh_repo}/operators/isovalent-networking/catalog-templates":/workdir mikefarah/yq:${yq_version} ".entries[] | select (.schema == \"olm.channel\" and .name == \"${previous_channel_name}\") | .entries[].name" /workdir/${template_file})

  if [ -n "${previous_entries}" ]; then
    sorted_previous=$(echo "${previous_entries}" | sort -V)
    latest_previous_entry=$(echo "${sorted_previous}" | tail -1)
    replaces_entry=${latest_previous_entry}
    skip_from=${latest_previous_entry}

    # Add the new channel to template.yaml
    docker run --rm -v "${rh_repo}/operators/isovalent-networking/catalog-templates":/workdir mikefarah/yq:${yq_version} -i \
      ".entries += [{\"schema\": \"olm.channel\", \"name\": \"${channel_name}\", \"package\": \"clife\", \"entries\": [{\"name\": \"${latest_previous_entry}\"}]}]" \
      /workdir/${template_file}

    # Update the default channel
    docker run --rm -v "${rh_repo}/operators/isovalent-networking/catalog-templates":/workdir mikefarah/yq:${yq_version} -i \
      "(.entries[] | select(.schema == \"olm.package\")).defaultChannel = \"${channel_name}\"" \
      /workdir/${template_file}
  else
    echo "New major release!!!"
  fi
else
  # This is a patch release for an existing channel.
  echo "Adding patch release to existing channel: ${channel_name}"
  sorted=$(echo "${entries}" | sort -V)
  replaces_entry=$(echo "${sorted}" | tail -1)
  
  # For skipRange, use the last entry from the PREVIOUS channel
  previous_minor=$(( bundle_minor - 1 ))
  previous_channel_name="${bundle_major}.${previous_minor}"
  previous_entries=$(docker run --rm -v "${rh_repo}/operators/isovalent-networking/catalog-templates":/workdir mikefarah/yq:${yq_version} ".entries[] | select (.schema == \"olm.channel\" and .name == \"${previous_channel_name}\") | .entries[].name" /workdir/${template_file})
  
  if [ -n "${previous_entries}" ]; then
    sorted_previous=$(echo "${previous_entries}" | sort -V)
    skip_from=$(echo "${sorted_previous}" | tail -1)
    
    # clife.v1.17.6-cee.1 was wrongly named clife.v0.0.1.
    # Don't use it in the skipRange.
    if [ "${skip_from}" = "clife.v0.0.1" ]; then
      skip_from=$(echo "${sorted_previous}" | sed -n '2p')
    fi
  else
    # Fallback: if no previous channel exists (edge case)
    skip_from=$(echo "${sorted}" | head -1)
    if [ "${skip_from}" = "clife.v0.0.1" ]; then
      skip_from=$(echo "${sorted}" | sed -n '2p')
    fi
  fi
fi

template="---
catalog_templates:
  - template_name: template.yaml
    channels: [\"${channel_name}\"]"
if [ -n "${replaces_entry}" ]; then
  template="${template}
    replaces: ${replaces_entry}"
fi
if [ -n "${skip_from}" ]; then
  skip_from_version=$(echo "${skip_from}" | sed -e "s/clife.v//")
  template="${template}
    skipRange: \">=${skip_from_version} <${tag#v}\""
fi

echo "Generated release-config.yaml:
${template}"
echo "${template}" > "${rh_repo}/operators/isovalent-networking/${tag}/${release_file}"
