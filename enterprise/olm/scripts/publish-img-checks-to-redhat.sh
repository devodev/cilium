#!/usr/bin/env bash

# Copyright (C) Isovalent, Inc. - All Rights Reserved.

# This script runs Red Hat preflight checks against the release images and publish the results.
# CL_TAG: the tag use ford the release version
# CL_PYXIS_TOKEN: the authentication token for Red Hat pyxis API
# CL_ORG: the container repository organization, e.g. quay.io/isovalent
# CL_SUFFIX: the suffix added to the images, defaults to empty

set -o errexit
set -o pipefail
set -o nounset

root_dir=$(git rev-parse --show-toplevel)
values_file="${root_dir}/enterprise/olm/manifests/values.yaml"

if [ -z "${CL_TAG+x}" ] ; then
  echo "CL_TAG, containing the release version number, must be provided"
  exit 1
fi
tag="${CL_TAG}"
echo "tag: ${tag}"
submit_res="${CL_SUBMIT:-false}"
org="${CL_ORG:-quay.io/isovalent}"
suffix="${CL_SUFFIX:-}"

# renovate: datasource=docker depName=mikefarah/yq
yq_version=4.53.2
# yq_get retrieves values of fields in values.yaml
yq_get_result=""
function yq_get {
  yq_get_result=$(docker run --rm -v "${values_file}":/workdir/values.yaml --user "$(id -u):$(id -g)" mikefarah/yq:${yq_version} e "$1" /workdir/values.yaml)
}

# preflight runs Red Hat container checks
function preflight {
  image="$1"
  token="$2"
  component_id="$3"
  submit="$4"
  output="$5"
  cmd="check container ${image} \
          --pyxis-api-token=${token} \
          --certification-component-id=${component_id}"
  if [ ${submit} = true ]; then
    cmd="$cmd \
	  --submit"
  fi
  echo "docker run --rm quay.io/opdev/preflight:stable ${cmd}  > $output"
  docker run --rm quay.io/opdev/preflight:stable ${cmd}  > $output
}

function preflight-eval {
  result_file="$1"
  for result in $(cat ${result_file} | jq '.passed'); do
     if [ $result != true ]; then
       return 1
     fi
  done
  return 0
}

res="preflight-res.json"
image="quay.io/isovalent/certgen-ubi:${tag}"
component_id="67e510bca8b964f645ea917c"
declare -A images
images+=( [0]="${org}/certgen-ubi" )
images+=( [1]="${org}/cilium-envoy-ubi" )
images+=( [2]="${org}/cilium-ubi" )
images+=( [3]="${org}/clife" )
images+=( [4]="${org}/clustermesh-apiserver-ubi" )
images+=( [5]="${org}/hubble-relay-ubi" )
images+=( [6]="${org}/operator-generic-ubi" )
images+=( [7]="${org}/startup-script-ubi" )
images+=( [8]="${org}/kubectl-ubi" )

declare -A cid
cid+=( [0]='67e510bca8b964f645ea917c' )
cid+=( [1]='67e26859ba4cf5e133ebf57e' )
cid+=( [2]='67e1161434298d081056926a' )
cid+=( [3]='682318ae567dc9a13d0e849b' )
cid+=( [4]='67e24f5acc50155a8ce3c950' )
cid+=( [5]='67e2482773fd1d2194aab2c3' )
cid+=( [6]='67e134c5c66279ded73d5d6f' )
cid+=( [7]='67e50d549096ba2e8e40446d' )
cid+=( [8]='699dac1e3fbf700b49c88f7d' )

declare -A tags
yq_get ".certgen.image.tag"
tags+=( [0]="${yq_get_result}" )
yq_get ".envoy.image.tag"
tags+=( [1]="${yq_get_result}" )
yq_get ".image.tag"
tags+=( [2]="${yq_get_result}" )
# CLife
tags+=( [3]="${tag}" )
yq_get ".clustermesh.apiserver.image.tag"
tags+=( [4]="${yq_get_result}" )
yq_get ".hubble.relay.image.tag"
tags+=( [5]="${yq_get_result}" )
yq_get ".operator.image.tag"
tags+=( [6]="${yq_get_result}" )
yq_get ".nodeinit.image.tag"
tags+=( [7]="${yq_get_result}" )
yq_get ".envoy.kubectl.image.tag"
tags+=( [8]="${yq_get_result}" )

for i in "${!images[@]}"; do
  preflight ${images[$i]}${suffix}:${tags[$i]} $CL_PYXIS_TOKEN ${cid[$i]} false $res
  if ! preflight-eval $res ; then
    echo "Preflight checks failed for image: ${images[i]}${suffix}:${tags[$i]}"
    cat $res
    exit 1
  fi
  i=$((i + 1))
done
echo "Preflight checks passed"

if [ "${submit_res}" == "true" ]; then
  for i in "${!images[@]}"; do
    preflight ${images[$i]}${suffix}:${tags[$i]} $CL_PYXIS_TOKEN ${cid[$i]} true $res
    if ! preflight-eval $res ; then
      echo "Preflight checks failed during submission for image: ${images[$i]}${suffix}:${tags[$i]}"
      cat $res
      exit 1
    fi
    i=$((i + 1))
  done
  echo "Preflight results submitted"
else
   echo "Preflight results submission disabled"
fi
