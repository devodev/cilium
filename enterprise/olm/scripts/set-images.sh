#!/usr/bin/env bash

# Copyright (C) Isovalent, Inc. - All Rights Reserved.

# This script looks at the current state and the environment variables set
# to populate helm values with the matching image versions.
# CL_REGISTRY: select a specific registry, defaults to quay.io/isovalent-dev
# CL_SUFFIX: whether a suffix needs to get appended, defaults to -ubi
# CL_IS_CI: whether an additional -ci suffix needs to get appended, defaults to true
# CL_TAG: the tag to use for in-tree images, defaults to the commit id of the head
# CRANE: the location of the crane binary

set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=docker depName=mikefarah/yq
yq_version=4.53.2  

root_dir=$(git rev-parse --show-toplevel)
values_file="${root_dir}/enterprise/olm/manifests/values.yaml"
registry="${CL_REGISTRY:-quay.io/isovalent-dev}"
is_ci="${CL_IS_CI:-true}"
echo "is_ci: ${is_ci}"
base_suffix="${CL_SUFFIX:--ubi}"
suffix="${base_suffix}"
if [ "${is_ci}" == "true" ]; then
  suffix="${suffix}-ci"
fi
echo "suffix: ${suffix}"
if [ -z "${CL_TAG+x}" ] ; then
  echo "Using the commit id of the head as tag, set CL_TAG to the desired value otherwise"
  tag="$(git rev-parse HEAD)"
else
  tag="${CL_TAG}"
fi
echo "tag: ${tag}"
crane="${CRANE:-${root_dir}/enterprise/olm/bin/crane}"
# Using a temporary file avoid getting a half processed result file if an issue occurs
tmp_file=$(mktemp)
function cleanup {
  rm -rf "${tmp_file}"
}
trap cleanup EXIT
trap cleanup SIGINT

cp "${values_file}" "${tmp_file}"
# yq_replace makes in place modifications of values.yaml
function yq_replace {
  docker run --rm -v "${tmp_file}":/workdir/values.yaml --user "$(id -u):$(id -g)" mikefarah/yq:${yq_version} e -i "$1" /workdir/values.yaml
}

# yq_get retrieves values of fields in values.yaml
yq_get_result=""
function yq_get {
  yq_get_result=$(docker run --rm -v "${tmp_file}":/workdir/values.yaml --user "$(id -u):$(id -g)" mikefarah/yq:${yq_version} e "$1" /workdir/values.yaml)
}

# get_digest gives the digest of the image from the image reference and tag
get_digest_result=""
function get_digest {
  get_digest_result=$(${crane} digest "$1:$2")
}
# $tmp_config gets mounted with yq_replace and -i is used
# Set the image tags
yq_replace ".image.tag = \"${tag}\""
yq_replace ".preflight.image.tag = \"${tag}\""
yq_replace ".operator.image.tag = \"${tag}\""
yq_replace ".hubble.relay.image.tag = \"${tag}\""
yq_replace ".clustermesh.apiserver.image.tag = \"${tag}\""
if [ "${is_ci}" != "true" ]; then
  yq_replace ".nodeinit.image.tag = \"${tag}\""
  yq_replace ".certgen.image.tag = \"${tag}\""
  yq_replace ".envoy.image.tag = \"${tag}\""
  yq_replace ".preflight.envoy.image.tag = \"${tag}\""
  yq_replace ".envoy.kubectl.image.tag = \"${tag}\""
fi
# Set the image repositories
yq_replace ".image.repository = \"${registry}/cilium${suffix}\""
yq_replace ".preflight.image.repository = \"${registry}/cilium${suffix}\""
yq_replace ".hubble.relay.image.repository = \"${registry}/hubble-relay${suffix}\""
yq_replace ".clustermesh.apiserver.image.repository = \"${registry}/clustermesh-apiserver${suffix}\""
yq_replace ".nodeinit.image.repository = \"${registry}/startup-script${suffix}\""
yq_replace ".certgen.image.repository = \"${registry}/certgen${suffix}\""
# Envoy UBI image is not build in isovalent/cilium but in isovalent/proxy workflow.
# It is an enterprise only external image.
yq_replace ".envoy.image.repository = \"${registry}/cilium-envoy${base_suffix}\""
yq_replace ".preflight.envoy.image.repository = \"${registry}/cilium-envoy${base_suffix}\""
yq_replace ".envoy.kubectl.image.repository = \"${registry}/kubectl${suffix}\""
yq_replace ".operator.image.repository = \"${registry}/operator\""
yq_replace ".operator.image.suffix = \"${suffix}\""
# cilium agent
echo "Process cilium agent"
yq_get ".image.repository"
img=${yq_get_result}
echo "get digest: ${img} ${tag}" 
get_digest "${img}" "${tag}"
digest=${get_digest_result}
echo "digest: ${digest}"
yq_replace ".image.digest = \"${digest}\""
yq_replace ".image.useDigest = true"
# preflight
echo "Process preflight"
yq_get ".preflight.image.repository"
img=${yq_get_result}
echo "get digest: ${img} ${tag}"
get_digest "${img}" "${tag}"
digest=${get_digest_result}
echo "digest: ${digest}"
yq_replace ".preflight.image.digest = \"${digest}\""
yq_replace ".preflight.image.useDigest = true"
# hubble relay
echo "Process hubble relay"
yq_get ".hubble.relay.image.repository"
img=${yq_get_result}
echo "get digest: ${img} ${tag}" 
get_digest "${img}" "${tag}"
echo "digest: ${digest}"
digest=${get_digest_result}
yq_replace ".hubble.relay.image.digest = \"${digest}\""
yq_replace ".hubble.relay.image.useDigest = true"
# clustermesh
echo "Process clustermesh"
yq_get ".clustermesh.apiserver.image.repository"
img=${yq_get_result}
echo "get digest: ${img} ${tag}" 
get_digest "${img}" "${tag}"
digest=${get_digest_result}
echo "digest: ${digest}"
yq_replace ".clustermesh.apiserver.image.digest = \"${digest}\""
yq_replace ".clustermesh.apiserver.image.useDigest = true"
# startup-script
echo "Process startup-script"
yq_get ".nodeinit.image.repository"
img=${yq_get_result}
yq_get ".nodeinit.image.tag"
startup_tag=${yq_get_result}
echo "get digest: ${img} ${startup_tag}"
get_digest "${img}" "${startup_tag}"
digest=${get_digest_result}
echo "digest: ${digest}"
yq_replace ".nodeinit.image.digest = \"${digest}\""
yq_replace ".nodeinit.image.useDigest = true"
# certgen
echo "Process certgen"
yq_get ".certgen.image.repository"
img=${yq_get_result}
yq_get ".certgen.image.tag"
certgen_tag=${yq_get_result}
echo "get digest: ${img} ${certgen_tag}"
get_digest "${img}" "${certgen_tag}"
digest=${get_digest_result}
echo "digest: ${digest}"
yq_replace ".certgen.image.digest = \"${digest}\""
yq_replace ".certgen.image.useDigest = true"
# envoy
echo "Process envoy"
yq_get ".envoy.image.repository"
img=${yq_get_result}
yq_get ".envoy.image.tag"
envoy_tag=${yq_get_result}
echo "get digest: ${img} ${envoy_tag}"
get_digest "${img}" "${envoy_tag}"
digest=${get_digest_result}
echo "digest: ${digest}"
yq_replace ".envoy.image.digest = \"${digest}\""
yq_replace ".envoy.image.useDigest = true"
echo "Process preflight envoy"
yq_get ".preflight.envoy.image.repository"
img=${yq_get_result}
yq_get ".preflight.envoy.image.tag"
envoy_tag=${yq_get_result}
echo "get digest: ${img} ${envoy_tag}"
get_digest "${img}" "${envoy_tag}"
digest=${get_digest_result}
echo "digest: ${digest}"
yq_replace ".preflight.envoy.image.digest = \"${digest}\""
yq_replace ".preflight.envoy.image.useDigest = true"

# kubectl
echo "Process kubectl"
yq_get ".envoy.kubectl.image.repository"
img=${yq_get_result}
yq_get ".envoy.kubectl.image.tag"
kubectl_tag=${yq_get_result}
echo "get digest: ${img} ${kubectl_tag}"
get_digest "${img}" "${kubectl_tag}"
digest=${get_digest_result}
echo "digest: ${digest}"
yq_replace ".envoy.kubectl.image.digest = \"${digest}\""
yq_replace ".envoy.kubectl.image.useDigest = true"
# operator
echo "Process operator"
yq_get ".operator.image.repository"
img=${yq_get_result}
yq_get ".operator.image.suffix"
op_suffix=${yq_get_result}
echo "get digest: ${img}-generic${op_suffix} ${tag}" 
get_digest "${img}-generic${op_suffix}" "${tag}"
digest=${get_digest_result}
echo "digest: ${digest}"
yq_replace ".operator.image.genericDigest = \"${digest}\""
yq_replace ".operator.image.useDigest = true"
cp "${tmp_file}" "${values_file}"

echo "values.yaml updated"
