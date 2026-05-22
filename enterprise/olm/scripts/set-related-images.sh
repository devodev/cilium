#!/usr/bin/env bash

# Copyright (C) Isovalent, Inc. - All Rights Reserved.

# This script looks at the current state and the environment variables set
# to populate the relatedImages field in the ClusterServiceVersion with the matching image versions.
# Due to the way opm works the base for ClusterServiceVersion is not updated but environment variables
# are set on the manager deployment, which get later added to the relatedImages field of the rendered
# ClusterServiceVersion.
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

# yq_replace_mgr makes in place modifications of manager.yaml
function yq_replace_mgr {
  docker run --rm -v "${root_dir}/enterprise/olm/config/manager/manager.yaml":/workdir/manager.yaml --user "$(id -u):$(id -g)" mikefarah/yq:${yq_version} e -i "$1" /workdir/manager.yaml
}

# yq_get_mgr_json retrieves values of fields in manager.yaml and gives a json format as output
yq_get_mgr_result=""
function yq_get_mgr_json {
  yq_get_mgr_result=$(docker run --rm -v "${root_dir}/enterprise/olm/config/manager/manager.yaml":/workdir/manager.yaml --user "$(id -u):$(id -g)" mikefarah/yq:${yq_version} e -o=json "$1" /workdir/manager.yaml)
}

# yq_get retrieves values of fields in values.yaml
yq_get_result=""
function yq_get {
  yq_get_result=$(docker run --rm -v "${values_file}":/workdir/values.yaml --user "$(id -u):$(id -g)" mikefarah/yq:${yq_version} e "$1" /workdir/values.yaml)
}

# get_digest gives the digest of the image from the image reference and tag
get_digest_result=""
function get_digest {
  get_digest_result=$(${crane} digest "$1:$2")
}

# Get the image digests and populate related images in the ClusterServiceVersion
related_imgs="["
# cilium agent
echo "Process cilium agent"
echo "get digest: ${registry}/cilium${suffix} ${tag}" 
get_digest "${registry}/cilium${suffix}" "${tag}"
digest=${get_digest_result}
echo "digest: ${digest}"
related_imgs+="{\"name\": \"RELATED_IMAGE_AGENT\",\"value\":\"${registry}/cilium${suffix}:${tag}@${digest}\"},"
# preflight
echo "Preflight does not need to be added to relatedImages as long as it is the same image as Cilium agent."
echo "opm does not accept the same image being referenced multiple times."
# echo "Process preflight"
# echo "get digest: ${registry}/cilium${suffix} ${tag}"
# get_digest "${registry}/cilium${suffix}" "${tag}"
# digest=${get_digest_result}
# echo "digest: ${digest}"
# related_imgs+="{\"name\": \"RELATED_IMAGE_PREFLIGHT\",\"value\":\"${registry}/cilium${suffix}:${tag}@${digest}\"},"
# hubble relay
echo "Process hubble relay"
echo "get digest: ${registry}/hubble-relay${suffix} ${tag}" 
get_digest "${registry}/hubble-relay${suffix}" "${tag}"
echo "digest: ${digest}"
digest=${get_digest_result}
related_imgs+="{\"name\": \"RELATED_IMAGE_HUBBLE-RELAY\",\"value\":\"${registry}/hubble-relay${suffix}:${tag}@${digest}\"},"
# clustermesh
echo "Process clustermesh"
echo "get digest: ${registry}/clustermesh-apiserver${suffix} ${tag}" 
get_digest "${registry}/clustermesh-apiserver${suffix}" "${tag}"
digest=${get_digest_result}
echo "digest: ${digest}"
related_imgs+="{\"name\": \"RELATED_IMAGE_CLUSTERMESH-APISERVER\",\"value\":\"${registry}/clustermesh-apiserver${suffix}:${tag}@${digest}\"},"
# startup-script
echo "Process startup-script"
if [ "${is_ci}" == "true" ]; then
  yq_get ".nodeinit.image.tag"
  startup_tag=${yq_get_result}
else
  startup_tag=${tag}
fi
echo "get digest: ${registry}/startup-script${suffix} ${startup_tag}" 
get_digest "${registry}/startup-script${suffix}" "${startup_tag}"
digest=${get_digest_result}
echo "digest: ${digest}"
related_imgs+="{\"name\": \"RELATED_IMAGE_NODEINIT\",\"value\":\"${registry}/startup-script${suffix}:${startup_tag}@${digest}\"},"
# certgen
echo "Process certgen"
if [ "${is_ci}" == "true" ]; then
  yq_get ".certgen.image.tag"
  certgen_tag=${yq_get_result}
else
  certgen_tag=${tag}
fi
echo "get digest: ${registry}/certgen${suffix} ${certgen_tag}" 
get_digest "${registry}/certgen${suffix}" "${certgen_tag}"
digest=${get_digest_result}
echo "digest: ${digest}"
related_imgs+="{\"name\": \"RELATED_IMAGE_CERTGEN\",\"value\":\"${registry}/certgen${suffix}:${certgen_tag}@${digest}\"},"
# envoy
echo "Process envoy"
if [ "${is_ci}" == "true" ]; then
  yq_get ".envoy.image.tag"
  envoy_tag=${yq_get_result}
else
  envoy_tag=${tag}
fi
echo "get digest: ${registry}/cilium-envoy${base_suffix} ${envoy_tag}"
get_digest "${registry}/cilium-envoy${base_suffix}" "${envoy_tag}"
digest=${get_digest_result}
echo "digest: ${digest}"
related_imgs+="{\"name\": \"RELATED_IMAGE_CILIUM-ENVOY\",\"value\":\"${registry}/cilium-envoy${base_suffix}:${envoy_tag}@${digest}\"},"
# kubectl
echo "Process kubectl"
if [ "${is_ci}" == "true" ]; then
  yq_get ".envoy.kubectl.image.tag"
  kubectl_tag=${yq_get_result}
else
  kubectl_tag=${tag}
fi
echo "get digest: ${registry}/kubectl${suffix} ${kubectl_tag}" 
get_digest "${registry}/kubectl${suffix}" "${kubectl_tag}"
digest=${get_digest_result}
echo "digest: ${digest}"
related_imgs+="{\"name\": \"RELATED_IMAGE_KUBECTL\",\"value\":\"${registry}/kubectl${suffix}:${kubectl_tag}@${digest}\"},"
# operator
echo "Process operator"
echo "get digest: ${registry}/operator-generic${suffix} ${tag}" 
get_digest "${registry}/operator-generic${suffix}" "${tag}"
digest=${get_digest_result}
echo "digest: ${digest}"
related_imgs+="{\"name\": \"RELATED_IMAGE_CILIUM-OPERATOR\",\"value\":\"${registry}/operator-generic${suffix}:${tag}@${digest}\"}"

related_imgs+="]"
# the deployment is the second document in the manifest file
yq_get_mgr_json "select(documentIndex == 1) | .spec.template.spec.containers[0].env | filter(.name != \"RELATED_IMAGE_*\")"
env_vars=${yq_get_mgr_result}
echo "existing variables:"
echo "${env_vars}"
yq_replace_mgr "(select(documentIndex == 1) | .spec.template.spec.containers[0].env) = ${env_vars}"
yq_replace_mgr "(select(documentIndex == 1) | .spec.template.spec.containers[0].env) += ${related_imgs}"

echo "Manager updated"
