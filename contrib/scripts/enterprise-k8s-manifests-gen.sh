#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

##@ API targets
# Set CRD_OPTIONS if not already set
CRD_OPTIONS="${CRD_OPTIONS:-"crd:crdVersions=v1,allowDangerousTypes=true"}"

# Set CRD_PATHS using the current working directory
CRD_PATHS="${SCRIPT_ROOT}/../../pkg/k8s/apis/isovalent.com/v1;${SCRIPT_ROOT}/../../pkg/k8s/apis/isovalent.com/v1alpha1;"

# Set CRDS_ISOVALENT_PATHS using the current working directory
CRDS_ISOVALENT_PATHS="${SCRIPT_ROOT}/../../pkg/k8s/apis/isovalent.com/client/crds/v1 ${SCRIPT_ROOT}/../../pkg/k8s/apis/isovalent.com/client/crds/v1alpha1"

# Set CRDS_ISOVALENT_V1 with the list of CRDs for v1alpha1
CRDS_ISOVALENT_V1="isovalentegressgatewaypolicies \
                   isovalentbgpclusterconfigs \
                   isovalentbgppeerconfigs \
                   isovalentbgpadvertisements \
                   isovalentbgpnodeconfigs \
                   isovalentbgpnodeconfigoverrides \
                   isovalentbgppolicies"

# Set CRDS_ISOVALENT_V1ALPHA1 with the list of CRDs for v1alpha1
CRDS_ISOVALENT_V1ALPHA1="isovalentfqdngroups \
                         isovalentinspectionconfigs \
                         isovalentsrv6sidmanagers \
                         isovalentsrv6locatorpools \
                         isovalentsrv6egresspolicies \
                         isovalentvrfs \
                         isovalentmulticastgroups \
                         isovalentmulticastnodes \
                         isovalentbfdprofiles \
                         isovalentbfdnodeconfigs \
                         isovalentbfdnodeconfigoverrides \
                         isovalentbgpvrfconfigs \
                         isovalentclusterwideencryptionpolicies \
                         isovalentwafpolicies \
                         lbservices \
                         lbbackendpools \
                         lbvips \
                         lbdeployments \
                         isovalentclusterwidenetworkpolicies \
                         isovalentnetworkpolicies \
                         clusterwideprivatenetworks \
                         privatenetworkendpointslices \
                         privatenetworkexternalendpoints \
                         privatenetworknodeattachments \
                         lbk8sbackendclusters \
                         fabricsecuritygroups \
                         isovalentcorevrfs \
                         isovalentcorevrfnodestatuses"

TMPDIR=$(mktemp -d -t cilium.tmpXXXXXXXX)
go run sigs.k8s.io/controller-tools/cmd/controller-gen ${CRD_OPTIONS} paths="${CRD_PATHS}" output:crd:artifacts:config="${TMPDIR}"
go run ${SCRIPT_ROOT}/../../tools/crdcheck "${TMPDIR}"

# Hack: IsovalentNetworkPolicy / IsovalentClusterwideNetworkPolicy embeds
# api.Rule, but adds additional fields. That's fine, but api.Rule has an
# AnyOf constraint that doesn't match INP / ICNP. So, add the relevant additional
# fields of egressPass and ingressPass to the AnyOf constraint.
for name in isovalentclusterwidenetworkpolicies isovalentnetworkpolicies; do
    file="${TMPDIR}/isovalent.com_${name}.yaml"
    yq -i '(.spec.versions[] | select (.name=="v1").schema.openAPIV3Schema.properties.spec.anyOf) += {"properties": {"ingressPass": {}}, "required": ["ingressPass"]}' "${file}"
    yq -i '(.spec.versions[] | select (.name=="v1").schema.openAPIV3Schema.properties.spec.anyOf) += {"properties": {"egressPass": {}}, "required": ["egressPass"]}' "${file}"
    yq -i '(.spec.versions[] | select (.name=="v1").schema.openAPIV3Schema.properties.specs.items.anyOf) += {"properties": {"ingressPass": {}}, "required": ["ingressPass"]}' "${file}"
    yq -i '(.spec.versions[] | select (.name=="v1").schema.openAPIV3Schema.properties.specs.items.anyOf) += {"properties": {"egressPass": {}}, "required": ["egressPass"]}' "${file}"
done

# Clean up old CRD state and start with a blank state.
for path in ${CRDS_ISOVALENT_PATHS}; do
	rm -rf "${path}" && mkdir "${path}"
done

for file in ${CRDS_ISOVALENT_V1}; do
	mv "${TMPDIR}/isovalent.com_${file}.yaml" "${SCRIPT_ROOT}/../../pkg/k8s/apis/isovalent.com/client/crds/v1/${file}.yaml"
done

for file in ${CRDS_ISOVALENT_V1ALPHA1}; do
	mv "${TMPDIR}/isovalent.com_${file}.yaml" "${SCRIPT_ROOT}/../../pkg/k8s/apis/isovalent.com/client/crds/v1alpha1/${file}.yaml"
done

rm -rf "${TMPDIR}"

# Lifecycle operator
# Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
go run sigs.k8s.io/controller-tools/cmd/controller-gen rbac:roleName=manager-role crd webhook paths="${SCRIPT_ROOT}/../../enterprise/olm/..." output:crd:artifacts:config="${SCRIPT_ROOT}/../../enterprise/olm/config/crd/bases" output:rbac:artifacts:config="${SCRIPT_ROOT}/../../enterprise/olm/config/rbac"
go run ${SCRIPT_ROOT}/../../tools/crdcheck "${SCRIPT_ROOT}/../../enterprise/olm/config/crd/bases"
