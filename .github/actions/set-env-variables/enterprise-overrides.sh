#!/usr/bin/env bash
#
# Use this script to override environment variables that get set in the
# upstream set-env-variables composite action.

set -ex

REGISTRY="quay.io"
REGISTRY_DEV="quay.io"
ARTIFACTORY_DEV="artifactory.devhub-cloud.cisco.com"
BACKUP_REGISTRY="docker.io"
echo "REGISTRY=$REGISTRY" >> $GITHUB_ENV
echo "REGISTRY_DEV=$REGISTRY_DEV" >> $GITHUB_ENV
echo "ARTIFACTORY_DEV=$ARTIFACTORY_DEV" >> $GITHUB_ENV
echo "BACKUP_REGISTRY=$BACKUP_REGISTRY" >> $GITHUB_ENV
echo "ORGANIZATION=isovalent-staging" >> $GITHUB_ENV
echo "ORGANIZATION_DEV=isovalent-dev" >> $GITHUB_ENV
echo "QUAY_ORGANIZATION=isovalent-staging" >> "$GITHUB_ENV"
echo "QUAY_ORGANIZATION_DEV=isovalent-dev" >> "$GITHUB_ENV"
echo "ARTIFACTORY_ORGANIZATION_DEV=isovalent-eng-docker" >> $GITHUB_ENV
echo "CILIUM_HELM_REPO_NAME=isovalent" >> "$GITHUB_ENV"
echo "CILIUM_HELM_REPO_URL=https://helm.isovalent.com" >> "$GITHUB_ENV"
echo "CILIUM_CLI_REPO=isovalent/cilium-cli-releases" >> "$GITHUB_ENV"
echo "CILIUM_OSS_HELM_REPO_NAME=cilium" >> $GITHUB_ENV
echo "CILIUM_OSS_HELM_REPO_URL=https://helm.cilium.io" >> $GITHUB_ENV
echo "CILIUM_OSS_CLI_REPO=cilium/cilium-cli" >> $GITHUB_ENV

echo "CHARTS_ORGANIZATION_DEV=isovalent-charts-dev" >> "$GITHUB_ENV"
echo "QUAY_CHARTS_ORGANIZATION_DEV=isovalent-charts-dev" >> "$GITHUB_ENV"
echo "QUAY_OSS_CHARTS_ORGANIZATION_DEV=cilium-charts-dev" >> $GITHUB_ENV
echo "BRANCH_SUFFIX=-ce" >> "$GITHUB_ENV"
echo "TAG_SUFFIX=-cee.1" >> "$GITHUB_ENV"
echo "EGRESS_GATEWAY_HELM_VALUES=--helm-set=egressGateway.enabled=true --helm-set=enterprise.egressGatewayHA.enabled=true \
    --helm-set=enterprise.egressGatewayHA.healthcheckTimeout=8s \
    --helm-set=enterprise.featureGate.approved='{EgressGatewayIPv4,EgressGatewayHA}'" >> "$GITHUB_ENV"
echo "BGP_CONTROL_PLANE_HELM_VALUES=--helm-set=enterprise.bgpControlPlane.enabled=true --helm-set=enterprise.bfd.enabled=true" >> "$GITHUB_ENV"
echo "CONN_DISRUPT_EXTRA_ARG=--include-conn-disrupt-test-egw-ha" >> "$GITHUB_ENV"
echo "CONN_DISRUPT_EXTRA_TEST=no-interrupted-connections-for-enterprise" >> "$GITHUB_ENV"

echo "CILIUM_CLI_RELEASE_REPO=isovalent/cilium-cli-releases" >> "$GITHUB_ENV"
CILIUM_CLI_VERSION=""
echo "CILIUM_CLI_VERSION=$CILIUM_CLI_VERSION" >> "$GITHUB_ENV"
echo "CILIUM_CLI_IMAGE_REPO=${REGISTRY_DEV}/isovalent-dev/cilium-cli-ci" >> $GITHUB_ENV
echo "CILIUM_CLI_IMAGE_REPO_ARTIFACTORY=${ARTIFACTORY_DEV}/isovalent-eng-docker/cilium-cli-ci" >> $GITHUB_ENV
echo "CILIUM_CLI_SKIP_BUILD=false" >> $GITHUB_ENV
echo "CILIUM_CLI_CODE_OWNERS_PATHS=CODEOWNERS,TESTOWNERS.enterprise" >> $GITHUB_ENV
echo "CILIUM_CLI_EXCLUDE_OWNERS=@isovalent/core-structure" >> $GITHUB_ENV

echo "PUSH_TO_DOCKER_HUB=false" >> "$GITHUB_ENV"

# CE Scalability specific overrides
source "$GITHUB_ACTION_PATH/enterprise-scalability-overrides.sh"

# CE feature gate specific overrides
echo "CILIUM_GINKGO_EXTRA_ARGS=-cilium.install-helm-overrides=enterprise.featureGate.minimumMaturity=Alpha" >> "$GITHUB_ENV"
echo "CILIUM_RUNTIME_EXTRA_ARGS=--feature-gates-minimum-maturity=Alpha" >> "$GITHUB_ENV"
echo "RUNTIME_DIRECTORY=enterprise/images/wolfi/runtime" >> $GITHUB_ENV
