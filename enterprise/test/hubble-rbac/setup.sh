#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

set -x

echo "Installing Cilium"
cilium_helm_args=(
  --namespace kube-system
  --version "$CILIUM_VERSION"
  --values "$SCRIPT_DIR"/helm/cilium.yaml
)
if [ -n "${ARTIFACTORY_PULL_SECRET_NAME:-}" ]; then
  cilium_helm_args+=(--set "imagePullSecrets[0].name=${ARTIFACTORY_PULL_SECRET_NAME}")
fi
helm upgrade --install cilium "$CILIUM_CHART_REPO" \
  "${cilium_helm_args[@]}"

echo "Installing ingress-nginx"
# install ingress
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update
helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx \
  --wait \
  --namespace ingress-nginx \
  --create-namespace \
  --version "$INGRESS_NGINX_VERSION" \
  --values "$SCRIPT_DIR"/helm/nginx.yaml

# the dex hostname needs to resolve to the control-plane IP so that
# hubble-rbac can reach it.
KIND_CTRLPLANE_IP="$(docker inspect "${KIND_CTRLPLANE_NAME}" | jq '.[0].NetworkSettings.Networks.kind.IPAddress' -r)"
echo ""
echo "Requesting sudo to update /etc/hosts and point 'dex.text' to the KinD IP"
sudo sed -i -n -e '/^.*\ dex.test/!p' -e '$a\'"${KIND_CTRLPLANE_IP}"' dex.test' /etc/hosts
helm repo add dex https://charts.dexidp.io
helm repo update

echo "Installing Dex"
helm upgrade --install dex dex/dex \
  --wait \
  --namespace dex \
  --create-namespace \
  --version "$DEX_VERSION" \
  --values "$SCRIPT_DIR"/helm/dex.yaml

echo "Checking dex ingress"
until [ "$(kubectl -n dex get ingress dex -ojson | jq '.status.loadBalancer.ingress[]?.hostname' -r)" != "" ]; do
  echo "waiting for Dex ingress to become ready"
  sleep 5
done

kubectl -n kube-system create secret generic hubble-timescape-ui  --from-literal session-key=fooobar --from-literal client-secret=test-client-secret

echo "Waiting for Hubble Relay to become ready"
kubectl -n kube-system rollout status deployment hubble-relay
