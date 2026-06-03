SHELL:=/bin/bash

NAME:=evpn-cluster

deploy-kind:
	../../../../contrib/scripts/kind.sh 1 2 $(NAME) "" none dual "0.0.0.0" 6443

deploy-lab:
	sudo EVPN_SOURCE_INTERFACE_FILTER="$(EVPN_SOURCE_INTERFACE_FILTER)" containerlab -t topo.yaml deploy

deploy-cilium-local:
	kind load --name $(NAME) docker-image quay.io/cilium/cilium-dev:local quay.io/cilium/operator-generic:local
	cilium install --chart-directory ../../../../install/kubernetes/cilium/ --values values.yaml \
		--set image.override=quay.io/cilium/cilium-dev:local --set image.pullPolicy=Never \
		--set operator.image.override=quay.io/cilium/operator-generic:local --set operator.image.pullPolicy=Never

wait-for-cilium:
	kubectl -n kube-system wait deploy/cilium-operator --for=jsonpath='.status.readyReplicas'=1 --timeout=300s
	kubectl -n kube-system wait ds/cilium --for=jsonpath='.status.numberReady'=1 --timeout=300s

deploy:
	$(MAKE) deploy-kind
	$(MAKE) deploy-lab
	$(MAKE) deploy-cilium-local
	$(MAKE) wait-for-cilium

reload:
	make destroy
	make deploy

destroy:
	kind delete clusters $(NAME)
	sudo containerlab -t topo.yaml destroy

config:
	kubectl apply -f bgp-config.yaml
	kubectl apply -f private-networks.yaml
