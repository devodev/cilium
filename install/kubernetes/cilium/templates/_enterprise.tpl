{{/*
Enterprise-only cilium-config entries
*/}}

{{- define "enterprise.cilium-config" }}

# Configuration options to enable overlapping PodCIDR support for clustermesh
{{- /* We additionally fallback to the specific setting used in v1.13-ce for backward compatibility */}}
enable-cluster-aware-addressing: {{ .Values.enterprise.clustermesh.enableOverlappingPodCIDRSupport | default .Values.clustermesh.enableOverlappingPodCIDRSupport | default "false" | quote }}
enable-inter-cluster-snat: {{ .Values.enterprise.clustermesh.enableOverlappingPodCIDRSupport | default .Values.clustermesh.enableOverlappingPodCIDRSupport | default "false" | quote }}

# Configuration options to enable SRv6 support
enable-srv6:               {{ .Values.enterprise.srv6.enabled            | default "false"   | quote }}
srv6-encap-mode:           {{ .Values.enterprise.srv6.encapMode          | default "reduced" | quote }}
srv6-locator-pool-enabled: {{ .Values.enterprise.srv6.locatorPoolEnabled | default "false"   | quote }}

{{- if .Values.enterprise.evpn.enabled }}
enable-evpn: "true"
evpn-vxlan-device: {{ .Values.enterprise.evpn.vxlanDevice | quote }}
evpn-vxlan-port: {{ .Values.enterprise.evpn.vxlanPort | quote }}
enable-evpn-security-group-tags: {{ .Values.enterprise.evpn.securityGroupTags.enabled | quote }}
evpn-default-security-group-id: {{ .Values.enterprise.evpn.securityGroupTags.defaultGroupID | quote }}
bpf-evpn-fib-map-max: {{ .Values.enterprise.evpn.fibMapMax | quote }}
{{- end }}

{{- if .Values.enterprise.bgpControlPlane.enabled }}
enable-enterprise-bgp-control-plane: "true"
enable-bgp-control-plane: "true"
bgp-secrets-namespace: {{ .Values.enterprise.bgpControlPlane.secretsNamespace.name | quote }}
# Status reporting for OSS BGP control plane is disabled when enterprise BGP control plane is enabled.
# Enterprise BGP control plane status reporting is enabled by default, but can be disabled by the user.
enable-bgp-control-plane-status-report: "false"
enable-enterprise-bgp-control-plane-status-report: {{ .Values.enterprise.bgpControlPlane.statusReport.enabled | quote }}
# Service health-checking integration in BGP control plane
enable-bgp-svc-health-checking: {{ .Values.enterprise.bgpControlPlane.enableServiceHealthChecking | default "false" | quote }}
enable-statedb-neighbor-sync: "true"
router-advertisement-interval: {{ .Values.enterprise.bgpControlPlane.routerAdvertisementInterval | quote }}
bgp-router-id-allocation-mode: {{ .Values.enterprise.bgpControlPlane.routerIDAllocation.mode | quote }}
enable-bgp-maintenance-graceful-shutdown-community: {{ .Values.enterprise.bgpControlPlane.nodeMaintenance.gracefulShutdownCommunity.enabled | default "false" | quote }}
bgp-maintenance-withdraw-time: {{ .Values.enterprise.bgpControlPlane.nodeMaintenance.withdrawTime | default "0s" | quote }}
enable-bgp-route-import: {{ .Values.enterprise.bgpControlPlane.routeImport.enabled | default "false" | quote }}
{{- end }}

{{/*
FQDN-ha proxy. Docs previously configured these directly with
extraConfig, so we can't set these values unless explicitly enabled.
*/}}
{{- if .Values.enterprise.dnsProxyHA.enabled }}
external-dns-proxy: "true"
{{- end }}
{{- if .Values.enterprise.dnsProxyHA.offlineMode.enabled }}
tofqdns-enable-offline-mode: "true"
{{- end }}

# BFD subsystem
enable-bfd: {{ .Values.enterprise.bfd.enabled | default "false" | quote }}

# Configuration options to enable multicast support
multicast-enabled: {{ .Values.enterprise.multicast.enabled | default "false" | quote }}

{{- if .Values.enterprise.egressGatewayHA.enabled }}
enable-ipv4-egress-gateway-ha: "true"
{{- end }}
{{- if hasKey .Values.enterprise.egressGatewayHA "reconciliationTriggerInterval" }}
egress-gateway-ha-reconciliation-trigger-interval: {{ .Values.enterprise.egressGatewayHA.reconciliationTriggerInterval | quote }}
{{- end }}
{{- if hasKey .Values.enterprise.egressGatewayHA "socketTermination" }}
enable-egress-gateway-ha-socket-termination: {{ .Values.enterprise.egressGatewayHA.socketTermination.enabled | default "false" | quote }}
{{- end }}
{{- if .Values.enterprise.egressGatewayHA.maxPolicyEntries }}
egress-gateway-ha-policy-map-max: {{ .Values.enterprise.egressGatewayHA.maxPolicyEntries | quote }}
{{- end }}
{{- if hasKey .Values.enterprise.egressGatewayHA "healthcheckTimeout" }}
egress-gateway-ha-healthcheck-timeout: {{ .Values.enterprise.egressGatewayHA.healthcheckTimeout | quote }}
{{- else if hasKey .Values.egressGateway "healthcheckTimeout" }}
egress-gateway-ha-healthcheck-timeout: {{ .Values.egressGateway.healthcheckTimeout | quote }}
{{- end }}
{{- if hasKey .Values.enterprise.egressGatewayHA "icmpHealthProbe" }}
enable-egress-gateway-ha-icmp-health-probe: {{ .Values.enterprise.egressGatewayHA.icmpHealthProbe.enabled | default "true" | quote }}
egress-gateway-ha-icmp-health-probe-interval: {{ .Values.enterprise.egressGatewayHA.icmpHealthProbe.interval | quote }}
egress-gateway-ha-icmp-health-probe-failure-threshold: {{ .Values.enterprise.egressGatewayHA.icmpHealthProbe.failureThreshold | quote }}
{{- end }}

{{- if .Values.enterprise.clustermesh.mixedRoutingMode.enabled }}
fallback-routing-mode: tunnel
{{- end }}
{{- if .Values.enterprise.preferredTunnelEndpointDevices }}
preferred-tunnel-endpoint-devices: {{ join "," .Values.enterprise.preferredTunnelEndpointDevices | quote }}
{{- end }}


feature-gates-approved: {{ .Values.enterprise.featureGate.approved | join "," | quote }}
feature-gates-strict: {{ .Values.enterprise.featureGate.strict | quote }}
{{- with .Values.enterprise.featureGate.minimumMaturity }}
feature-gates-minimum-maturity: {{ . | quote }}
{{- end }}

{{- if .Values.enterprise.multiNetwork.enabled }}
# Multi-network support
enable-multi-network: {{ .Values.enterprise.multiNetwork.enabled | quote }}
{{- if hasKey .Values.enterprise.multiNetwork "autoDirectNodeRoutes" }}
multi-network-auto-direct-node-routes: {{ .Values.enterprise.multiNetwork.autoDirectNodeRoutes | quote }}
{{- end }}
{{- if hasKey .Values.enterprise.multiNetwork "autoCreateDefaultPodNetwork" }}
auto-create-default-pod-network: {{ .Values.enterprise.multiNetwork.autoCreateDefaultPodNetwork | quote }}
{{- end }}
{{- end }}

{{- if .Values.hubble.export }}
{{- if .Values.hubble.export.static.enabled }}
hubble-export-format-version: {{ .Values.hubble.export.static.formatVersion | quote }}
{{- with .Values.hubble.export.static.fileRotationInterval }}
hubble-export-file-rotation-interval: {{ . | quote }}
{{- end }}
{{- with .Values.hubble.export.static.rateLimit }}
hubble-export-rate-limit: {{ . | quote }}
{{- end }}
{{- with .Values.hubble.export.static.overrideNodeName }}
hubble-export-node-name: {{ . | quote }}
{{- end }}
{{- with .Values.hubble.export.static.aggregation }}
hubble-export-aggregation: {{ . | join " " | quote }}
{{- end }}
{{- with .Values.hubble.export.static.aggregationIgnoreSourcePort }}
hubble-export-aggregation-ignore-source-port: {{ . | quote }}
{{- end }}
{{- with .Values.hubble.export.static.aggregationRenewTTL }}
hubble-export-aggregation-renew-ttl: {{ . | quote }}
{{- end }}
{{- with .Values.hubble.export.static.aggregationStateFilter }}
hubble-export-aggregation-state-filter: {{ . | join " " | quote }}
{{- end }}
{{- with .Values.hubble.export.static.aggregationTTL }}
hubble-export-aggregation-ttl: {{ . | quote }}
{{- end }}
{{- end }}
{{- end }}

{{- $defaultExportTimescapeEnabled := .Values.hubble.export.timescape.enabled }}
{{- $defaultExportTimescapeTarget := .Values.hubble.export.timescape.target }}
{{- $defaultExportTimescapeAggregation := .Values.hubble.export.timescape.aggregation }}
{{- $defaultExportTimescapeAggregationStateFilter := .Values.hubble.export.timescape.aggregationStateFilter }}
{{- $defaultExportTimescapeAggregationRenewTTL := .Values.hubble.export.timescape.aggregationRenewTTL }}
{{- $defaultExportTimescapeUseCiliumServiceResolver := .Values.hubble.export.timescape.useCiliumServiceResolver }}
{{- $defaultExportTimescapeTLSEnabled := .Values.hubble.export.timescape.tls.enabled }}
{{- $defaultExportTimescapeTLSmTLSEnabled := .Values.hubble.export.timescape.tls.mtls.enabled }}
{{- $defaultExportTimescapeTLSCAOverriden := not (.Values.hubble.export.timescape.tls.ca.configMap.name | empty) }}

# If integrated Timescape is enabled, we enable the Hubble timescape exporter
# and export aggregation by default.
{{- if .Values.hubble.timescape.enabled }}
{{- $targetNamespace := (include "cilium.namespace" .) }}
{{- if .Values.hubble.timescape.clustermesh.primary.namespace }}
{{- $targetNamespace = .Values.hubble.timescape.clustermesh.primary.namespace }}
{{- end }}
{{- $defaultExportTimescapeEnabled = true }}
{{- $defaultExportTimescapeTarget = printf "hubble-timescape.%s.svc.cluster.local:4261" $targetNamespace }}
{{- $defaultExportTimescapeAggregation = list "connection" }}
{{- $defaultExportTimescapeAggregationStateFilter = list "new" "error" }}
{{- $defaultExportTimescapeAggregationRenewTTL = "false" }}
{{- $defaultExportTimescapeUseCiliumServiceResolver = "true" }}
{{- if eq (include "hubble.timescape.tls.enabled" .) "true" }}
{{- $defaultExportTimescapeTLSEnabled = "true" }}
{{- $defaultExportTimescapeTLSmTLSEnabled = "true" }}
{{- $defaultExportTimescapeTLSCAOverriden = "true" }}
{{- end }}
{{- end }}

{{- if $defaultExportTimescapeEnabled }}
hubble-export-timescape-enabled: "true"
{{- with $defaultExportTimescapeTarget }}
hubble-export-timescape-target: {{ . | quote }}
{{- end }}
{{- with .Values.hubble.export.timescape.allowList }}
hubble-export-timescape-allowlist: {{ . | join " " | quote }}
{{- end }}
{{- with .Values.hubble.export.timescape.denyList }}
hubble-export-timescape-denylist: {{ . | join " " | quote }}
{{- end }}
{{- with .Values.hubble.export.timescape.fieldMask }}
hubble-export-timescape-fieldmask: {{ . | join " " | quote }}
{{- end }}
{{- with .Values.hubble.export.timescape.nodeName }}
hubble-export-timescape-node-name: {{ . | quote }}
{{- end }}
{{- with $defaultExportTimescapeAggregation }}
hubble-export-timescape-aggregation: {{ . | join " " | quote }}
{{- end }}
{{- with .Values.hubble.export.timescape.aggregationIgnoreSourcePort }}
hubble-export-timescape-aggregation-ignore-source-port: {{ . | quote }}
{{- end }}
{{- with $defaultExportTimescapeAggregationRenewTTL }}
hubble-export-timescape-aggregation-renew-ttl: {{ . | quote }}
{{- end }}
{{- with $defaultExportTimescapeAggregationStateFilter }}
hubble-export-timescape-aggregation-state-filter: {{ . | join " " | quote }}
{{- end }}
{{- with .Values.hubble.export.timescape.aggregationTTL }}
hubble-export-timescape-aggregation-ttl: {{ . | quote }}
{{- end }}
{{- with .Values.hubble.export.timescape.maxBufferSize }}
hubble-export-timescape-max-buffer-size: {{ . | quote }}
{{- end }}
{{- with .Values.hubble.export.timescape.reportDroppedFlowsInterval }}
hubble-export-timescape-report-dropped-flows-interval: {{ . | quote }}
{{- end }}
{{- with $defaultExportTimescapeUseCiliumServiceResolver }}
hubble-export-timescape-use-cilium-service-resolver: {{ . | quote }}
{{- end }}
{{- with $defaultExportTimescapeTLSEnabled }}
hubble-export-timescape-tls-enabled: {{ . | quote }}
{{- end }}
{{- if $defaultExportTimescapeTLSmTLSEnabled }}
hubble-export-timescape-tls-cert-file: /var/lib/cilium/tls/hubble-export-timescape/client.crt
hubble-export-timescape-tls-key-file: /var/lib/cilium/tls/hubble-export-timescape/client.key
{{- end }}
{{- if $defaultExportTimescapeTLSCAOverriden }}
hubble-export-timescape-tls-ca-files: /var/lib/cilium/tls/hubble-export-timescape/client-ca.crt
{{- end }}
{{- end }}

# XXX: At some point we might want to have it enabled by default when
# .Values.hubble.timescape.enabled is true.
hubble-connectionlog-export-enabled: {{ .Values.hubble.export.connectionlog.enabled | quote }}
{{- if .Values.hubble.export.connectionlog.enabled }}
hubble-connectionlog-export-interval: {{ .Values.hubble.export.connectionlog.exportInterval | quote }}
hubble-connectionlog-export-file-path: {{ .Values.hubble.export.connectionlog.filePath | quote }}
hubble-connectionlog-export-file-max-size-mb: {{ .Values.hubble.export.connectionlog.fileMaxSizeMb | quote }}
hubble-connectionlog-export-file-max-backups: {{ .Values.hubble.export.connectionlog.fileMaxBackups | quote }}
hubble-connectionlog-export-file-compress: {{ .Values.hubble.export.connectionlog.fileCompress | quote }}
{{- end }}

enable-phantom-services: {{ .Values.enterprise.clustermesh.phantomServices.enabled | quote}}

{{- if .Values.enterprise.encryption.policy.enabled }}
enable-encryption-policy: {{ .Values.enterprise.encryption.policy.enabled | quote }}
{{- if .Values.enterprise.encryption.policy.fallbackBehavior }}
encryption-policy-fallback-behavior: {{ .Values.enterprise.encryption.policy.fallbackBehavior | quote }}
{{- end }}
{{- end }}

{{- if .Values.enterprise.loadbalancer.enabled }}
loadbalancer-cp-enabled: "true"
loadbalancer-cp-secrets-namespace: {{ .Values.envoyConfig.secretsNamespace.name | quote }}
loadbalancer-metrics-enabled: "true"
loadbalancer-envoy-health-state-sync-enabled: "true"
loadbalancer-cp-t2-hc-event-logging-enabled: "true"
loadbalancer-cp-t2-hc-event-logging-state-dir: "{{ .Values.daemon.runPath }}"
envoy-health-check-event-server-enabled: "true"
enable-active-lb-health-checking: "true"
enable-ipip-termination: "true"
bpf-lb-ipip-sock-mark: "true"
loadbalancer-gateway-api-enabled: {{ .Values.enterprise.loadbalancer.gatewayAPI.enabled | quote }}
{{- end }}

{{- if .Values.enterprise.gatewayAPI.deployment.enabled }}
gateway-api-deployment-controller-enabled: "true"
gateway-api-deployment-dataplane-default-envoy-image: {{ include "cilium.image" .Values.envoy.image | quote }}
gateway-api-deployment-dataplane-default-envoy-log-level: {{ default "error" .Values.envoy.log.defaultLevel | quote }}
gateway-api-deployment-dataplane-default-envoy-admin-port: {{ .Values.envoy.debug.admin.port | quote }}
gateway-api-deployment-dataplane-default-replicas: {{ .Values.enterprise.gatewayAPI.deployment.dataplane.defaultReplicas | quote }}
{{- end }}

waf-enabled: {{ .Values.enterprise.waf.enabled | quote }}
{{- if .Values.enterprise.waf.enabled }}
waf-mode: {{ .Values.enterprise.waf.mode | quote }}
waf-policy-profile: {{ .Values.enterprise.waf.policyProfile | quote }}
waf-failure-mode: {{ .Values.enterprise.waf.failureMode | quote }}
{{- end }}

{{- if or .Values.envoyConfig.enabled .Values.ingressController.enabled .Values.gatewayAPI.enabled (and (hasKey .Values "loadBalancer") (eq .Values.loadBalancer.l7.backend "envoy")) }}
envoy-config-policy-mode: {{ .Values.envoyConfig.policy.mode | quote }}
envoy-config-policy-regen-interval: {{ include "validateDuration" .Values.envoyConfig.policy.regenerationInterval | quote }}
{{- end }}

diagnostics-export-file: {{ .Values.enterprise.diagnostics.exportFilePath | quote }}
diagnostics-interval: {{ .Values.enterprise.diagnostics.interval | quote }}
diagnostics-constants: {{ .Values.enterprise.diagnostics.constants | join "," | quote }}

# Private networks
private-networks-enabled: {{ .Values.enterprise.privateNetworks.enabled | quote }}
private-networks-mode: {{ .Values.enterprise.privateNetworks.mode | quote }}
private-networks-external-endpoints-enabled: {{ .Values.enterprise.privateNetworks.externalEndpoints.enabled | quote }}
private-networks-api-port: {{ .Values.enterprise.privateNetworks.api.port | quote }}
private-networks-health-check-interval: {{ .Values.enterprise.privateNetworks.healthcheck.interval | quote }}
private-networks-health-check-timeout: {{ .Values.enterprise.privateNetworks.healthcheck.timeout | quote }}
private-networks-nad-integration-enabled: {{ .Values.enterprise.privateNetworks.networkAttachmentDefinitions.enabled | quote }}
private-networks-nad-cni-log-file: {{ .Values.enterprise.privateNetworks.networkAttachmentDefinitions.cniLogFile | quote }}
private-networks-nad-cni-log-format: {{ .Values.enterprise.privateNetworks.networkAttachmentDefinitions.cniLogFormat | quote }}
{{- if not (kindIs "invalid" .Values.enterprise.privateNetworks.hostReachability) }}
private-networks-host-reachability: {{ .Values.enterprise.privateNetworks.hostReachability | quote }}
{{- end }}
{{- if .Values.enterprise.privateNetworks.hostSNATIPv4 }}
private-networks-host-snat-ipv4: {{ .Values.enterprise.privateNetworks.hostSNATIPv4 | quote }}
{{- end }}
{{- if .Values.enterprise.privateNetworks.hostSNATIPv6 }}
private-networks-host-snat-ipv6: {{ .Values.enterprise.privateNetworks.hostSNATIPv6 | quote }}
{{- end }}
private-networks-api-tls-enabled: {{ .Values.enterprise.privateNetworks.api.tls.enabled | quote }}
{{- if .Values.enterprise.privateNetworks.api.tls.enabled }}
private-networks-api-tls-server-cert-file: "/var/lib/cilium/privnet/api/tls/server.crt"
private-networks-api-tls-server-key-file: "/var/lib/cilium/privnet/api/tls/server.key"
private-networks-api-tls-client-cert-file: "/var/lib/cilium/privnet/api/tls/client.crt"
private-networks-api-tls-client-key-file: "/var/lib/cilium/privnet/api/tls/client.key"
private-networks-api-tls-ca-files: "/var/lib/cilium/privnet/api/tls/ca.crt"
{{- end }}

{{- if .Values.enterprise.privateNetworks.enabled }}
private-networks-webhook-enabled: {{ .Values.enterprise.privateNetworks.webhook.enabled | quote }}
private-networks-webhook-hostport: {{ print ":" .Values.enterprise.privateNetworks.webhook.port | quote }}
private-networks-webhook-tls-key-file: /var/lib/cilium/privnet/webhook/tls/server.key
private-networks-webhook-tls-cert-file: /var/lib/cilium/privnet/webhook/tls/server.crt
private-networks-webhook-network-binding: {{ .Values.enterprise.privateNetworks.webhook.vms.networkBinding | quote }}
private-networks-webhook-inventory-url: {{ .Values.enterprise.privateNetworks.webhook.vms.inventory.url | quote }}
private-networks-webhook-inventory-bearer-token-file: "/var/lib/cilium/privnet/webhook/forklift-inventory/token"
{{- if .Values.enterprise.privateNetworks.webhook.vms.inventory.caBundle.configMap.name }}
private-networks-webhook-inventory-ca-bundle-file: "/var/lib/cilium/privnet/webhook/forklift-inventory/ca.crt"
{{- end }}

{{- if .Values.enterprise.privateNetworks.autoExternalEndpoints }}
{{- if .Values.enterprise.privateNetworks.autoExternalEndpoints.enabled }}
private-networks-auto-external-endpoints-enabled: "true"
{{- with .Values.enterprise.privateNetworks.autoExternalEndpoints.secretsNamespace }}
private-networks-auto-external-endpoints-secrets-namespace: {{ .name | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}

# Passive inspection for pod traffic
enable-passive-inspection: {{ .Values.enterprise.inspection.enabled | quote }}

enable-health-server-without-active-checks: {{ .Values.enterprise.healthServerWithoutActiveChecks.enabled | quote }}

{{- end }}
