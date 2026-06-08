{{/*
_extensions.tpl contains template blocks that are intended to allow packagers
to modify or extend the default chart behaviors.
*/}}

{{/*
Allow packagers to add extra volumes to cilium-agent.
*/}}
{{- define "cilium-agent.volumes.extra" }}
{{- include "hubble.timescape.export.extraVolumes" . }}
{{- if and .Values.enterprise.privateNetworks.enabled .Values.enterprise.privateNetworks.api.tls.enabled }}
- name: private-networks-api-tls
  projected:
    defaultMode: 0400
    sources:
    - secret:
        name: {{ if eq .Values.enterprise.privateNetworks.api.tls.method "manual" }}{{ .Values.enterprise.privateNetworks.api.tls.manual.server.existingSecret }}{{ else }}cilium-private-networks-api-server{{ end }}
        optional: true
        items:
        - key: tls.crt
          path: server.crt
        - key: tls.key
          path: server.key
        {{- if not .Values.tls.caBundle.enabled }}
        - key: ca.crt
          path: ca.crt
        {{- else }}
    - {{ .Values.tls.caBundle.useSecret | ternary "secret" "configMap" }}:
        name: {{ .Values.tls.caBundle.name }}
        optional: true
        items:
        - key: {{ .Values.tls.caBundle.key }}
          path: ca.crt
        {{- end }}
    - secret:
        name: {{ if eq .Values.enterprise.privateNetworks.api.tls.method "manual" }}{{ .Values.enterprise.privateNetworks.api.tls.manual.client.existingSecret }}{{ else }}cilium-private-networks-api-client{{ end }}
        optional: true
        items:
        - key: tls.crt
          path: client.crt
        - key: tls.key
          path: client.key
{{- end }}
{{- end }}

{{- define "cilium-agent.volumeMounts.extra" }}
{{- include "hubble.timescape.export.extraVolumeMounts" . }}
{{- if and .Values.enterprise.privateNetworks.enabled .Values.enterprise.privateNetworks.api.tls.enabled }}
- name: private-networks-api-tls
  mountPath: /var/lib/cilium/privnet/api/tls
  readOnly: true
{{- end }}
{{- end }}

{{/*
Allow packagers to set dnsPolicy for cilium-agent.
*/}}
{{- define "cilium-agent.dnsPolicy" }}
{{- if .Values.dnsPolicy }}
dnsPolicy: {{ .Values.dnsPolicy }}
{{- end }}
{{- end }}

{{/*
Allow packagers to add extra volumes to cilium-operator.
*/}}
{{- define "cilium-operator.volumes.extra" }}
{{- if and
  .Values.enterprise.privateNetworks.enabled
  .Values.enterprise.privateNetworks.webhook.enabled
}}
- name: privnet-webhook-certs
  secret:
    defaultMode: 0400
    {{- if eq .Values.enterprise.privateNetworks.webhook.tls.method "manual" }}
    secretName: {{ .Values.enterprise.privateNetworks.webhook.tls.manual.existingSecret }}
    {{- else }}
    secretName: cilium-private-networks-webhook-cert
    {{- end }}
    optional: true
    items:
    - key: tls.crt
      path: server.crt
    - key: tls.key
      path: server.key
- name: privnet-webhook-inventory
  projected:
    defaultMode: 0400
    sources:
    {{- if .Values.enterprise.privateNetworks.webhook.vms.inventory.caBundle.configMap.name }}
    - configMap:
        name: {{ .Values.enterprise.privateNetworks.webhook.vms.inventory.caBundle.configMap.name }}
        items:
        - key: {{ .Values.enterprise.privateNetworks.webhook.vms.inventory.caBundle.configMap.key }}
          path: ca.crt
    {{- end }}
    - secret:
        name: cilium-private-networks-forklift-inventory-token
        items:
        - key: token
          path: token
{{- end }}
{{- if and
    .Values.enterprise.privateNetworks.enabled
    .Values.enterprise.privateNetworks.autoExternalEndpoints
    .Values.enterprise.privateNetworks.autoExternalEndpoints.enabled
    .Values.enterprise.privateNetworks.autoExternalEndpoints.providers
}}
- name:  private-network-auto-external-endpoints
  configMap:
    name: cilium-private-networks-auto-external-endpoints-providers
{{- end }}
{{- end }}

{{- define "cilium-operator.volumeMounts.extra" }}
{{- if and
  .Values.enterprise.privateNetworks.enabled
  .Values.enterprise.privateNetworks.webhook.enabled
}}
- mountPath: /var/lib/cilium/privnet/webhook/tls
  name: privnet-webhook-certs
  readOnly: true
- mountPath: /var/lib/cilium/privnet/webhook/forklift-inventory
  name: privnet-webhook-inventory
  readOnly: true
{{- end }}
{{- if and
    .Values.enterprise.privateNetworks.enabled
    .Values.enterprise.privateNetworks.autoExternalEndpoints
    .Values.enterprise.privateNetworks.autoExternalEndpoints.enabled
    .Values.enterprise.privateNetworks.autoExternalEndpoints.providers
}}
- mountPath: /var/lib/cilium/privnet/auto-external-endpoints-config
  name: private-network-auto-external-endpoints
  readOnly: true
{{- end }}
{{- end }}

{{/*
Allow packagers to set securityContext for cilium-operator.
*/}}
{{- define "cilium.operator.securityContext" }}
{{- $base := (deepCopy (.Values.operator.securityContext | default dict)) }}
{{- $caps := (get $base "capabilities") | default dict }}
{{- $add  := (get $caps "add") | default nil }}
{{- if and .Values.enterprise.egressGatewayHA.enabled .Values.enterprise.egressGatewayHA.icmpHealthProbe.enabled }}
{{- $add = concat ($add | default (list)) (list "NET_RAW") }}
{{- end }}
{{- if $add }}
{{- $_ := set $caps "add" (uniq $add) }}
{{- end }}
{{- if $caps }}
{{- $_ := set $base "capabilities" $caps }}
{{- end }}
{{- if (ne (toYaml $base | trim) "") }}
{{ toYaml $base }}
{{- end }}
{{- end }}

{{/*
Intentionally empty to allow downstream chart packagers to add extra
containers to hubble-relay without having to modify the deployment manifest
directly.
*/}}
{{- define "hubble-relay.containers.extra" }}
{{- if .Values.hubble.rbac.enabled -}}
{{- toYaml (list (tpl (include "container.rbac" .) . | fromYaml)) -}}
{{- end -}}
{{- end }}

{{/*
Allow packagers to add extra volumes to relay.
*/}}
{{- define "hubble-relay.volumes.extra" }}
{{- if .Values.hubble.rbac.enabled -}}
{{- $rbacVolumes := tpl `
- name: hubble-rbac-policy
  configMap:
    name: {{ .Values.hubble.rbac.policy.configMap.name }}
    defaultMode: 0400
{{- if .Values.hubble.rbac.auth.oidc.ca.configMap.name }}
- name: hubble-rbac-tls-oidc
  configMap:
    name: {{ .Values.hubble.rbac.auth.oidc.ca.configMap.name }}
    items:
    - key: {{ .Values.hubble.rbac.auth.oidc.ca.configMap.key }}
      path: hubble-oidc-provider-ca.pem
{{- end }}
` . | fromYamlArray -}}
{{- toYaml $rbacVolumes -}}
{{- end -}}
{{- end }}

{{/*
Allow packagers to modify how hubble-relay TLS is configured.

A packager may want to change when TLS is enabled or prevent users from
disabling TLS. This means the template needs to allow overriding, not just
adding, which is why this template is not empty by default, like the ones
above.
*/}}
{{- define "hubble-relay.config.tls" }}
{{- if and .Values.hubble.tls.enabled .Values.hubble.relay.tls.server.enabled (not .Values.hubble.rbac.enabled) }}
tls-relay-server-cert-file: /var/lib/hubble-relay/tls/server.crt
tls-relay-server-key-file: /var/lib/hubble-relay/tls/server.key
{{- if .Values.hubble.relay.tls.server.mtls }}
tls-relay-client-ca-files: /var/lib/hubble-relay/tls/hubble-server-ca.crt
{{- end }}
{{- else }}
disable-server-tls: true
{{- end }}
{{- end }}

{{- define "hubble-relay.config.listenAddress" -}}
{{- if .Values.hubble.rbac.enabled -}}
localhost:{{- include "hubble-relay.config.listenPort" . -}}
{{- else -}}
{{- .Values.hubble.relay.listenHost }}:{{- include "hubble-relay.config.listenPort" . -}}
{{- end -}}
{{- end }}

{{- define "hubble-relay.config.listenPort" -}}
{{- if .Values.hubble.rbac.enabled -}}
4246
{{- else -}}
{{- .Values.hubble.relay.listenPort }}
{{- end -}}
{{- end }}

{{- define "hubble-relay.service.targetPort" -}}
{{- if .Values.hubble.rbac.enabled -}}
grpc-rbac
{{- else -}}
grpc
{{- end -}}
{{- end }}

{{/*
Allow packagers to add extra configuration to certgen.
*/}}
{{- define "certgen.config.extra" -}}
{{- if eq (include "hubble.timescape.tls.enabled" .) "true" }}
{{- $certValidityStr := printf "%dh" (mul .Values.hubble.tls.auto.certValidityDuration 24) }}
    {{- if or
      (not .Values.hubble.timescape.clustermesh.primary.id)
      (eq (int64 .Values.hubble.timescape.clustermesh.primary.id) (int64 .Values.cluster.id))
    }}
    - name: hubble-timescape-server-certs
      namespace: {{ include "cilium.namespace" . }}
      commonName: "hubble-timescape"
      hosts:
      - "hubble-timescape"
      - "hubble-timescape.{{ .Release.Namespace }}.svc.cluster.local"
      - "hubble-timescape.{{ .Release.Namespace }}.svc"
      - "localhost"
      {{- range $dns := .Values.hubble.timescape.tls.server.extraDnsNames }}
      - {{ $dns | quote }}
      {{- end }}
      {{- range $ip := .Values.hubble.timescape.tls.server.extraIpAddresses }}
      - {{ $ip | quote }}
      {{- end }}
      usage:
      - signing
      - key encipherment
      - server auth
      - client auth # needed for grpc health probe
      validity: {{ $certValidityStr }}
    {{- end }}
    - name: hubble-timescape-client-certs
      namespace: {{ include "cilium.namespace" . }}
      commonName: "hubble-timescape-client"
      hosts:
      - "hubble-timescape"
      usage:
      - signing
      - key encipherment
      - client auth # needed for grpc health probe
      validity: {{ $certValidityStr }}
{{- end }}
{{- end }}

{{/*
Allow packagers to add extra configuration to certgen.
*/}}
{{- define "certgen.config.extra" -}}
{{- end }}

{{/*
Allow packagers to add extra arguments to the clustermesh-apiserver apiserver container.
*/}}
{{- define "clustermesh.apiserver.args.extra" -}}
{{- if .Values.enterprise.privateNetworks.enabled }}
- --private-networks-enabled
{{- end }}
{{- end }}

{{/*
Allow packagers to add extra arguments to the clustermesh-apiserver kvstoremesh container.
*/}}
{{- define "clustermesh.kvstoremesh.args.extra" -}}
{{- end }}

{{/*
Return true when WAF is configured to override bundled CRS from an OCI image.
*/}}
{{- define "enterprise.waf.crs.customImageEnabled" -}}
{{- $image := .Values.enterprise.waf.crs.image -}}
{{- if and .Values.enterprise.waf.enabled (or $image.override $image.repository) -}}
true
{{- end -}}
{{- end }}

{{/*
Allow packagers to add lifecycle hooks to the cilium-envoy container.
*/}}
{{- define "envoy.lifecycle"}}
{{- if and .Values.envoy.gracefulRestart .Values.envoy.gracefulRestart.enabled }}
postStart:
  exec:
    command:
    - sh
    - -c
    - cp /var/run/cilium-envoy/restart/next_epoch /var/run/cilium-envoy/restart/epoch
{{- end }}
{{- end }}

{{/*
Allow packagers to add init containers to the cilium-envoy pods.
*/}}
{{- define "envoy.initContainers" -}}
{{- $wafCRSImageEnabled := eq (include "enterprise.waf.crs.customImageEnabled" .) "true" -}}
{{- if or (and .Values.envoy.gracefulRestart .Values.envoy.gracefulRestart.enabled) $wafCRSImageEnabled }}
initContainers:
{{- if and .Values.envoy.gracefulRestart .Values.envoy.gracefulRestart.enabled }}
- name: get-hot-restart-epoch
  image: {{ include "cilium.image" .Values.envoy.kubectl.image }}
  volumeMounts:
  - name: envoy-hot-restart-sockets
    mountPath: /var/run/cilium-envoy/hot-restart-sockets
  - name: envoy-restart-epoch-state
    mountPath: /var/run/cilium-envoy/restart
  securityContext:
    runAsUser: 0
    allowPrivilegeEscalation: false
    capabilities:
      drop:
      - ALL
  command:
    - sh
    - -c
    - |
      # This init-container is used to facilitate a graceful restart of cilium-envoy. A
      # state file is used to cooridinate the restart-epoch passed to the envoy process.
      #
      # epoch >  0: graceful restart
      # epoch == 0: fresh start
      #
      # See: https://www.envoyproxy.io/docs/envoy/latest/operations/cli#cmdoption-restart-epoch
      #

      STATE_FILE=/var/run/cilium-envoy/restart/epoch
      NEXT_STATE_FILE=/var/run/cilium-envoy/restart/next_epoch
      SOCKET_PATH=/var/run/cilium-envoy/hot-restart-sockets/hot-restart.sock

      # get last epoch that was started on this node
      last_epoch=0
      if [ -f "${STATE_FILE}" ]; then
        epoch_raw=$(cat "${STATE_FILE}")
        case "${epoch_raw}" in
          ''|*[!0-9]*) echo "State file is invalid: '${epoch_raw}'; will start fresh" ;;
          *) last_epoch="${epoch_raw}"
             echo "Read last_epoch=${last_epoch} from state file" ;;
        esac
      else
        echo "No state file found; will start fresh"
      fi

      # check if the parent process is listening on hot-restart socket
      parent_sock="${SOCKET_PATH}_parent_${last_epoch}"
      if grep -qF "${parent_sock}" /proc/net/unix; then
        next_epoch=$((last_epoch + 1))
        echo "Parent is listening on socket (${parent_sock}); will hot restart with epoch=${next_epoch}"
      else
        next_epoch=0
        echo "Parent is not listening on socket (${parent_sock}); will start fresh"
      fi

      echo "${next_epoch}" > "${NEXT_STATE_FILE}"
      echo "Committed next_epoch=${next_epoch}"

{{- end }}
{{- if $wafCRSImageEnabled }}
- name: prepare-waf-crs
  image: {{ include "cilium.image" .Values.enterprise.waf.crs.image | quote }}
  imagePullPolicy: {{ .Values.enterprise.waf.crs.image.pullPolicy }}
  env:
  - name: WAF_CRS_SOURCE_PATH
    value: {{ .Values.enterprise.waf.crs.sourcePath | quote }}
  command:
  - sh
  - -c
  - |
    set -eu
    test -d "${WAF_CRS_SOURCE_PATH}/rules"
    if [ ! -f "${WAF_CRS_SOURCE_PATH}/crs-setup.conf" ] && [ ! -f "${WAF_CRS_SOURCE_PATH}/crs-setup.conf.example" ]; then
      echo "${WAF_CRS_SOURCE_PATH} must contain crs-setup.conf or crs-setup.conf.example" >&2
      exit 1
    fi
    cp -R "${WAF_CRS_SOURCE_PATH}/." /waf-crs/crs/
    if [ ! -f /waf-crs/crs/crs-setup.conf ]; then
      cp /waf-crs/crs/crs-setup.conf.example /waf-crs/crs/crs-setup.conf
    fi
    test -f /waf-crs/crs/crs-setup.conf
    test -d /waf-crs/crs/rules
  securityContext:
    runAsUser: 0
    allowPrivilegeEscalation: false
    capabilities:
      drop:
      - ALL
  volumeMounts:
  - name: waf-crs
    mountPath: /waf-crs/crs
    readOnly: false
{{- end }}
{{- end }}
{{- end }}

{{/*
Allow packagers to add extra args to the cilium-envoy container.
*/}}
{{- define "envoy.args.extra" -}}
{{- if and .Values.envoy.gracefulRestart .Values.envoy.gracefulRestart.enabled }}
- '--restart-epoch'
- '@/var/run/cilium-envoy/restart/next_epoch'
- '--socket-path /var/run/cilium-envoy/hot-restart-sockets/hot-restart.sock'
- '--skip-hot-restart-on-no-parent'
- '--parent-shutdown-time-s {{ .Values.envoy.gracefulRestart.parentShutdownSeconds }}'
- '--drain-time-s {{ .Values.envoy.gracefulRestart.drainTimeSeconds }}'
- '--drain-strategy gradual'
{{- end }}
{{- end }}

{{/*
Allow packagers to add extra env vars to the cilium-envoy container.
*/}}
{{- define "envoy.env.extra" -}}
{{- if .Values.enterprise.waf.enabled }}
- name: ENVOY_DYNAMIC_MODULES_SEARCH_PATH
  value: /usr/lib
{{- end }}
{{- end }}

{{/*
Allow packagers to add extra volume mounts to the cilium-envoy container.
*/}}
{{- define "envoy.volumeMounts.extra" -}}
{{- if and .Values.envoy.gracefulRestart .Values.envoy.gracefulRestart.enabled }}
- mountPath: /dev/shm
  name: envoy-shared-memory
- mountPath: /var/run/cilium-envoy/hot-restart-sockets
  name: envoy-hot-restart-sockets
  readOnly: false
- mountPath: /var/run/cilium-envoy/restart
  name: envoy-restart-epoch-state
{{- end }}
{{- if eq (include "enterprise.waf.crs.customImageEnabled" .) "true" }}
- mountPath: /etc/coraza/crs
  name: waf-crs
  readOnly: true
{{- end }}
{{- end }}

{{/*
Allow packagers to add extra volumes to the cilium-envoy pods.
*/}}
{{- define "envoy.hostPathMounts.extra" -}}
{{- if and .Values.envoy.gracefulRestart .Values.envoy.gracefulRestart.enabled }}
  - hostPath:
      path: "/dev/envoy/shm"
      type: DirectoryOrCreate
    name: envoy-shared-memory
  - hostPath:
      path: "{{ .Values.daemon.runPath }}/cilium-envoy/hot-restart-sockets"
      type: DirectoryOrCreate
    name: envoy-hot-restart-sockets
  - hostPath:
      path: "{{ .Values.daemon.runPath }}/cilium-envoy/restart"
      type: DirectoryOrCreate
    name: envoy-restart-epoch-state
{{- end }}
{{- if eq (include "enterprise.waf.crs.customImageEnabled" .) "true" }}
  - name: waf-crs
    emptyDir: {}
{{- end }}
{{- end }}


{{/*
Allow packagers to define set of ports for cilium-envoy container.
The template needs to allow overriding ports spec not just adding.
*/}}
{{- define "envoy.ports" -}}
        {{- if .Values.envoy.prometheus.enabled }}
        {{- if and (eq .Values.envoy.prometheus.enabled true) (.Values.envoy.gracefulRestart) (eq .Values.envoy.gracefulRestart.enabled false) }}
        ports:
        - name: envoy-metrics
          containerPort: {{ .Values.envoy.prometheus.port }}
          hostPort: {{ .Values.envoy.prometheus.port }}
          protocol: TCP
        {{- if and .Values.envoy.debug.admin.enabled .Values.envoy.debug.admin.port }}
        - name: envoy-admin
          containerPort: {{ .Values.envoy.debug.admin.port }}
          hostPort: {{ .Values.envoy.debug.admin.port }}
          protocol: TCP
        {{- end }}
        {{- end }}
        {{- end }}
{{- end }}

{{/*
Allow packagers to define update strategy for cilium-envoy pods.
*/}}
{{- define "envoy.updateStrategy" -}}
{{- if and (.Values.envoy.gracefulRestart) (.Values.envoy.gracefulRestart.enabled) }}
updateStrategy:
  type: RollingUpdate
  rollingUpdate:
    maxUnavailable: 0
    maxSurge: 100
{{- else }}
  {{- with .Values.envoy.updateStrategy }}
updateStrategy:
  {{- toYaml . | trim | nindent 2 }}
  {{- end }}
{{- end }}
{{- end }}

{{/*
Allow packagers to define affinity for cilium-envoy pods.
*/}}
{{- define "envoy.affinity" -}}
{{- if and .Values.envoy.gracefulRestart .Values.envoy.gracefulRestart.enabled }}
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 1
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: k8s-app
            operator: In
            values:
            - cilium-envoy
        topologyKey: kubernetes.io/hostname
  podAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 1
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: k8s-app
            operator: In
            values:
            - cilium
        topologyKey: kubernetes.io/hostname
  nodeAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 1
      preference:
        matchExpressions:
        - key: cilium.io/no-schedule
          operator: NotIn
          values:
          - "true"
{{- else }}
{{- with .Values.envoy.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
{{- end }}
