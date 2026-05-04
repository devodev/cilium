{{- define "hubble.timescape.podAnnotations" -}}
{{- if .Values.hubble.timescape.rollOutPods }}
hubble-timescape-config-configmap-checksum: {{ include (print $.Template.BasePath "/hubble-timescape/timescape-configmap.yaml") . | sha256sum | quote }}
{{- if .Values.hubble.timescape.clickhouse.rollOutPods }}
hubble-timescape-clickhouse-settings-configmap-checksum: {{ include (print $.Template.BasePath "/hubble-timescape/timescape-clickhouse-configmap.yaml") . | sha256sum | quote }}
{{- end }}
{{- /* This annotation will ensure that the pod is restarted on pvc size change */}}
{{- if .Values.hubble.timescape.persistence.enabled }}
{{- with .Values.hubble.timescape.persistence.volumeSize }}
hubble-timescape-clickhouse-volume-size: {{ . }}
{{- end }}
{{- end }}
{{- end }}
{{- with .Values.hubble.timescape.annotations }}
{{ toYaml . }}
{{- end }}
{{- with .Values.hubble.timescape.podAnnotations }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "hubble.timescape.selectorLabels" -}}
k8s-app: hubble-timescape
app.kubernetes.io/name: hubble-timescape
app.kubernetes.io/part-of: cilium
{{- end }}

{{- define "hubble.timescape.podLabels" -}}
{{ include "hubble.timescape.selectorLabels" . }}
{{- with .Values.hubble.timescape.labels }}
{{ toYaml . }}
{{- end }}
{{- with .Values.hubble.timescape.podLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "hubble.timescape.service.annotations" }}
{{- if .Values.hubble.timescape.clustermesh.primary.id }}
service.cilium.io/global: "true"
{{- if not (eq (int64 .Values.hubble.timescape.clustermesh.primary.id) (int64 .Values.cluster.id)) }}
service.cilium.io/shared: "false"
{{- end }}
{{- end }}
{{ with .Values.hubble.timescape.annotations }}
{{- toYaml . }}
{{- end }}
{{ with .Values.hubble.timescape.service.annotations }}
{{- toYaml . }}
{{- end }}
{{- end }}

{{- define "hubble.timescape.service.labels" }}
{{ include "hubble.timescape.labels" . }}
{{ with .Values.hubble.timescape.service.labels }}
{{- toYaml . }}
{{- end }}
{{- end }}

{{- define "hubble.timescape.tls.enabled" -}}
{{- and .Values.hubble.timescape.enabled
(or
  (eq .Values.hubble.timescape.tls.enabled true)
  (and (kindIs "invalid" .Values.hubble.timescape.tls.enabled) .Values.hubble.tls.enabled)
)
-}}
{{- end }}

{{- define "hubble.timescape.ui.auth.enabled" -}}
{{- or
  .Values.hubble.timescape.ui.auth.enabled
  .Values.hubble.rbac.enabled
-}}
{{- end }}

{{- define "hubble.timescape.probe" -}}
grpc:
  port: 8083
{{- end }}

{{- define "hubble.timescape.servicemonitor.endpoint" -}}
- port:  {{ .port }}
  interval: {{ .values.interval | quote }}
  {{- with .values.scrapeTimeout }}
  scrapeTimeout: {{ . | quote }}
  {{- end }}
  honorLabels: true
  path: /metrics
  {{- with .values.relabelings }}
  relabelings:
  {{- toYaml . | nindent 2 }}
  {{- end }}
  {{- with .values.metricRelabelings }}
  metricRelabelings:
  {{- toYaml . | nindent 2 }}
  {{- end }}
{{- end }}

{{- define "hubble.timescape.export.extraVolumes" -}}
{{- if eq (include "hubble.timescape.tls.enabled" .) "true" }}
- name: hubble-export-timescape-tls
  projected:
    defaultMode: 0400
    sources:
    - secret:
        name: {{ .Values.hubble.timescape.tls.client.existingSecret | default "hubble-timescape-client-certs" }}
        optional: true
        items:
        - key: tls.crt
          path: client.crt
        - key: tls.key
          path: client.key
        - key: ca.crt
          path: client-ca.crt
{{- else if and
  .Values.hubble.export.timescape.enabled
  .Values.hubble.export.timescape.tls.enabled
  (or .Values.hubble.export.timescape.tls.mtls.enabled .Values.hubble.export.timescape.tls.ca.configMap.name)
}}
- name: hubble-export-timescape-tls
  projected:
    # note: the leading zero means this number is in octal representation: do not remove it
    defaultMode: 0400
    sources:
    {{- if .Values.hubble.export.timescape.tls.mtls.enabled }}
    - secret:
        name: {{ .Values.hubble.export.timescape.tls.mtls.secretName | default "hubble-export-timescape-mtls-certs" }}
        optional: true
        items:
        - key: tls.crt
          path: client.crt
        - key: tls.key
          path: client.key
    {{- end }}
    {{- if .Values.hubble.export.timescape.tls.ca.configMap.name }}
    - configMap:
        name: {{ .Values.hubble.export.timescape.tls.ca.configMap.name }}
        optional: true
        items:
        - key: {{ .Values.hubble.export.timescape.tls.ca.configMap.key }}
          path: client-ca.crt
    {{- end }}
{{- end }}
{{- end }}

{{- define "hubble.timescape.export.extraVolumeMounts" -}}
{{- if or
  (eq (include "hubble.timescape.tls.enabled" .) "true")
  (and
    .Values.hubble.export.timescape.enabled
    .Values.hubble.export.timescape.tls.enabled
    (or .Values.hubble.export.timescape.tls.mtls.enabled .Values.hubble.export.timescape.tls.ca.configMap.name)
  )
}}
- name: hubble-export-timescape-tls
  mountPath: /var/lib/cilium/tls/hubble-export-timescape
  readOnly: true
{{- end }}
{{- end }}

{{- define "hubble.timescape.ingester.k8sImporter.clusterRole.rules" -}}
- apiGroups:
  - ""
  resources:
  - namespaces
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - apiextensions.k8s.io
  resources:
  - customresourcedefinitions
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - networking.k8s.io
  resources:
  - networkpolicies
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - cilium.io
  resources:
  - ciliumnetworkpolicies
  - ciliumclusterwidenetworkpolicies
  - ciliumidentities
  - ciliumnodes
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - isovalent.com
  resources:
  - isovalentnetworkpolicies
  - isovalentclusterwidenetworkpolicies
  verbs:
  - get
  - list
  - watch
{{- end }}
