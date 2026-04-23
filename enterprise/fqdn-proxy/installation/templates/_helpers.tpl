{{/*
Expand the name of the chart.
*/}}
{{- define "dnsproxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "dnsproxy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Return user specify priorityClass or default criticalPriorityClass
Usage:
  include "cilium.priorityClass" (list $ <priorityClass> <criticalPriorityClass>)
where:
* `priorityClass`: is user specify priorityClass e.g `.Values.operator.priorityClassName`
* `criticalPriorityClass`: default criticalPriorityClass, e.g `"system-cluster-critical"`
  This value is used when `priorityClass` is `nil` and
  `.Values.enableCriticalPriorityClass=true` and kubernetes supported it.
*/}}
{{- define "priorityClass" -}}
{{- $root := index . 0 -}}
{{- $priorityClass := index . 1 -}}
{{- $criticalPriorityClass := index . 2 -}}
{{- if $priorityClass }}
  {{- $priorityClass }}
{{- else if and $root.Values.enableCriticalPriorityClass $criticalPriorityClass -}}
  {{- if and (eq $root.Release.Namespace "kube-system") (semverCompare ">=1.10-0" $root.Capabilities.KubeVersion.Version) -}}
    {{- $criticalPriorityClass }}
  {{- else if semverCompare ">=1.17-0" $root.Capabilities.KubeVersion.Version -}}
    {{- $criticalPriorityClass }}
  {{- end -}}
{{- end -}}
{{- end -}}


{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "dnsproxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "dnsproxy.labels" -}}
helm.sh/chart: {{ include "dnsproxy.chart" . }}
{{ include "dnsproxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "dnsproxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dnsproxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "dnsproxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "dnsproxy.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Merge required security context for dnsproxy with user supplied securityContext.
*/}}
{{- define "dnsproxy.securityContext" -}}
{{- $caps := list "NET_ADMIN" "NET_RAW" -}}
{{- if .Values.offlineMode.enabled -}}
  {{- $caps = append $caps "BPF" -}}
{{- end -}}
{{- $ctx := dict "capabilities" (dict "add" $caps) -}}
{{- mustMerge (deepCopy .Values.securityContext) $ctx | toYaml -}}
{{- end -}}
