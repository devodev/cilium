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
{{- $ctx := dict "capabilities" (dict "add" $caps "drop" (list "ALL")) -}}
{{- mustMerge (deepCopy .Values.securityContext) $ctx | toYaml -}}
{{- end -}}
