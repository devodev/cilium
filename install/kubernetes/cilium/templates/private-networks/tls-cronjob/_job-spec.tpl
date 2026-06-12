{{- define "private-networks-generate-certs.job.spec" }}
{{- $certValidityStr := printf "%dh" (mul .Values.enterprise.privateNetworks.api.tls.cronJob.certValidityDuration 24) -}}
spec:
  template:
    metadata:
      labels:
        k8s-app: cilium-private-networks-generate-certs
        {{- with .Values.certgen.podLabels }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
    spec:
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: certgen
          image: {{ include "cilium.image" .Values.certgen.image | quote }}
          imagePullPolicy: {{ .Values.certgen.image.pullPolicy }}
          securityContext:
            capabilities:
              drop:
              - ALL
            allowPrivilegeEscalation: false
          {{- with .Values.certgen.resources }}
          resources:
          {{- toYaml . | nindent 12 }}
          {{- end }}
          command:
            - "/usr/bin/cilium-certgen"
          args:
            {{- if .Values.debug.enabled }}
            - "--debug"
            {{- end }}
            - "--ca-generate={{ .Values.certgen.generateCA }}"
            - "--ca-reuse-secret"
            - "--ca-secret-namespace={{ include "cilium.namespace" . }}"
            - "--ca-secret-name=cilium-ca"
            - "--ca-common-name=Cilium CA"
            - "--ca-enforce-validity-throughout-leaves-duration={{ .Values.certgen.enforceCAValidityThroughoutLeavesDuration }}"
          env:
            - name: CILIUM_CERTGEN_CONFIG
              value: |
                certs:
                - name: cilium-private-networks-api-server
                  namespace: {{ include "cilium.namespace" . }}
                  commonName: {{ .Values.cluster.name | quote }}
                  hosts:
                  - {{ .Values.cluster.name | quote }}
                  usage:
                  - signing
                  - key encipherment
                  - server auth
                  validity: {{ $certValidityStr }}
                - name: cilium-private-networks-api-client
                  namespace: {{ include "cilium.namespace" . }}
                  commonName: {{ printf "%s-client" .Values.cluster.name | quote }}
                  usage:
                  - signing
                  - key encipherment
                  - client auth
                  validity: {{ $certValidityStr }}
          {{- with .Values.certgen.extraVolumeMounts }}
          volumeMounts:
          {{- toYaml . | nindent 10 }}
          {{- end }}
      hostNetwork: false
      {{- with .Values.certgen.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- if .Values.certgen.priorityClassName }}
      priorityClassName: {{ .Values.certgen.priorityClassName }}
      {{- end }}
      {{- with .Values.certgen.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      serviceAccountName: "cilium-private-networks-generate-certs"
      automountServiceAccountToken: true
      {{- with .Values.imagePullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      restartPolicy: OnFailure
      {{- with .Values.certgen.extraVolumes }}
      volumes:
      {{- toYaml . | nindent 6 }}
      {{- end }}
      {{- with .Values.certgen.affinity }}
      affinity:
      {{- toYaml . | nindent 8 }}
      {{- end }}
  {{- with .Values.certgen.ttlSecondsAfterFinished }}
  ttlSecondsAfterFinished: {{ . }}
  {{- end }}
{{- end }}
