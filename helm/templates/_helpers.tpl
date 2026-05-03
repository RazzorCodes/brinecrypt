{{- define "brinecrypt.name" -}}
{{- .Release.Name }}
{{- end }}

{{- define "brinecrypt.labels" -}}
app.kubernetes.io/name: brinecrypt
app.kubernetes.io/instance: {{ .Release.Name }}
app: brinecrypt
{{- end }}

{{- define "brinecrypt.selectorLabels" -}}
app: brinecrypt
{{- end }}

{{- define "brinecrypt.syncNamespace" -}}
{{- if .Values.syncNamespace }}{{ .Values.syncNamespace }}{{- else }}{{ .Release.Namespace }}{{- end }}
{{- end }}

{{- define "brinekey.name" -}}
{{- printf "%s-brinekey" .Release.Name -}}
{{- end }}

{{- define "brinekey.brinecryptURL" -}}
{{- if .Values.brinekey.brinecryptUrl }}{{ .Values.brinekey.brinecryptUrl }}{{- else }}http://{{ include "brinecrypt.name" . }}:{{ .Values.service.port }}{{- end }}
{{- end }}
