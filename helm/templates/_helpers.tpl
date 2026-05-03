{{- define "brinecrypt.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "brinecrypt.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end }}

{{- define "brinecrypt.labels" -}}
app.kubernetes.io/name: {{ include "brinecrypt.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
app: brinecrypt
{{- end }}

{{- define "brinecrypt.selectorLabels" -}}
app: brinecrypt
{{- end }}

{{- define "brinecrypt.syncNamespace" -}}
{{- if .Values.syncNamespace }}{{ .Values.syncNamespace }}{{- else }}{{ .Release.Namespace }}{{- end }}
{{- end }}

{{- define "brinekey.name" -}}
{{- printf "%s-brinekey" (include "brinecrypt.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "brinekey.brinecryptURL" -}}
{{- if .Values.brinekey.brinecryptUrl }}{{ .Values.brinekey.brinecryptUrl }}{{- else }}http://{{ include "brinecrypt.fullname" . }}:{{ .Values.service.port }}{{- end }}
{{- end }}
