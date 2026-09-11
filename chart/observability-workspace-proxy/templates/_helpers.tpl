{{/*
Expand the name of the chart.
*/}}
{{- define "observability-workspace-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "observability-workspace-proxy.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "observability-workspace-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "observability-workspace-proxy.labels" -}}
helm.sh/chart: {{ include "observability-workspace-proxy.chart" . }}
{{ include "observability-workspace-proxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "observability-workspace-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "observability-workspace-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name
*/}}
{{- define "observability-workspace-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "observability-workspace-proxy.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Proxy container args
*/}}
{{- define "observability-workspace-proxy.args" -}}
- --listen-address={{ .Values.proxy.listenAddress }}
- --metrics-address={{ .Values.proxy.metricsAddress }}
- --upstream={{ required "proxy.upstream is required" .Values.proxy.upstream }}
- --thalassa-api-url={{ .Values.proxy.thalassaApiUrl }}
- --organisation-id={{ required "proxy.organisationId is required" .Values.proxy.organisationId }}
- --service-account-id={{ required "proxy.serviceAccountId is required" .Values.proxy.serviceAccountId }}
- --subject-token-file={{ .Values.projectedToken.path }}
- --inbound-auth={{ .Values.proxy.inboundAuth }}
- --upstream-timeout={{ .Values.proxy.upstreamTimeout }}
- --max-body-bytes={{ .Values.proxy.maxBodyBytes }}
- --token-refresh-skew={{ .Values.proxy.tokenRefreshSkew }}
{{- if ne .Values.proxy.inboundAuth "none" }}
- --auth-audience={{ required "proxy.authAudience is required when inboundAuth != none" .Values.proxy.authAudience }}
{{- end }}
{{- if eq .Values.proxy.inboundAuth "rbac" }}
- --rbac-resource-api-group={{ .Values.proxy.rbac.resourceApiGroup }}
- --rbac-resource={{ required "proxy.rbac.resource is required when inboundAuth=rbac" .Values.proxy.rbac.resource }}
- --rbac-verb={{ required "proxy.rbac.verb is required when inboundAuth=rbac" .Values.proxy.rbac.verb }}
{{- if .Values.proxy.rbac.namespace }}
- --rbac-namespace={{ .Values.proxy.rbac.namespace }}
{{- end }}
{{- if .Values.proxy.rbac.resourceName }}
- --rbac-resource-name={{ .Values.proxy.rbac.resourceName }}
{{- end }}
{{- end }}
{{- if .Values.tls.enabled }}
- --tls-cert-file=/etc/proxy/tls/tls.crt
- --tls-key-file=/etc/proxy/tls/tls.key
{{- end }}
{{- end }}
