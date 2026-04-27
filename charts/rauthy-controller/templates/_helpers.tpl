{{/*
Expand the name of the chart.
*/}}
{{- define "rauthy-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "rauthy-controller.fullname" -}}
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
{{- define "rauthy-controller.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Image tag
*/}}
{{- define "rauthy-controller.imageTag" -}}
{{- if .Values.image.tag }}
{{- .Values.image.tag }}
{{- else }}
{{- .Chart.AppVersion }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "rauthy-controller.labels" -}}
{{- include "rauthy-controller.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ include "rauthy-controller.chart" . }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "rauthy-controller.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rauthy-controller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Name of the Secret containing Rauthy credentials
*/}}
{{- define "rauthy-controller.secretName" -}}
{{- required "rauthy.existingSecret is required" .Values.rauthy.existingSecret }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "rauthy-controller.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "rauthy-controller.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
RBAC scope
*/}}
{{- define "rauthy-controller.rbacScope" -}}
{{- $scope := .Values.rbac.scope | default "auto" -}}
{{- if eq $scope "auto" -}}
{{- if eq (len .Values.watchNamespaces) 0 -}}
cluster
{{- else -}}
namespaced
{{- end -}}
{{- else -}}
{{- $scope -}}
{{- end -}}
{{- end }}