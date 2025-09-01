{{/*
Expand the name of the chart.
*/}}
{{- define "stamp-bpf.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "stamp-bpf.fullname" -}}
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
{{- define "stamp-bpf.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "stamp-bpf.labels" -}}
helm.sh/chart: {{ include "stamp-bpf.chart" . }}
{{ include "stamp-bpf.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "stamp-bpf.selectorLabels" -}}
app.kubernetes.io/name: {{ include "stamp-bpf.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "stamp-bpf.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "stamp-bpf.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name for sender resources
*/}}
{{- define "stamp-bpf.sender.fullname" -}}
{{- printf "%s-sender" (include "stamp-bpf.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create the name for reflector resources
*/}}
{{- define "stamp-bpf.reflector.fullname" -}}
{{- printf "%s-reflector" (include "stamp-bpf.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create the name for sender PodMonitor
*/}}
{{- define "stamp-bpf.sender.podmonitor" -}}
{{- printf "%s-sender" (include "stamp-bpf.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create the name for reflector PodMonitor
*/}}
{{- define "stamp-bpf.reflector.podmonitor" -}}
{{- printf "%s-reflector" (include "stamp-bpf.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create the name for the namespace
*/}}
{{- define "stamp-bpf.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride }}
{{- end }}

{{/*
Generate image name
*/}}
{{- define "stamp-bpf.image" -}}
{{- $repository := .repository -}}
{{- $tag := .tag -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end }}

{{/*
Generate sender image name
*/}}
{{- define "stamp-bpf.sender.image" -}}
{{- $image := dict -}}
{{- if .Values.sender.image -}}
  {{- $image = .Values.sender.image -}}
{{- else -}}
  {{- $image = .Values.global.image -}}
{{- end -}}
{{- include "stamp-bpf.image" $image -}}
{{- end -}}


{{/*
Generate reflector image name
*/}}
{{- define "stamp-bpf.reflector.image" -}}
{{- $image := dict -}}
{{- if .Values.reflector.image -}}
  {{- $image = .Values.reflector.image -}}
{{- else -}}
  {{- $image = .Values.global.image -}}
{{- end -}}
{{- include "stamp-bpf.image" $image -}}
{{- end -}}


{{/*
Generate pod security context
*/}}
{{- define "stamp-bpf.podSecurityContext" -}}
{{- if $.Values.global.security.podSecurityContext -}}
{{- toYaml $.Values.global.security.podSecurityContext -}}
{{- else -}}
{{- toYaml .Values.security.podSecurityContext -}}
{{- end -}}
{{- end }}

{{/*
Generate container security context
*/}}
{{- define "stamp-bpf.containerSecurityContext" -}}
{{- if $.Values.global.security.containerSecurityContext -}}
{{- toYaml $.Values.global.security.containerSecurityContext -}}
{{- else -}}
{{- toYaml .Values.security.containerSecurityContext -}}
{{- end -}}
{{- end }}

{{/*
Generate node selector
*/}}
{{- define "stamp-bpf.nodeSelector" -}}
{{- if .nodeSelector -}}
{{- toYaml .nodeSelector -}}
{{- else -}}
{{- toYaml $.Values.global.nodeSelector -}}
{{- end -}}
{{- end }}

{{/*
Generate tolerations
*/}}
{{- define "stamp-bpf.tolerations" -}}
{{- if .tolerations -}}
{{- toYaml .tolerations -}}
{{- else -}}
{{- toYaml $.Values.global.tolerations -}}
{{- end -}}
{{- end }}

{{/*
Generate affinity
*/}}
{{- define "stamp-bpf.affinity" -}}
{{- if .affinity -}}
{{- toYaml .affinity -}}
{{- else -}}
{{- toYaml $.Values.global.affinity -}}
{{- end -}}
{{- end }}

{{/*
Generate sender container arguments
*/}}
{{- define "stamp-bpf.sender.args" -}}
{{- $args := list -}}
{{- $args = append $args .Values.sender.interface -}}
{{- if .reflectorIP -}}
{{- $args = append $args .reflectorIP -}}
{{- end -}}
{{- if ne (int .Values.sender.sourcePort) 862 -}}
{{- $args = append $args (printf "-s=%d" .Values.sender.sourcePort) -}}
{{- end -}}
{{- if ne (int .Values.sender.destinationPort) 862 -}}
{{- $args = append $args (printf "-d=%d" .Values.sender.destinationPort) -}}
{{- end -}}
{{- if ne (int .Values.sender.count) 0 -}}
{{- $args = append $args (printf "-c=%d" .Values.sender.count) -}}
{{- end -}}
{{- if ne (float64 .Values.sender.interval) 1.0 -}}
{{- $args = append $args (printf "-i=%f" .Values.sender.interval) -}}
{{- end -}}
{{- if ne (int .Values.sender.timeout) 1 -}}
{{- $args = append $args (printf "-w=%d" .Values.sender.timeout) -}}
{{- end -}}
{{- if .Values.sender.debug -}}
{{- $args = append $args "--debug" -}}
{{- end -}}
{{- if .Values.sender.histogram.enabled -}}
{{- $args = append $args "--hist" -}}
{{- if ne (int .Values.sender.histogram.bins) 28 -}}
{{- $args = append $args (printf "--bins=%d" .Values.sender.histogram.bins) -}}
{{- end -}}
{{- if ne (int .Values.sender.histogram.floor) 25 -}}
{{- $args = append $args (printf "--floor=%d" .Values.sender.histogram.floor) -}}
{{- end -}}
{{- if ne (int .Values.sender.histogram.ceiling) 75 -}}
{{- $args = append $args (printf "--ceiling=%d" .Values.sender.histogram.ceiling) -}}
{{- end -}}
{{- if ne .Values.sender.histogram.path "/tmp/sender-hist" -}}
{{- $args = append $args (printf "--histpath=%s" .Values.sender.histogram.path) -}}
{{- end -}}
{{- end -}}
{{- if .Values.sender.enforceSync -}}
{{- $args = append $args "--enforce-sync" -}}
{{- end -}}
{{- if .Values.sender.enforcePTP -}}
{{- $args = append $args "--enforce-ptp" -}}
{{- end -}}
{{- range .Values.sender.extraArgs -}}
{{- $args = append $args . -}}
{{- end -}}
{{- toYaml $args -}}
{{- end }}

{{/*
Generate reflector container arguments
*/}}
{{- define "stamp-bpf.reflector.args" -}}
{{- $args := list -}}
{{- $args = append $args .Values.reflector.interface -}}
{{- if ne (int .Values.reflector.port) 862 -}}
{{- $args = append $args (printf "-p=%d" .Values.reflector.port) -}}
{{- end -}}
{{- if .Values.reflector.debug -}}
{{- $args = append $args "--debug" -}}
{{- end -}}
{{- if .Values.reflector.output -}}
{{- $args = append $args "--output" -}}
{{- end -}}
{{- if .Values.reflector.histogram.enabled -}}
{{- $args = append $args "--hist" -}}
{{- if ne (int .Values.reflector.histogram.bins) 28 -}}
{{- $args = append $args (printf "--bins=%d" .Values.reflector.histogram.bins) -}}
{{- end -}}
{{- if ne (int .Values.reflector.histogram.floor) 25 -}}
{{- $args = append $args (printf "--floor=%d" .Values.reflector.histogram.floor) -}}
{{- end -}}
{{- if ne (int .Values.reflector.histogram.ceiling) 75 -}}
{{- $args = append $args (printf "--ceiling=%d" .Values.reflector.histogram.ceiling) -}}
{{- end -}}
{{- if ne .Values.reflector.histogram.path "/tmp/reflector-hist" -}}
{{- $args = append $args (printf "--histpath=%s" .Values.reflector.histogram.path) -}}
{{- end -}}
{{- end -}}
{{- if .Values.reflector.enforceSync -}}
{{- $args = append $args "--enforce-sync" -}}
{{- end -}}
{{- if .Values.reflector.enforcePTP -}}
{{- $args = append $args "--enforce-ptp" -}}
{{- end -}}
{{- range .Values.reflector.extraArgs -}}
{{- $args = append $args . -}}
{{- end -}}
{{- toYaml $args -}}
{{- end }}