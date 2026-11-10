{{/*
Chart name, truncated to the 63 characters Kubernetes allows in names.
*/}}
{{- define "dbgateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name. If the release name contains the chart name, it is
used as the full name.
*/}}
{{- define "dbgateway.fullname" -}}
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

{{- define "dbgateway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "dbgateway.labels" -}}
helm.sh/chart: {{ include "dbgateway.chart" . }}
{{ include "dbgateway.selectorLabels" . }}
app.kubernetes.io/version: {{ include "dbgateway.imageTag" . | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: dbgateway
{{- end }}

{{- define "dbgateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dbgateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "dbgateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "dbgateway.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "dbgateway.imageTag" -}}
{{- .Values.image.tag | default .Chart.AppVersion | toString }}
{{- end }}

{{- define "dbgateway.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (include "dbgateway.imageTag" .) }}
{{- end }}
{{- end }}

{{- define "dbgateway.configMapName" -}}
{{- default (include "dbgateway.fullname" .) .Values.existingConfigMap }}
{{- end }}

{{- define "dbgateway.configMapKey" -}}
{{- if .Values.existingConfigMap }}
{{- .Values.existingConfigMapKey }}
{{- else -}}
dbgateway.yaml
{{- end }}
{{- end }}

{{- define "dbgateway.secretName" -}}
{{- printf "%s-env" (include "dbgateway.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "dbgateway.pvcName" -}}
{{- default (printf "%s-data" (include "dbgateway.fullname" .)) .Values.persistence.existingClaim }}
{{- end }}

{{/*
Whether the chart renders (and can inspect) the configuration.
*/}}
{{- define "dbgateway.ownsConfig" -}}
{{- if not .Values.existingConfigMap }}true{{ end }}
{{- end }}

{{/*
server section of the values configuration (empty dict when absent).
*/}}
{{- define "dbgateway.serverConfig" -}}
{{- $config := .Values.config | default dict }}
{{- toYaml (get $config "server" | default dict) }}
{{- end }}

{{/*
Store driver from the configuration: "sqlite" (the dbgateway default),
"postgres", or "" when the configuration is an existing ConfigMap.
*/}}
{{- define "dbgateway.storeDriver" -}}
{{- if include "dbgateway.ownsConfig" . }}
{{- $config := .Values.config | default dict }}
{{- $store := get $config "store" | default dict }}
{{- get $store "driver" | default "sqlite" }}
{{- end }}
{{- end }}

{{/*
Audit output from the configuration: "file" (the dbgateway default),
"stdout", "postgres", or "" when the configuration is an existing ConfigMap.
*/}}
{{- define "dbgateway.auditOutput" -}}
{{- if include "dbgateway.ownsConfig" . }}
{{- $config := .Values.config | default dict }}
{{- $audit := get $config "audit" | default dict }}
{{- get $audit "output" | default "file" }}
{{- end }}
{{- end }}

{{/*
Whether only one pod may run at a time: the SQLite store, or a persistent
volume (ReadWriteOnce, and the audit files must not be shared).
*/}}
{{- define "dbgateway.singleton" -}}
{{- if or (eq (include "dbgateway.storeDriver" .) "sqlite") .Values.persistence.enabled }}true{{ end }}
{{- end }}

{{- define "dbgateway.replicas" -}}
{{- if include "dbgateway.singleton" . }}1{{ else }}{{ .Values.replicaCount }}{{ end }}
{{- end }}

{{/*
Host part of a listen address ("0.0.0.0:8443" -> "0.0.0.0", "[::1]:80" -> "[::1]").
*/}}
{{- define "dbgateway.listenHost" -}}
{{- regexReplaceAll ":[0-9]+$" . "" }}
{{- end }}

{{- define "dbgateway.listenPort" -}}
{{- regexFind "[0-9]+$" . }}
{{- end }}

{{- define "dbgateway.isLoopback" -}}
{{- $host := include "dbgateway.listenHost" . | trimPrefix "[" | trimSuffix "]" }}
{{- if or (eq $host "localhost") (eq $host "::1") (hasPrefix "127." $host) }}true{{ end }}
{{- end }}

{{/*
server.public_url: from the configuration, else https://<first ingress host>.
*/}}
{{- define "dbgateway.publicURL" -}}
{{- $server := include "dbgateway.serverConfig" . | fromYaml }}
{{- if $server.public_url }}
{{- $server.public_url | trimSuffix "/" }}
{{- else if and .Values.ingress.enabled .Values.ingress.hosts }}
{{- with (first .Values.ingress.hosts).host }}{{ printf "https://%s" . }}{{ end }}
{{- end }}
{{- end }}

{{/*
The dbgateway configuration file rendered from values, with public_url and
metrics_listen filled in.
*/}}
{{- define "dbgateway.config" -}}
{{- $config := deepCopy (.Values.config | default dict) }}
{{- $server := get $config "server" | default dict }}
{{- $publicURL := include "dbgateway.publicURL" . }}
{{- if $publicURL }}
{{- $_ := set $server "public_url" $publicURL }}
{{- end }}
{{- if and .Values.metrics.enabled (not $server.metrics_listen) }}
{{- $_ := set $server "metrics_listen" (printf "0.0.0.0:%v" .Values.ports.metrics) }}
{{- end }}
{{- $_ := set $config "server" $server }}
{{- toYaml $config }}
{{- end }}

{{/*
Checks of the values that would otherwise only fail when the pod starts (or,
worse, run in a way that loses data). Rendered by the Deployment.
*/}}
{{- define "dbgateway.validate" -}}
{{- $replicas := int .Values.replicaCount }}
{{- if lt $replicas 1 }}
{{- fail "dbgateway: replicaCount must be at least 1" }}
{{- end }}
{{- if include "dbgateway.ownsConfig" . }}
{{- if not .Values.config }}
{{- fail "dbgateway: set `config` (the dbgateway configuration) or `existingConfigMap`" }}
{{- end }}
{{- if not .Values.config.auth }}
{{- fail "dbgateway: config.auth is required: configure auth.oidc or auth.passkeys (see https://kyosu-1.github.io/dbgateway/authentication)" }}
{{- end }}
{{- $server := include "dbgateway.serverConfig" . | fromYaml }}
{{- $listen := $server.listen | default "" | toString }}
{{- if not $listen }}
{{- fail (printf "dbgateway: set config.server.listen to 0.0.0.0:%v (the default 127.0.0.1:8443 is not reachable from outside the pod)" .Values.ports.http) }}
{{- end }}
{{- if include "dbgateway.isLoopback" $listen }}
{{- fail (printf "dbgateway: config.server.listen %q is a loopback address, which the Service and probes cannot reach; use 0.0.0.0:%v" $listen .Values.ports.http) }}
{{- end }}
{{- if ne (include "dbgateway.listenPort" $listen) (toString .Values.ports.http) }}
{{- fail (printf "dbgateway: the port of config.server.listen (%q) must equal ports.http (%v)" $listen .Values.ports.http) }}
{{- end }}
{{- $publicURL := include "dbgateway.publicURL" . }}
{{- if not $publicURL }}
{{- fail "dbgateway: set config.server.public_url to the external https URL of dbgateway (or enable the Ingress, which provides it)" }}
{{- end }}
{{- if not (hasPrefix "https://" $publicURL) }}
{{- fail (printf "dbgateway: config.server.public_url %q must use https; terminate TLS in front of dbgateway" $publicURL) }}
{{- end }}
{{- if .Values.ingress.enabled }}
{{- $publicHost := regexReplaceAll "^https://([^/:]+).*$" $publicURL "${1}" }}
{{- $hosts := list }}
{{- range .Values.ingress.hosts }}{{ $hosts = append $hosts .host }}{{ end }}
{{- if not (has $publicHost $hosts) }}
{{- fail (printf "dbgateway: the host of config.server.public_url (%s) is not one of ingress.hosts (%s); sign-in redirects and OAuth metadata use public_url" $publicHost (join ", " $hosts)) }}
{{- end }}
{{- end }}
{{- if and .Values.metrics.enabled $server.metrics_listen }}
{{- $ml := $server.metrics_listen | toString }}
{{- if include "dbgateway.isLoopback" $ml }}
{{- fail (printf "dbgateway: metrics.enabled needs config.server.metrics_listen on all interfaces (0.0.0.0:%v), not %q; or remove it and the chart sets it" .Values.ports.metrics $ml) }}
{{- end }}
{{- if ne (include "dbgateway.listenPort" $ml) (toString .Values.ports.metrics) }}
{{- fail (printf "dbgateway: the port of config.server.metrics_listen (%q) must equal ports.metrics (%v)" $ml .Values.ports.metrics) }}
{{- end }}
{{- end }}
{{- end }}
{{- if and .Values.metrics.serviceMonitor.enabled (not .Values.metrics.enabled) }}
{{- fail "dbgateway: metrics.serviceMonitor.enabled requires metrics.enabled" }}
{{- end }}
{{- if gt $replicas 1 }}
{{- if eq (include "dbgateway.storeDriver" .) "sqlite" }}
{{- fail "dbgateway: replicaCount > 1 requires the PostgreSQL store (config.store.driver: postgres, dsn_env: ...); the SQLite store supports a single instance. See https://kyosu-1.github.io/dbgateway/ha" }}
{{- end }}
{{- if eq (include "dbgateway.auditOutput" .) "file" }}
{{- fail "dbgateway: replicaCount > 1 requires config.audit.output: postgres (or stdout); audit files would live on each pod's ephemeral volume. See https://kyosu-1.github.io/dbgateway/ha" }}
{{- end }}
{{- if .Values.persistence.enabled }}
{{- fail "dbgateway: replicaCount > 1 requires persistence.enabled: false; the volume holds the SQLite store and audit files of a single instance" }}
{{- end }}
{{- end }}
{{- end }}
