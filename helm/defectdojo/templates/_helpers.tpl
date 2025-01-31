{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "defectdojo.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "defectdojo.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "defectdojo.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}


{{/*
  Determine the hostname to use for PostgreSQL/Redis.
*/}}
{{- define "postgresql.hostname" -}}
{{- if eq .Values.database "postgresql" -}}
{{- if .Values.postgresql.enabled -}}
{{- if eq .Values.postgresql.architecture "replication" -}}
{{- printf "%s-%s-%s" .Release.Name "postgresql" .Values.postgresql.primary.name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name "postgresql" | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- else -}}
{{- printf "%s" .Values.postgresql.postgresServer -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- define "postgresqlha.hostname" -}}
{{- if eq .Values.database "postgresqlha" -}}
{{- if .Values.postgresqlha.enabled -}}
{{- printf "%s-%s" .Release.Name "postgresqlha-pgpool" | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s" .Values.postgresqlha.postgresServer -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- define "redis.hostname" -}}
{{- if eq .Values.celery.broker "redis" -}}
{{- if .Values.redis.enabled -}}
{{- printf "%s-%s" .Release.Name "redis-master" | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s" (.Values.celery.brokerHost | default .Values.redis.redisServer) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
  Determine the protocol to use for Redis.
*/}}
{{- define "redis.scheme" -}}
{{- if eq .Values.celery.broker "redis" -}}
{{- if .Values.redis.transportEncryption.enabled -}}
{{- printf "rediss" -}}
{{- else if eq .Values.redis.scheme "sentinel" -}}
{{- printf "sentinel" -}}
{{- else -}}
{{- printf "redis" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
  Builds the repository names for use with local or private registries
*/}}
{{- define "celery.repository" -}}
{{- printf "%s" .Values.repositoryPrefix -}}/defectdojo-django
{{- end -}}

{{- define "django.nginx.repository" -}}
{{- printf "%s" .Values.repositoryPrefix -}}/defectdojo-nginx
{{- end -}}

{{- define "django.uwsgi.repository" -}}
{{- printf "%s" .Values.repositoryPrefix -}}/defectdojo-django
{{- end -}}

{{- define "initializer.repository" -}}
{{- printf "%s" .Values.repositoryPrefix -}}/defectdojo-django
{{- end -}}

{{- define "initializer.jobname" -}}
{{- if .Values.initializer.staticName -}}
{{ .Release.Name }}-initializer
{{- else -}}
{{ .Release.Name }}-initializer-{{- printf "%s" now | date "2006-01-02-15-04" -}}
{{- end -}}
{{- end -}}

{{/*
  Creates the array for DD_ALLOWED_HOSTS in configmap
*/}}
{{- define "django.allowed_hosts" -}}
{{- if .Values.alternativeHosts -}}
{{- $hosts := .Values.host -}}
{{- printf "%s,%s" $hosts (join "," .Values.alternativeHosts) -}}
{{- else -}}
{{ .Values.host }}
{{- end -}}
{{- end -}}

{{/*
  Creates the persistentVolumeName
*/}}
{{- define "django.pvc_name" -}}
{{- if .Values.django.mediaPersistentVolume.persistentVolumeClaim.create -}}
{{- printf "%s-django-media" .Release.Name -}}
{{- else -}}
{{ .Values.django.mediaPersistentVolume.persistentVolumeClaim.name }}
{{- end -}}
{{- end -}}

{{/*
  Define db-migration-checker
*/}}
{{- define "dbMigrationChecker" -}}
- name: db-migration-checker
  command:
  - sh
  - -c
  - while ! /app/manage.py migrate --check; do echo "Database is not migrated to the latest state yet"; sleep 5; done; echo "Database is migrated to the latest state";
  image: '{{ template "django.uwsgi.repository" . }}:{{ .Values.tag }}'
  imagePullPolicy: {{ .Values.imagePullPolicy }}
  {{- if .Values.securityContext.enabled }}
  securityContext:
    {{- toYaml .Values.securityContext.djangoSecurityContext | nindent 4 }}
  {{- end }}
  envFrom:
  - configMapRef:
      name: {{ .fullName }}
  - secretRef:
      name: {{ .fullName }}-extrasecrets
      optional: true
  env:
  {{- if .Values.django.uwsgi.enableDebug }}
  - name: DD_DEBUG
    value: 'True'
  {{- end }}
  - name: DD_DATABASE_PASSWORD
    valueFrom:
      secretKeyRef:
        {{- if eq .Values.database "postgresql" }}
          name: {{ .Values.postgresql.auth.existingSecret | default "defectdojo-postgresql-specific" }}
          key: {{ .Values.postgresql.auth.secretKeys.userPasswordKey | default "postgresql-password" }}
        {{- else if eq .Values.database "postgresqlha" }}
          name: {{ .Values.postgresqlha.postgresql.existingSecret | default "defectdojo-postgresql-ha-specific" }}
          key: postgresql-postgres-password
        {{- end }}
  {{- if .Values.extraEnv }}
  {{- toYaml .Values.extraEnv | nindent 2 }}
  {{- end }}
  resources:
    {{- toYaml .Values.dbMigrationChecker.resources | nindent 4 }}
{{- end -}}
