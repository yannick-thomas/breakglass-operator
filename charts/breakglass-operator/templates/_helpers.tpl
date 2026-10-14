{{- define "breakglass.fullname" -}}
{{- if gt (len .Release.Name) 28 -}}
{{- fail "release name must be at most 28 characters (metrics Service name limit)" -}}
{{- end -}}
{{- .Release.Name -}}
{{- end -}}

{{- define "breakglass.labels" -}}
app.kubernetes.io/name: breakglass-operator
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

{{- define "breakglass.managerSelector" -}}
app.kubernetes.io/name: breakglass-operator
app.kubernetes.io/instance: {{ .Release.Name | quote }}
control-plane: controller-manager
{{- end -}}

{{- define "breakglass.image" -}}
{{- if and .digest .tag -}}
{{- fail "set either image.digest or image.tag, never both" -}}
{{- else if .digest -}}
{{- printf "%s@%s" .repository .digest -}}
{{- else if .tag -}}
{{- printf "%s:%s" .repository .tag -}}
{{- else -}}
{{- fail "set image.digest from a gated release (or image.tag for development)" -}}
{{- end -}}
{{- end -}}

{{- define "breakglass.podSecurity" -}}
runAsNonRoot: true
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "breakglass.containerSecurity" -}}
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false
capabilities:
  drop: [ALL]
{{- end -}}
