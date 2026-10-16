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

{{- define "breakglass.admissionSelector" -}}
app.kubernetes.io/name: breakglass-operator
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/component: admission
{{- end -}}

{{/*
Placement and trust-anchor arguments shared by the manager and admission
(ADR-005). Both Deployments render them from this one definition so their
namespace scope and the trusted controller identity cannot differ.
*/}}
{{- define "breakglass.placementArgs" -}}
- {{ printf "--allowed-target-namespaces=%s" (join "," .Values.allowedTargetNamespaces) | quote }}
- {{ printf "--control-namespaces=%s" (join "," .Values.controlNamespaces) | quote }}
- {{ printf "--request-controller-username=system:serviceaccount:%s:%s-controller-manager" .Release.Namespace (include "breakglass.fullname" .) | quote }}
{{- end -}}

{{/* Pod placement shared by the manager and admission Deployments. */}}
{{- define "breakglass.podScheduling" -}}
{{- with .root.Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .root.Values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .root.Values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .root.Values.priorityClassName }}
priorityClassName: {{ . | quote }}
{{- end }}
{{- if .root.Values.availability.spreadAcrossHosts }}
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: DoNotSchedule
    nodeTaintsPolicy: Honor
    labelSelector:
      matchLabels:
        {{- .selector | nindent 8 }}
{{- end }}
{{- end -}}
