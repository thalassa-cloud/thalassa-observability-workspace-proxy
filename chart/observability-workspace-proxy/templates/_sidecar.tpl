{{- /* Sidecar container snippet for embedding in application pods. */ -}}
{{- define "observability-workspace-proxy.sidecarContainer" -}}
- name: observability-workspace-proxy
  image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  args:
    {{- include "observability-workspace-proxy.args" . | nindent 4 }}
  ports:
    - name: proxy
      containerPort: {{ regexReplaceAll ".*:(\\d+)$" .Values.proxy.listenAddress "${1}" | int }}
      protocol: TCP
  livenessProbe:
    httpGet:
      path: /healthz
      port: proxy
  readinessProbe:
    httpGet:
      path: /readyz
      port: proxy
  resources:
    {{- toYaml .Values.resources | nindent 4 }}
  securityContext:
    {{- toYaml .Values.securityContext | nindent 4 }}
  volumeMounts:
    - name: thalassa-token
      mountPath: {{ dir .Values.projectedToken.path }}
      readOnly: true
{{- end -}}

{{- define "observability-workspace-proxy.sidecarVolume" -}}
- name: thalassa-token
  projected:
    sources:
      - serviceAccountToken:
          path: {{ base .Values.projectedToken.path }}
          audience: {{ .Values.projectedToken.audience | quote }}
          expirationSeconds: {{ .Values.projectedToken.expirationSeconds }}
{{- end -}}
