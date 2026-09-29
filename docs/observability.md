# Operational metrics

The operator exposes its metrics through controller-runtime's standard
`/metrics` endpoint. Prometheus metrics are operational telemetry, not a
durable audit trail.

The default Kustomize package enables authenticated/authorized HTTPS metrics,
but it deliberately leaves the optional cert-manager metrics certificate,
ServiceMonitor, and NetworkPolicy overlay disabled. Enable and test those
pieces explicitly in a production overlay; do not infer that a development
metrics endpoint already has your cluster's desired TLS and network boundary.

## Privacy and cardinality boundary

The metric vocabulary deliberately excludes usernames, groups, session or
binding names, UIDs, namespaces, role names, profile names, incident/ticket
IDs, reasons, and API error text. These values may contain personal or
sensitive data and can grow without bound. Use Kubernetes audit logs and the
durable audit/SIEM pipeline for per-session investigation.

Only bounded labels are exposed:

* `scope`: `namespaced`, `cluster`, or `unknown` (`cluster` is reserved for a
  future API; the current profile-based API grants namespaced access only)
* `transition`: `activated`, `denied`, `expired`, `revoked`, `suspended`,
  `drifted`, or `unknown`
* request `transition`: `pending`, `approved`, `denied`, `expired`,
  `provisioning`, `session_created`, `failed`, or `unknown`
* `reason`: `missing`, `ownership`, `uid_mismatch`, `role_ref`, `subjects`,
  `binding_reference`, `missing_expiry`, `integrity_unknown`, or `unknown`
  for binding drift; curated-role drift uses only `missing`, `uid_mismatch`,
  `rules_hash`, `snapshot_missing`, or `unknown`.
* binding `operation`: `grant`, `restore`, `cleanup`, or `unknown`
* `result`: `success`, `error`, or `unknown`
* admission `operation`: `create`, `update`, or `unknown`
* admission `outcome`: `allowed`, `denied`, `error`, or `unknown`

## Metrics

| Metric | Meaning |
| --- | --- |
| `breakglass_active_sessions{scope}` | Sessions whose last persisted phase is `Active`. |
| `breakglass_sessions_past_expiry{scope}` | Active sessions with a missing or elapsed expiry. This should remain zero. |
| `breakglass_session_state_collection_success` | Whether the state collector could list sessions from the manager cache. |
| `breakglass_session_transitions_total{transition,scope}` | Persisted lifecycle transitions. One session can produce multiple transition events over its lifecycle. |
| `breakglass_binding_drift_total{reason,scope}` | Detected managed-binding integrity failures. |
| `breakglass_curated_role_drift_total{reason,scope}` | Detected curated ClusterRole identity or rule-set drift. |
| `breakglass_binding_operations_total{operation,result,scope}` | Privileged RBAC binding actions; routine no-op reconciliations are excluded. |
| `breakglass_expiry_cleanup_lag_seconds{scope}` | Histogram of delay between expiry and successful binding cleanup. |
| `breakglass_admission_requests_total{operation,outcome}` | Terminal webhook decisions. `denied` means policy rejection; `error` signals an admission dependency or internal failure. |
| `breakglass_request_transitions_total{transition}` | Persisted request lifecycle transitions. This contains no requester, profile, namespace, reason, or request identifier. |

The manager also exposes controller-runtime reconciliation, workqueue, Go, and
process metrics. Prefer those generic metrics for controller throughput and
resource health rather than recreating them here.

## Integration contract

`metrics.DefaultRecorder` is registered automatically in controller-runtime's
registry and implements `metrics.LifecycleRecorder`. A reconciler can keep the
interface optional and call its methods after semantic lifecycle boundaries:

* Record a transition only after the relevant status update succeeds.
* Record a cleanup failure or success around the actual cleanup operation, not
  for ordinary no-op reconciles.
* Record drift only on the first transition into the corresponding integrity
  failure state; never use raw errors as a label.
* Observe expiry cleanup lag immediately after a successful expiry cleanup.

`RegisterSessionStateCollector(reader, resolveScope)` must be called once
after manager construction. Its cache-backed collector derives active and
past-expiry gauges at scrape time, which remains accurate through manager
restarts and reconciliation retries. On a successful collection it emits all
three scope series, including zero values; `session_state_collection_success`
distinguishes that healthy zero from an unavailable cache. The caller provides the bounded
`ScopeResolver`; a profile-based API should derive scope from a persisted
binding/profile snapshot, not from a raw profile or namespace label.

## Suggested alerts

* Critical: `breakglass_sessions_past_expiry > 0`.
* Critical: `breakglass_session_state_collection_success == 0` for more than
  one scrape interval; otherwise a zero session gauge cannot be trusted.
* Critical: `increase(breakglass_binding_operations_total{operation="cleanup",result="error"}[5m]) > 0`.
* High severity: `increase(breakglass_binding_drift_total[5m]) > 0`.
* Critical: `increase(breakglass_curated_role_drift_total[5m]) > 0`.
* High severity: `increase(breakglass_admission_requests_total{outcome="error"}[5m]) > 0`; this can block all new requests because the webhook is fail-closed.
* High severity: `increase(breakglass_request_transitions_total{transition="failed"}[5m]) > 0` after approval provisioning is enabled.
* SLO: alert if the 99th percentile of
  `breakglass_expiry_cleanup_lag_seconds` exceeds the documented expiry
  cleanup objective for several minutes.
* Controller health: `increase(controller_runtime_reconcile_errors_total{controller="breakglasssession"}[5m]) > 0`.
