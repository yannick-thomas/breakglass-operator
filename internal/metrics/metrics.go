/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package metrics exposes privacy-safe operational metrics for the
// BreakGlass controller. It deliberately accepts only bounded label values;
// audit details such as subjects, reasons, session names, and namespaces do
// not belong in Prometheus labels.
package metrics

import (
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	controllerruntimemetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	metricNamespace       = "breakglass"
	metricLabelTransition = "transition"
	metricLabelScope      = "scope"
	metricLabelReason     = "reason"
	metricLabelOperation  = "operation"
	metricLabelResult     = "result"
	metricLabelOutcome    = "outcome"
)

// Scope describes the breadth of a grant without revealing its target
// namespace. Unknown is used when a request cannot be resolved to a scope.
type Scope string

const (
	ScopeNamespaced Scope = "namespaced"
	ScopeCluster    Scope = "cluster"
	ScopeUnknown    Scope = "unknown"
)

// ScopeFromBindingKind converts a persisted RBAC binding kind into a bounded
// scope label. It intentionally does not need a namespace or profile name.
func ScopeFromBindingKind(kind string) Scope {
	switch kind {
	case "RoleBinding":
		return ScopeNamespaced
	case "ClusterRoleBinding":
		return ScopeCluster
	default:
		return ScopeUnknown
	}
}

// LifecycleTransition is a persisted BreakGlassSession lifecycle transition.
type LifecycleTransition string

const (
	TransitionActivated LifecycleTransition = "activated"
	TransitionDenied    LifecycleTransition = "denied"
	TransitionExpired   LifecycleTransition = "expired"
	TransitionRevoked   LifecycleTransition = "revoked"
	TransitionSuspended LifecycleTransition = "suspended"
	TransitionDrifted   LifecycleTransition = "drifted"
	TransitionUnknown   LifecycleTransition = "unknown"
)

// BindingDriftReason is a fixed vocabulary for a binding-integrity failure.
// Do not pass API errors or object identifiers as a metric label.
type BindingDriftReason string

const (
	DriftMissing          BindingDriftReason = "missing"
	DriftOwnership        BindingDriftReason = "ownership"
	DriftUIDMismatch      BindingDriftReason = "uid_mismatch"
	DriftRoleRef          BindingDriftReason = "role_ref"
	DriftSubjects         BindingDriftReason = "subjects"
	DriftBindingReference BindingDriftReason = "binding_reference"
	DriftMissingExpiry    BindingDriftReason = "missing_expiry"
	DriftIntegrityUnknown BindingDriftReason = "integrity_unknown"
	DriftUnknown          BindingDriftReason = "unknown"
)

// CuratedRoleDriftReason is a fixed vocabulary for a curated ClusterRole
// integrity failure. It intentionally excludes role names and rule contents.
type CuratedRoleDriftReason string

const (
	CuratedRoleMissing         CuratedRoleDriftReason = "missing"
	CuratedRoleUIDMismatch     CuratedRoleDriftReason = "uid_mismatch"
	CuratedRoleRulesHash       CuratedRoleDriftReason = "rules_hash"
	CuratedRoleSnapshotMissing CuratedRoleDriftReason = "snapshot_missing"
	CuratedRoleUnknown         CuratedRoleDriftReason = "unknown"
)

// BindingOperation identifies a privileged RBAC lifecycle action.
type BindingOperation string

const (
	BindingOperationGrant   BindingOperation = "grant"
	BindingOperationRestore BindingOperation = "restore"
	BindingOperationCleanup BindingOperation = "cleanup"
	BindingOperationUnknown BindingOperation = "unknown"
)

// BindingOperationResult records whether a privileged RBAC lifecycle action
// reached its desired state.
type BindingOperationResult string

const (
	BindingOperationSuccess       BindingOperationResult = "success"
	BindingOperationError         BindingOperationResult = "error"
	BindingOperationUnknownResult BindingOperationResult = "unknown"
)

// AdmissionOperation identifies the Kubernetes operation that reached the
// BreakGlassSession admission boundary. It intentionally excludes resource
// names, users, groups, and namespaces.
type AdmissionOperation string

const (
	AdmissionOperationCreate  AdmissionOperation = "create"
	AdmissionOperationUpdate  AdmissionOperation = "update"
	AdmissionOperationUnknown AdmissionOperation = "unknown"
)

// AdmissionOutcome is the terminal result of a BreakGlassSession admission
// decision. The fixed vocabulary keeps the metric safe for Prometheus labels.
type AdmissionOutcome string

const (
	AdmissionOutcomeAllowed AdmissionOutcome = "allowed"
	AdmissionOutcomeDenied  AdmissionOutcome = "denied"
	AdmissionOutcomeError   AdmissionOutcome = "error"
	AdmissionOutcomeUnknown AdmissionOutcome = "unknown"
)

// LifecycleRecorder is the small interface a reconciler needs to emit
// operational telemetry. It makes controller tests independent of the global
// Prometheus registry.
type LifecycleRecorder interface {
	RecordTransition(LifecycleTransition, Scope)
	RecordBindingDrift(BindingDriftReason, Scope)
	RecordCuratedRoleDrift(CuratedRoleDriftReason, Scope)
	RecordBindingOperation(BindingOperation, BindingOperationResult, Scope)
	ObserveExpiryCleanupLag(Scope, time.Duration)
}

// AdmissionRecorder is the small interface webhooks need to report a
// terminal admission decision without exposing request-specific data.
type AdmissionRecorder interface {
	RecordAdmissionRequest(AdmissionOperation, AdmissionOutcome)
}

// Recorder owns the bounded-label Prometheus collectors used by the
// controller. Metrics are best-effort operational telemetry, not an audit
// record.
type Recorder struct {
	transitions       *prometheus.CounterVec
	bindingDrift      *prometheus.CounterVec
	curatedRoleDrift  *prometheus.CounterVec
	bindingOperations *prometheus.CounterVec
	expiryCleanupLag  *prometheus.HistogramVec
	admissionRequests *prometheus.CounterVec
}

var _ LifecycleRecorder = (*Recorder)(nil)
var _ AdmissionRecorder = (*Recorder)(nil)

// DefaultRecorder is registered in controller-runtime's registry, which is
// served by the manager's standard metrics endpoint.
var DefaultRecorder = MustNewRecorder(controllerruntimemetrics.Registry)

// NewRecorder constructs and registers the lifecycle collectors with the
// supplied registry. Supplying a dedicated registry keeps unit tests isolated
// from controller-runtime's process-wide registry.
func NewRecorder(registry prometheus.Registerer) (*Recorder, error) {
	if registry == nil {
		return nil, fmt.Errorf("register BreakGlass metrics: registry is nil")
	}

	recorder := &Recorder{
		transitions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "session_transitions_total",
			Help:      "Total number of BreakGlassSession lifecycle transitions.",
		}, []string{metricLabelTransition, metricLabelScope}),
		bindingDrift: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "binding_drift_total",
			Help:      "Total number of detected managed RBAC binding integrity failures.",
		}, []string{metricLabelReason, metricLabelScope}),
		curatedRoleDrift: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "curated_role_drift_total",
			Help:      "Total number of detected curated ClusterRole integrity failures.",
		}, []string{metricLabelReason, metricLabelScope}),
		bindingOperations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "binding_operations_total",
			Help:      "Total number of managed RBAC binding lifecycle operations.",
		}, []string{metricLabelOperation, metricLabelResult, metricLabelScope}),
		expiryCleanupLag: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metricNamespace,
			Name:      "expiry_cleanup_lag_seconds",
			Help:      "Elapsed time between a session expiry and successful binding cleanup.",
			Buckets:   []float64{0.1, 0.5, 1, 5, 15, 30, 60, 300, 900},
		}, []string{metricLabelScope}),
		admissionRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "admission_requests_total",
			Help:      "Total number of terminal BreakGlassSession admission decisions.",
		}, []string{metricLabelOperation, metricLabelOutcome}),
	}

	collectors := []prometheus.Collector{
		recorder.transitions,
		recorder.bindingDrift,
		recorder.curatedRoleDrift,
		recorder.bindingOperations,
		recorder.expiryCleanupLag,
		recorder.admissionRequests,
	}
	for i, collector := range collectors {
		if err := registry.Register(collector); err != nil {
			for _, registered := range collectors[:i] {
				registry.Unregister(registered)
			}
			return nil, fmt.Errorf("register BreakGlass metrics: %w", err)
		}
	}

	return recorder, nil
}

// MustNewRecorder is NewRecorder for process-level metrics registration.
func MustNewRecorder(registry prometheus.Registerer) *Recorder {
	recorder, err := NewRecorder(registry)
	if err != nil {
		panic(err)
	}
	return recorder
}

// RecordTransition records a lifecycle transition after the associated status
// change has been persisted.
func (r *Recorder) RecordTransition(transition LifecycleTransition, scope Scope) {
	if r == nil {
		return
	}
	r.transitions.WithLabelValues(string(normalizeTransition(transition)), string(normalizeScope(scope))).Inc()
}

// RecordBindingDrift records a detected binding-integrity failure. Call this
// once for the status transition that represents the failure, not on every
// retry of the same reconciler error.
func (r *Recorder) RecordBindingDrift(reason BindingDriftReason, scope Scope) {
	if r == nil {
		return
	}
	r.bindingDrift.WithLabelValues(string(normalizeDriftReason(reason)), string(normalizeScope(scope))).Inc()
}

// RecordCuratedRoleDrift records a curated ClusterRole identity or rule-set
// failure after the session was suspended. Call it once per transition.
func (r *Recorder) RecordCuratedRoleDrift(reason CuratedRoleDriftReason, scope Scope) {
	if r == nil {
		return
	}
	r.curatedRoleDrift.WithLabelValues(string(normalizeCuratedRoleDriftReason(reason)), string(normalizeScope(scope))).Inc()
}

// RecordBindingOperation records a privileged binding action. Regular
// no-op reconciliations should not call this method.
func (r *Recorder) RecordBindingOperation(operation BindingOperation, result BindingOperationResult, scope Scope) {
	if r == nil {
		return
	}
	r.bindingOperations.WithLabelValues(
		string(normalizeBindingOperation(operation)),
		string(normalizeBindingOperationResult(result)),
		string(normalizeScope(scope)),
	).Inc()
}

// ObserveExpiryCleanupLag records the duration after expiry at which the
// binding was successfully removed. Negative values are clock skew and are
// safely represented as zero.
func (r *Recorder) ObserveExpiryCleanupLag(scope Scope, lag time.Duration) {
	if r == nil {
		return
	}
	seconds := lag.Seconds()
	if seconds < 0 {
		seconds = 0
	}
	r.expiryCleanupLag.WithLabelValues(string(normalizeScope(scope))).Observe(seconds)
}

// RecordAdmissionRequest records one terminal admission decision. It must not
// be called with untrusted request fields; operation and outcome are normalized
// to fixed, low-cardinality vocabularies before they become metric labels.
func (r *Recorder) RecordAdmissionRequest(operation AdmissionOperation, outcome AdmissionOutcome) {
	if r == nil {
		return
	}
	r.admissionRequests.WithLabelValues(
		string(normalizeAdmissionOperation(operation)),
		string(normalizeAdmissionOutcome(outcome)),
	).Inc()
}

func normalizeScope(scope Scope) Scope {
	switch scope {
	case ScopeNamespaced, ScopeCluster, ScopeUnknown:
		return scope
	default:
		return ScopeUnknown
	}
}

func normalizeTransition(transition LifecycleTransition) LifecycleTransition {
	switch transition {
	case TransitionActivated, TransitionDenied, TransitionExpired, TransitionRevoked, TransitionSuspended, TransitionDrifted, TransitionUnknown:
		return transition
	default:
		return TransitionUnknown
	}
}

func normalizeDriftReason(reason BindingDriftReason) BindingDriftReason {
	switch reason {
	case DriftMissing, DriftOwnership, DriftUIDMismatch, DriftRoleRef, DriftSubjects, DriftBindingReference, DriftMissingExpiry, DriftIntegrityUnknown, DriftUnknown:
		return reason
	default:
		return DriftUnknown
	}
}

func normalizeCuratedRoleDriftReason(reason CuratedRoleDriftReason) CuratedRoleDriftReason {
	switch reason {
	case CuratedRoleMissing, CuratedRoleUIDMismatch, CuratedRoleRulesHash, CuratedRoleSnapshotMissing, CuratedRoleUnknown:
		return reason
	default:
		return CuratedRoleUnknown
	}
}

func normalizeBindingOperation(operation BindingOperation) BindingOperation {
	switch operation {
	case BindingOperationGrant, BindingOperationRestore, BindingOperationCleanup, BindingOperationUnknown:
		return operation
	default:
		return BindingOperationUnknown
	}
}

func normalizeBindingOperationResult(result BindingOperationResult) BindingOperationResult {
	switch result {
	case BindingOperationSuccess, BindingOperationError, BindingOperationUnknownResult:
		return result
	default:
		return BindingOperationUnknownResult
	}
}

func normalizeAdmissionOperation(operation AdmissionOperation) AdmissionOperation {
	switch operation {
	case AdmissionOperationCreate, AdmissionOperationUpdate, AdmissionOperationUnknown:
		return operation
	default:
		return AdmissionOperationUnknown
	}
}

func normalizeAdmissionOutcome(outcome AdmissionOutcome) AdmissionOutcome {
	switch outcome {
	case AdmissionOutcomeAllowed, AdmissionOutcomeDenied, AdmissionOutcomeError, AdmissionOutcomeUnknown:
		return outcome
	default:
		return AdmissionOutcomeUnknown
	}
}
