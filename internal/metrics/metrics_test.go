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

package metrics

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
)

func TestRecorderNormalizesAllMetricLabels(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	recorder, err := NewRecorder(registry)
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}

	recorder.RecordTransition(TransitionActivated, ScopeNamespaced)
	recorder.RecordTransition(LifecycleTransition("engineer@example.com"), Scope("production-payments"))
	recorder.RecordBindingDrift(DriftMissing, ScopeCluster)
	recorder.RecordBindingDrift(BindingDriftReason("INC-1092"), Scope("production-payments"))
	recorder.RecordCuratedRoleDrift(CuratedRoleRulesHash, ScopeNamespaced)
	recorder.RecordCuratedRoleDrift(CuratedRoleDriftReason("breakglass-pod-observer"), Scope("production-payments"))
	recorder.RecordRequestSourceIntegrity(RequestSourceMissing, ScopeNamespaced)
	recorder.RecordRequestSourceIntegrity(RequestSourceIntegrityReason("incident-db-approval"), Scope("production-payments"))
	recorder.RecordBindingOperation(BindingOperationGrant, BindingOperationSuccess, ScopeNamespaced)
	recorder.RecordBindingOperation(BindingOperation("breakglass-engineer@example.com"), BindingOperationResult("failed: forbidden"), Scope("production-payments"))
	recorder.ObserveExpiryCleanupLag(ScopeNamespaced, -time.Second)
	recorder.RecordAdmissionRequest(AdmissionOperationCreate, AdmissionOutcomeAllowed)
	recorder.RecordAdmissionRequest(AdmissionOperation("engineer@example.com"), AdmissionOutcome("INC-1092"))
	recorder.RecordRequestTransition(RequestTransitionPending)
	recorder.RecordRequestTransition(RequestTransition("INC-1092"))

	assertMetricValue(t, registry, "breakglass_session_transitions_total", map[string]string{
		metricLabelTransition: string(TransitionActivated),
		metricLabelScope:      string(ScopeNamespaced),
	}, 1)
	assertMetricValue(t, registry, "breakglass_session_transitions_total", map[string]string{
		metricLabelTransition: string(TransitionUnknown),
		metricLabelScope:      string(ScopeUnknown),
	}, 1)
	assertMetricValue(t, registry, "breakglass_binding_drift_total", map[string]string{
		metricLabelReason: string(DriftMissing),
		metricLabelScope:  string(ScopeCluster),
	}, 1)
	assertMetricValue(t, registry, "breakglass_curated_role_drift_total", map[string]string{
		metricLabelReason: string(CuratedRoleRulesHash),
		metricLabelScope:  string(ScopeNamespaced),
	}, 1)
	assertMetricValue(t, registry, "breakglass_request_source_integrity_failures_total", map[string]string{
		metricLabelReason: string(RequestSourceMissing),
		metricLabelScope:  string(ScopeNamespaced),
	}, 1)
	assertMetricValue(t, registry, "breakglass_request_source_integrity_failures_total", map[string]string{
		metricLabelReason: string(RequestSourceUnknown),
		metricLabelScope:  string(ScopeUnknown),
	}, 1)
	assertMetricValue(t, registry, "breakglass_curated_role_drift_total", map[string]string{
		metricLabelReason: string(CuratedRoleUnknown),
		metricLabelScope:  string(ScopeUnknown),
	}, 1)
	assertMetricValue(t, registry, "breakglass_binding_drift_total", map[string]string{
		metricLabelReason: string(DriftUnknown),
		metricLabelScope:  string(ScopeUnknown),
	}, 1)
	for _, operation := range []BindingOperation{BindingOperationReserve, BindingOperationRecoverReservation} {
		recorder.RecordBindingOperation(operation, BindingOperationSuccess, ScopeNamespaced)
		assertMetricValue(t, registry, "breakglass_binding_operations_total", map[string]string{
			metricLabelOperation: string(operation), metricLabelResult: string(BindingOperationSuccess), metricLabelScope: string(ScopeNamespaced),
		}, 1)
	}
	assertMetricValue(t, registry, "breakglass_binding_operations_total", map[string]string{
		metricLabelOperation: string(BindingOperationGrant),
		metricLabelResult:    string(BindingOperationSuccess),
		metricLabelScope:     string(ScopeNamespaced),
	}, 1)
	assertMetricValue(t, registry, "breakglass_binding_operations_total", map[string]string{
		metricLabelOperation: string(BindingOperationUnknown),
		metricLabelResult:    string(BindingOperationUnknownResult),
		metricLabelScope:     string(ScopeUnknown),
	}, 1)
	assertMetricValue(t, registry, "breakglass_admission_requests_total", map[string]string{
		metricLabelOperation: string(AdmissionOperationCreate),
		metricLabelOutcome:   string(AdmissionOutcomeAllowed),
	}, 1)
	assertMetricValue(t, registry, "breakglass_request_transitions_total", map[string]string{
		metricLabelTransition: string(RequestTransitionPending),
	}, 1)
	assertMetricValue(t, registry, "breakglass_request_transitions_total", map[string]string{
		metricLabelTransition: string(RequestTransitionUnknown),
	}, 1)
	assertMetricValue(t, registry, "breakglass_admission_requests_total", map[string]string{
		metricLabelOperation: string(AdmissionOperationUnknown),
		metricLabelOutcome:   string(AdmissionOutcomeUnknown),
	}, 1)

	assertOnlyBoundedLabels(t, registry)
}

func TestSessionStateCollectorEmitsZeroesAndNeverLeaksSessionData(t *testing.T) {
	now := time.Date(2026, time.September, 25, 12, 0, 0, 0, time.UTC)
	scheme := runtime.NewScheme()
	if err := accessv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add BreakGlassSession scheme: %v", err)
	}

	activeNamespaced := newSession("session-engineer@example.com", accessv1alpha1.PhaseActive, now.Add(time.Minute), &accessv1alpha1.BindingReference{
		Kind:      "RoleBinding",
		Namespace: "customer-payments-production",
		Name:      "breakglass-engineer@example.com",
		UID:       "sensitive-uid",
	})
	expiredNamespaced := newSession("INC-1092", accessv1alpha1.PhaseActive, now.Add(-time.Minute), &accessv1alpha1.BindingReference{
		Kind:      "RoleBinding",
		Namespace: "customer-payments-production",
		Name:      "breakglass-INC-1092",
		UID:       "sensitive-uid-2",
	})
	activeCluster := newSession("cluster-session", accessv1alpha1.PhaseActive, now.Add(time.Minute), &accessv1alpha1.BindingReference{
		Kind: "ClusterRoleBinding",
		Name: "breakglass-cluster-session",
		UID:  "sensitive-uid-3",
	})
	activeUnknown := newSession("unknown-session", accessv1alpha1.PhaseActive, now.Add(time.Minute), nil)
	activeWithoutExpiry := newSession("missing-expiry-session", accessv1alpha1.PhaseActive, now.Add(time.Minute), nil)
	activeWithoutExpiry.Status.ExpiresAt = nil
	suspended := newSession("suspended-session", accessv1alpha1.PhaseSuspended, now.Add(-time.Minute), nil)

	cache := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		activeNamespaced,
		expiredNamespaced,
		activeCluster,
		activeUnknown,
		activeWithoutExpiry,
		suspended,
	).Build()
	collector := NewSessionStateCollectorWithClock(cache, scopeFromBindingReference, func() time.Time { return now })
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(collector)

	assertMetricValue(t, registry, "breakglass_active_sessions", map[string]string{metricLabelScope: string(ScopeNamespaced)}, 2)
	assertMetricValue(t, registry, "breakglass_active_sessions", map[string]string{metricLabelScope: string(ScopeCluster)}, 1)
	assertMetricValue(t, registry, "breakglass_active_sessions", map[string]string{metricLabelScope: string(ScopeUnknown)}, 2)
	assertMetricValue(t, registry, "breakglass_sessions_past_expiry", map[string]string{metricLabelScope: string(ScopeNamespaced)}, 1)
	assertMetricValue(t, registry, "breakglass_sessions_past_expiry", map[string]string{metricLabelScope: string(ScopeCluster)}, 0)
	assertMetricValue(t, registry, "breakglass_sessions_past_expiry", map[string]string{metricLabelScope: string(ScopeUnknown)}, 1)
	assertMetricValue(t, registry, "breakglass_session_state_collection_success", nil, 1)

	assertOnlyBoundedLabels(t, registry)
}

func TestSessionStateCollectorReportsCacheFailure(t *testing.T) {
	collector := NewSessionStateCollectorWithClock(failingReader{}, nil, time.Now)
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(collector)

	assertMetricValue(t, registry, "breakglass_session_state_collection_success", nil, 0)
}

func TestSessionStateCollectorEmitsAllZeroScopeSeriesForAnEmptyCache(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := accessv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add BreakGlassSession scheme: %v", err)
	}

	cache := fake.NewClientBuilder().WithScheme(scheme).Build()
	collector := NewSessionStateCollectorWithClock(cache, scopeFromBindingReference, time.Now)
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(collector)

	for _, scope := range []Scope{ScopeNamespaced, ScopeCluster, ScopeUnknown} {
		labels := map[string]string{metricLabelScope: string(scope)}
		assertMetricValue(t, registry, "breakglass_active_sessions", labels, 0)
		assertMetricValue(t, registry, "breakglass_sessions_past_expiry", labels, 0)
	}
	assertMetricValue(t, registry, "breakglass_session_state_collection_success", nil, 1)
}

func scopeFromBindingReference(session *accessv1alpha1.BreakGlassSession) Scope {
	if session.Status.BindingRef == nil {
		return ScopeUnknown
	}
	return ScopeFromBindingKind(session.Status.BindingRef.Kind)
}

func newSession(name string, phase accessv1alpha1.SessionPhase, expiresAt time.Time, bindingRef *accessv1alpha1.BindingReference) *accessv1alpha1.BreakGlassSession {
	expires := metav1.NewTime(expiresAt)
	return &accessv1alpha1.BreakGlassSession{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: accessv1alpha1.BreakGlassSessionSpec{
			AccessProfile:    "production-pod-observer",
			AccessProfileUID: "profile-uid",
			Subject: accessv1alpha1.SubjectReference{
				Kind: accessv1alpha1.SubjectKindUser,
				Name: "engineer@example.com",
			},
			Reason:   "INC-1092: confidential customer incident",
			Duration: "30m",
		},
		Status: accessv1alpha1.BreakGlassSessionStatus{
			Phase:      phase,
			ExpiresAt:  &expires,
			BindingRef: bindingRef,
		},
	}
}

type failingReader struct{}

func (failingReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("cache is unavailable")
}

func (failingReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("cache is unavailable")
}

func assertMetricValue(t *testing.T, registry *prometheus.Registry, name string, labels map[string]string, want float64) {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			metricLabels := make(map[string]string, len(metric.GetLabel()))
			for _, label := range metric.GetLabel() {
				metricLabels[label.GetName()] = label.GetValue()
			}
			if !labelsEqual(metricLabels, labels) {
				continue
			}
			if metric.GetGauge() != nil {
				if got := metric.GetGauge().GetValue(); got != want {
					t.Fatalf("%s%v gauge = %v, want %v", name, labels, got, want)
				}
				return
			}
			if metric.GetCounter() != nil {
				if got := metric.GetCounter().GetValue(); got != want {
					t.Fatalf("%s%v counter = %v, want %v", name, labels, got, want)
				}
				return
			}
		}
	}
	t.Fatalf("metric %s%v was not found", name, labels)
}

func assertOnlyBoundedLabels(t *testing.T, registry *prometheus.Registry) {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	allowed := map[string]map[string]bool{
		metricLabelScope: {
			string(ScopeNamespaced): true,
			string(ScopeCluster):    true,
			string(ScopeUnknown):    true,
		},
		metricLabelTransition: {
			string(TransitionActivated):             true,
			string(TransitionDenied):                true,
			string(TransitionExpired):               true,
			string(TransitionRevoked):               true,
			string(TransitionSuspended):             true,
			string(TransitionDrifted):               true,
			string(TransitionUnknown):               true,
			string(RequestTransitionPending):        true,
			string(RequestTransitionApproved):       true,
			string(RequestTransitionProvisioning):   true,
			string(RequestTransitionSessionCreated): true,
			string(RequestTransitionFailed):         true,
		},
		metricLabelReason: {
			string(DriftMissing):                     true,
			string(DriftOwnership):                   true,
			string(DriftUIDMismatch):                 true,
			string(DriftRoleRef):                     true,
			string(DriftSubjects):                    true,
			string(DriftBindingReference):            true,
			string(DriftMissingExpiry):               true,
			string(DriftIntegrityUnknown):            true,
			string(DriftUnknown):                     true,
			string(CuratedRoleRulesHash):             true,
			string(CuratedRoleSnapshotMissing):       true,
			string(RequestSourceReference):           true,
			string(RequestSourceMissing):             true,
			string(RequestSourceUIDMismatch):         true,
			string(RequestSourceContentMismatch):     true,
			string(RequestSourceReservationMismatch): true,
			string(RequestSourceSessionUIDMismatch):  true,
			string(RequestSourcePhase):               true,
			string(RequestSourceTTLInvalid):          true,
			string(RequestSourceExpired):             true,
			string(RequestSourceApprovalReference):   true,
			string(RequestSourceApprovalMissing):     true,
			string(RequestSourceApprovalUIDMismatch): true,
			string(RequestSourceApprovalInvalid):     true,
		},
		metricLabelOperation: {
			string(BindingOperationReserve):            true,
			string(BindingOperationRecoverReservation): true,
			string(BindingOperationGrant):              true,
			string(BindingOperationRestore):            true,
			string(BindingOperationCleanup):            true,
			string(BindingOperationUnknown):            true,
			string(AdmissionOperationCreate):           true,
			string(AdmissionOperationUpdate):           true,
		},
		metricLabelResult: {
			string(BindingOperationSuccess):       true,
			string(BindingOperationError):         true,
			string(BindingOperationUnknownResult): true,
		},
		metricLabelOutcome: {
			string(AdmissionOutcomeAllowed): true,
			string(AdmissionOutcomeDenied):  true,
			string(AdmissionOutcomeError):   true,
			string(AdmissionOutcomeUnknown): true,
		},
	}

	for _, family := range families {
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if !allowed[label.GetName()][label.GetValue()] {
					t.Fatalf("metric %q has an unsafe or unbounded label %q=%q", family.GetName(), label.GetName(), label.GetValue())
				}
			}
		}
	}
}

func labelsEqual(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for key, wantValue := range want {
		if got[key] != wantValue {
			return false
		}
	}
	return true
}
