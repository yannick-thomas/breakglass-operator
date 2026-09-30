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

package controller

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	breakglassmetrics "github.com/yannick-thomas/breakglass-operator/internal/metrics"
)

func TestRequestReconcileInitializesADeadlineAndPendingStatus(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 29, 12, 0, 0, 0, time.UTC)
	request := testBreakGlassRequestForController(now)
	metrics := &recordingRequestMetrics{}
	reconciler := &BreakGlassRequestReconciler{
		Client:  newTestClient(testScheme(t), request),
		Clock:   func() time.Time { return now },
		Metrics: metrics,
	}

	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(request)})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 15*time.Minute {
		t.Fatalf("RequeueAfter = %s, want 15m", result.RequeueAfter)
	}

	updated := &accessv1alpha1.BreakGlassRequest{}
	if err := reconciler.Get(context.Background(), client.ObjectKeyFromObject(request), updated); err != nil {
		t.Fatalf("get request after Reconcile(): %v", err)
	}
	if updated.Status.Phase != accessv1alpha1.RequestPhasePending {
		t.Fatalf("phase = %q, want Pending", updated.Status.Phase)
	}
	if updated.Status.ExpiresAt == nil || !updated.Status.ExpiresAt.Time.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("expiresAt = %#v, want %s", updated.Status.ExpiresAt, now.Add(15*time.Minute))
	}
	if updated.Status.ObservedGeneration != request.Generation {
		t.Fatalf("observedGeneration = %d, want %d", updated.Status.ObservedGeneration, request.Generation)
	}
	if !hasCondition(updated.Status.Conditions, RequestAwaitingApprovalCondition, metav1.ConditionTrue, "AwaitingApproval") {
		t.Fatalf("conditions = %#v, want AwaitingApproval=True", updated.Status.Conditions)
	}
	if len(metrics.transitions) != 1 || metrics.transitions[0] != breakglassmetrics.RequestTransitionPending {
		t.Fatalf("request transitions = %#v, want [pending]", metrics.transitions)
	}
}

func TestRequestReconcileExpiresAnUnconsumedRequest(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 29, 12, 0, 0, 0, time.UTC)
	request := testBreakGlassRequestForController(now.Add(-16 * time.Minute))
	metrics := &recordingRequestMetrics{}
	reconciler := &BreakGlassRequestReconciler{
		Client:  newTestClient(testScheme(t), request),
		Clock:   func() time.Time { return now },
		Metrics: metrics,
	}

	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(request)})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Fatalf("expired request requeue = %s, want none", result.RequeueAfter)
	}

	updated := &accessv1alpha1.BreakGlassRequest{}
	if err := reconciler.Get(context.Background(), client.ObjectKeyFromObject(request), updated); err != nil {
		t.Fatalf("get request after Reconcile(): %v", err)
	}
	if updated.Status.Phase != accessv1alpha1.RequestPhaseExpired {
		t.Fatalf("phase = %q, want Expired", updated.Status.Phase)
	}
	if !hasCondition(updated.Status.Conditions, RequestAwaitingApprovalCondition, metav1.ConditionFalse, "RequestExpired") {
		t.Fatalf("conditions = %#v, want AwaitingApproval=False (RequestExpired)", updated.Status.Conditions)
	}
	if len(metrics.transitions) != 1 || metrics.transitions[0] != breakglassmetrics.RequestTransitionExpired {
		t.Fatalf("request transitions = %#v, want [expired]", metrics.transitions)
	}
}

func TestRequestReconcilePreservesTerminalDecisions(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 29, 12, 0, 0, 0, time.UTC)
	request := testBreakGlassRequestForController(now.Add(-time.Hour))
	request.Status.Phase = accessv1alpha1.RequestPhaseDenied
	reconciler := &BreakGlassRequestReconciler{
		Client: newTestClient(testScheme(t), request),
		Clock:  func() time.Time { return now },
	}

	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(request)}); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	updated := &accessv1alpha1.BreakGlassRequest{}
	if err := reconciler.Get(context.Background(), client.ObjectKeyFromObject(request), updated); err != nil {
		t.Fatalf("get request after Reconcile(): %v", err)
	}
	if updated.Status.Phase != accessv1alpha1.RequestPhaseDenied {
		t.Fatalf("phase = %q, want Denied", updated.Status.Phase)
	}
	if updated.Status.ExpiresAt != nil {
		t.Fatalf("terminal request unexpectedly changed status: %#v", updated.Status)
	}
}

func TestRequestReconcileFailsClosedForAnInvalidSnapshottedTTL(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 29, 12, 0, 0, 0, time.UTC)
	request := testBreakGlassRequestForController(now)
	request.Spec.RequestTTL = "0s"
	reconciler := &BreakGlassRequestReconciler{
		Client: newTestClient(testScheme(t), request),
	}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(request)}); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	updated := &accessv1alpha1.BreakGlassRequest{}
	if err := reconciler.Get(context.Background(), client.ObjectKeyFromObject(request), updated); err != nil {
		t.Fatalf("get request after Reconcile(): %v", err)
	}
	if updated.Status.Phase != accessv1alpha1.RequestPhaseFailed {
		t.Fatalf("phase = %q, want Failed", updated.Status.Phase)
	}
}

func TestRequestReconcileConsumesOneApprovedDecisionIntoOneReservedSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 29, 12, 0, 0, 0, time.UTC)
	request := testBreakGlassRequestForController(now)
	request.Status.Phase = accessv1alpha1.RequestPhasePending
	request.Spec.AccessProfile = "production-pod-observer"
	request.Spec.AccessProfileUID = "profile-uid"
	request.Spec.Requester = accessv1alpha1.SubjectReference{Kind: accessv1alpha1.SubjectKindUser, Name: "engineer@example.com"}
	request.Spec.Duration = "15m"
	request.Spec.Reason = "Investigating active production incident"
	approval := &accessv1alpha1.BreakGlassApproval{
		ObjectMeta: metav1.ObjectMeta{Name: accessv1alpha1.ApprovalNameForRequestUID(string(request.UID)), UID: types.UID("approval-uid")},
		Spec: accessv1alpha1.BreakGlassApprovalSpec{
			RequestRef: accessv1alpha1.BreakGlassRequestReference{Name: request.Name, UID: string(request.UID)},
			Decision:   accessv1alpha1.ApprovalDecisionApproved,
			Approver:   accessv1alpha1.SubjectReference{Kind: accessv1alpha1.SubjectKindUser, Name: "approver@example.com"},
		},
	}
	metrics := &recordingRequestMetrics{}
	reconciler := &BreakGlassRequestReconciler{
		Client:                    newTestClient(testScheme(t), request, approval),
		Clock:                     func() time.Time { return now },
		Metrics:                   metrics,
		RequestControllerUsername: "system:serviceaccount:breakglass-operator-system:breakglass-operator-controller-manager",
	}
	key := client.ObjectKeyFromObject(request)

	for _, want := range []accessv1alpha1.RequestPhase{
		accessv1alpha1.RequestPhaseApproved,
		accessv1alpha1.RequestPhaseProvisioning,
		accessv1alpha1.RequestPhaseSessionCreated,
	} {
		result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
		if err != nil {
			t.Fatalf("Reconcile() error = %v", err)
		}
		if want == accessv1alpha1.RequestPhaseApproved || want == accessv1alpha1.RequestPhaseProvisioning {
			if !result.Requeue {
				t.Fatalf("transition to %q must requeue immediately", want)
			}
		} else if result.Requeue {
			t.Fatalf("terminal transition to %q must not requeue immediately", want)
		}
		updated := &accessv1alpha1.BreakGlassRequest{}
		if err := reconciler.Get(context.Background(), key, updated); err != nil {
			t.Fatalf("get request after Reconcile(): %v", err)
		}
		if updated.Status.Phase != want {
			t.Fatalf("phase = %q, want %q", updated.Status.Phase, want)
		}
	}

	updated := &accessv1alpha1.BreakGlassRequest{}
	if err := reconciler.Get(context.Background(), key, updated); err != nil {
		t.Fatalf("get request after provisioning: %v", err)
	}
	if updated.Status.ApprovalRef == nil || updated.Status.ApprovalRef.UID != string(approval.UID) {
		t.Fatalf("approvalRef = %#v, want approval UID", updated.Status.ApprovalRef)
	}
	if updated.Status.SessionRef == nil || updated.Status.SessionRef.UID == "" {
		t.Fatalf("sessionRef = %#v, want completed server UID", updated.Status.SessionRef)
	}

	sessions := &accessv1alpha1.BreakGlassSessionList{}
	if err := reconciler.List(context.Background(), sessions); err != nil {
		t.Fatalf("list sessions after provisioning: %v", err)
	}
	if len(sessions.Items) != 1 {
		t.Fatalf("sessions = %#v, want exactly one", sessions.Items)
	}
	session := sessions.Items[0]
	if session.Spec.RequestRef == nil || session.Spec.RequestRef.Name != request.Name || session.Spec.RequestRef.UID != string(request.UID) {
		t.Fatalf("session requestRef = %#v, want request UID source", session.Spec.RequestRef)
	}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("terminal Reconcile() error = %v", err)
	}
	if err := reconciler.List(context.Background(), sessions); err != nil {
		t.Fatalf("list sessions after terminal reconcile: %v", err)
	}
	if len(sessions.Items) != 1 {
		t.Fatalf("terminal reconcile created %d sessions, want one", len(sessions.Items))
	}
}

func testBreakGlassRequestForController(createdAt time.Time) *accessv1alpha1.BreakGlassRequest {
	return &accessv1alpha1.BreakGlassRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "request-incident",
			UID:               types.UID("request-uid"),
			Generation:        3,
			CreationTimestamp: metav1.NewTime(createdAt),
		},
		Spec: accessv1alpha1.BreakGlassRequestSpec{RequestTTL: "15m"},
	}
}

type recordingRequestMetrics struct {
	transitions []breakglassmetrics.RequestTransition
}

func (r *recordingRequestMetrics) RecordRequestTransition(transition breakglassmetrics.RequestTransition) {
	r.transitions = append(r.transitions, transition)
}
