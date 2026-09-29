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
		Client:     newTestClient(testScheme(t), request),
		RequestTTL: 15 * time.Minute,
		Clock:      func() time.Time { return now },
		Metrics:    metrics,
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
		Client:     newTestClient(testScheme(t), request),
		RequestTTL: 15 * time.Minute,
		Clock:      func() time.Time { return now },
		Metrics:    metrics,
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
		Client:     newTestClient(testScheme(t), request),
		RequestTTL: 15 * time.Minute,
		Clock:      func() time.Time { return now },
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

func TestRequestReconcileRejectsAZeroTTL(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 29, 12, 0, 0, 0, time.UTC)
	request := testBreakGlassRequestForController(now)
	reconciler := &BreakGlassRequestReconciler{
		Client: newTestClient(testScheme(t), request),
	}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(request)}); err == nil {
		t.Fatal("Reconcile() accepted zero request TTL")
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
	}
}

type recordingRequestMetrics struct {
	transitions []breakglassmetrics.RequestTransition
}

func (r *recordingRequestMetrics) RecordRequestTransition(transition breakglassmetrics.RequestTransition) {
	r.transitions = append(r.transitions, transition)
}
