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
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	breakglassmetrics "github.com/yannick-thomas/breakglass-operator/internal/metrics"
)

const RequestAwaitingApprovalCondition = "AwaitingApproval"

// BreakGlassRequestReconciler establishes the fail-closed lifecycle boundary
// for untrusted access intent. It intentionally creates no session and no RBAC
// binding: approval and source-verified provisioning are added as one later
// milestone.
type BreakGlassRequestReconciler struct {
	client.Client
	RequestTTL time.Duration
	Clock      func() time.Time
	Metrics    breakglassmetrics.RequestLifecycleRecorder
}

// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglassrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglassrequests/status,verbs=get;update;patch

// Reconcile writes the deadline derived from the server creation timestamp and
// configured request TTL. It does not trust a client-supplied deadline and
// marks all unconsumed requests expired once the deadline passes.
func (r *BreakGlassRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if r.RequestTTL <= 0 {
		return ctrl.Result{}, fmt.Errorf("request TTL must be greater than zero")
	}

	request := &accessv1alpha1.BreakGlassRequest{}
	if err := r.Get(ctx, req.NamespacedName, request); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if requestTerminal(request.Status.Phase) {
		return ctrl.Result{}, nil
	}

	now := r.now()
	expiresAt := request.CreationTimestamp.Add(r.RequestTTL)
	previousPhase := request.Status.Phase
	if request.Status.ExpiresAt == nil || !request.Status.ExpiresAt.Time.Equal(expiresAt) {
		request.Status.ExpiresAt = &metav1.Time{Time: expiresAt}
	}

	if !now.Before(expiresAt) {
		request.Status.Phase = accessv1alpha1.RequestPhaseExpired
		meta.SetStatusCondition(&request.Status.Conditions, metav1.Condition{
			Type:               RequestAwaitingApprovalCondition,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: request.Generation,
			Reason:             "RequestExpired",
			Message:            "The request expired before it was consumed by a session",
		})
	} else if request.Status.Phase == "" {
		request.Status.Phase = accessv1alpha1.RequestPhasePending
		meta.SetStatusCondition(&request.Status.Conditions, metav1.Condition{
			Type:               RequestAwaitingApprovalCondition,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: request.Generation,
			Reason:             "AwaitingApproval",
			Message:            "The request is valid and awaits an approval decision",
		})
	}
	request.Status.ObservedGeneration = request.Generation

	if err := r.updateStatusIfChanged(ctx, request); err != nil {
		return ctrl.Result{}, err
	}
	if previousPhase != request.Status.Phase && r.Metrics != nil {
		r.Metrics.RecordRequestTransition(requestTransitionForPhase(request.Status.Phase))
	}
	if request.Status.Phase == accessv1alpha1.RequestPhaseExpired {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{RequeueAfter: expiresAt.Sub(now)}, nil
}

func (r *BreakGlassRequestReconciler) now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}

func (r *BreakGlassRequestReconciler) updateStatusIfChanged(ctx context.Context, request *accessv1alpha1.BreakGlassRequest) error {
	stored := &accessv1alpha1.BreakGlassRequest{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(request), stored); err != nil {
		return err
	}
	if equality.Semantic.DeepEqual(stored.Status, request.Status) {
		return nil
	}
	stored.Status = request.Status
	if err := r.Status().Update(ctx, stored); err != nil {
		if apierrors.IsConflict(err) {
			return nil
		}
		return err
	}
	return nil
}

func requestTerminal(phase accessv1alpha1.RequestPhase) bool {
	switch phase {
	case accessv1alpha1.RequestPhaseDenied,
		accessv1alpha1.RequestPhaseExpired,
		accessv1alpha1.RequestPhaseSessionCreated,
		accessv1alpha1.RequestPhaseFailed:
		return true
	default:
		return false
	}
}

func requestTransitionForPhase(phase accessv1alpha1.RequestPhase) breakglassmetrics.RequestTransition {
	switch phase {
	case accessv1alpha1.RequestPhasePending:
		return breakglassmetrics.RequestTransitionPending
	case accessv1alpha1.RequestPhaseApproved:
		return breakglassmetrics.RequestTransitionApproved
	case accessv1alpha1.RequestPhaseDenied:
		return breakglassmetrics.RequestTransitionDenied
	case accessv1alpha1.RequestPhaseExpired:
		return breakglassmetrics.RequestTransitionExpired
	case accessv1alpha1.RequestPhaseProvisioning:
		return breakglassmetrics.RequestTransitionProvisioning
	case accessv1alpha1.RequestPhaseSessionCreated:
		return breakglassmetrics.RequestTransitionSessionCreated
	case accessv1alpha1.RequestPhaseFailed:
		return breakglassmetrics.RequestTransitionFailed
	default:
		return breakglassmetrics.RequestTransitionUnknown
	}
}

// SetupWithManager configures the request lifecycle reconciler. The request is
// cluster-scoped, so no namespace watch may be used as a security filter.
func (r *BreakGlassRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&accessv1alpha1.BreakGlassRequest{}).
		Named("breakglassrequest").
		Complete(r)
}
