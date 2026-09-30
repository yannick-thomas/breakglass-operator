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
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	breakglassmetrics "github.com/yannick-thomas/breakglass-operator/internal/metrics"
)

const (
	RequestAwaitingApprovalCondition = "AwaitingApproval"
	RequestProvisionedCondition      = "Provisioned"
	approvalRequestNameField         = ".spec.requestRef.name"
)

// BreakGlassRequestReconciler establishes the fail-closed lifecycle boundary
// for untrusted access intent and the sole controller-created session path.
// It never creates a RoleBinding directly; the existing Session controller is
// still the only component that turns a validated session into a grant.
type BreakGlassRequestReconciler struct {
	client.Client
	Clock                     func() time.Time
	Metrics                   breakglassmetrics.RequestLifecycleRecorder
	RequestControllerUsername string
}

// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglassrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglassrequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglassapprovals,verbs=get;list;watch
// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglasssessions,verbs=get;list;create

// Reconcile writes the deadline derived from the server creation timestamp and
// admission-snapshotted request TTL. It does not trust status as the deadline
// source and marks all unconsumed requests expired once that deadline passes.
func (r *BreakGlassRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	request := &accessv1alpha1.BreakGlassRequest{}
	if err := r.Get(ctx, req.NamespacedName, request); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	requestTTL, err := time.ParseDuration(request.Spec.RequestTTL)
	if err != nil || requestTTL <= 0 {
		return r.fail(ctx, request, "InvalidRequestTTL", "The immutable request TTL is not a positive duration")
	}

	now := r.now()
	expiresAt := request.CreationTimestamp.Add(requestTTL)
	if requestTerminal(request.Status.Phase) {
		return ctrl.Result{}, nil
	}
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
	} else if request.Status.Phase == accessv1alpha1.RequestPhasePending {
		approval, err := r.approvalForRequest(ctx, request)
		if err != nil {
			return r.fail(ctx, request, "InvalidApproval", "The deterministic approval slot is not a valid independent decision")
		}
		if approval != nil {
			request.Status.ApprovalRef = &accessv1alpha1.BreakGlassObjectReference{Name: approval.Name, UID: string(approval.UID)}
			switch approval.Spec.Decision {
			case accessv1alpha1.ApprovalDecisionDenied:
				request.Status.Phase = accessv1alpha1.RequestPhaseDenied
				meta.SetStatusCondition(&request.Status.Conditions, metav1.Condition{
					Type:               RequestAwaitingApprovalCondition,
					Status:             metav1.ConditionFalse,
					ObservedGeneration: request.Generation,
					Reason:             "Denied",
					Message:            "An authorized approver denied this request",
				})
			case accessv1alpha1.ApprovalDecisionApproved:
				request.Status.Phase = accessv1alpha1.RequestPhaseApproved
				meta.SetStatusCondition(&request.Status.Conditions, metav1.Condition{
					Type:               RequestAwaitingApprovalCondition,
					Status:             metav1.ConditionFalse,
					ObservedGeneration: request.Generation,
					Reason:             "Approved",
					Message:            "An authorized approver accepted this request",
				})
			}
		}
	} else if request.Status.Phase == accessv1alpha1.RequestPhaseApproved {
		if r.RequestControllerUsername == "" {
			return r.fail(ctx, request, "ControllerIdentityNotConfigured", "The request controller identity is not configured")
		}
		request.Status.Phase = accessv1alpha1.RequestPhaseProvisioning
		request.Status.SessionRef = &accessv1alpha1.BreakGlassObjectReference{Name: accessv1alpha1.SessionNameForRequestUID(string(request.UID))}
		meta.SetStatusCondition(&request.Status.Conditions, metav1.Condition{
			Type:               RequestProvisionedCondition,
			Status:             metav1.ConditionUnknown,
			ObservedGeneration: request.Generation,
			Reason:             "SessionReserved",
			Message:            "The controller reserved the one session name for this request",
		})
	} else if request.Status.Phase == accessv1alpha1.RequestPhaseProvisioning {
		if err := r.provisionSession(ctx, request); err != nil {
			return ctrl.Result{}, err
		}
	}
	request.Status.ObservedGeneration = request.Generation

	updated, err := r.updateStatusIfChanged(ctx, request)
	if err != nil {
		return ctrl.Result{}, err
	}
	if updated && previousPhase != request.Status.Phase && r.Metrics != nil {
		r.Metrics.RecordRequestTransition(requestTransitionForPhase(request.Status.Phase))
	}
	if request.Status.Phase == accessv1alpha1.RequestPhaseExpired {
		return ctrl.Result{}, nil
	}
	// Do not rely solely on the cache delivering this controller's own status
	// update. Approval and provisioning are deliberately persisted one step at
	// a time for crash safety, so those intermediate transitions must also cause
	// an immediate continuation of the deterministic state machine. Pending is
	// intentionally event-driven: an approval watch will wake the controller.
	if updated && previousPhase != request.Status.Phase &&
		(request.Status.Phase == accessv1alpha1.RequestPhaseApproved || request.Status.Phase == accessv1alpha1.RequestPhaseProvisioning) {
		return ctrl.Result{Requeue: true}, nil
	}
	return ctrl.Result{RequeueAfter: expiresAt.Sub(now)}, nil
}

func (r *BreakGlassRequestReconciler) approvalForRequest(ctx context.Context, request *accessv1alpha1.BreakGlassRequest) (*accessv1alpha1.BreakGlassApproval, error) {
	approval := &accessv1alpha1.BreakGlassApproval{}
	name := accessv1alpha1.ApprovalNameForRequestUID(string(request.UID))
	if err := r.Get(ctx, client.ObjectKey{Name: name}, approval); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if approval.Spec.RequestRef.Name != request.Name || approval.Spec.RequestRef.UID != string(request.UID) ||
		approval.Spec.Approver.Kind != accessv1alpha1.SubjectKindUser || approval.Spec.Approver.Name == request.Spec.Requester.Name ||
		(approval.Spec.Decision != accessv1alpha1.ApprovalDecisionApproved && approval.Spec.Decision != accessv1alpha1.ApprovalDecisionDenied) {
		return nil, apierrors.NewInvalid(accessv1alpha1.GroupVersion.WithKind("BreakGlassApproval").GroupKind(), approval.Name, nil)
	}
	return approval, nil
}

func (r *BreakGlassRequestReconciler) provisionSession(ctx context.Context, request *accessv1alpha1.BreakGlassRequest) error {
	if request.Status.SessionRef == nil || request.Status.SessionRef.Name == "" || request.Status.SessionRef.UID != "" {
		return r.markFailed(ctx, request, "InvalidSessionReservation", "The request has no valid controller-reserved session name")
	}
	session := &accessv1alpha1.BreakGlassSession{}
	if err := r.Get(ctx, client.ObjectKey{Name: request.Status.SessionRef.Name}, session); err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		session = &accessv1alpha1.BreakGlassSession{
			ObjectMeta: metav1.ObjectMeta{Name: request.Status.SessionRef.Name},
			Spec: accessv1alpha1.BreakGlassSessionSpec{
				AccessProfile:    request.Spec.AccessProfile,
				AccessProfileUID: request.Spec.AccessProfileUID,
				Subject:          request.Spec.Requester,
				Duration:         request.Spec.Duration,
				Reason:           request.Spec.Reason,
				RequestRef: &accessv1alpha1.BreakGlassRequestReference{
					Name: request.Name,
					UID:  string(request.UID),
				},
			},
		}
		if err := r.Create(ctx, session); err != nil {
			return err
		}
	}
	if session.Spec.RequestRef == nil || session.Spec.RequestRef.Name != request.Name || session.Spec.RequestRef.UID != string(request.UID) {
		return r.markFailed(ctx, request, "SessionSourceMismatch", "The reserved session name belongs to a different request")
	}
	if session.UID == "" {
		return apierrors.NewInternalError(fmt.Errorf("created BreakGlassSession %q has no server-assigned UID", session.Name))
	}
	request.Status.SessionRef.UID = string(session.UID)
	request.Status.Phase = accessv1alpha1.RequestPhaseSessionCreated
	meta.SetStatusCondition(&request.Status.Conditions, metav1.Condition{
		Type:               RequestProvisionedCondition,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: request.Generation,
		Reason:             "SessionCreated",
		Message:            "The controller created the reserved session object",
	})
	return nil
}

func (r *BreakGlassRequestReconciler) fail(ctx context.Context, request *accessv1alpha1.BreakGlassRequest, reason, message string) (ctrl.Result, error) {
	if err := r.markFailed(ctx, request, reason, message); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *BreakGlassRequestReconciler) markFailed(ctx context.Context, request *accessv1alpha1.BreakGlassRequest, reason, message string) error {
	previousPhase := request.Status.Phase
	request.Status.Phase = accessv1alpha1.RequestPhaseFailed
	request.Status.ObservedGeneration = request.Generation
	meta.SetStatusCondition(&request.Status.Conditions, metav1.Condition{
		Type:               RequestProvisionedCondition,
		Status:             metav1.ConditionFalse,
		ObservedGeneration: request.Generation,
		Reason:             reason,
		Message:            message,
	})
	updated, err := r.updateStatusIfChanged(ctx, request)
	if err != nil {
		return err
	}
	if updated && previousPhase != request.Status.Phase && r.Metrics != nil {
		r.Metrics.RecordRequestTransition(breakglassmetrics.RequestTransitionFailed)
	}
	return nil
}

func (r *BreakGlassRequestReconciler) now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}

func (r *BreakGlassRequestReconciler) updateStatusIfChanged(ctx context.Context, request *accessv1alpha1.BreakGlassRequest) (bool, error) {
	stored := &accessv1alpha1.BreakGlassRequest{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(request), stored); err != nil {
		return false, err
	}
	if equality.Semantic.DeepEqual(stored.Status, request.Status) {
		return false, nil
	}
	stored.Status = request.Status
	if err := r.Status().Update(ctx, stored); err != nil {
		if apierrors.IsConflict(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
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
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &accessv1alpha1.BreakGlassApproval{}, approvalRequestNameField, func(obj client.Object) []string {
		approval := obj.(*accessv1alpha1.BreakGlassApproval)
		if approval.Spec.RequestRef.Name == "" {
			return nil
		}
		return []string{approval.Spec.RequestRef.Name}
	}); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&accessv1alpha1.BreakGlassRequest{}).
		Watches(&accessv1alpha1.BreakGlassApproval{}, handler.EnqueueRequestsFromMapFunc(r.requestsForApproval)).
		Named("breakglassrequest").
		Complete(r)
}

func (r *BreakGlassRequestReconciler) requestsForApproval(_ context.Context, obj client.Object) []reconcile.Request {
	approval := obj.(*accessv1alpha1.BreakGlassApproval)
	if approval.Spec.RequestRef.Name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: approval.Spec.RequestRef.Name}}}
}
