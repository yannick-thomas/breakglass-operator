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
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/adapter/apiconv"
	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	breakglassmetrics "github.com/yannick-thomas/breakglass-operator/internal/metrics"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/requestlifecycle"
)

const (
	RequestAwaitingApprovalCondition = requestlifecycle.ConditionAwaitingApproval
	RequestProvisionedCondition      = requestlifecycle.ConditionProvisioned
	approvalRequestNameField         = ".spec.requestRef.name"
)

// BreakGlassRequestReconciler adapts the request lifecycle use case to
// controller-runtime. It never creates a RoleBinding directly; the session
// controller remains the only component that turns a session into a grant.
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

// Reconcile hands one BreakGlassRequest to the request lifecycle use case.
func (r *BreakGlassRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	obj := &accessv1alpha1.BreakGlassRequest{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	var telemetry requestlifecycle.Telemetry
	if r.Metrics != nil {
		telemetry = requestTelemetry{recorder: r.Metrics}
	}
	lifecycle := &requestlifecycle.Lifecycle{
		Approvals:                 cachedApprovalSource{Reader: r.Client},
		Sessions:                  sessionGateway{Client: r.Client},
		Telemetry:                 telemetry,
		RequestControllerUsername: r.RequestControllerUsername,
		Clock:                     r.Clock,
	}
	request := apiconv.ToDomainRequest(obj)
	result, err := lifecycle.Reconcile(ctx, &request, requestStore{Client: r.Client, Key: client.ObjectKeyFromObject(obj)})
	return ctrl.Result{RequeueAfter: result.RequeueAfter}, err
}

// cachedApprovalSource reads approvals from the cache. The session lifecycle
// re-verifies the decision with a direct read before any grant.
type cachedApprovalSource struct {
	Reader client.Reader
}

func (s cachedApprovalSource) Approval(ctx context.Context, name string) (access.Approval, error) {
	approval := &accessv1alpha1.BreakGlassApproval{}
	if err := s.Reader.Get(ctx, client.ObjectKey{Name: name}, approval); err != nil {
		return access.Approval{}, apiconv.Classify(err)
	}
	return apiconv.ToDomainApproval(approval), nil
}

type sessionGateway struct {
	Client client.Client
}

func (g sessionGateway) Get(ctx context.Context, name string) (requestlifecycle.SessionRecord, error) {
	session := &accessv1alpha1.BreakGlassSession{}
	if err := g.Client.Get(ctx, client.ObjectKey{Name: name}, session); err != nil {
		return requestlifecycle.SessionRecord{}, apiconv.Classify(err)
	}
	return sessionRecord(session), nil
}

func (g sessionGateway) Create(ctx context.Context, name string, spec access.SessionSpec) (requestlifecycle.SessionRecord, error) {
	session := &accessv1alpha1.BreakGlassSession{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: accessv1alpha1.BreakGlassSessionSpec{
			AccessProfile:    spec.AccessProfile,
			AccessProfileUID: spec.AccessProfileUID,
			Subject: accessv1alpha1.SubjectReference{
				Kind: accessv1alpha1.SubjectKind(spec.Subject.Kind), Name: spec.Subject.Name, Namespace: spec.Subject.Namespace,
			},
			Duration: spec.Duration,
			Reason:   spec.Reason,
		},
	}
	if spec.RequestRef != nil {
		session.Spec.RequestRef = &accessv1alpha1.BreakGlassRequestReference{Name: spec.RequestRef.Name, UID: spec.RequestRef.UID}
	}
	if err := g.Client.Create(ctx, session); err != nil {
		return requestlifecycle.SessionRecord{}, apiconv.Classify(err)
	}
	return sessionRecord(session), nil
}

func sessionRecord(session *accessv1alpha1.BreakGlassSession) requestlifecycle.SessionRecord {
	return requestlifecycle.SessionRecord{
		Name:       session.Name,
		UID:        string(session.UID),
		RequestRef: apiconv.ToDomainRequestRef(session.Spec.RequestRef),
	}
}

type requestStore struct {
	Client client.Client
	Key    client.ObjectKey
}

func (s requestStore) UpdateStatusIfChanged(ctx context.Context, request *access.Request) (bool, error) {
	stored := &accessv1alpha1.BreakGlassRequest{}
	if err := s.Client.Get(ctx, s.Key, stored); err != nil {
		return false, err
	}
	status := apiconv.ToAPIRequestStatus(request.Status)
	if equality.Semantic.DeepEqual(stored.Status, status) {
		return false, nil
	}
	stored.Status = status
	if err := s.Client.Status().Update(ctx, stored); err != nil {
		if apierrors.IsConflict(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

type requestTelemetry struct {
	recorder breakglassmetrics.RequestLifecycleRecorder
}

func (t requestTelemetry) Transition(phase access.RequestPhase) {
	t.recorder.RecordRequestTransition(requestTransitionForPhase(phase))
}

func requestTransitionForPhase(phase access.RequestPhase) breakglassmetrics.RequestTransition {
	switch phase {
	case access.RequestPhasePending:
		return breakglassmetrics.RequestTransitionPending
	case access.RequestPhaseApproved:
		return breakglassmetrics.RequestTransitionApproved
	case access.RequestPhaseDenied:
		return breakglassmetrics.RequestTransitionDenied
	case access.RequestPhaseExpired:
		return breakglassmetrics.RequestTransitionExpired
	case access.RequestPhaseProvisioning:
		return breakglassmetrics.RequestTransitionProvisioning
	case access.RequestPhaseSessionCreated:
		return breakglassmetrics.RequestTransitionSessionCreated
	case access.RequestPhaseFailed:
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
