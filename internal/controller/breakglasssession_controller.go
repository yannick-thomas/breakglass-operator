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

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/adapter/apiconv"
	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	breakglassmetrics "github.com/yannick-thomas/breakglass-operator/internal/metrics"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/sessionlifecycle"
)

// The lifecycle rules live in internal/usecase/sessionlifecycle and
// internal/domain/access. These names are kept for callers of this package.
const (
	// BreakGlassFinalizer ensures that RBAC bindings are deleted when the session CR is deleted.
	BreakGlassFinalizer = access.Finalizer
	// Label keys used for ownership tracking.
	ManagedByLabelKey        = access.ManagedByLabelKey
	ManagedByLabelValue      = access.ManagedByLabelValue
	SessionLabelKey          = access.SessionLabelKey
	SessionNamespaceLabelKey = access.SessionNamespaceLabelKey
	SessionUIDLabelKey       = access.SessionUIDLabelKey

	AccessGrantedCondition    = access.ConditionAccessGranted
	BindingIntegrityCondition = access.ConditionBindingIntegrity
	AccessProfileCondition    = access.ConditionAccessProfileValid
	CuratedRoleCondition      = access.ConditionCuratedRoleValid
	RequestSourceCondition    = access.ConditionRequestSourceValid

	// DefaultBindingIntegrityCheckInterval bounds how long a missed RBAC watch
	// event can leave an active session unchecked.
	DefaultBindingIntegrityCheckInterval = sessionlifecycle.DefaultIntegrityCheckInterval

	// accessProfileField indexes sessions by their immutable profile reference.
	// It keeps profile-policy changes proportional to the affected sessions,
	// rather than scanning every BreakGlassSession in the cluster.
	accessProfileField = ".spec.accessProfile"
	// requestSourceField indexes approval-workflow sessions by the name of the
	// immutable request they cite. The request UID is verified after retrieval;
	// the name is only a cache index and never an authorization decision.
	requestSourceField = ".spec.requestRef.name"
	// recordedBindingField indexes sessions by the namespace and name of the
	// binding recorded in their status. It maps a binding event to its
	// session even after the binding's labels were removed.
	recordedBindingField = ".status.bindingRef"
)

// BreakGlassSessionReconciler adapts the session lifecycle use case to
// controller-runtime. It loads the session, translates it, delegates every
// decision to sessionlifecycle.Lifecycle, and maps the result back.
type BreakGlassSessionReconciler struct {
	client.Client
	// APIReader bypasses the controller cache for policy reads. A stale
	// AccessProfile must not authorize a new grant or prolong an active one.
	// Tests may omit it and use Client as a safe fallback.
	APIReader          client.Reader
	Scheme             *runtime.Scheme
	Recorder           record.EventRecorder
	MaxSessionDuration time.Duration
	// Metrics is optional operational telemetry. It must never be used as an
	// audit source or to decide whether access is granted.
	Metrics breakglassmetrics.LifecycleRecorder
	// AllowedTargetNamespaces optionally restricts profiles this manager may
	// activate. An empty map preserves the development default; production
	// overlays set this to the same namespaces granted RoleBinding RBAC.
	AllowedTargetNamespaces map[string]struct{}
	// ControlNamespaces optionally restricts the namespaces in which profiles
	// and sessions may live. It must not overlap AllowedTargetNamespaces.
	ControlNamespaces map[string]struct{}
	// IntegrityCheckInterval overrides the periodic active-binding verification
	// interval. A non-positive value uses DefaultBindingIntegrityCheckInterval.
	IntegrityCheckInterval time.Duration
}

func (r *BreakGlassSessionReconciler) policyReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

// lifecycle wires the use case to this reconciler's Kubernetes clients.
func (r *BreakGlassSessionReconciler) lifecycle(namespace string) *sessionlifecycle.Lifecycle {
	var telemetry sessionlifecycle.Telemetry
	if r.Metrics != nil {
		telemetry = lifecycleTelemetry{recorder: r.Metrics}
	}
	return &sessionlifecycle.Lifecycle{
		Policy:                 apiPolicySource{Reader: r.policyReader(), Namespace: namespace},
		Bindings:               roleBindingGateway{Client: r.Client, Lister: r.policyReader()},
		Telemetry:              telemetry,
		MaxSessionDuration:     r.MaxSessionDuration,
		Scope:                  r.AllowedTargetNamespaces,
		Control:                r.ControlNamespaces,
		IntegrityCheckInterval: r.IntegrityCheckInterval,
	}
}

// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglasssessions,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglasssessions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglasssessions/finalizers,verbs=update
// +kubebuilder:rbac:groups=access.breakglass.io,resources=accessprofiles,verbs=get;list;watch
// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglassrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglassapprovals,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,resourceNames=breakglass-pod-observer,verbs=get;bind
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile hands one BreakGlassSession to the lifecycle use case.
func (r *BreakGlassSessionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	obj := &accessv1alpha1.BreakGlassSession{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	result, err := r.lifecycle(obj.Namespace).Reconcile(ctx, apiconv.ToDomainSession(obj),
		sessionStore{Client: r.Client, Object: obj},
		sessionEvents{Recorder: r.Recorder, Object: obj})
	return ctrl.Result{RequeueAfter: result.RequeueAfter}, err
}

// SetupWithManager sets up the controller with the Session, its fixed
// AccessProfile, its approval-workflow source, and the RoleBindings it creates.
func (r *BreakGlassSessionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &accessv1alpha1.BreakGlassSession{}, accessProfileField, accessProfileNameIndex); err != nil {
		return fmt.Errorf("index BreakGlassSessions by AccessProfile: %w", err)
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &accessv1alpha1.BreakGlassSession{}, requestSourceField, requestSourceNameIndex); err != nil {
		return fmt.Errorf("index BreakGlassSessions by request source: %w", err)
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &accessv1alpha1.BreakGlassSession{}, recordedBindingField, recordedBindingIndex); err != nil {
		return fmt.Errorf("index BreakGlassSessions by recorded binding: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&accessv1alpha1.BreakGlassSession{}).
		Watches(
			&rbacv1.RoleBinding{},
			handler.EnqueueRequestsFromMapFunc(r.findSessionForBinding),
		).
		Watches(
			&accessv1alpha1.AccessProfile{},
			handler.EnqueueRequestsFromMapFunc(r.findSessionsForAccessProfile),
			// Profile status is advisory and must not affect a grant. Reconcile
			// sessions only when policy changes; create and delete events remain
			// enabled so a newly available or deleted policy is handled promptly.
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Watches(
			&accessv1alpha1.BreakGlassRequest{},
			handler.EnqueueRequestsFromMapFunc(r.findSessionsForBreakGlassRequest),
		).
		Watches(
			&accessv1alpha1.BreakGlassApproval{},
			handler.EnqueueRequestsFromMapFunc(r.findSessionsForBreakGlassApproval),
		).
		Named("breakglasssession").
		Complete(r)
}

// findSessionForBinding maps a RoleBinding change to its session. A
// replacement object at the recorded location maps to its session so it can
// be suspended; unrelated objects that merely carry a forged label or owner
// reference do not get to create reconcile work.
func (r *BreakGlassSessionReconciler) findSessionForBinding(ctx context.Context, obj client.Object) []ctrl.Request {
	rb, ok := obj.(*rbacv1.RoleBinding)
	if !ok {
		return nil
	}
	claimed, ok := apiconv.ToDomainBinding(rb).ManagedSession()
	if !ok {
		// A binding whose labels were removed or forged still belongs to the
		// session that recorded its location; that session must see the drift
		// now, not at its next periodic check.
		return r.sessionsRecordingBinding(ctx, rb)
	}
	key := client.ObjectKey{Namespace: claimed.Namespace, Name: claimed.Name}

	session := &accessv1alpha1.BreakGlassSession{}
	if err := r.Get(ctx, key, session); err != nil || string(session.UID) != claimed.UID {
		return nil
	}
	domainSession := apiconv.ToDomainSession(session)
	reference := domainSession.Status.BindingRef
	if reference == nil {
		reference = domainSession.ExpectedBindingRef()
	}
	if !reference.Locates(apiconv.ToDomainBinding(rb)) {
		return nil
	}
	return []ctrl.Request{{NamespacedName: key}}
}

func (r *BreakGlassSessionReconciler) sessionsRecordingBinding(ctx context.Context, rb *rbacv1.RoleBinding) []ctrl.Request {
	sessions := &accessv1alpha1.BreakGlassSessionList{}
	if err := r.List(ctx, sessions, client.MatchingFields{recordedBindingField: rb.Namespace + "/" + rb.Name}); err != nil {
		return nil
	}
	requests := make([]ctrl.Request, 0, len(sessions.Items))
	for i := range sessions.Items {
		requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&sessions.Items[i])})
	}
	return requests
}

func recordedBindingIndex(obj client.Object) []string {
	session, ok := obj.(*accessv1alpha1.BreakGlassSession)
	if !ok || session.Status.BindingRef == nil || session.Status.BindingRef.Name == "" {
		return nil
	}
	return []string{session.Status.BindingRef.Namespace + "/" + session.Status.BindingRef.Name}
}

func accessProfileNameIndex(obj client.Object) []string {
	session, ok := obj.(*accessv1alpha1.BreakGlassSession)
	if !ok || session.Spec.AccessProfile == "" {
		return nil
	}
	return []string{session.Spec.AccessProfile}
}

func requestSourceNameIndex(obj client.Object) []string {
	session, ok := obj.(*accessv1alpha1.BreakGlassSession)
	if !ok || session.Spec.RequestRef == nil || session.Spec.RequestRef.Name == "" {
		return nil
	}
	return []string{session.Spec.RequestRef.Name}
}

func (r *BreakGlassSessionReconciler) findSessionsForAccessProfile(ctx context.Context, obj client.Object) []ctrl.Request {
	profile, ok := obj.(*accessv1alpha1.AccessProfile)
	if !ok || profile.Name == "" {
		return nil
	}
	return r.sessionsMatching(ctx, profile.Namespace, accessProfileField, profile.Name)
}

func (r *BreakGlassSessionReconciler) findSessionsForBreakGlassRequest(ctx context.Context, obj client.Object) []ctrl.Request {
	request, ok := obj.(*accessv1alpha1.BreakGlassRequest)
	if !ok || request.Name == "" {
		return nil
	}
	return r.sessionsMatching(ctx, request.Namespace, requestSourceField, request.Name)
}

func (r *BreakGlassSessionReconciler) findSessionsForBreakGlassApproval(ctx context.Context, obj client.Object) []ctrl.Request {
	approval, ok := obj.(*accessv1alpha1.BreakGlassApproval)
	if !ok || approval.Spec.RequestRef.Name == "" {
		return nil
	}
	return r.sessionsMatching(ctx, approval.Namespace, requestSourceField, approval.Spec.RequestRef.Name)
}

// sessionsMatching lists the sessions in one namespace whose indexed field
// has the value. References never cross namespaces.
func (r *BreakGlassSessionReconciler) sessionsMatching(ctx context.Context, namespace, field, value string) []ctrl.Request {
	sessions := &accessv1alpha1.BreakGlassSessionList{}
	if err := r.List(ctx, sessions, client.InNamespace(namespace), client.MatchingFields{field: value}); err != nil {
		return nil
	}
	requests := make([]ctrl.Request, 0, len(sessions.Items))
	for i := range sessions.Items {
		requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&sessions.Items[i])})
	}
	return requests
}
