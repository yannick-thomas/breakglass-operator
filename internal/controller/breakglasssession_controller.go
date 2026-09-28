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
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	breakglassmetrics "github.com/yannick-thomas/breakglass-operator/internal/metrics"
)

const (
	// BreakGlassFinalizer ensures that RBAC bindings are deleted when the session CR is deleted.
	BreakGlassFinalizer = "access.breakglass.io/finalizer"
	// Label keys used for self-healing and ownership tracking.
	ManagedByLabelKey   = "app.kubernetes.io/managed-by"
	ManagedByLabelValue = "breakglass-operator"
	SessionLabelKey     = "access.breakglass.io/session"
	SessionUIDLabelKey  = "access.breakglass.io/session-uid"

	// AccessGrantedCondition records whether the RBAC grant currently exists and is usable.
	AccessGrantedCondition = "AccessGranted"
	// BindingIntegrityCondition records whether the binding still matches the
	// identity and content recorded when the session was activated.
	BindingIntegrityCondition = "BindingIntegrity"
	// AccessProfileCondition records whether the immutable profile snapshot is
	// still present and matches the administrator-controlled policy.
	AccessProfileCondition = "AccessProfileValid"

	// DefaultBindingIntegrityCheckInterval bounds how long a missed RBAC watch
	// event can leave an active session unchecked. It deliberately trades a
	// modest periodic read for fail-closed detection of binding replacement or
	// tampering.
	DefaultBindingIntegrityCheckInterval = time.Minute

	// Binding names include a short, deterministic digest of the immutable
	// session UID. This avoids predictable name reuse across delete/recreate
	// cycles while remaining short enough for Kubernetes object-name limits.
	bindingNamePrefix     = "breakglass-"
	bindingUIDHashLength  = 12
	maxKubernetesNameSize = 253
)

// BreakGlassSessionReconciler reconciles a BreakGlassSession object
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

// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglasssessions,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglasssessions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglasssessions/finalizers,verbs=update
// +kubebuilder:rbac:groups=access.breakglass.io,resources=accessprofiles,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,resourceNames=breakglass-pod-observer,verbs=bind
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile coordinates the lifecycle of BreakGlassSessions. A binding's
// server-assigned UID is persisted at activation and is the only authoritative
// proof that a later object may be inspected or deleted. Drift is fail-closed:
// the controller suspends a session rather than recreating a missing or
// modified binding.
func (r *BreakGlassSessionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// 1. Fetch the BreakGlassSession
	session := &accessv1alpha1.BreakGlassSession{}
	if err := r.Get(ctx, req.NamespacedName, session); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 2. Handle Deletion (CR is being deleted)
	if !session.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(session, BreakGlassFinalizer) {
			log.Info("Cleaning up RBAC bindings for deleted BreakGlassSession", "session", session.Name)
			cleanup, err := r.cleanupBindingWithResult(ctx, session)
			if err != nil {
				return ctrl.Result{}, err
			}
			if cleanup.IntegrityIssue != nil {
				// A replacement object is not ours to delete. Removing the
				// finalizer lets deletion complete while preserving that object
				// for investigation.
				log.Info("Could not safely delete untrusted RBAC binding during BreakGlassSession cleanup", "session", session.Name, "reason", cleanup.IntegrityIssue.Code)
			}
			controllerutil.RemoveFinalizer(session, BreakGlassFinalizer)
			if err := r.Update(ctx, session); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Ensure Finalizer is present to prevent orphan RBAC bindings
	if !controllerutil.ContainsFinalizer(session, BreakGlassFinalizer) {
		controllerutil.AddFinalizer(session, BreakGlassFinalizer)
		if err := r.Update(ctx, session); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// 3. Handle Manual Revocation (spec.Revoked == true)
	if session.Spec.Revoked {
		return r.reconcileRevocation(ctx, session)
	}

	// 4. Handle terminal phases. A suspended session is deliberately terminal:
	// creating a replacement binding would turn a detected integrity violation
	// into a privilege re-grant.
	switch session.Status.Phase {
	case accessv1alpha1.PhaseExpired, accessv1alpha1.PhaseDenied, accessv1alpha1.PhaseSuspended, accessv1alpha1.PhaseRevoked:
		return ctrl.Result{}, nil
	}

	// 5. Active lifecycle, including periodic binding integrity verification.
	if session.Status.ExpiresAt != nil {
		return r.reconcileActiveSession(ctx, session)
	}

	// An Active status without an expiry cannot be safely bounded by the TTL
	// controller. Do not grant or preserve access in that state.
	if session.Status.Phase == accessv1alpha1.PhaseActive {
		return r.suspendForIntegrity(ctx, session, &bindingIntegrityIssue{
			Code:            "missing_expiry",
			ConditionReason: "BindingExpiryMissing",
			Message:         "active session has no recorded expiry time",
		})
	}

	// 6. First Activation: resolve the immutable, administrator-owned profile
	// before creating any privileged RBAC object.
	grant, duration, err := r.resolveAccessGrant(ctx, session)
	if err != nil {
		if !isRequestDenied(err) {
			return ctrl.Result{}, err
		}
		log.Error(err, "BreakGlassSession could not be activated", "session", session.Name)
		session.Status.Phase = accessv1alpha1.PhaseDenied
		r.setAccessGrantedCondition(session, metav1.ConditionFalse, "InvalidSpec", err.Error())
		if r.Recorder != nil {
			r.Recorder.Eventf(session, corev1.EventTypeWarning, "AccessDenied",
				"Emergency access request was denied: %v", err)
		}
		if statusErr := r.Status().Update(ctx, session); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		r.recordTransition(breakglassmetrics.TransitionDenied, session)
		return ctrl.Result{}, nil
	}
	session.Status.Grant = grant

	// Create the RBAC binding before marking the session active. The returned
	// UID is persisted in status and becomes the authority for all later
	// cleanup and integrity checks.
	bindingRef, err := r.ensureBindingReference(ctx, session)
	if err != nil {
		if isBindingCollision(err) {
			session.Status.Phase = accessv1alpha1.PhaseDenied
			r.setAccessGrantedCondition(session, metav1.ConditionFalse, "BindingCollision", "The requested binding name is already in use by another object")
			r.setBindingIntegrityCondition(session, metav1.ConditionFalse, "BindingCollision", "The requested binding name is already in use by another object")
			if r.Recorder != nil {
				r.Recorder.Eventf(session, corev1.EventTypeWarning, "AccessDenied", "Emergency access request was denied because its binding name is already in use")
			}
			if statusErr := r.Status().Update(ctx, session); statusErr != nil {
				return ctrl.Result{}, statusErr
			}
			r.recordTransition(breakglassmetrics.TransitionDenied, session)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(duration))
	session.Status.BindingName = bindingRef.Name
	session.Status.BindingRef = bindingRef
	session.Status.StartTime = &now
	session.Status.ExpiresAt = &expiresAt
	session.Status.Phase = accessv1alpha1.PhaseActive
	r.setAccessGrantedCondition(session, metav1.ConditionTrue, "AccessGranted", "Emergency access binding is active")
	r.setBindingIntegrityCondition(session, metav1.ConditionTrue, "BindingVerified", "The emergency access binding identity and content were verified")
	r.setAccessProfileCondition(session, metav1.ConditionTrue, "AccessProfileVerified", "The immutable AccessProfile snapshot was verified")

	targetDesc := fmt.Sprintf("namespace %q", grant.TargetNamespace)

	if r.Recorder != nil {
		r.Recorder.Eventf(session, corev1.EventTypeNormal, "AccessGranted",
			"Granted %s %q access on %s to %s %q until %s",
			grant.RoleRef.Kind, grant.RoleRef.Name, targetDesc,
			session.Spec.Subject.Kind, session.Spec.Subject.Name,
			expiresAt.Format(time.RFC3339))
	}

	if err := r.Status().Update(ctx, session); err != nil {
		return ctrl.Result{}, err
	}
	r.recordTransition(breakglassmetrics.TransitionActivated, session)

	log.Info("BreakGlassSession activated successfully", "session", session.Name, "expiresAt", expiresAt)
	return ctrl.Result{RequeueAfter: r.activeRequeueAfter(expiresAt.Time)}, nil
}

func (r *BreakGlassSessionReconciler) reconcileActiveSession(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// A profile snapshot is required for every secure session. We deliberately
	// do not migrate active grants from the former free-form API: doing so would
	// preserve a privilege decision that was never authorized through a profile.
	if session.Status.Grant == nil {
		return r.suspendForProfile(ctx, session, &accessProfileIssue{
			ConditionReason: "AccessProfileSnapshotMissing",
			Message:         "active session has no resolved AccessProfile snapshot",
		})
	}
	profileIssue, err := r.verifyAccessProfile(ctx, session)
	if err != nil {
		return ctrl.Result{}, err
	}
	if profileIssue != nil {
		return r.suspendForProfile(ctx, session, profileIssue)
	}

	// Sessions created before status.bindingRef was introduced are migrated only
	// when the existing binding already proves durable ownership and exact
	// desired content. Any ambiguity is suspended rather than adopted.
	if session.Status.BindingRef == nil {
		bindingRef, issue, err := r.discoverBindingReference(ctx, session)
		if err != nil {
			return ctrl.Result{}, err
		}
		if issue != nil {
			return r.suspendForIntegrity(ctx, session, issue)
		}
		session.Status.BindingRef = bindingRef
		session.Status.BindingName = bindingRef.Name
		r.setBindingIntegrityCondition(session, metav1.ConditionTrue, "BindingReferenceRecorded", "The legacy emergency access binding identity was recorded")
		if err := r.Status().Update(ctx, session); err != nil {
			return ctrl.Result{}, err
		}
	}

	now := time.Now()
	if !now.Before(session.Status.ExpiresAt.Time) {
		log.Info("Session duration expired, revoking RBAC access", "session", session.Name)
		return r.expireSession(ctx, session)
	}

	issue, err := r.verifyBindingIntegrity(ctx, session)
	if err != nil {
		return ctrl.Result{}, err
	}
	if issue != nil {
		return r.suspendForIntegrity(ctx, session, issue)
	}

	remaining := r.activeRequeueAfter(session.Status.ExpiresAt.Time)
	log.Info("Session is active, integrity check scheduled", "session", session.Name, "requeueAfter", remaining)
	return ctrl.Result{RequeueAfter: remaining}, nil
}

func (r *BreakGlassSessionReconciler) reconcileRevocation(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (ctrl.Result, error) {
	if session.Status.Phase == accessv1alpha1.PhaseRevoked {
		return ctrl.Result{}, nil
	}

	logf.FromContext(ctx).Info("Session manually revoked by administrator", "session", session.Name)
	cleanup, err := r.cleanupBindingWithResult(ctx, session)
	if err != nil {
		return ctrl.Result{}, err
	}

	session.Status.Phase = accessv1alpha1.PhaseRevoked
	r.setAccessGrantedCondition(session, metav1.ConditionFalse, "AccessRevoked", "Emergency access was manually revoked")
	r.setCleanupIntegrityCondition(session, cleanup)
	if r.Recorder != nil {
		r.Recorder.Eventf(session, corev1.EventTypeWarning, "AccessRevoked", "Emergency access manually revoked by admin")
		if cleanup.IntegrityIssue != nil {
			r.Recorder.Eventf(session, corev1.EventTypeWarning, "BindingIntegrityLost", "Emergency access binding could not be safely removed: %s", cleanup.IntegrityIssue.Code)
		}
	}
	if err := r.Status().Update(ctx, session); err != nil {
		return ctrl.Result{}, err
	}
	r.recordTransition(breakglassmetrics.TransitionRevoked, session)
	return ctrl.Result{}, nil
}

func (r *BreakGlassSessionReconciler) expireSession(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (ctrl.Result, error) {
	cleanup, err := r.cleanupBindingWithResult(ctx, session)
	if err != nil {
		return ctrl.Result{}, err
	}

	session.Status.Phase = accessv1alpha1.PhaseExpired
	r.setAccessGrantedCondition(session, metav1.ConditionFalse, "AccessExpired", "Emergency access duration elapsed")
	r.setCleanupIntegrityCondition(session, cleanup)
	if r.Recorder != nil {
		r.Recorder.Eventf(session, corev1.EventTypeWarning, "AccessExpired", "Emergency access expired at %s", session.Status.ExpiresAt.Format(time.RFC3339))
		if cleanup.IntegrityIssue != nil {
			r.Recorder.Eventf(session, corev1.EventTypeWarning, "BindingIntegrityLost", "Emergency access binding could not be safely removed: %s", cleanup.IntegrityIssue.Code)
		}
	}
	if err := r.Status().Update(ctx, session); err != nil {
		return ctrl.Result{}, err
	}
	r.recordTransition(breakglassmetrics.TransitionExpired, session)
	if cleanup.Deleted && r.Metrics != nil && session.Status.ExpiresAt != nil {
		r.Metrics.ObserveExpiryCleanupLag(SessionScope(session), time.Since(session.Status.ExpiresAt.Time))
	}
	return ctrl.Result{}, nil
}

func (r *BreakGlassSessionReconciler) suspendForIntegrity(ctx context.Context, session *accessv1alpha1.BreakGlassSession, issue *bindingIntegrityIssue) (ctrl.Result, error) {
	// Delete only the exact UID persisted in status. For a missing or replaced
	// object cleanup is intentionally a no-op; the controller must never delete
	// an object it did not create.
	cleanup, err := r.cleanupBindingWithResult(ctx, session)
	if err != nil {
		return ctrl.Result{}, err
	}
	if cleanup.IntegrityIssue != nil && issue == nil {
		issue = cleanup.IntegrityIssue
	}
	if issue == nil {
		issue = &bindingIntegrityIssue{Code: "integrity_unknown", ConditionReason: "BindingIntegrityUnknown", Message: "the emergency access binding could not be verified"}
	}

	session.Status.Phase = accessv1alpha1.PhaseSuspended
	r.setAccessGrantedCondition(session, metav1.ConditionFalse, "BindingIntegrityLost", "Emergency access was suspended because its binding failed integrity verification")
	r.setBindingIntegrityCondition(session, metav1.ConditionFalse, issue.ConditionReason, issue.Message)
	if r.Recorder != nil {
		r.Recorder.Eventf(session, corev1.EventTypeWarning, "BindingIntegrityLost", "Emergency access suspended because its binding failed integrity verification: %s", issue.Code)
	}
	if err := r.Status().Update(ctx, session); err != nil {
		return ctrl.Result{}, err
	}
	r.recordTransition(breakglassmetrics.TransitionSuspended, session)
	r.recordBindingDrift(issue, session)
	return ctrl.Result{}, nil
}

func (r *BreakGlassSessionReconciler) setCleanupIntegrityCondition(session *accessv1alpha1.BreakGlassSession, cleanup bindingCleanupResult) {
	if cleanup.IntegrityIssue != nil {
		r.setBindingIntegrityCondition(session, metav1.ConditionFalse, cleanup.IntegrityIssue.ConditionReason, cleanup.IntegrityIssue.Message)
		return
	}
	r.setBindingIntegrityCondition(session, metav1.ConditionTrue, "BindingRemoved", "The emergency access binding was removed using its recorded identity")
}

func (r *BreakGlassSessionReconciler) activeRequeueAfter(expiresAt time.Time) time.Duration {
	remaining := time.Until(expiresAt)
	// Keep an expiry race from turning into a zero RequeueAfter, which means
	// "do not requeue" to controller-runtime. The next reconcile will take the
	// expiry branch and remove the exact UID-tracked binding.
	if remaining <= 0 {
		return time.Millisecond
	}
	interval := r.IntegrityCheckInterval
	if interval <= 0 {
		interval = DefaultBindingIntegrityCheckInterval
	}
	if remaining < interval {
		return remaining
	}
	return interval
}

// validateSession performs request checks that cannot be expressed solely by
// the CRD schema. Profile policy is resolved separately from the API server.
func (r *BreakGlassSessionReconciler) validateSession(session *accessv1alpha1.BreakGlassSession) (time.Duration, error) {
	duration, err := time.ParseDuration(session.Spec.Duration)
	if err != nil {
		return 0, fmt.Errorf("duration %q is not a valid Go duration: %w", session.Spec.Duration, err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("duration must be greater than zero")
	}
	if r.MaxSessionDuration > 0 && duration > r.MaxSessionDuration {
		return 0, fmt.Errorf("duration %s exceeds the configured maximum of %s", duration, r.MaxSessionDuration)
	}
	if session.Spec.AccessProfile == "" || session.Spec.AccessProfileUID == "" {
		return 0, fmt.Errorf("accessProfile and server-assigned accessProfileUID are required")
	}
	if session.Spec.Subject.Kind != accessv1alpha1.SubjectKindUser || session.Spec.Subject.Name == "" {
		return 0, fmt.Errorf("a self-service session must have an authenticated User subject")
	}
	if session.Spec.Subject.Namespace != "" {
		return 0, fmt.Errorf("a User subject must not specify subject.namespace")
	}
	return duration, nil
}

// requestDeniedError identifies a semantic request failure that should be
// persisted as Denied instead of retried. API connectivity failures are not
// wrapped in this type and remain retryable.
type requestDeniedError struct {
	err error
}

func (e *requestDeniedError) Error() string { return e.err.Error() }
func (e *requestDeniedError) Unwrap() error { return e.err }

func denyRequest(err error) error {
	return &requestDeniedError{err: err}
}

func isRequestDenied(err error) bool {
	var denied *requestDeniedError
	return errors.As(err, &denied)
}

// resolveAccessGrant obtains the selected policy and turns it into the
// controller-owned snapshot used for the whole session. The profile's UID is
// checked in addition to its name so delete/recreate cannot change a request.
func (r *BreakGlassSessionReconciler) resolveAccessGrant(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (*accessv1alpha1.ResolvedAccess, time.Duration, error) {
	duration, err := r.validateSession(session)
	if err != nil {
		return nil, 0, denyRequest(err)
	}

	profile := &accessv1alpha1.AccessProfile{}
	if err := r.policyReader().Get(ctx, client.ObjectKey{Name: session.Spec.AccessProfile}, profile); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, 0, denyRequest(fmt.Errorf("AccessProfile %q does not exist", session.Spec.AccessProfile))
		}
		return nil, 0, err
	}
	if profile.UID == "" || string(profile.UID) != session.Spec.AccessProfileUID {
		return nil, 0, denyRequest(fmt.Errorf("AccessProfile %q no longer matches the authorized profile UID", session.Spec.AccessProfile))
	}
	maxDuration, err := validateAccessProfile(profile)
	if err != nil {
		return nil, 0, denyRequest(err)
	}
	if duration > maxDuration {
		return nil, 0, denyRequest(fmt.Errorf("duration %s exceeds AccessProfile maximum of %s", duration, maxDuration))
	}
	if !r.targetNamespaceAllowed(profile.Spec.TargetNamespace) {
		return nil, 0, denyRequest(fmt.Errorf("AccessProfile %q targets namespace %q outside this manager's allowed namespace set", profile.Name, profile.Spec.TargetNamespace))
	}

	return &accessv1alpha1.ResolvedAccess{
		AccessProfile:    profile.Name,
		AccessProfileUID: string(profile.UID),
		RoleRef:          profile.Spec.RoleRef,
		TargetNamespace:  profile.Spec.TargetNamespace,
	}, duration, nil
}

func validateAccessProfile(profile *accessv1alpha1.AccessProfile) (time.Duration, error) {
	if profile.Spec.RoleRef.Kind != "ClusterRole" || profile.Spec.RoleRef.Name == "" {
		return 0, fmt.Errorf("AccessProfile %q must reference a curated ClusterRole", profile.Name)
	}
	if profile.Spec.TargetNamespace == "" {
		return 0, fmt.Errorf("AccessProfile %q must specify a targetNamespace", profile.Name)
	}
	maxDuration, err := time.ParseDuration(profile.Spec.MaxDuration)
	if err != nil || maxDuration <= 0 {
		return 0, fmt.Errorf("AccessProfile %q has an invalid positive maxDuration", profile.Name)
	}
	return maxDuration, nil
}

func (r *BreakGlassSessionReconciler) targetNamespaceAllowed(namespace string) bool {
	if len(r.AllowedTargetNamespaces) == 0 {
		return true
	}
	_, allowed := r.AllowedTargetNamespaces[namespace]
	return allowed
}

func (r *BreakGlassSessionReconciler) setAccessGrantedCondition(
	session *accessv1alpha1.BreakGlassSession,
	status metav1.ConditionStatus,
	reason, message string,
) {
	meta.SetStatusCondition(&session.Status.Conditions, metav1.Condition{
		Type:               AccessGrantedCondition,
		Status:             status,
		ObservedGeneration: session.Generation,
		Reason:             reason,
		Message:            message,
	})
}

func (r *BreakGlassSessionReconciler) setBindingIntegrityCondition(
	session *accessv1alpha1.BreakGlassSession,
	status metav1.ConditionStatus,
	reason, message string,
) {
	meta.SetStatusCondition(&session.Status.Conditions, metav1.Condition{
		Type:               BindingIntegrityCondition,
		Status:             status,
		ObservedGeneration: session.Generation,
		Reason:             reason,
		Message:            message,
	})
}

func (r *BreakGlassSessionReconciler) setAccessProfileCondition(
	session *accessv1alpha1.BreakGlassSession,
	status metav1.ConditionStatus,
	reason, message string,
) {
	meta.SetStatusCondition(&session.Status.Conditions, metav1.Condition{
		Type:               AccessProfileCondition,
		Status:             status,
		ObservedGeneration: session.Generation,
		Reason:             reason,
		Message:            message,
	})
}

type accessProfileIssue struct {
	ConditionReason string
	Message         string
}

// verifyAccessProfile confirms that an active grant still refers to precisely
// the immutable policy it was authorized against. Deleting a profile, reusing
// its name, or bypassing its immutability is a fail-closed condition.
func (r *BreakGlassSessionReconciler) verifyAccessProfile(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (*accessProfileIssue, error) {
	grant := session.Status.Grant
	if grant == nil {
		return &accessProfileIssue{ConditionReason: "AccessProfileSnapshotMissing", Message: "active session has no resolved AccessProfile snapshot"}, nil
	}
	if grant.AccessProfile != session.Spec.AccessProfile || grant.AccessProfileUID != session.Spec.AccessProfileUID {
		return &accessProfileIssue{ConditionReason: "AccessProfileSnapshotMismatch", Message: "the resolved AccessProfile snapshot differs from the immutable request"}, nil
	}

	profile := &accessv1alpha1.AccessProfile{}
	if err := r.policyReader().Get(ctx, client.ObjectKey{Name: grant.AccessProfile}, profile); err != nil {
		if apierrors.IsNotFound(err) {
			return &accessProfileIssue{ConditionReason: "AccessProfileMissing", Message: "the AccessProfile was deleted while the session was active"}, nil
		}
		return nil, err
	}
	if string(profile.UID) != grant.AccessProfileUID {
		return &accessProfileIssue{ConditionReason: "AccessProfileUIDMismatch", Message: "a different AccessProfile object now uses the recorded profile name"}, nil
	}
	if _, err := validateAccessProfile(profile); err != nil {
		return &accessProfileIssue{ConditionReason: "AccessProfileInvalid", Message: "the active AccessProfile no longer passes semantic validation"}, nil
	}
	if !r.targetNamespaceAllowed(profile.Spec.TargetNamespace) {
		return &accessProfileIssue{ConditionReason: "AccessProfileOutOfScope", Message: "the active AccessProfile targets a namespace outside this manager's allowed namespace set"}, nil
	}
	if profile.Spec.RoleRef != grant.RoleRef || profile.Spec.TargetNamespace != grant.TargetNamespace {
		return &accessProfileIssue{ConditionReason: "AccessProfilePolicyDrift", Message: "the AccessProfile policy differs from the resolved session snapshot"}, nil
	}
	return nil, nil
}

func (r *BreakGlassSessionReconciler) suspendForProfile(ctx context.Context, session *accessv1alpha1.BreakGlassSession, issue *accessProfileIssue) (ctrl.Result, error) {
	cleanup, err := r.cleanupBindingWithResult(ctx, session)
	if err != nil {
		return ctrl.Result{}, err
	}
	if issue == nil {
		issue = &accessProfileIssue{ConditionReason: "AccessProfileUnknown", Message: "the AccessProfile could not be verified"}
	}

	session.Status.Phase = accessv1alpha1.PhaseSuspended
	r.setAccessGrantedCondition(session, metav1.ConditionFalse, "AccessProfileInvalid", "Emergency access was suspended because its AccessProfile failed verification")
	r.setAccessProfileCondition(session, metav1.ConditionFalse, issue.ConditionReason, issue.Message)
	r.setCleanupIntegrityCondition(session, cleanup)
	if r.Recorder != nil {
		r.Recorder.Eventf(session, corev1.EventTypeWarning, "AccessProfileInvalid", "Emergency access suspended because its AccessProfile failed verification: %s", issue.ConditionReason)
	}
	if err := r.Status().Update(ctx, session); err != nil {
		return ctrl.Result{}, err
	}
	r.recordTransition(breakglassmetrics.TransitionSuspended, session)
	return ctrl.Result{}, nil
}

type bindingIntegrityIssue struct {
	// Code is a stable, low-cardinality machine value for metrics and events.
	Code string
	// ConditionReason conforms to metav1.Condition's CamelCase reason syntax.
	ConditionReason string
	Message         string
}

type bindingCleanupResult struct {
	Deleted        bool
	IntegrityIssue *bindingIntegrityIssue
}

// SessionScope converts persisted controller state to a bounded metric label.
// It intentionally never returns a namespace, profile, role, or identity.
func SessionScope(session *accessv1alpha1.BreakGlassSession) breakglassmetrics.Scope {
	if session.Status.BindingRef != nil {
		return breakglassmetrics.ScopeFromBindingKind(session.Status.BindingRef.Kind)
	}
	// The profile snapshot is safe to use only as a boolean scope decision; its
	// namespace value is never emitted as a label.
	if session.Status.Grant != nil && session.Status.Grant.TargetNamespace != "" {
		return breakglassmetrics.ScopeNamespaced
	}
	return breakglassmetrics.ScopeUnknown
}

func (r *BreakGlassSessionReconciler) recordTransition(transition breakglassmetrics.LifecycleTransition, session *accessv1alpha1.BreakGlassSession) {
	if r.Metrics != nil {
		r.Metrics.RecordTransition(transition, SessionScope(session))
	}
}

func (r *BreakGlassSessionReconciler) recordBindingOperation(operation breakglassmetrics.BindingOperation, result breakglassmetrics.BindingOperationResult, session *accessv1alpha1.BreakGlassSession) {
	if r.Metrics != nil {
		r.Metrics.RecordBindingOperation(operation, result, SessionScope(session))
	}
}

func (r *BreakGlassSessionReconciler) recordBindingDrift(issue *bindingIntegrityIssue, session *accessv1alpha1.BreakGlassSession) {
	if r.Metrics == nil || issue == nil {
		return
	}
	var reason breakglassmetrics.BindingDriftReason
	switch issue.Code {
	case "missing":
		reason = breakglassmetrics.DriftMissing
	case "ownership":
		reason = breakglassmetrics.DriftOwnership
	case "uid_mismatch":
		reason = breakglassmetrics.DriftUIDMismatch
	case "role_ref":
		reason = breakglassmetrics.DriftRoleRef
	case "subjects":
		reason = breakglassmetrics.DriftSubjects
	case "binding_reference":
		reason = breakglassmetrics.DriftBindingReference
	case "missing_expiry":
		reason = breakglassmetrics.DriftMissingExpiry
	case "integrity_unknown":
		reason = breakglassmetrics.DriftIntegrityUnknown
	default:
		reason = breakglassmetrics.DriftUnknown
	}
	r.Metrics.RecordBindingDrift(reason, SessionScope(session))
}

type bindingCollisionError struct {
	message string
}

func (e *bindingCollisionError) Error() string {
	return e.message
}

func isBindingCollision(err error) bool {
	_, ok := err.(*bindingCollisionError)
	return ok
}

// ensureBinding exists for focused unit tests and callers that only need the
// binding side effect. Activation uses ensureBindingReference so it can persist
// the server-assigned UID in status.
func (r *BreakGlassSessionReconciler) ensureBinding(ctx context.Context, session *accessv1alpha1.BreakGlassSession) error {
	bindingRef, err := r.ensureBindingReference(ctx, session)
	if err != nil {
		return err
	}
	session.Status.BindingName = bindingRef.Name
	session.Status.BindingRef = bindingRef
	return nil
}

// ensureBindingReference creates a new binding, or recovers an exact binding
// left behind when a previous create succeeded but the subsequent status write
// failed. It never updates an existing binding.
func (r *BreakGlassSessionReconciler) ensureBindingReference(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (*accessv1alpha1.BindingReference, error) {
	expected := expectedBindingReference(session)
	if expected.Namespace == "" || session.Status.Grant == nil {
		return nil, fmt.Errorf("cannot create a binding without a resolved namespaced AccessProfile grant")
	}
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      expected.Name,
			Namespace: expected.Namespace,
			Labels:    managedBindingLabels(session),
		},
		RoleRef:  expectedRoleRef(session),
		Subjects: []rbacv1.Subject{expectedSubject(session)},
	}
	if err := controllerutil.SetControllerReference(session, rb, r.Scheme); err != nil {
		return nil, err
	}
	if err := r.Create(ctx, rb); err == nil {
		r.recordBindingOperation(breakglassmetrics.BindingOperationGrant, breakglassmetrics.BindingOperationSuccess, session)
		return bindingReferenceFromObject(rb)
	} else if !apierrors.IsAlreadyExists(err) {
		r.recordBindingOperation(breakglassmetrics.BindingOperationGrant, breakglassmetrics.BindingOperationError, session)
		return nil, err
	}

	existing := &rbacv1.RoleBinding{}
	if err := r.Get(ctx, client.ObjectKey{Name: expected.Name, Namespace: expected.Namespace}, existing); err != nil {
		r.recordBindingOperation(breakglassmetrics.BindingOperationGrant, breakglassmetrics.BindingOperationError, session)
		return nil, err
	}
	if issue := bindingMatchesExpected(session, existing); issue != nil {
		r.recordBindingOperation(breakglassmetrics.BindingOperationGrant, breakglassmetrics.BindingOperationError, session)
		return nil, &bindingCollisionError{message: fmt.Sprintf("refusing to adopt existing RoleBinding %s/%s: %s", existing.Namespace, existing.Name, issue.Code)}
	}
	r.recordBindingOperation(breakglassmetrics.BindingOperationRestore, breakglassmetrics.BindingOperationSuccess, session)
	return bindingReferenceFromObject(existing)
}

func expectedBindingReference(session *accessv1alpha1.BreakGlassSession) *accessv1alpha1.BindingReference {
	bindingName := session.Status.BindingName
	if bindingName == "" {
		bindingName = bindingNameForSession(session)
	}
	targetNamespace := ""
	if session.Status.Grant != nil {
		targetNamespace = session.Status.Grant.TargetNamespace
	}
	return &accessv1alpha1.BindingReference{Kind: "RoleBinding", Name: bindingName, Namespace: targetNamespace}
}

func bindingNameForSession(session *accessv1alpha1.BreakGlassSession) string {
	digest := sha256.Sum256([]byte(session.UID))
	suffix := fmt.Sprintf("-%x", digest[:])[:bindingUIDHashLength+1]
	maxSessionNameLength := maxKubernetesNameSize - len(bindingNamePrefix) - len(suffix)
	sessionName := session.Name
	if len(sessionName) > maxSessionNameLength {
		sessionName = sessionName[:maxSessionNameLength]
	}
	sessionName = strings.Trim(sessionName, "-")
	if sessionName == "" {
		sessionName = "session"
	}
	return bindingNamePrefix + sessionName + suffix
}

func bindingReferenceMatchesSession(ref *accessv1alpha1.BindingReference, session *accessv1alpha1.BreakGlassSession) bool {
	if ref == nil {
		return false
	}
	expected := expectedBindingReference(session)
	return ref.Kind == expected.Kind && ref.Name == expected.Name && ref.Namespace == expected.Namespace
}

func bindingReferenceMatchesObjectLocation(ref *accessv1alpha1.BindingReference, obj client.Object) bool {
	if ref == nil || ref.Name != obj.GetName() || ref.Namespace != obj.GetNamespace() {
		return false
	}
	_, isRoleBinding := obj.(*rbacv1.RoleBinding)
	return isRoleBinding && ref.Kind == "RoleBinding"
}

func bindingReferenceFromObject(obj client.Object) (*accessv1alpha1.BindingReference, error) {
	if obj.GetUID() == "" {
		return nil, fmt.Errorf("RBAC binding %s returned without a server-assigned UID", client.ObjectKeyFromObject(obj))
	}
	ref := &accessv1alpha1.BindingReference{
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
		UID:       string(obj.GetUID()),
	}
	if _, ok := obj.(*rbacv1.RoleBinding); !ok {
		return nil, fmt.Errorf("unsupported RBAC binding type %T", obj)
	}
	ref.Kind = "RoleBinding"
	return ref, nil
}

func expectedSubject(session *accessv1alpha1.BreakGlassSession) rbacv1.Subject {
	return rbacv1.Subject{
		Kind: string(session.Spec.Subject.Kind),
		Name: session.Spec.Subject.Name,
	}
}

func expectedRoleRef(session *accessv1alpha1.BreakGlassSession) rbacv1.RoleRef {
	if session.Status.Grant == nil {
		return rbacv1.RoleRef{}
	}
	return rbacv1.RoleRef{
		APIGroup: rbacv1.GroupName,
		Kind:     session.Status.Grant.RoleRef.Kind,
		Name:     session.Status.Grant.RoleRef.Name,
	}
}

func managedBindingLabels(session *accessv1alpha1.BreakGlassSession) map[string]string {
	return map[string]string{
		ManagedByLabelKey:  ManagedByLabelValue,
		SessionLabelKey:    session.Name,
		SessionUIDLabelKey: string(session.UID),
	}
}

func hasManagedBindingLabels(labels map[string]string, session *accessv1alpha1.BreakGlassSession) bool {
	expected := managedBindingLabels(session)
	for key, value := range expected {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func hasSessionControllerOwnerReference(obj client.Object, session *accessv1alpha1.BreakGlassSession) bool {
	for _, owner := range obj.GetOwnerReferences() {
		if owner.APIVersion == accessv1alpha1.GroupVersion.String() &&
			owner.Kind == "BreakGlassSession" &&
			owner.Name == session.Name &&
			owner.UID == session.UID &&
			owner.Controller != nil && *owner.Controller {
			return true
		}
	}
	return false
}

// isManagedBindingForSession is intentionally stricter than an owner-reference
// fallback: labels and owner reference corroborate the binding's managed state.
// Once status.bindingRef exists, its UID is the authority for safe deletion.
func isManagedBindingForSession(obj client.Object, session *accessv1alpha1.BreakGlassSession) bool {
	return hasSessionControllerOwnerReference(obj, session) && hasManagedBindingLabels(obj.GetLabels(), session)
}

func bindingMatchesExpected(session *accessv1alpha1.BreakGlassSession, obj client.Object) *bindingIntegrityIssue {
	if !bindingReferenceMatchesObjectLocation(expectedBindingReference(session), obj) {
		return &bindingIntegrityIssue{
			Code:            "binding_reference",
			ConditionReason: "BindingReferenceInvalid",
			Message:         "the RBAC binding kind, name, or namespace differs from the session record",
		}
	}
	if !isManagedBindingForSession(obj, session) {
		return &bindingIntegrityIssue{
			Code:            "ownership",
			ConditionReason: "BindingOwnershipLost",
			Message:         "the RBAC binding no longer has the expected owner reference and labels",
		}
	}

	expectedRole := expectedRoleRef(session)
	expectedSubjects := []rbacv1.Subject{expectedSubject(session)}
	binding, ok := obj.(*rbacv1.RoleBinding)
	if !ok {
		return &bindingIntegrityIssue{Code: "binding_reference", ConditionReason: "BindingReferenceInvalid", Message: "the referenced object is not an RBAC binding"}
	}
	if !equality.Semantic.DeepEqual(binding.RoleRef, expectedRole) {
		return &bindingIntegrityIssue{Code: "role_ref", ConditionReason: "BindingRoleRefDrift", Message: "the RBAC binding role reference differs from the approved session"}
	}
	if !equality.Semantic.DeepEqual(binding.Subjects, expectedSubjects) {
		return &bindingIntegrityIssue{Code: "subjects", ConditionReason: "BindingSubjectsDrift", Message: "the RBAC binding subjects differ from the approved session"}
	}
	return nil
}

// discoverBindingReference supports one-way migration of sessions created by
// earlier releases. It never recreates or adopts an ambiguous object.
func (r *BreakGlassSessionReconciler) discoverBindingReference(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (*accessv1alpha1.BindingReference, *bindingIntegrityIssue, error) {
	expected := expectedBindingReference(session)
	obj, err := r.getBindingForReference(ctx, expected)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, &bindingIntegrityIssue{Code: "missing", ConditionReason: "BindingMissing", Message: "the emergency access binding no longer exists"}, nil
		}
		return nil, nil, err
	}
	if issue := bindingMatchesExpected(session, obj); issue != nil {
		return nil, issue, nil
	}
	bindingRef, err := bindingReferenceFromObject(obj)
	if err != nil {
		return nil, &bindingIntegrityIssue{Code: "binding_reference", ConditionReason: "BindingReferenceInvalid", Message: "the emergency access binding has no server-assigned UID"}, nil
	}
	return bindingRef, nil, nil
}

func (r *BreakGlassSessionReconciler) verifyBindingIntegrity(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (*bindingIntegrityIssue, error) {
	bindingRef := session.Status.BindingRef
	if bindingRef == nil || bindingRef.UID == "" || !bindingReferenceMatchesSession(bindingRef, session) {
		return &bindingIntegrityIssue{Code: "binding_reference", ConditionReason: "BindingReferenceInvalid", Message: "the recorded emergency access binding identity is invalid"}, nil
	}

	obj, err := r.getBindingForReference(ctx, bindingRef)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return &bindingIntegrityIssue{Code: "missing", ConditionReason: "BindingMissing", Message: "the emergency access binding no longer exists"}, nil
		}
		return nil, err
	}
	if string(obj.GetUID()) != bindingRef.UID {
		return &bindingIntegrityIssue{Code: "uid_mismatch", ConditionReason: "BindingUIDMismatch", Message: "a different RBAC binding object now uses the recorded binding name"}, nil
	}
	return bindingMatchesExpected(session, obj), nil
}

func (r *BreakGlassSessionReconciler) getBindingForReference(ctx context.Context, ref *accessv1alpha1.BindingReference) (client.Object, error) {
	if ref == nil {
		return nil, fmt.Errorf("cannot get a nil RBAC binding reference")
	}
	if ref.Kind != "RoleBinding" || ref.Namespace == "" {
		return nil, fmt.Errorf("unsupported RBAC binding kind %q", ref.Kind)
	}
	rb := &rbacv1.RoleBinding{}
	if err := r.Get(ctx, client.ObjectKey{Name: ref.Name, Namespace: ref.Namespace}, rb); err != nil {
		return nil, err
	}
	return rb, nil
}

// cleanupBinding is kept as a small compatibility wrapper for callers that do
// not need the integrity result.
func (r *BreakGlassSessionReconciler) cleanupBinding(ctx context.Context, session *accessv1alpha1.BreakGlassSession) error {
	_, err := r.cleanupBindingWithResult(ctx, session)
	return err
}

// cleanupBindingWithResult deletes only the binding object whose UID was
// recorded at activation. It uses a UID deletion precondition to close the
// get/delete race against delete-and-recreate replacement attacks.
func (r *BreakGlassSessionReconciler) cleanupBindingWithResult(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (bindingCleanupResult, error) {
	bindingRef := session.Status.BindingRef
	if bindingRef == nil {
		// A never-activated request has nothing to clean up. For a legacy active
		// session with a secure resolved grant, attempt the strict one-way
		// reference migration before acting. A free-form pre-profile session is
		// intentionally not guessed at or deleted by name during upgrade.
		if session.Status.StartTime == nil && session.Status.ExpiresAt == nil {
			return bindingCleanupResult{}, nil
		}
		if session.Status.Grant == nil {
			return bindingCleanupResult{IntegrityIssue: &bindingIntegrityIssue{
				Code:            "binding_reference",
				ConditionReason: "BindingReferenceInvalid",
				Message:         "active session has no secure profile snapshot or binding identity",
			}}, nil
		}
		var issue *bindingIntegrityIssue
		var err error
		bindingRef, issue, err = r.discoverBindingReference(ctx, session)
		if err != nil {
			return bindingCleanupResult{}, err
		}
		if issue != nil {
			return bindingCleanupResult{IntegrityIssue: issue}, nil
		}
		session.Status.BindingRef = bindingRef
		session.Status.BindingName = bindingRef.Name
	}

	if bindingRef.UID == "" || !bindingReferenceMatchesSession(bindingRef, session) {
		return bindingCleanupResult{IntegrityIssue: &bindingIntegrityIssue{
			Code:            "binding_reference",
			ConditionReason: "BindingReferenceInvalid",
			Message:         "the recorded emergency access binding identity is invalid",
		}}, nil
	}

	obj, err := r.getBindingForReference(ctx, bindingRef)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return bindingCleanupResult{IntegrityIssue: &bindingIntegrityIssue{Code: "missing", ConditionReason: "BindingMissing", Message: "the emergency access binding no longer exists"}}, nil
		}
		return bindingCleanupResult{}, err
	}
	if string(obj.GetUID()) != bindingRef.UID {
		return bindingCleanupResult{IntegrityIssue: &bindingIntegrityIssue{Code: "uid_mismatch", ConditionReason: "BindingUIDMismatch", Message: "a different RBAC binding object now uses the recorded binding name"}}, nil
	}

	uid := types.UID(bindingRef.UID)
	if err := r.Delete(ctx, obj, client.Preconditions{UID: &uid}); err != nil {
		if apierrors.IsNotFound(err) {
			return bindingCleanupResult{IntegrityIssue: &bindingIntegrityIssue{Code: "missing", ConditionReason: "BindingMissing", Message: "the emergency access binding no longer exists"}}, nil
		}
		if apierrors.IsConflict(err) {
			r.recordBindingOperation(breakglassmetrics.BindingOperationCleanup, breakglassmetrics.BindingOperationError, session)
			return bindingCleanupResult{IntegrityIssue: &bindingIntegrityIssue{Code: "uid_mismatch", ConditionReason: "BindingUIDMismatch", Message: "the emergency access binding changed before it could be deleted"}}, nil
		}
		r.recordBindingOperation(breakglassmetrics.BindingOperationCleanup, breakglassmetrics.BindingOperationError, session)
		return bindingCleanupResult{}, err
	}
	r.recordBindingOperation(breakglassmetrics.BindingOperationCleanup, breakglassmetrics.BindingOperationSuccess, session)
	return bindingCleanupResult{Deleted: true}, nil
}

// findSessionForBinding maps changes in RBAC bindings back to their parent BreakGlassSession
func (r *BreakGlassSessionReconciler) findSessionForBinding(ctx context.Context, obj client.Object) []ctrl.Request {
	sessionName, sessionUID := bindingSessionHint(obj)
	if sessionName == "" || sessionUID == "" {
		return nil
	}

	session := &accessv1alpha1.BreakGlassSession{}
	if err := r.Get(ctx, client.ObjectKey{Name: sessionName}, session); err != nil || session.UID != sessionUID {
		return nil
	}

	// A replacement object intentionally maps to its session so it can be
	// suspended, but unrelated objects that merely carry a forged label or owner
	// reference do not get to create arbitrary reconcile work.
	reference := session.Status.BindingRef
	if reference == nil {
		reference = expectedBindingReference(session)
	}
	if !bindingReferenceMatchesObjectLocation(reference, obj) {
		return nil
	}

	return []ctrl.Request{{NamespacedName: types.NamespacedName{Name: sessionName}}}
}

func bindingSessionHint(obj client.Object) (string, types.UID) {
	for _, owner := range obj.GetOwnerReferences() {
		if owner.APIVersion == accessv1alpha1.GroupVersion.String() && owner.Kind == "BreakGlassSession" && owner.Name != "" && owner.UID != "" && owner.Controller != nil && *owner.Controller {
			return owner.Name, owner.UID
		}
	}
	labels := obj.GetLabels()
	if labels[ManagedByLabelKey] == ManagedByLabelValue && labels[SessionLabelKey] != "" && labels[SessionUIDLabelKey] != "" {
		return labels[SessionLabelKey], types.UID(labels[SessionUIDLabelKey])
	}
	return "", ""
}

// SetupWithManager sets up the controller with the Session, its fixed
// AccessProfile, and the namespaced RoleBindings it creates.
func (r *BreakGlassSessionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&accessv1alpha1.BreakGlassSession{}).
		Watches(
			&rbacv1.RoleBinding{},
			handler.EnqueueRequestsFromMapFunc(r.findSessionForBinding),
		).
		Watches(
			&accessv1alpha1.AccessProfile{},
			handler.EnqueueRequestsFromMapFunc(r.findSessionsForAccessProfile),
		).
		Named("breakglasssession").
		Complete(r)
}

func (r *BreakGlassSessionReconciler) findSessionsForAccessProfile(ctx context.Context, obj client.Object) []ctrl.Request {
	profile, ok := obj.(*accessv1alpha1.AccessProfile)
	if !ok || profile.Name == "" {
		return nil
	}

	sessions := &accessv1alpha1.BreakGlassSessionList{}
	if err := r.List(ctx, sessions); err != nil {
		return nil
	}
	requests := make([]ctrl.Request, 0)
	for i := range sessions.Items {
		session := &sessions.Items[i]
		if session.Spec.AccessProfile == profile.Name {
			requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(session)})
		}
	}
	return requests
}
