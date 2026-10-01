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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

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
	// CuratedRoleCondition records whether the role rules and identity match the
	// immutable snapshot taken before the binding was created.
	CuratedRoleCondition = "CuratedRoleValid"
	// RequestSourceCondition records whether a session created for the approval
	// workflow still has its exact, independently verifiable request source.
	// It is intentionally separate from binding integrity: a valid binding must
	// still be removed when the request, decision, or their UID linkage fails.
	RequestSourceCondition = "RequestSourceValid"

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

	requestSourceSessionUIDMismatch = "session_uid_mismatch"

	// accessProfileField indexes sessions by their immutable profile reference.
	// It keeps profile-policy changes proportional to the affected sessions,
	// rather than scanning every BreakGlassSession in the cluster.
	accessProfileField = ".spec.accessProfile"
	// requestSourceField indexes approval-workflow sessions by the name of the
	// immutable request they cite. The request UID is verified after retrieval;
	// the name is only a cache index and never an authorization decision.
	requestSourceField = ".spec.requestRef.name"

	clusterRoleKind = "ClusterRole"
	roleBindingKind = "RoleBinding"

	bindingIssueMissing           = "missing"
	bindingIssueUIDMismatch       = "uid_mismatch"
	bindingIssueReference         = "binding_reference"
	bindingReferenceInvalidReason = "BindingReferenceInvalid"
	bindingMissingReason          = "BindingMissing"
	bindingUIDMismatchReason      = "BindingUIDMismatch"
	bindingMissingMessage         = "the emergency access binding no longer exists"
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
// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglassrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglassapprovals,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,resourceNames=breakglass-pod-observer,verbs=get;bind
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
				r.recordCleanupIntegrityIssue(cleanup, session)
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
		// Do not depend on the metadata-only finalizer update being observed by
		// the workqueue. A freshly accepted request must always proceed to its
		// policy resolution and bounded activation path.
		return ctrl.Result{RequeueAfter: time.Nanosecond}, nil
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

	// Sessions from the approval workflow must continuously prove their source,
	// not merely pass admission at creation time. This catches a request or its
	// decision being deleted/recreated while the session is waiting to activate
	// or already active. Direct self-service sessions have no request source.
	if session.Spec.RequestRef != nil {
		sourceIssue, err := r.verifyRequestSource(ctx, session)
		if err != nil {
			return ctrl.Result{}, err
		}
		if sourceIssue != nil {
			return r.suspendForRequestSource(ctx, session, sourceIssue)
		}
	}

	// Activation deliberately has two durable steps. A Reserved binding has the
	// approved RoleRef but no subjects and therefore grants no access; its UID,
	// grant snapshot, and expiry are persisted before the subject is added.
	// This prevents a create-before-status failure from leaving an untracked,
	// authorizing RoleBinding behind.
	if session.Status.Phase == accessv1alpha1.PhasePending && session.Status.BindingRef != nil {
		return r.reconcileReservedSession(ctx, session)
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
		// A prior reconciliation can have created the deterministic binding and
		// then lost its status write. Resolve errors must therefore run the same
		// strict cleanup recovery as every other terminal path before recording
		// denial; otherwise a deleted/replaced profile could strand live access.
		cleanup, cleanupErr := r.cleanupBindingWithResult(ctx, session)
		if cleanupErr != nil {
			return ctrl.Result{}, cleanupErr
		}
		log.Error(err, "BreakGlassSession could not be activated", "session", session.Name)
		session.Status.Phase = accessv1alpha1.PhaseDenied
		r.setAccessGrantedCondition(session, metav1.ConditionFalse, "InvalidSpec", err.Error())
		if cleanup.Deleted || cleanup.IntegrityIssue != nil {
			r.setCleanupIntegrityCondition(session, cleanup)
		}
		if r.Recorder != nil {
			r.Recorder.Eventf(session, corev1.EventTypeWarning, "AccessDenied",
				"Emergency access request was denied: %v", err)
			if cleanup.IntegrityIssue != nil {
				r.Recorder.Eventf(session, corev1.EventTypeWarning, "BindingIntegrityLost", "Emergency access binding could not be safely removed: %s", cleanup.IntegrityIssue.Code)
			}
		}
		if statusErr := r.Status().Update(ctx, session); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		r.recordTransition(breakglassmetrics.TransitionDenied, session)
		r.recordCleanupIntegrityIssue(cleanup, session)
		return ctrl.Result{}, nil
	}
	session.Status.Grant = grant

	// First reserve a non-authorizing binding and persist its server-assigned
	// UID. The subject is added only by reconcileReservedSession after this
	// status checkpoint succeeds.
	bindingRef, err := r.ensureReservedBindingReference(ctx, session)
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
	session.Status.Phase = accessv1alpha1.PhasePending
	r.setAccessGrantedCondition(session, metav1.ConditionFalse, "BindingReserved", "Emergency access binding is reserved but not yet active")
	r.setBindingIntegrityCondition(session, metav1.ConditionTrue, "BindingReserved", "The non-authorizing emergency access binding identity was recorded")
	r.setAccessProfileCondition(session, metav1.ConditionTrue, "AccessProfileVerified", "The immutable AccessProfile snapshot was verified")
	r.setCuratedRoleCondition(session, metav1.ConditionTrue, "CuratedRoleVerified", "The curated ClusterRole identity and rules were verified")
	if session.Spec.RequestRef != nil {
		r.setRequestSourceCondition(session, metav1.ConditionTrue, "RequestSourceVerified", "The approved request source and immutable decision were verified")
	}

	if err := r.Status().Update(ctx, session); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: time.Nanosecond}, nil
}

func (r *BreakGlassSessionReconciler) reconcileReservedSession(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (ctrl.Result, error) {
	if session.Status.Grant == nil || session.Status.ExpiresAt == nil {
		return r.suspendForIntegrity(ctx, session, &bindingIntegrityIssue{
			Code:            bindingIssueReference,
			ConditionReason: bindingReferenceInvalidReason,
			Message:         "reserved session has no complete grant snapshot or expiry",
		})
	}
	if !time.Now().Before(session.Status.ExpiresAt.Time) {
		return r.expireSession(ctx, session)
	}
	profileIssue, err := r.verifyAccessProfile(ctx, session)
	if err != nil {
		return ctrl.Result{}, err
	}
	if profileIssue != nil {
		return r.suspendForProfile(ctx, session, profileIssue)
	}
	roleIssue, err := r.verifyCuratedRole(ctx, session)
	if err != nil {
		return ctrl.Result{}, err
	}
	if roleIssue != nil {
		return r.suspendForCuratedRole(ctx, session, roleIssue)
	}

	binding, granted, issue, err := r.bindingForReservedActivation(ctx, session)
	if err != nil {
		return ctrl.Result{}, err
	}
	if issue != nil {
		return r.suspendForIntegrity(ctx, session, issue)
	}
	if !granted {
		binding.Subjects = []rbacv1.Subject{expectedSubject(session)}
		if err := r.Update(ctx, binding); err != nil {
			return ctrl.Result{}, err
		}
	}

	session.Status.Phase = accessv1alpha1.PhaseActive
	r.setAccessGrantedCondition(session, metav1.ConditionTrue, "AccessGranted", "Emergency access binding is active")
	r.setBindingIntegrityCondition(session, metav1.ConditionTrue, "BindingVerified", "The emergency access binding identity and content were verified")
	if err := r.Status().Update(ctx, session); err != nil {
		return ctrl.Result{}, err
	}
	r.recordTransition(breakglassmetrics.TransitionActivated, session)

	targetDesc := fmt.Sprintf("namespace %q", session.Status.Grant.TargetNamespace)
	if r.Recorder != nil {
		r.Recorder.Eventf(session, corev1.EventTypeNormal, "AccessGranted",
			"Granted %s %q access on %s to %s %q until %s",
			session.Status.Grant.RoleRef.Kind, session.Status.Grant.RoleRef.Name, targetDesc,
			session.Spec.Subject.Kind, session.Spec.Subject.Name,
			session.Status.ExpiresAt.Format(time.RFC3339))
	}
	return ctrl.Result{RequeueAfter: r.activeRequeueAfter(session.Status.ExpiresAt.Time)}, nil
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
	roleIssue, err := r.verifyCuratedRole(ctx, session)
	if err != nil {
		return ctrl.Result{}, err
	}
	if roleIssue != nil {
		return r.suspendForCuratedRole(ctx, session, roleIssue)
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
	r.recordCleanupIntegrityIssue(cleanup, session)
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
	r.recordCleanupIntegrityIssue(cleanup, session)
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

// recordCleanupIntegrityIssue keeps terminal cleanup incidents visible even
// when the session ends as Revoked or Expired rather than Suspended.
func (r *BreakGlassSessionReconciler) recordCleanupIntegrityIssue(cleanup bindingCleanupResult, session *accessv1alpha1.BreakGlassSession) {
	if cleanup.IntegrityIssue != nil {
		r.recordBindingDrift(cleanup.IntegrityIssue, session)
	}
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

// requestSourceIssue describes a semantic failure in the approval-workflow
// provenance of a session. It deliberately contains no object names, users,
// or incident reasons so it can be converted to a bounded metric reason.
type requestSourceIssue struct {
	Code            string
	ConditionReason string
	Message         string
}

// verifyRequestSource re-checks every persisted link in the approval path
// using direct API reads. It is required before a request-sourced session can
// first create a binding and on every later active integrity check.
//
// A request's deadline is a decision deadline, not an active-session TTL. It
// is enforced until the session is active; otherwise a manager outage could
// turn an expired request into a late grant. Once active, the session's own
// immutable expiry remains the authority for the temporary RoleBinding.
func (r *BreakGlassSessionReconciler) verifyRequestSource(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (*requestSourceIssue, error) {
	request, issue, err := r.requestForSessionSource(ctx, session)
	if err != nil || issue != nil {
		return issue, err
	}
	if issue := validateRequestSessionReservation(request, session); issue != nil {
		return issue, nil
	}
	if issue := validateRequestDecisionDeadline(request, session); issue != nil {
		return issue, nil
	}
	return r.verifyRequestApproval(ctx, request)
}

func (r *BreakGlassSessionReconciler) requestForSessionSource(
	ctx context.Context,
	session *accessv1alpha1.BreakGlassSession,
) (*accessv1alpha1.BreakGlassRequest, *requestSourceIssue, error) {
	ref := session.Spec.RequestRef
	if ref == nil || ref.Name == "" || ref.UID == "" {
		return nil, &requestSourceIssue{
			Code:            "request_reference",
			ConditionReason: "RequestReferenceInvalid",
			Message:         "the approval-workflow session has no complete immutable request reference",
		}, nil
	}

	request := &accessv1alpha1.BreakGlassRequest{}
	if err := r.policyReader().Get(ctx, client.ObjectKey{Name: ref.Name}, request); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, &requestSourceIssue{
				Code:            "request_missing",
				ConditionReason: "RequestMissing",
				Message:         "the approved source request no longer exists",
			}, nil
		}
		return nil, nil, err
	}
	if string(request.UID) != ref.UID {
		return nil, &requestSourceIssue{
			Code:            "request_uid_mismatch",
			ConditionReason: "RequestUIDMismatch",
			Message:         "a different request object now uses the recorded source request name",
		}, nil
	}
	if request.Spec.AccessProfile != session.Spec.AccessProfile ||
		request.Spec.AccessProfileUID != session.Spec.AccessProfileUID ||
		request.Spec.Requester != session.Spec.Subject ||
		request.Spec.Duration != session.Spec.Duration ||
		request.Spec.Reason != session.Spec.Reason {
		return nil, &requestSourceIssue{
			Code:            "request_content_mismatch",
			ConditionReason: "RequestContentMismatch",
			Message:         "the session fields differ from the immutable approved request",
		}, nil
	}
	return request, nil, nil
}

func validateRequestSessionReservation(
	request *accessv1alpha1.BreakGlassRequest,
	session *accessv1alpha1.BreakGlassSession,
) *requestSourceIssue {
	if request.Status.SessionRef == nil || request.Status.SessionRef.Name != session.Name {
		return &requestSourceIssue{
			Code:            "session_reservation_mismatch",
			ConditionReason: "SessionReservationMismatch",
			Message:         "the source request does not reserve this session name",
		}
	}
	switch request.Status.Phase {
	case accessv1alpha1.RequestPhaseProvisioning:
		// Creation and the subsequent request-status write are separate API
		// operations. During that short recovery-safe window the reservation may
		// not yet contain the server-assigned session UID.
		if request.Status.SessionRef.UID != "" && request.Status.SessionRef.UID != string(session.UID) {
			return &requestSourceIssue{
				Code:            requestSourceSessionUIDMismatch,
				ConditionReason: "SessionUIDMismatch",
				Message:         "the request reservation cites a different session object",
			}
		}
	case accessv1alpha1.RequestPhaseSessionCreated:
		if request.Status.SessionRef.UID == "" || request.Status.SessionRef.UID != string(session.UID) {
			return &requestSourceIssue{
				Code:            requestSourceSessionUIDMismatch,
				ConditionReason: "SessionUIDMismatch",
				Message:         "the source request does not cite this server-assigned session UID",
			}
		}
	default:
		return &requestSourceIssue{
			Code:            "request_phase",
			ConditionReason: "RequestNotProvisioned",
			Message:         "the source request is not in a session-provisioned lifecycle phase",
		}
	}
	return nil
}

func validateRequestDecisionDeadline(
	request *accessv1alpha1.BreakGlassRequest,
	session *accessv1alpha1.BreakGlassSession,
) *requestSourceIssue {
	requestTTL, err := time.ParseDuration(request.Spec.RequestTTL)
	if err != nil || requestTTL <= 0 {
		return &requestSourceIssue{
			Code:            "request_ttl_invalid",
			ConditionReason: "RequestTTLInvalid",
			Message:         "the immutable source request has no valid positive request TTL",
		}
	}
	if session.Status.ExpiresAt == nil && !time.Now().Before(request.CreationTimestamp.Add(requestTTL)) {
		return &requestSourceIssue{
			Code:            "request_expired",
			ConditionReason: "RequestExpired",
			Message:         "the source request expired before this session became active",
		}
	}
	return nil
}

func (r *BreakGlassSessionReconciler) verifyRequestApproval(
	ctx context.Context,
	request *accessv1alpha1.BreakGlassRequest,
) (*requestSourceIssue, error) {
	approvalRef := request.Status.ApprovalRef
	if approvalRef == nil || approvalRef.Name != accessv1alpha1.ApprovalNameForRequestUID(string(request.UID)) || approvalRef.UID == "" {
		return &requestSourceIssue{
			Code:            "approval_reference",
			ConditionReason: "ApprovalReferenceInvalid",
			Message:         "the source request has no complete deterministic approval reference",
		}, nil
	}
	approval := &accessv1alpha1.BreakGlassApproval{}
	if err := r.policyReader().Get(ctx, client.ObjectKey{Name: approvalRef.Name}, approval); err != nil {
		if apierrors.IsNotFound(err) {
			return &requestSourceIssue{
				Code:            "approval_missing",
				ConditionReason: "ApprovalMissing",
				Message:         "the source request approval no longer exists",
			}, nil
		}
		return nil, err
	}
	if string(approval.UID) != approvalRef.UID {
		return &requestSourceIssue{
			Code:            "approval_uid_mismatch",
			ConditionReason: "ApprovalUIDMismatch",
			Message:         "a different approval object now uses the recorded decision name",
		}, nil
	}
	if approval.Spec.RequestRef.Name != request.Name || approval.Spec.RequestRef.UID != string(request.UID) ||
		approval.Spec.Decision != accessv1alpha1.ApprovalDecisionApproved ||
		approval.Spec.Approver.Kind != accessv1alpha1.SubjectKindUser ||
		approval.Spec.Approver.Name == "" || approval.Spec.Approver.Name == request.Spec.Requester.Name {
		return &requestSourceIssue{
			Code:            "approval_invalid",
			ConditionReason: "ApprovalInvalid",
			Message:         "the source request approval is not an independent approved decision",
		}, nil
	}
	return nil, nil
}

func (r *BreakGlassSessionReconciler) suspendForRequestSource(ctx context.Context, session *accessv1alpha1.BreakGlassSession, issue *requestSourceIssue) (ctrl.Result, error) {
	cleanup, err := r.cleanupBindingWithResult(ctx, session)
	if err != nil {
		return ctrl.Result{}, err
	}
	if issue == nil {
		issue = &requestSourceIssue{Code: "source_unknown", ConditionReason: "RequestSourceUnknown", Message: "the approval-workflow session source could not be verified"}
	}

	session.Status.Phase = accessv1alpha1.PhaseSuspended
	r.setAccessGrantedCondition(session, metav1.ConditionFalse, "RequestSourceInvalid", "Emergency access was suspended because its approval-workflow source failed verification")
	r.setRequestSourceCondition(session, metav1.ConditionFalse, issue.ConditionReason, issue.Message)
	r.setCleanupIntegrityCondition(session, cleanup)
	if r.Recorder != nil {
		r.Recorder.Eventf(session, corev1.EventTypeWarning, "RequestSourceInvalid", "Emergency access suspended because its approval-workflow source failed verification: %s", issue.Code)
	}
	if err := r.Status().Update(ctx, session); err != nil {
		return ctrl.Result{}, err
	}
	r.recordTransition(breakglassmetrics.TransitionSuspended, session)
	r.recordRequestSourceIntegrity(issue, session)
	r.recordCleanupIntegrityIssue(cleanup, session)
	return ctrl.Result{}, nil
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
	if session.Spec.RequestRef == nil && profile.Spec.EffectiveDeliveryMode() != accessv1alpha1.AccessDeliveryModeSelfService {
		return nil, 0, denyRequest(fmt.Errorf("AccessProfile %q requires the approval workflow", profile.Name))
	}
	if session.Spec.RequestRef != nil && profile.Spec.EffectiveDeliveryMode() != accessv1alpha1.AccessDeliveryModeApprovalRequired {
		return nil, 0, denyRequest(fmt.Errorf("AccessProfile %q does not authorize a controller-sourced approval workflow session", profile.Name))
	}
	if duration > maxDuration {
		return nil, 0, denyRequest(fmt.Errorf("duration %s exceeds AccessProfile maximum of %s", duration, maxDuration))
	}
	if !r.targetNamespaceAllowed(profile.Spec.TargetNamespace) {
		return nil, 0, denyRequest(fmt.Errorf("AccessProfile %q targets namespace %q outside this manager's allowed namespace set", profile.Name, profile.Spec.TargetNamespace))
	}

	role := &rbacv1.ClusterRole{}
	if err := r.policyReader().Get(ctx, client.ObjectKey{Name: profile.Spec.RoleRef.Name}, role); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, 0, denyRequest(fmt.Errorf("curated ClusterRole %q does not exist", profile.Spec.RoleRef.Name))
		}
		return nil, 0, err
	}
	if role.UID == "" {
		return nil, 0, denyRequest(fmt.Errorf("curated ClusterRole %q has no server-assigned UID", role.Name))
	}

	return &accessv1alpha1.ResolvedAccess{
		AccessProfile:    profile.Name,
		AccessProfileUID: string(profile.UID),
		RoleRef:          profile.Spec.RoleRef,
		RoleUID:          string(role.UID),
		RoleRulesHash:    curatedRoleRulesHash(role.Rules),
		TargetNamespace:  profile.Spec.TargetNamespace,
	}, duration, nil
}

func validateAccessProfile(profile *accessv1alpha1.AccessProfile) (time.Duration, error) {
	if profile.Spec.RoleRef.Kind != clusterRoleKind || profile.Spec.RoleRef.Name == "" {
		return 0, fmt.Errorf("AccessProfile %q must reference a curated ClusterRole", profile.Name)
	}
	if profile.Spec.TargetNamespace == "" {
		return 0, fmt.Errorf("AccessProfile %q must specify a targetNamespace", profile.Name)
	}
	maxDuration, err := time.ParseDuration(profile.Spec.MaxDuration)
	if err != nil || maxDuration <= 0 {
		return 0, fmt.Errorf("AccessProfile %q has an invalid positive maxDuration", profile.Name)
	}
	if mode := profile.Spec.EffectiveDeliveryMode(); mode != accessv1alpha1.AccessDeliveryModeSelfService && mode != accessv1alpha1.AccessDeliveryModeApprovalRequired {
		return 0, fmt.Errorf("AccessProfile %q has an unsupported delivery mode", profile.Name)
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

func (r *BreakGlassSessionReconciler) setCuratedRoleCondition(
	session *accessv1alpha1.BreakGlassSession,
	status metav1.ConditionStatus,
	reason, message string,
) {
	meta.SetStatusCondition(&session.Status.Conditions, metav1.Condition{
		Type:               CuratedRoleCondition,
		Status:             status,
		ObservedGeneration: session.Generation,
		Reason:             reason,
		Message:            message,
	})
}

func (r *BreakGlassSessionReconciler) setRequestSourceCondition(
	session *accessv1alpha1.BreakGlassSession,
	status metav1.ConditionStatus,
	reason, message string,
) {
	meta.SetStatusCondition(&session.Status.Conditions, metav1.Condition{
		Type:               RequestSourceCondition,
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

type curatedRoleIssue struct {
	ConditionReason string
	Message         string
}

// verifyCuratedRole uses a direct API read on every active integrity check.
// It deliberately avoids a broad ClusterRole watch/list permission: role names
// are profile-controlled and should remain explicitly enumerated in manager RBAC.
func (r *BreakGlassSessionReconciler) verifyCuratedRole(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (*curatedRoleIssue, error) {
	grant := session.Status.Grant
	if grant == nil || grant.RoleRef.Kind != clusterRoleKind || grant.RoleRef.Name == "" || grant.RoleUID == "" || grant.RoleRulesHash == "" {
		return &curatedRoleIssue{ConditionReason: "CuratedRoleSnapshotMissing", Message: "the active session has no complete curated ClusterRole integrity snapshot"}, nil
	}

	role := &rbacv1.ClusterRole{}
	if err := r.policyReader().Get(ctx, client.ObjectKey{Name: grant.RoleRef.Name}, role); err != nil {
		if apierrors.IsNotFound(err) {
			return &curatedRoleIssue{ConditionReason: "CuratedRoleMissing", Message: "the curated ClusterRole no longer exists"}, nil
		}
		return nil, err
	}
	if string(role.UID) != grant.RoleUID {
		return &curatedRoleIssue{ConditionReason: "CuratedRoleUIDMismatch", Message: "a different curated ClusterRole object now uses the recorded role name"}, nil
	}
	if curatedRoleRulesHash(role.Rules) != grant.RoleRulesHash {
		return &curatedRoleIssue{ConditionReason: "CuratedRoleRulesDrift", Message: "the curated ClusterRole rules differ from the approved session snapshot"}, nil
	}
	return nil, nil
}

func (r *BreakGlassSessionReconciler) suspendForCuratedRole(ctx context.Context, session *accessv1alpha1.BreakGlassSession, issue *curatedRoleIssue) (ctrl.Result, error) {
	cleanup, err := r.cleanupBindingWithResult(ctx, session)
	if err != nil {
		return ctrl.Result{}, err
	}
	if issue == nil {
		issue = &curatedRoleIssue{ConditionReason: "CuratedRoleUnknown", Message: "the curated ClusterRole could not be verified"}
	}

	session.Status.Phase = accessv1alpha1.PhaseSuspended
	r.setAccessGrantedCondition(session, metav1.ConditionFalse, "CuratedRoleInvalid", "Emergency access was suspended because its curated ClusterRole failed integrity verification")
	r.setCuratedRoleCondition(session, metav1.ConditionFalse, issue.ConditionReason, issue.Message)
	r.setCleanupIntegrityCondition(session, cleanup)
	if r.Recorder != nil {
		r.Recorder.Eventf(session, corev1.EventTypeWarning, "CuratedRoleInvalid", "Emergency access suspended because its curated ClusterRole failed integrity verification: %s", issue.ConditionReason)
	}
	if err := r.Status().Update(ctx, session); err != nil {
		return ctrl.Result{}, err
	}
	r.recordTransition(breakglassmetrics.TransitionSuspended, session)
	r.recordCuratedRoleDrift(issue, session)
	r.recordCleanupIntegrityIssue(cleanup, session)
	return ctrl.Result{}, nil
}

func (r *BreakGlassSessionReconciler) recordCuratedRoleDrift(issue *curatedRoleIssue, session *accessv1alpha1.BreakGlassSession) {
	if r.Metrics == nil || issue == nil {
		return
	}
	var reason breakglassmetrics.CuratedRoleDriftReason
	switch issue.ConditionReason {
	case "CuratedRoleMissing":
		reason = breakglassmetrics.CuratedRoleMissing
	case "CuratedRoleUIDMismatch":
		reason = breakglassmetrics.CuratedRoleUIDMismatch
	case "CuratedRoleRulesDrift":
		reason = breakglassmetrics.CuratedRoleRulesHash
	case "CuratedRoleSnapshotMissing":
		reason = breakglassmetrics.CuratedRoleSnapshotMissing
	default:
		reason = breakglassmetrics.CuratedRoleUnknown
	}
	r.Metrics.RecordCuratedRoleDrift(reason, SessionScope(session))
}

func (r *BreakGlassSessionReconciler) recordRequestSourceIntegrity(issue *requestSourceIssue, session *accessv1alpha1.BreakGlassSession) {
	if r.Metrics == nil || issue == nil {
		return
	}
	var reason breakglassmetrics.RequestSourceIntegrityReason
	switch issue.Code {
	case "request_reference":
		reason = breakglassmetrics.RequestSourceReference
	case "request_missing":
		reason = breakglassmetrics.RequestSourceMissing
	case "request_uid_mismatch":
		reason = breakglassmetrics.RequestSourceUIDMismatch
	case "request_content_mismatch":
		reason = breakglassmetrics.RequestSourceContentMismatch
	case "session_reservation_mismatch":
		reason = breakglassmetrics.RequestSourceReservationMismatch
	case requestSourceSessionUIDMismatch:
		reason = breakglassmetrics.RequestSourceSessionUIDMismatch
	case "request_phase":
		reason = breakglassmetrics.RequestSourcePhase
	case "request_ttl_invalid":
		reason = breakglassmetrics.RequestSourceTTLInvalid
	case "request_expired":
		reason = breakglassmetrics.RequestSourceExpired
	case "approval_reference":
		reason = breakglassmetrics.RequestSourceApprovalReference
	case "approval_missing":
		reason = breakglassmetrics.RequestSourceApprovalMissing
	case "approval_uid_mismatch":
		reason = breakglassmetrics.RequestSourceApprovalUIDMismatch
	case "approval_invalid":
		reason = breakglassmetrics.RequestSourceApprovalInvalid
	default:
		reason = breakglassmetrics.RequestSourceUnknown
	}
	r.Metrics.RecordRequestSourceIntegrity(reason, SessionScope(session))
}

func curatedRoleRulesHash(rules []rbacv1.PolicyRule) string {
	canonicalRules := make([]rbacv1.PolicyRule, len(rules))
	for i, rule := range rules {
		canonicalRules[i] = rule
		slices.Sort(canonicalRules[i].APIGroups)
		slices.Sort(canonicalRules[i].Resources)
		slices.Sort(canonicalRules[i].ResourceNames)
		slices.Sort(canonicalRules[i].Verbs)
		slices.Sort(canonicalRules[i].NonResourceURLs)
	}
	slices.SortFunc(canonicalRules, func(leftRule, rightRule rbacv1.PolicyRule) int {
		left, _ := json.Marshal(leftRule)
		right, _ := json.Marshal(rightRule)
		return strings.Compare(string(left), string(right))
	})
	payload, _ := json.Marshal(canonicalRules)
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
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
	if session.Spec.RequestRef == nil && profile.Spec.EffectiveDeliveryMode() != accessv1alpha1.AccessDeliveryModeSelfService {
		return &accessProfileIssue{ConditionReason: "AccessProfileDeliveryModeDrift", Message: "the profile no longer permits a direct self-service session"}, nil
	}
	if session.Spec.RequestRef != nil && profile.Spec.EffectiveDeliveryMode() != accessv1alpha1.AccessDeliveryModeApprovalRequired {
		return &accessProfileIssue{ConditionReason: "AccessProfileDeliveryModeDrift", Message: "the profile no longer permits an approval-workflow session"}, nil
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
	r.recordCleanupIntegrityIssue(cleanup, session)
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
	case bindingIssueMissing:
		reason = breakglassmetrics.DriftMissing
	case "ownership":
		reason = breakglassmetrics.DriftOwnership
	case bindingIssueUIDMismatch:
		reason = breakglassmetrics.DriftUIDMismatch
	case "role_ref":
		reason = breakglassmetrics.DriftRoleRef
	case "subjects":
		reason = breakglassmetrics.DriftSubjects
	case bindingIssueReference:
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

// ensureReservedBindingReference creates a binding with no subjects. It is a
// durable, non-authorizing reservation: the caller must first persist its UID
// in Session status before reconcileReservedSession can add the user subject.
func (r *BreakGlassSessionReconciler) ensureReservedBindingReference(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (*accessv1alpha1.BindingReference, error) {
	expected := expectedBindingReference(session)
	if expected.Namespace == "" || session.Status.Grant == nil {
		return nil, fmt.Errorf("cannot reserve a binding without a resolved namespaced AccessProfile grant")
	}
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      expected.Name,
			Namespace: expected.Namespace,
			Labels:    managedBindingLabels(session),
		},
		RoleRef: expectedRoleRef(session),
	}
	if err := controllerutil.SetControllerReference(session, binding, r.Scheme); err != nil {
		return nil, err
	}
	if err := r.Create(ctx, binding); err == nil {
		r.recordBindingOperation(breakglassmetrics.BindingOperationGrant, breakglassmetrics.BindingOperationSuccess, session)
		return bindingReferenceFromObject(binding)
	} else if !apierrors.IsAlreadyExists(err) {
		r.recordBindingOperation(breakglassmetrics.BindingOperationGrant, breakglassmetrics.BindingOperationError, session)
		return nil, err
	}

	existing := &rbacv1.RoleBinding{}
	if err := r.Get(ctx, client.ObjectKey{Name: expected.Name, Namespace: expected.Namespace}, existing); err != nil {
		r.recordBindingOperation(breakglassmetrics.BindingOperationGrant, breakglassmetrics.BindingOperationError, session)
		return nil, err
	}
	if issue := bindingMatchesReservation(session, existing); issue != nil {
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
	return &accessv1alpha1.BindingReference{Kind: roleBindingKind, Name: bindingName, Namespace: targetNamespace}
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
	return isRoleBinding && ref.Kind == roleBindingKind
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
	ref.Kind = roleBindingKind
	return ref, nil
}

func expectedSubject(session *accessv1alpha1.BreakGlassSession) rbacv1.Subject {
	return rbacv1.Subject{
		// Kubernetes defaults a User subject's API group to
		// rbac.authorization.k8s.io when it persists a RoleBinding. Record the
		// canonical value here as well, so integrity checks do not mistake that
		// server-side defaulting for subject drift.
		APIGroup: rbacv1.GroupName,
		Kind:     string(session.Spec.Subject.Kind),
		Name:     session.Spec.Subject.Name,
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
	if issue := bindingMatchesExpectedMetadata(session, obj); issue != nil {
		return issue
	}
	binding := obj.(*rbacv1.RoleBinding)
	if !equality.Semantic.DeepEqual(binding.Subjects, []rbacv1.Subject{expectedSubject(session)}) {
		return &bindingIntegrityIssue{Code: "subjects", ConditionReason: "BindingSubjectsDrift", Message: "the RBAC binding subjects differ from the approved session"}
	}
	return nil
}

func bindingMatchesReservation(session *accessv1alpha1.BreakGlassSession, obj client.Object) *bindingIntegrityIssue {
	if issue := bindingMatchesExpectedMetadata(session, obj); issue != nil {
		return issue
	}
	binding := obj.(*rbacv1.RoleBinding)
	if len(binding.Subjects) != 0 {
		return &bindingIntegrityIssue{Code: "subjects", ConditionReason: "BindingSubjectsDrift", Message: "the reserved RBAC binding unexpectedly has subjects"}
	}
	return nil
}

func bindingMatchesExpectedMetadata(session *accessv1alpha1.BreakGlassSession, obj client.Object) *bindingIntegrityIssue {
	if !bindingReferenceMatchesObjectLocation(expectedBindingReference(session), obj) {
		return &bindingIntegrityIssue{
			Code:            bindingIssueReference,
			ConditionReason: bindingReferenceInvalidReason,
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

	binding, ok := obj.(*rbacv1.RoleBinding)
	if !ok {
		return &bindingIntegrityIssue{Code: bindingIssueReference, ConditionReason: bindingReferenceInvalidReason, Message: "the referenced object is not an RBAC binding"}
	}
	if !equality.Semantic.DeepEqual(binding.RoleRef, expectedRoleRef(session)) {
		return &bindingIntegrityIssue{Code: "role_ref", ConditionReason: "BindingRoleRefDrift", Message: "the RBAC binding role reference differs from the approved session"}
	}
	return nil
}

// bindingForReservedActivation verifies the recorded UID before allowing the
// one-way transition from an empty-subject reservation to an active grant. If
// a write succeeded but its status update failed, the expected subject already
// present is accepted so the controller can persist Active without recreating
// or mutating a replacement object.
func (r *BreakGlassSessionReconciler) bindingForReservedActivation(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (*rbacv1.RoleBinding, bool, *bindingIntegrityIssue, error) {
	bindingRef := session.Status.BindingRef
	if bindingRef == nil || bindingRef.UID == "" || !bindingReferenceMatchesSession(bindingRef, session) {
		return nil, false, &bindingIntegrityIssue{Code: bindingIssueReference, ConditionReason: bindingReferenceInvalidReason, Message: "the recorded reserved binding identity is invalid"}, nil
	}
	binding := &rbacv1.RoleBinding{}
	if err := r.Get(ctx, client.ObjectKey{Name: bindingRef.Name, Namespace: bindingRef.Namespace}, binding); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, &bindingIntegrityIssue{Code: bindingIssueMissing, ConditionReason: bindingMissingReason, Message: bindingMissingMessage}, nil
		}
		return nil, false, nil, err
	}
	if string(binding.UID) != bindingRef.UID {
		return nil, false, &bindingIntegrityIssue{Code: bindingIssueUIDMismatch, ConditionReason: bindingUIDMismatchReason, Message: "a different RBAC binding object now uses the recorded binding name"}, nil
	}
	reservationIssue := bindingMatchesReservation(session, binding)
	if reservationIssue == nil {
		return binding, false, nil, nil
	}
	if issue := bindingMatchesExpected(session, binding); issue == nil {
		return binding, true, nil, nil
	}
	return nil, false, reservationIssue, nil
}

// discoverBindingReference supports one-way migration of sessions created by
// earlier releases. It never recreates or adopts an ambiguous object.
func (r *BreakGlassSessionReconciler) discoverBindingReference(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (*accessv1alpha1.BindingReference, *bindingIntegrityIssue, error) {
	expected := expectedBindingReference(session)
	obj, err := r.getBindingForReference(ctx, expected)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, &bindingIntegrityIssue{Code: bindingIssueMissing, ConditionReason: bindingMissingReason, Message: bindingMissingMessage}, nil
		}
		return nil, nil, err
	}
	if issue := bindingMatchesExpected(session, obj); issue != nil {
		return nil, issue, nil
	}
	bindingRef, err := bindingReferenceFromObject(obj)
	if err != nil {
		return nil, &bindingIntegrityIssue{Code: bindingIssueReference, ConditionReason: bindingReferenceInvalidReason, Message: "the emergency access binding has no server-assigned UID"}, nil
	}
	return bindingRef, nil, nil
}

func (r *BreakGlassSessionReconciler) verifyBindingIntegrity(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (*bindingIntegrityIssue, error) {
	bindingRef := session.Status.BindingRef
	if bindingRef == nil || bindingRef.UID == "" || !bindingReferenceMatchesSession(bindingRef, session) {
		return &bindingIntegrityIssue{Code: bindingIssueReference, ConditionReason: bindingReferenceInvalidReason, Message: "the recorded emergency access binding identity is invalid"}, nil
	}

	obj, err := r.getBindingForReference(ctx, bindingRef)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return &bindingIntegrityIssue{Code: bindingIssueMissing, ConditionReason: bindingMissingReason, Message: bindingMissingMessage}, nil
		}
		return nil, err
	}
	if string(obj.GetUID()) != bindingRef.UID {
		return &bindingIntegrityIssue{Code: bindingIssueUIDMismatch, ConditionReason: bindingUIDMismatchReason, Message: "a different RBAC binding object now uses the recorded binding name"}, nil
	}
	return bindingMatchesExpected(session, obj), nil
}

func (r *BreakGlassSessionReconciler) getBindingForReference(ctx context.Context, ref *accessv1alpha1.BindingReference) (client.Object, error) {
	if ref == nil {
		return nil, fmt.Errorf("cannot get a nil RBAC binding reference")
	}
	if ref.Kind != roleBindingKind || ref.Namespace == "" {
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

// cleanupBindingWithResult deletes only a binding whose controller ownership is
// proven. Normally that proof is the UID recorded at reservation. The only
// unrecorded recovery permitted below is an empty-subject reservation, which
// cannot authorize access; a live binding is never recovered without its
// persisted UID.
func (r *BreakGlassSessionReconciler) cleanupBindingWithResult(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (bindingCleanupResult, error) {
	bindingRef := session.Status.BindingRef
	unrecordedBinding := false
	if bindingRef == nil {
		// Recover a narrow empty-subject reservation left by a failed status
		// checkpoint. This never adopts or deletes an authorizing binding without
		// a persisted UID, and it does not run for legacy status shapes.
		recoveredRef, issue, err := r.findUnrecordedBindingReference(ctx, session)
		if err != nil {
			return bindingCleanupResult{}, err
		}
		if issue != nil {
			return bindingCleanupResult{IntegrityIssue: issue}, nil
		}
		if recoveredRef != nil {
			bindingRef = recoveredRef
			unrecordedBinding = true
		}
	}

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
				Code:            bindingIssueReference,
				ConditionReason: bindingReferenceInvalidReason,
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

	if bindingRef.UID == "" || (!unrecordedBinding && !bindingReferenceMatchesSession(bindingRef, session)) {
		return bindingCleanupResult{IntegrityIssue: &bindingIntegrityIssue{
			Code:            bindingIssueReference,
			ConditionReason: bindingReferenceInvalidReason,
			Message:         "the recorded emergency access binding identity is invalid",
		}}, nil
	}

	obj, err := r.getBindingForReference(ctx, bindingRef)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return bindingCleanupResult{IntegrityIssue: &bindingIntegrityIssue{Code: bindingIssueMissing, ConditionReason: bindingMissingReason, Message: bindingMissingMessage}}, nil
		}
		return bindingCleanupResult{}, err
	}
	if string(obj.GetUID()) != bindingRef.UID {
		r.recordBindingOperation(breakglassmetrics.BindingOperationCleanup, breakglassmetrics.BindingOperationError, session)
		return bindingCleanupResult{IntegrityIssue: &bindingIntegrityIssue{Code: bindingIssueUIDMismatch, ConditionReason: bindingUIDMismatchReason, Message: "a different RBAC binding object now uses the recorded binding name"}}, nil
	}

	uid := types.UID(bindingRef.UID)
	if err := r.Delete(ctx, obj, client.Preconditions{UID: &uid}); err != nil {
		if apierrors.IsNotFound(err) {
			return bindingCleanupResult{IntegrityIssue: &bindingIntegrityIssue{Code: bindingIssueMissing, ConditionReason: bindingMissingReason, Message: bindingMissingMessage}}, nil
		}
		if apierrors.IsConflict(err) {
			r.recordBindingOperation(breakglassmetrics.BindingOperationCleanup, breakglassmetrics.BindingOperationError, session)
			return bindingCleanupResult{IntegrityIssue: &bindingIntegrityIssue{Code: bindingIssueUIDMismatch, ConditionReason: bindingUIDMismatchReason, Message: "the emergency access binding changed before it could be deleted"}}, nil
		}
		r.recordBindingOperation(breakglassmetrics.BindingOperationCleanup, breakglassmetrics.BindingOperationError, session)
		return bindingCleanupResult{}, err
	}
	r.recordBindingOperation(breakglassmetrics.BindingOperationCleanup, breakglassmetrics.BindingOperationSuccess, session)
	return bindingCleanupResult{Deleted: true}, nil
}

// findUnrecordedBindingReference discovers only an empty-subject reservation
// created by this controller in the create-before-status persistence window. A
// target namespace cannot be recovered from blank Session status, so a direct
// lookup is not possible: use the high-entropy Session UID label, then
// independently corroborate the deterministic name and controller owner
// reference. A namespaced production manager searches only its configured
// target namespaces, so this recovery never requires broader RoleBinding RBAC
// than the grant path itself.
//
// A result is intentionally not written back to status here. Callers use it
// only to perform immediate UID-precondition cleanup on a terminal path. A
// non-terminal reconciliation instead reaches ensureReservedBindingReference and
// persists the recovered reference after policy validation succeeds.
func (r *BreakGlassSessionReconciler) findUnrecordedBindingReference(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (*accessv1alpha1.BindingReference, *bindingIntegrityIssue, error) {
	if session.Status.BindingName != "" || session.Status.Grant != nil ||
		session.Status.StartTime != nil || session.Status.ExpiresAt != nil {
		return nil, nil, nil
	}
	var bindings []rbacv1.RoleBinding
	listBindings := func(options ...client.ListOption) error {
		list := &rbacv1.RoleBindingList{}
		options = append(options, client.MatchingLabels(managedBindingLabels(session)))
		if err := r.policyReader().List(ctx, list, options...); err != nil {
			return err
		}
		bindings = append(bindings, list.Items...)
		return nil
	}
	if len(r.AllowedTargetNamespaces) == 0 {
		if err := listBindings(); err != nil {
			return nil, nil, err
		}
	} else {
		for namespace := range r.AllowedTargetNamespaces {
			if err := listBindings(client.InNamespace(namespace)); err != nil {
				return nil, nil, err
			}
		}
	}

	expectedName := bindingNameForSession(session)
	var matching []*accessv1alpha1.BindingReference
	for i := range bindings {
		binding := &bindings[i]
		if binding.Name != expectedName || len(binding.Subjects) != 0 || !isManagedBindingForSession(binding, session) {
			continue
		}
		ref, err := bindingReferenceFromObject(binding)
		if err != nil {
			return nil, &bindingIntegrityIssue{
				Code:            bindingIssueReference,
				ConditionReason: bindingReferenceInvalidReason,
				Message:         "a managed emergency access binding has no server-assigned UID",
			}, nil
		}
		matching = append(matching, ref)
	}

	switch len(matching) {
	case 0:
		return nil, nil, nil
	case 1:
		return matching[0], nil, nil
	default:
		return nil, &bindingIntegrityIssue{
			Code:            bindingIssueReference,
			ConditionReason: bindingReferenceInvalidReason,
			Message:         "multiple managed RoleBindings match an unrecorded emergency access session",
		}, nil
	}
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
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &accessv1alpha1.BreakGlassSession{}, accessProfileField, accessProfileNameIndex); err != nil {
		return fmt.Errorf("index BreakGlassSessions by AccessProfile: %w", err)
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &accessv1alpha1.BreakGlassSession{}, requestSourceField, requestSourceNameIndex); err != nil {
		return fmt.Errorf("index BreakGlassSessions by request source: %w", err)
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

	sessions := &accessv1alpha1.BreakGlassSessionList{}
	if err := r.List(ctx, sessions, client.MatchingFields{accessProfileField: profile.Name}); err != nil {
		return nil
	}
	requests := make([]ctrl.Request, 0)
	for i := range sessions.Items {
		requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&sessions.Items[i])})
	}
	return requests
}

func (r *BreakGlassSessionReconciler) findSessionsForBreakGlassRequest(ctx context.Context, obj client.Object) []ctrl.Request {
	request, ok := obj.(*accessv1alpha1.BreakGlassRequest)
	if !ok || request.Name == "" {
		return nil
	}
	return r.sessionsForRequestSourceName(ctx, request.Name)
}

func (r *BreakGlassSessionReconciler) findSessionsForBreakGlassApproval(ctx context.Context, obj client.Object) []ctrl.Request {
	approval, ok := obj.(*accessv1alpha1.BreakGlassApproval)
	if !ok || approval.Spec.RequestRef.Name == "" {
		return nil
	}
	return r.sessionsForRequestSourceName(ctx, approval.Spec.RequestRef.Name)
}

func (r *BreakGlassSessionReconciler) sessionsForRequestSourceName(ctx context.Context, requestName string) []ctrl.Request {
	sessions := &accessv1alpha1.BreakGlassSessionList{}
	if err := r.List(ctx, sessions, client.MatchingFields{requestSourceField: requestName}); err != nil {
		return nil
	}
	requests := make([]ctrl.Request, 0, len(sessions.Items))
	for i := range sessions.Items {
		requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&sessions.Items[i])})
	}
	return requests
}
