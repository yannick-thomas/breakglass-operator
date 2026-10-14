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

// Package sessionlifecycle is the use case that turns an admitted
// BreakGlassSession into time-bounded access and takes it away again.
//
// A binding's server-assigned UID is persisted at activation and is the only
// proof that a later object may be inspected or deleted. Drift is fail-closed:
// the lifecycle suspends a session rather than recreating a missing or
// modified binding.
//
// The package depends on the domain and its own ports only. Kubernetes access
// is provided by adapters in internal/controller.
package sessionlifecycle

import (
	"context"
	"time"

	"github.com/go-logr/logr"

	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
)

// DefaultIntegrityCheckInterval bounds how long a missed binding watch event
// can leave an active session unchecked. It trades a modest periodic read for
// fail-closed detection of binding replacement or tampering.
const DefaultIntegrityCheckInterval = time.Minute

// immediately requeues right after a durable checkpoint, without depending on
// the watch delivering the controller's own write.
const immediately = time.Nanosecond

// Lifecycle reconciles sessions.
type Lifecycle struct {
	Policy   PolicySource
	Bindings BindingGateway
	// Telemetry is optional.
	Telemetry Telemetry
	// MaxSessionDuration is the manager-wide limit; zero disables it.
	MaxSessionDuration time.Duration
	// Scope restricts the namespaces in which access may be granted.
	Scope access.NamespaceScope
	// IntegrityCheckInterval overrides DefaultIntegrityCheckInterval when
	// positive.
	IntegrityCheckInterval time.Duration
	// Clock is optional; it defaults to time.Now.
	Clock func() time.Time
}

// Result tells the caller when to reconcile the session again. A zero value
// means "only on the next change".
type Result struct {
	RequeueAfter time.Duration
}

// run carries the per-reconciliation collaborators.
type run struct {
	*Lifecycle
	store  SessionStore
	events Events
	log    logr.Logger
}

// Reconcile advances one session by at most one durable step.
func (l *Lifecycle) Reconcile(ctx context.Context, s *access.Session, store SessionStore, events Events) (Result, error) {
	if events == nil {
		events = noEvents{}
	}
	r := &run{Lifecycle: l, store: store, events: events, log: logr.FromContextOrDiscard(ctx)}

	if s.Deleting {
		return r.finalize(ctx, s)
	}
	// The finalizer prevents an orphaned binding. Do not depend on the
	// metadata-only update being observed: requeue to continue right away.
	if !s.HasFinalizer {
		if err := store.AddFinalizer(ctx, s); err != nil {
			return Result{}, err
		}
		return Result{RequeueAfter: immediately}, nil
	}

	if s.Spec.Revoked {
		return r.revoke(ctx, s)
	}
	if s.Status.Phase.Terminal() {
		return Result{}, nil
	}

	// Approval-workflow sessions must continuously prove their source, not
	// merely pass admission at creation time. This catches a request or its
	// decision being deleted or recreated while the session waits or runs.
	if s.Spec.RequestRef != nil {
		issue, err := l.verifyRequestSource(ctx, s)
		if err != nil {
			return Result{}, err
		}
		if issue != nil {
			return r.suspendForRequestSource(ctx, s, issue)
		}
	}

	// Activation has two durable steps. A reserved binding has the approved
	// role but no subjects and grants nothing; its UID, the grant snapshot,
	// and the expiry are persisted before the subject is added. A failed
	// status write therefore never leaves an untracked authorizing binding.
	if s.Status.Phase == access.PhasePending && s.Status.BindingRef != nil {
		return r.promoteReservation(ctx, s)
	}
	if s.Status.ExpiresAt != nil {
		return r.reconcileActive(ctx, s)
	}
	// An active session without expiry cannot be bounded. Do not preserve it.
	if s.Status.Phase == access.PhaseActive {
		return r.suspendForBinding(ctx, s, access.MissingExpiry())
	}
	return r.activate(ctx, s)
}

func (r *run) finalize(ctx context.Context, s *access.Session) (Result, error) {
	if !s.HasFinalizer {
		return Result{}, nil
	}
	r.log.Info("Cleaning up RBAC bindings for deleted BreakGlassSession", "session", s.Name)
	cleanup, err := r.CleanupBinding(ctx, s)
	if err != nil {
		return Result{}, err
	}
	if cleanup.Issue != nil {
		// A replacement object is not ours to delete. Removing the finalizer
		// lets deletion complete while preserving that object for
		// investigation.
		r.log.Info("Could not safely delete untrusted RBAC binding during BreakGlassSession cleanup", "session", s.Name, "reason", cleanup.Issue.Code)
	}
	if err := r.store.RemoveFinalizer(ctx, s); err != nil {
		return Result{}, err
	}
	r.recordCleanupIssue(cleanup, s)
	return Result{}, nil
}

// activate resolves the immutable, administrator-owned profile and reserves a
// non-authorizing binding before any privileged RBAC object exists.
func (r *run) activate(ctx context.Context, s *access.Session) (Result, error) {
	grant, duration, err := r.ResolveGrant(ctx, s)
	if err != nil {
		if !IsDenied(err) {
			return Result{}, err
		}
		return r.deny(ctx, s, err)
	}
	s.Status.Grant = grant

	ref, err := r.ReserveBinding(ctx, s)
	if err != nil {
		if !IsBindingCollision(err) {
			return Result{}, err
		}
		const message = "The requested binding name is already in use by another object"
		now := r.now()
		s.Status.Phase = access.PhaseDenied
		s.SetCondition(access.ConditionAccessGranted, access.ConditionFalse, "BindingCollision", message, now)
		s.SetCondition(access.ConditionBindingIntegrity, access.ConditionFalse, "BindingCollision", message, now)
		r.events.Event(EventWarning, "AccessDenied", "Emergency access request was denied because its binding name is already in use")
		if err := r.store.UpdateStatus(ctx, s); err != nil {
			return Result{}, err
		}
		r.telemetry().Transition(TransitionDenied, s)
		return Result{}, nil
	}

	now := r.now()
	expiresAt := now.Add(duration)
	s.Status.BindingName = ref.Name
	s.Status.BindingRef = ref
	s.Status.StartTime = &now
	s.Status.ExpiresAt = &expiresAt
	s.Status.Phase = access.PhasePending
	s.SetCondition(access.ConditionAccessGranted, access.ConditionFalse, "BindingReserved", "Emergency access binding is reserved but not yet active", now)
	s.SetCondition(access.ConditionBindingIntegrity, access.ConditionTrue, "BindingReserved", "The non-authorizing emergency access binding identity was recorded", now)
	s.SetCondition(access.ConditionAccessProfileValid, access.ConditionTrue, "AccessProfileVerified", "The immutable AccessProfile snapshot was verified", now)
	s.SetCondition(access.ConditionCuratedRoleValid, access.ConditionTrue, "CuratedRoleVerified", "The curated ClusterRole identity and rules were verified", now)
	if s.Spec.RequestRef != nil {
		s.SetCondition(access.ConditionRequestSourceValid, access.ConditionTrue, "RequestSourceVerified", "The approved request source and immutable decision were verified", now)
	}
	if err := r.store.UpdateStatus(ctx, s); err != nil {
		return Result{}, err
	}
	return Result{RequeueAfter: immediately}, nil
}

// promoteReservation makes the one-way transition from a recorded,
// empty-subject reservation to an authorizing binding.
func (r *run) promoteReservation(ctx context.Context, s *access.Session) (Result, error) {
	if s.Status.Grant == nil || s.Status.ExpiresAt == nil {
		return r.suspendForBinding(ctx, s, access.BindingReferenceInvalid("reserved session has no complete grant snapshot or expiry"))
	}
	if s.Expired(r.now()) {
		return r.expire(ctx, s)
	}
	if issue, err := r.verifyProfile(ctx, s); err != nil || issue != nil {
		if err != nil {
			return Result{}, err
		}
		return r.suspendForProfile(ctx, s, issue)
	}
	if issue, err := r.VerifyCuratedRole(ctx, s); err != nil || issue != nil {
		if err != nil {
			return Result{}, err
		}
		return r.suspendForRole(ctx, s, issue)
	}

	binding, granted, issue, err := r.bindingForPromotion(ctx, s)
	if err != nil {
		return Result{}, err
	}
	if issue != nil {
		return r.suspendForBinding(ctx, s, issue)
	}
	if !granted {
		// Policy reads may have delayed promotion past the decision deadline.
		// Recheck provenance immediately before the authorizing write.
		if s.Spec.RequestRef != nil {
			issue, err := r.verifyRequestSource(ctx, s)
			if err != nil {
				return Result{}, err
			}
			if issue != nil {
				return r.suspendForRequestSource(ctx, s, issue)
			}
		}
		if err := r.Bindings.SetSubjects(ctx, binding, []access.BindingSubject{s.ExpectedSubject()}); err != nil {
			r.telemetry().BindingOperation(OperationGrant, false, s)
			return Result{}, err
		}
		r.telemetry().BindingOperation(OperationGrant, true, s)
	}

	now := r.now()
	s.Status.Phase = access.PhaseActive
	s.SetCondition(access.ConditionAccessGranted, access.ConditionTrue, "AccessGranted", "Emergency access binding is active", now)
	s.SetCondition(access.ConditionBindingIntegrity, access.ConditionTrue, "BindingVerified", "The emergency access binding identity and content were verified", now)
	if err := r.store.UpdateStatus(ctx, s); err != nil {
		return Result{}, err
	}
	r.telemetry().Transition(TransitionActivated, s)

	grant := s.Status.Grant
	r.events.Event(EventNormal, "AccessGranted", "Granted %s %q access on namespace %q to %s %q until %s",
		grant.RoleRef.Kind, grant.RoleRef.Name, grant.TargetNamespace,
		s.Spec.Subject.Kind, s.Spec.Subject.Name, s.Status.ExpiresAt.Format(time.RFC3339))
	return Result{RequeueAfter: r.RequeueAfter(*s.Status.ExpiresAt)}, nil
}

// reconcileActive re-verifies an active grant and expires it on time.
func (r *run) reconcileActive(ctx context.Context, s *access.Session) (Result, error) {
	// A profile snapshot is required for every secure session. Active grants
	// from the former free-form API are deliberately not migrated: that would
	// preserve a privilege decision never authorized through a profile.
	if s.Status.Grant == nil {
		return r.suspendForProfile(ctx, s, access.ProfileSnapshotMissing())
	}
	if issue, err := r.verifyProfile(ctx, s); err != nil || issue != nil {
		if err != nil {
			return Result{}, err
		}
		return r.suspendForProfile(ctx, s, issue)
	}
	if issue, err := r.VerifyCuratedRole(ctx, s); err != nil || issue != nil {
		if err != nil {
			return Result{}, err
		}
		return r.suspendForRole(ctx, s, issue)
	}

	// Sessions created before status.bindingRef existed are migrated only when
	// the existing binding already proves durable ownership and exact desired
	// content. Any ambiguity suspends instead of adopting.
	if s.Status.BindingRef == nil {
		ref, issue, err := r.discoverBindingRef(ctx, s)
		if err != nil {
			return Result{}, err
		}
		if issue != nil {
			return r.suspendForBinding(ctx, s, issue)
		}
		s.Status.BindingRef = ref
		s.Status.BindingName = ref.Name
		s.SetCondition(access.ConditionBindingIntegrity, access.ConditionTrue, "BindingReferenceRecorded", "The legacy emergency access binding identity was recorded", r.now())
		if err := r.store.UpdateStatus(ctx, s); err != nil {
			return Result{}, err
		}
	}

	if s.Expired(r.now()) {
		r.log.Info("Session duration expired, revoking RBAC access", "session", s.Name)
		return r.expire(ctx, s)
	}
	issue, err := r.VerifyBinding(ctx, s)
	if err != nil {
		return Result{}, err
	}
	if issue != nil {
		return r.suspendForBinding(ctx, s, issue)
	}

	remaining := r.RequeueAfter(*s.Status.ExpiresAt)
	r.log.Info("Session is active, integrity check scheduled", "session", s.Name, "requeueAfter", remaining)
	return Result{RequeueAfter: remaining}, nil
}

// RequeueAfter returns when an active session expiring at expiresAt must be
// checked again.
func (l *Lifecycle) RequeueAfter(expiresAt time.Time) time.Duration {
	interval := l.IntegrityCheckInterval
	if interval <= 0 {
		interval = DefaultIntegrityCheckInterval
	}
	return access.RequeueAfter(l.now(), expiresAt, interval)
}

func (l *Lifecycle) now() time.Time {
	if l.Clock != nil {
		return l.Clock()
	}
	return time.Now()
}

func (l *Lifecycle) telemetry() Telemetry {
	if l.Telemetry == nil {
		return noTelemetry{}
	}
	return l.Telemetry
}
