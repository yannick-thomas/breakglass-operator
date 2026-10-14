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

package sessionlifecycle

import (
	"context"
	"time"

	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
)

// Every terminal transition below follows the same order: remove the exact
// recorded binding, update the conditions, emit events, persist the status,
// and only then record telemetry. Telemetry for a write that failed would be
// counted again on retry.

func (r *run) revoke(ctx context.Context, s *access.Session) (Result, error) {
	if s.Status.Phase == access.PhaseRevoked {
		return Result{}, nil
	}
	r.log.Info("Session manually revoked by administrator", "session", s.Name)
	cleanup, err := r.CleanupBinding(ctx, s)
	if err != nil {
		return Result{}, err
	}

	s.Status.Phase = access.PhaseRevoked
	s.SetCondition(access.ConditionAccessGranted, access.ConditionFalse, "AccessRevoked", "Emergency access was manually revoked", r.now())
	r.setCleanupCondition(s, cleanup)
	r.events.Event(EventWarning, "AccessRevoked", "Emergency access manually revoked by admin")
	r.emitCleanupIssue(cleanup)
	if err := r.store.UpdateStatus(ctx, s); err != nil {
		return Result{}, err
	}
	r.telemetry().Transition(TransitionRevoked, s)
	r.recordCleanupIssue(cleanup, s)
	return Result{}, nil
}

func (r *run) expire(ctx context.Context, s *access.Session) (Result, error) {
	cleanup, err := r.CleanupBinding(ctx, s)
	if err != nil {
		return Result{}, err
	}
	// After expiry a missing binding is the desired end state, not drift: the
	// independent expiry guard removes it when the controller is behind or
	// down. Deletion while the session is active is still detected by the
	// binding watch and the periodic integrity check, and a replacement
	// binding (UID mismatch) remains an integrity issue here.
	alreadyRemoved := cleanup.Issue != nil && cleanup.Issue.Code == access.BindingIssueMissing
	if alreadyRemoved {
		cleanup.Issue = nil
	}

	now := r.now()
	s.Status.Phase = access.PhaseExpired
	s.SetCondition(access.ConditionAccessGranted, access.ConditionFalse, "AccessExpired", "Emergency access duration elapsed", now)
	if alreadyRemoved {
		s.SetCondition(access.ConditionBindingIntegrity, access.ConditionTrue, "BindingAlreadyRemoved", "The emergency access binding was already removed when expiry cleanup ran", now)
	} else {
		r.setCleanupCondition(s, cleanup)
	}
	r.events.Event(EventWarning, "AccessExpired", "Emergency access expired at %s", s.Status.ExpiresAt.Format(time.RFC3339))
	if alreadyRemoved {
		r.events.Event(EventNormal, "BindingAlreadyRemoved", "Emergency access binding was already removed when expiry cleanup ran")
	}
	r.emitCleanupIssue(cleanup)
	if err := r.store.UpdateStatus(ctx, s); err != nil {
		return Result{}, err
	}
	r.telemetry().Transition(TransitionExpired, s)
	r.recordCleanupIssue(cleanup, s)
	if cleanup.Deleted && s.Status.ExpiresAt != nil {
		r.telemetry().ExpiryCleanupLag(s, r.now().Sub(*s.Status.ExpiresAt))
	}
	return Result{}, nil
}

// deny makes a policy denial terminal after cleaning up a reservation that an
// interrupted status write may have left. Cleanup failures stay retryable.
func (r *run) deny(ctx context.Context, s *access.Session, cause error) (Result, error) {
	cleanup, err := r.CleanupBinding(ctx, s)
	if err != nil {
		return Result{}, err
	}
	r.log.Error(cause, "BreakGlassSession could not be activated", "session", s.Name)
	s.Status.Phase = access.PhaseDenied
	s.SetCondition(access.ConditionAccessGranted, access.ConditionFalse, "InvalidSpec", cause.Error(), r.now())
	if cleanup.Deleted || cleanup.Issue != nil {
		r.setCleanupCondition(s, cleanup)
	}
	r.events.Event(EventWarning, "AccessDenied", "Emergency access request was denied: %v", cause)
	r.emitCleanupIssue(cleanup)
	if err := r.store.UpdateStatus(ctx, s); err != nil {
		return Result{}, err
	}
	r.telemetry().Transition(TransitionDenied, s)
	r.recordCleanupIssue(cleanup, s)
	return Result{}, nil
}

// suspendForBinding deletes only the exact UID persisted in status. For a
// missing or replaced object cleanup is intentionally a no-op: the lifecycle
// never deletes an object it did not create.
func (r *run) suspendForBinding(ctx context.Context, s *access.Session, issue *access.Issue) (Result, error) {
	cleanup, err := r.CleanupBinding(ctx, s)
	if err != nil {
		return Result{}, err
	}
	if issue == nil {
		issue = cleanup.Issue
	}
	if issue == nil {
		issue = access.IntegrityUnknown()
	}

	now := r.now()
	s.Status.Phase = access.PhaseSuspended
	s.SetCondition(access.ConditionAccessGranted, access.ConditionFalse, "BindingIntegrityLost", "Emergency access was suspended because its binding failed integrity verification", now)
	s.SetCondition(access.ConditionBindingIntegrity, access.ConditionFalse, issue.Reason, issue.Message, now)
	r.events.Event(EventWarning, "BindingIntegrityLost", "Emergency access suspended because its binding failed integrity verification: %s", issue.Code)
	if err := r.store.UpdateStatus(ctx, s); err != nil {
		return Result{}, err
	}
	r.telemetry().Transition(TransitionSuspended, s)
	r.telemetry().BindingDrift(issue, s)
	return Result{}, nil
}

func (r *run) suspendForRequestSource(ctx context.Context, s *access.Session, issue *access.Issue) (Result, error) {
	cleanup, err := r.CleanupBinding(ctx, s)
	if err != nil {
		return Result{}, err
	}
	if issue == nil {
		issue = access.SourceUnknown()
	}

	now := r.now()
	s.Status.Phase = access.PhaseSuspended
	s.SetCondition(access.ConditionAccessGranted, access.ConditionFalse, "RequestSourceInvalid", "Emergency access was suspended because its approval-workflow source failed verification", now)
	s.SetCondition(access.ConditionRequestSourceValid, access.ConditionFalse, issue.Reason, issue.Message, now)
	r.setCleanupCondition(s, cleanup)
	r.events.Event(EventWarning, "RequestSourceInvalid", "Emergency access suspended because its approval-workflow source failed verification: %s", issue.Code)
	if err := r.store.UpdateStatus(ctx, s); err != nil {
		return Result{}, err
	}
	r.telemetry().Transition(TransitionSuspended, s)
	r.telemetry().RequestSourceIntegrity(issue, s)
	r.recordCleanupIssue(cleanup, s)
	return Result{}, nil
}

func (r *run) suspendForRole(ctx context.Context, s *access.Session, issue *access.Issue) (Result, error) {
	cleanup, err := r.CleanupBinding(ctx, s)
	if err != nil {
		return Result{}, err
	}
	if issue == nil {
		issue = &access.Issue{Reason: access.RoleIssueUnknown, Message: "the curated ClusterRole could not be verified"}
	}

	now := r.now()
	s.Status.Phase = access.PhaseSuspended
	s.SetCondition(access.ConditionAccessGranted, access.ConditionFalse, "CuratedRoleInvalid", "Emergency access was suspended because its curated ClusterRole failed integrity verification", now)
	s.SetCondition(access.ConditionCuratedRoleValid, access.ConditionFalse, issue.Reason, issue.Message, now)
	r.setCleanupCondition(s, cleanup)
	r.events.Event(EventWarning, "CuratedRoleInvalid", "Emergency access suspended because its curated ClusterRole failed integrity verification: %s", issue.Reason)
	if err := r.store.UpdateStatus(ctx, s); err != nil {
		return Result{}, err
	}
	r.telemetry().Transition(TransitionSuspended, s)
	r.telemetry().CuratedRoleDrift(issue, s)
	r.recordCleanupIssue(cleanup, s)
	return Result{}, nil
}

func (r *run) suspendForProfile(ctx context.Context, s *access.Session, issue *access.Issue) (Result, error) {
	cleanup, err := r.CleanupBinding(ctx, s)
	if err != nil {
		return Result{}, err
	}
	if issue == nil {
		issue = &access.Issue{Reason: "AccessProfileUnknown", Message: "the AccessProfile could not be verified"}
	}

	now := r.now()
	s.Status.Phase = access.PhaseSuspended
	s.SetCondition(access.ConditionAccessGranted, access.ConditionFalse, "AccessProfileInvalid", "Emergency access was suspended because its AccessProfile failed verification", now)
	s.SetCondition(access.ConditionAccessProfileValid, access.ConditionFalse, issue.Reason, issue.Message, now)
	r.setCleanupCondition(s, cleanup)
	r.events.Event(EventWarning, "AccessProfileInvalid", "Emergency access suspended because its AccessProfile failed verification: %s", issue.Reason)
	if err := r.store.UpdateStatus(ctx, s); err != nil {
		return Result{}, err
	}
	r.telemetry().Transition(TransitionSuspended, s)
	r.recordCleanupIssue(cleanup, s)
	return Result{}, nil
}

func (r *run) setCleanupCondition(s *access.Session, cleanup CleanupResult) {
	if cleanup.Issue != nil {
		s.SetCondition(access.ConditionBindingIntegrity, access.ConditionFalse, cleanup.Issue.Reason, cleanup.Issue.Message, r.now())
		return
	}
	s.SetCondition(access.ConditionBindingIntegrity, access.ConditionTrue, "BindingRemoved", "The emergency access binding was removed using its recorded identity", r.now())
}

func (r *run) emitCleanupIssue(cleanup CleanupResult) {
	if cleanup.Issue != nil {
		r.events.Event(EventWarning, "BindingIntegrityLost", "Emergency access binding could not be safely removed: %s", cleanup.Issue.Code)
	}
}

// recordCleanupIssue keeps terminal cleanup incidents visible even when the
// session ends as Revoked or Expired rather than Suspended.
func (l *Lifecycle) recordCleanupIssue(cleanup CleanupResult, s *access.Session) {
	if cleanup.Issue != nil {
		l.telemetry().BindingDrift(cleanup.Issue, s)
	}
}
