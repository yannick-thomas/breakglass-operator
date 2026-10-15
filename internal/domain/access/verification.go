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

package access

import "time"

// The checks in this file re-verify an active or activating session against
// the live policy objects it was authorized by. They return an Issue when
// trust is lost and nil when the session may keep its access. Lookups are
// performed by the caller; "not found" outcomes have their own constructors.

// ProfileSnapshotIssue checks the session's recorded profile snapshot before
// the live profile is read.
func (s *Session) ProfileSnapshotIssue() *Issue {
	grant := s.Status.Grant
	if grant == nil {
		return ProfileSnapshotMissing()
	}
	if grant.AccessProfile != s.Spec.AccessProfile || grant.AccessProfileUID != s.Spec.AccessProfileUID {
		return &Issue{Reason: "AccessProfileSnapshotMismatch", Message: "the resolved AccessProfile snapshot differs from the immutable request"}
	}
	return nil
}

// ProfileSnapshotMissing reports an active session without a profile snapshot.
// Such a grant was never authorized through a profile and is not migrated.
func ProfileSnapshotMissing() *Issue {
	return &Issue{Reason: "AccessProfileSnapshotMissing", Message: "active session has no resolved AccessProfile snapshot"}
}

// ProfileMissing reports a profile deleted while the session was active.
func ProfileMissing() *Issue {
	return &Issue{Reason: "AccessProfileMissing", Message: "the AccessProfile was deleted while the session was active"}
}

// ProfileIssue checks the live profile against the session's snapshot. Any
// deletion, name reuse, or policy change fails closed.
func (s *Session) ProfileIssue(profile Profile, placement Placement) *Issue {
	grant := s.Status.Grant
	if profile.UID != grant.AccessProfileUID {
		return &Issue{Reason: "AccessProfileUIDMismatch", Message: "a different AccessProfile object now uses the recorded profile name"}
	}
	if _, defect := profile.Check(); defect != ProfileValid {
		return &Issue{Reason: "AccessProfileInvalid", Message: "the active AccessProfile no longer passes semantic validation"}
	}
	if placement.CheckProfile(profile) != nil {
		return &Issue{Reason: "AccessProfileOutOfScope", Message: "the active AccessProfile is outside this manager's control or target namespace set"}
	}
	if profile.RoleRef != grant.RoleRef || profile.TargetNamespace != grant.TargetNamespace {
		return &Issue{Reason: "AccessProfilePolicyDrift", Message: "the AccessProfile policy differs from the resolved session snapshot"}
	}
	if !profile.Permits(s.Spec.Channel()) {
		if s.Spec.Channel() == ChannelDirect {
			return &Issue{Reason: "AccessProfileDeliveryModeDrift", Message: "the profile no longer permits a direct self-service session"}
		}
		return &Issue{Reason: "AccessProfileDeliveryModeDrift", Message: "the profile no longer permits an approval-workflow session"}
	}
	return nil
}

// RoleSnapshotIssue checks that the session recorded a complete curated-role
// snapshot before the live role is read.
func (s *Session) RoleSnapshotIssue() *Issue {
	grant := s.Status.Grant
	if grant == nil || grant.RoleRef.Kind != ClusterRoleKind || grant.RoleRef.Name == "" || grant.RoleUID == "" || grant.RoleRulesHash == "" {
		return &Issue{Reason: RoleIssueSnapshotMissing, Message: "the active session has no complete curated ClusterRole integrity snapshot"}
	}
	return nil
}

// RoleMissing reports a deleted curated role.
func RoleMissing() *Issue {
	return &Issue{Reason: RoleIssueMissing, Message: "the curated ClusterRole no longer exists"}
}

// RoleIssue checks the live curated role against the snapshot. Editing a role
// would otherwise silently widen every active session that binds it.
func (s *Session) RoleIssue(role Role) *Issue {
	grant := s.Status.Grant
	if role.UID != grant.RoleUID {
		return &Issue{Reason: RoleIssueUIDMismatch, Message: "a different curated ClusterRole object now uses the recorded role name"}
	}
	if role.RulesHash != grant.RoleRulesHash {
		return &Issue{Reason: RoleIssueRulesDrift, Message: "the curated ClusterRole rules differ from the approved session snapshot"}
	}
	return nil
}

// SourceReferenceIssue checks that an approval-workflow session cites its
// request completely.
func (s *Session) SourceReferenceIssue() *Issue {
	if ref := s.Spec.RequestRef; ref == nil || !ref.Complete() {
		return &Issue{Code: SourceIssueReference, Reason: "RequestReferenceInvalid", Message: "the approval-workflow session has no complete immutable request reference"}
	}
	return nil
}

// SourceRequestMissing reports a deleted source request.
func SourceRequestMissing() *Issue {
	return &Issue{Code: SourceIssueMissing, Reason: "RequestMissing", Message: "the approved source request no longer exists"}
}

// SourceRequestIssue checks the live source request: same object, same
// intent, a reservation of exactly this session, and, until the session is
// active, an open decision window. A request's deadline is a decision
// deadline, not a session TTL; once active, the session's own expiry rules.
func (s *Session) SourceRequestIssue(r Request, now time.Time) *Issue {
	if r.UID != s.Spec.RequestRef.UID {
		return &Issue{Code: SourceIssueUIDMismatch, Reason: "RequestUIDMismatch", Message: "a different request object now uses the recorded source request name"}
	}
	if !r.MatchesSession(s.Spec) {
		return &Issue{Code: SourceIssueContentMismatch, Reason: "RequestContentMismatch", Message: "the session fields differ from the immutable approved request"}
	}
	if issue := s.reservationIssue(r); issue != nil {
		return issue
	}
	return s.DecisionDeadlineIssue(r, now)
}

// DecisionDeadlineIssue enforces the request's decision deadline until the
// session is active; otherwise a manager outage could turn an expired request
// into a late grant. Once active, the session's own expiry is the authority.
func (s *Session) DecisionDeadlineIssue(r Request, now time.Time) *Issue {
	if _, ok := r.Deadline(); !ok {
		return &Issue{Code: SourceIssueTTLInvalid, Reason: "RequestTTLInvalid", Message: "the immutable source request has no valid positive request TTL"}
	}
	if s.Status.Phase != PhaseActive && !r.DecisionOpen(now) {
		return &Issue{Code: SourceIssueExpired, Reason: "RequestExpired", Message: "the source request expired before this session became active"}
	}
	return nil
}

func (s *Session) reservationIssue(r Request) *Issue {
	ref := r.Status.SessionRef
	if ref == nil || ref.Name != s.Name {
		return &Issue{Code: SourceIssueReservationMismatch, Reason: "SessionReservationMismatch", Message: "the source request does not reserve this session name"}
	}
	switch r.Status.Phase {
	case RequestPhaseProvisioning:
		// Creating the session and recording its UID on the request are two
		// writes. In between, the reservation may not yet carry the UID.
		if ref.UID != "" && ref.UID != s.UID {
			return &Issue{Code: SourceIssueSessionUIDMismatch, Reason: "SessionUIDMismatch", Message: "the request reservation cites a different session object"}
		}
	case RequestPhaseSessionCreated:
		if ref.UID == "" || ref.UID != s.UID {
			return &Issue{Code: SourceIssueSessionUIDMismatch, Reason: "SessionUIDMismatch", Message: "the source request does not cite this server-assigned session UID"}
		}
	default:
		return &Issue{Code: SourceIssuePhase, Reason: "RequestNotProvisioned", Message: "the source request is not in a session-provisioned lifecycle phase"}
	}
	return nil
}

// SourceApprovalRefIssue checks that the request records its approval in the
// one deterministic slot.
func SourceApprovalRefIssue(r Request) *Issue {
	ref := r.Status.ApprovalRef
	if ref == nil || ref.Name != r.ApprovalName() || ref.UID == "" {
		return &Issue{Code: SourceIssueApprovalReference, Reason: "ApprovalReferenceInvalid", Message: "the source request has no complete deterministic approval reference"}
	}
	return nil
}

// SourceApprovalMissing reports a deleted approval.
func SourceApprovalMissing() *Issue {
	return &Issue{Code: SourceIssueApprovalMissing, Reason: "ApprovalMissing", Message: "the source request approval no longer exists"}
}

// SourceApprovalIssue checks the live approval: the recorded object, and an
// independent approval of exactly this request.
func SourceApprovalIssue(r Request, a Approval) *Issue {
	if a.UID != r.Status.ApprovalRef.UID {
		return &Issue{Code: SourceIssueApprovalUIDMismatch, Reason: "ApprovalUIDMismatch", Message: "a different approval object now uses the recorded decision name"}
	}
	if !a.Approves(r) {
		return &Issue{Code: SourceIssueApprovalInvalid, Reason: "ApprovalInvalid", Message: "the source request approval is not an independent approved decision"}
	}
	return nil
}

// SourceUnknown is the fail-closed fallback when no specific issue is known.
func SourceUnknown() *Issue {
	return &Issue{Code: SourceIssueUnknown, Reason: "RequestSourceUnknown", Message: "the approval-workflow session source could not be verified"}
}
