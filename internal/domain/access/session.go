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

import (
	"fmt"
	"time"
)

// SessionPhase is the lifecycle state of a session.
type SessionPhase string

const (
	PhasePending   SessionPhase = "Pending"
	PhaseActive    SessionPhase = "Active"
	PhaseSuspended SessionPhase = "Suspended"
	PhaseDenied    SessionPhase = "Denied"
	PhaseExpired   SessionPhase = "Expired"
	PhaseRevoked   SessionPhase = "Revoked"
)

// Terminal reports whether the session can never grant access again. A
// suspended session is deliberately terminal: recreating its binding would
// turn a detected integrity violation into a privilege re-grant.
func (p SessionPhase) Terminal() bool {
	switch p {
	case PhaseExpired, PhaseDenied, PhaseSuspended, PhaseRevoked:
		return true
	default:
		return false
	}
}

// Condition types recorded on a session.
const (
	// ConditionAccessGranted records whether the grant exists and is usable.
	ConditionAccessGranted = "AccessGranted"
	// ConditionBindingIntegrity records whether the binding still matches the
	// identity and content recorded at activation.
	ConditionBindingIntegrity = "BindingIntegrity"
	// ConditionAccessProfileValid records whether the immutable profile
	// snapshot still matches the administrator-controlled policy.
	ConditionAccessProfileValid = "AccessProfileValid"
	// ConditionCuratedRoleValid records whether the role identity and rules
	// match the snapshot taken before the binding was created.
	ConditionCuratedRoleValid = "CuratedRoleValid"
	// ConditionRequestSourceValid records whether an approval-workflow session
	// still has its exact, independently verifiable request source.
	ConditionRequestSourceValid = "RequestSourceValid"
)

// SessionSpec is the immutable access intent of a session.
type SessionSpec struct {
	AccessProfile    string
	AccessProfileUID string
	Subject          Subject
	Duration         string
	Reason           string
	RequestRef       *ObjectRef
	Revoked          bool
}

// Channel returns how the session was requested.
func (s SessionSpec) Channel() Channel {
	if s.RequestRef != nil {
		return ChannelApproval
	}
	return ChannelDirect
}

// Grant is the immutable policy snapshot resolved when the session was first
// activated. Every later integrity check compares against it.
type Grant struct {
	AccessProfile    string
	AccessProfileUID string
	RoleRef          RoleRef
	RoleUID          string
	RoleRulesHash    string
	TargetNamespace  string
}

// Role is the observed identity and rule digest of a curated ClusterRole.
type Role struct {
	Name      string
	UID       string
	RulesHash string
}

// NewGrant snapshots a profile and its curated role.
func NewGrant(profile Profile, role Role) Grant {
	return Grant{
		AccessProfile:    profile.Name,
		AccessProfileUID: profile.UID,
		RoleRef:          profile.RoleRef,
		RoleUID:          role.UID,
		RoleRulesHash:    role.RulesHash,
		TargetNamespace:  profile.TargetNamespace,
	}
}

// SessionStatus is the controller-owned state of a session.
type SessionStatus struct {
	Phase       SessionPhase
	StartTime   *time.Time
	ExpiresAt   *time.Time
	BindingName string
	BindingRef  *BindingRef
	Grant       *Grant
	Conditions  []Condition
}

// Session is a time-bounded grant of one profile to one person. It lives in
// the control namespace of its profile.
type Session struct {
	Name         string
	Namespace    string
	UID          string
	Generation   int64
	Deleting     bool
	HasFinalizer bool

	Spec   SessionSpec
	Status SessionStatus
}

// SetCondition records a condition observed at the session's generation.
func (s *Session) SetCondition(conditionType string, status ConditionStatus, reason, message string, now time.Time) {
	SetCondition(&s.Status.Conditions, Condition{
		Type:               conditionType,
		Status:             status,
		ObservedGeneration: s.Generation,
		Reason:             reason,
		Message:            message,
	}, now)
}

// Expired reports whether the recorded expiry has been reached.
func (s *Session) Expired(now time.Time) bool {
	return s.Status.ExpiresAt != nil && !now.Before(*s.Status.ExpiresAt)
}

// ValidateSessionSpec performs the checks the CRD schema cannot express and
// returns the requested duration. maxDuration of zero disables the
// manager-wide limit; the profile limit is checked separately.
func ValidateSessionSpec(spec SessionSpec, maxDuration time.Duration) (time.Duration, error) {
	duration, err := time.ParseDuration(spec.Duration)
	if err != nil {
		return 0, fmt.Errorf("duration %q is not a valid Go duration: %w", spec.Duration, err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("duration must be greater than zero")
	}
	if maxDuration > 0 && duration > maxDuration {
		return 0, fmt.Errorf("duration %s exceeds the configured maximum of %s", duration, maxDuration)
	}
	if spec.AccessProfile == "" || spec.AccessProfileUID == "" {
		return 0, fmt.Errorf("accessProfile and server-assigned accessProfileUID are required")
	}
	if spec.Subject.Kind != SubjectKindUser || spec.Subject.Name == "" {
		return 0, fmt.Errorf("a self-service session must have an authenticated User subject")
	}
	if spec.Subject.Namespace != "" {
		return 0, fmt.Errorf("a User subject must not specify subject.namespace")
	}
	return duration, nil
}

// CheckProfileForSession decides whether a profile authorizes the session
// with the requested duration within the manager's placement. It returns a
// denial reason, never an infrastructure error.
func CheckProfileForSession(spec SessionSpec, duration time.Duration, profile Profile, placement Placement) error {
	if profile.UID == "" || profile.UID != spec.AccessProfileUID {
		return fmt.Errorf("AccessProfile %q no longer matches the authorized profile UID", spec.AccessProfile)
	}
	maxDuration, defect := profile.Check()
	if defect != ProfileValid {
		return profile.DefectError(defect)
	}
	if !profile.Permits(spec.Channel()) {
		if spec.Channel() == ChannelDirect {
			return fmt.Errorf("AccessProfile %q requires the approval workflow", profile.Name)
		}
		return fmt.Errorf("AccessProfile %q does not authorize a controller-sourced approval workflow session", profile.Name)
	}
	if duration > maxDuration {
		return fmt.Errorf("duration %s exceeds AccessProfile maximum of %s", duration, maxDuration)
	}
	return placement.CheckProfile(profile)
}

// RequeueAfter bounds how long an active session stays unchecked: the next
// integrity check, or its expiry if that comes first. It never returns zero,
// which a reconciler would read as "do not requeue".
func RequeueAfter(now, expiresAt time.Time, interval time.Duration) time.Duration {
	remaining := expiresAt.Sub(now)
	if remaining <= 0 {
		return time.Millisecond
	}
	if remaining < interval {
		return remaining
	}
	return interval
}
