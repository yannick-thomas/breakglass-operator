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
	"time"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/adapter/apiconv"
	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	breakglassmetrics "github.com/yannick-thomas/breakglass-operator/internal/metrics"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/sessionlifecycle"
)

// SessionScope converts persisted controller state to a bounded metric label.
// It intentionally never returns a namespace, profile, role, or identity.
func SessionScope(session *accessv1alpha1.BreakGlassSession) breakglassmetrics.Scope {
	return sessionScope(apiconv.ToDomainSession(session))
}

func sessionScope(s *access.Session) breakglassmetrics.Scope {
	if s.Status.BindingRef != nil {
		return breakglassmetrics.ScopeFromBindingKind(s.Status.BindingRef.Kind)
	}
	// The profile snapshot is used only as a boolean scope decision; its
	// namespace is never emitted as a label.
	if s.Status.Grant != nil && s.Status.Grant.TargetNamespace != "" {
		return breakglassmetrics.ScopeNamespaced
	}
	return breakglassmetrics.ScopeUnknown
}

// lifecycleTelemetry maps use-case signals to Prometheus metrics.
type lifecycleTelemetry struct {
	recorder breakglassmetrics.LifecycleRecorder
}

var _ sessionlifecycle.Telemetry = lifecycleTelemetry{}

func (t lifecycleTelemetry) Transition(transition sessionlifecycle.Transition, s *access.Session) {
	var value breakglassmetrics.LifecycleTransition
	switch transition {
	case sessionlifecycle.TransitionActivated:
		value = breakglassmetrics.TransitionActivated
	case sessionlifecycle.TransitionDenied:
		value = breakglassmetrics.TransitionDenied
	case sessionlifecycle.TransitionExpired:
		value = breakglassmetrics.TransitionExpired
	case sessionlifecycle.TransitionRevoked:
		value = breakglassmetrics.TransitionRevoked
	case sessionlifecycle.TransitionSuspended:
		value = breakglassmetrics.TransitionSuspended
	default:
		value = breakglassmetrics.TransitionUnknown
	}
	t.recorder.RecordTransition(value, sessionScope(s))
}

func (t lifecycleTelemetry) BindingOperation(op sessionlifecycle.BindingOperation, success bool, s *access.Session) {
	var operation breakglassmetrics.BindingOperation
	switch op {
	case sessionlifecycle.OperationReserve:
		operation = breakglassmetrics.BindingOperationReserve
	case sessionlifecycle.OperationRecoverReservation:
		operation = breakglassmetrics.BindingOperationRecoverReservation
	case sessionlifecycle.OperationGrant:
		operation = breakglassmetrics.BindingOperationGrant
	case sessionlifecycle.OperationCleanup:
		operation = breakglassmetrics.BindingOperationCleanup
	default:
		operation = breakglassmetrics.BindingOperationUnknown
	}
	result := breakglassmetrics.BindingOperationError
	if success {
		result = breakglassmetrics.BindingOperationSuccess
	}
	t.recorder.RecordBindingOperation(operation, result, sessionScope(s))
}

func (t lifecycleTelemetry) BindingDrift(issue *access.Issue, s *access.Session) {
	if issue == nil {
		return
	}
	t.recorder.RecordBindingDrift(bindingDriftReason(issue.Code), sessionScope(s))
}

func bindingDriftReason(code string) breakglassmetrics.BindingDriftReason {
	switch code {
	case access.BindingIssueMissing:
		return breakglassmetrics.DriftMissing
	case access.BindingIssueOwnership:
		return breakglassmetrics.DriftOwnership
	case access.BindingIssueUIDMismatch:
		return breakglassmetrics.DriftUIDMismatch
	case access.BindingIssueRoleRef:
		return breakglassmetrics.DriftRoleRef
	case access.BindingIssueSubjects:
		return breakglassmetrics.DriftSubjects
	case access.BindingIssueReference:
		return breakglassmetrics.DriftBindingReference
	case access.BindingIssueMissingExpiry:
		return breakglassmetrics.DriftMissingExpiry
	case access.BindingIssueUnknown:
		return breakglassmetrics.DriftIntegrityUnknown
	default:
		return breakglassmetrics.DriftUnknown
	}
}

func (t lifecycleTelemetry) CuratedRoleDrift(issue *access.Issue, s *access.Session) {
	if issue == nil {
		return
	}
	var reason breakglassmetrics.CuratedRoleDriftReason
	switch issue.Reason {
	case access.RoleIssueMissing:
		reason = breakglassmetrics.CuratedRoleMissing
	case access.RoleIssueUIDMismatch:
		reason = breakglassmetrics.CuratedRoleUIDMismatch
	case access.RoleIssueRulesDrift:
		reason = breakglassmetrics.CuratedRoleRulesHash
	case access.RoleIssueSnapshotMissing:
		reason = breakglassmetrics.CuratedRoleSnapshotMissing
	default:
		reason = breakglassmetrics.CuratedRoleUnknown
	}
	t.recorder.RecordCuratedRoleDrift(reason, sessionScope(s))
}

func (t lifecycleTelemetry) RequestSourceIntegrity(issue *access.Issue, s *access.Session) {
	if issue == nil {
		return
	}
	var reason breakglassmetrics.RequestSourceIntegrityReason
	switch issue.Code {
	case access.SourceIssueReference:
		reason = breakglassmetrics.RequestSourceReference
	case access.SourceIssueMissing:
		reason = breakglassmetrics.RequestSourceMissing
	case access.SourceIssueUIDMismatch:
		reason = breakglassmetrics.RequestSourceUIDMismatch
	case access.SourceIssueContentMismatch:
		reason = breakglassmetrics.RequestSourceContentMismatch
	case access.SourceIssueReservationMismatch:
		reason = breakglassmetrics.RequestSourceReservationMismatch
	case access.SourceIssueSessionUIDMismatch:
		reason = breakglassmetrics.RequestSourceSessionUIDMismatch
	case access.SourceIssuePhase:
		reason = breakglassmetrics.RequestSourcePhase
	case access.SourceIssueTTLInvalid:
		reason = breakglassmetrics.RequestSourceTTLInvalid
	case access.SourceIssueExpired:
		reason = breakglassmetrics.RequestSourceExpired
	case access.SourceIssueApprovalReference:
		reason = breakglassmetrics.RequestSourceApprovalReference
	case access.SourceIssueApprovalMissing:
		reason = breakglassmetrics.RequestSourceApprovalMissing
	case access.SourceIssueApprovalUIDMismatch:
		reason = breakglassmetrics.RequestSourceApprovalUIDMismatch
	case access.SourceIssueApprovalInvalid:
		reason = breakglassmetrics.RequestSourceApprovalInvalid
	default:
		reason = breakglassmetrics.RequestSourceUnknown
	}
	t.recorder.RecordRequestSourceIntegrity(reason, sessionScope(s))
}

func (t lifecycleTelemetry) ExpiryCleanupLag(s *access.Session, lag time.Duration) {
	t.recorder.ObserveExpiryCleanupLag(sessionScope(s), lag)
}
