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

// Issue is a detected loss of trust in a session's grant. It deliberately
// carries no object names, identities, or incident reasons, so its code can be
// used as a bounded metric label.
type Issue struct {
	// Code is a stable, low-cardinality machine value for metrics and events.
	// It is empty for issues that are reported by their reason.
	Code string
	// Reason follows the CamelCase syntax of condition reasons.
	Reason  string
	Message string
}

// Binding issue codes.
const (
	BindingIssueMissing       = "missing"
	BindingIssueUIDMismatch   = "uid_mismatch"
	BindingIssueReference     = "binding_reference"
	BindingIssueSubjects      = "subjects"
	BindingIssueOwnership     = "ownership"
	BindingIssueRoleRef       = "role_ref"
	BindingIssueMissingExpiry = "missing_expiry"
	BindingIssueUnknown       = "integrity_unknown"
)

const (
	bindingReferenceInvalidReason = "BindingReferenceInvalid"
	bindingSubjectsDriftReason    = "BindingSubjectsDrift"
)

// BindingMissing reports that the recorded binding no longer exists.
func BindingMissing() *Issue {
	return &Issue{Code: BindingIssueMissing, Reason: "BindingMissing", Message: "the emergency access binding no longer exists"}
}

// BindingUIDMismatch reports that another object now uses the binding name.
func BindingUIDMismatch() *Issue {
	return &Issue{Code: BindingIssueUIDMismatch, Reason: "BindingUIDMismatch", Message: "a different RBAC binding object now uses the recorded binding name"}
}

// BindingChangedBeforeDelete reports a binding modified between read and
// delete.
func BindingChangedBeforeDelete() *Issue {
	return &Issue{Code: BindingIssueUIDMismatch, Reason: "BindingUIDMismatch", Message: "the emergency access binding changed before it could be deleted"}
}

// BindingReferenceInvalid reports a missing or inconsistent binding identity.
func BindingReferenceInvalid(message string) *Issue {
	return &Issue{Code: BindingIssueReference, Reason: bindingReferenceInvalidReason, Message: message}
}

// MissingExpiry reports an active session without a recorded expiry.
func MissingExpiry() *Issue {
	return &Issue{Code: BindingIssueMissingExpiry, Reason: "BindingExpiryMissing", Message: "active session has no recorded expiry time"}
}

// IntegrityUnknown is the fail-closed fallback when no specific issue is known.
func IntegrityUnknown() *Issue {
	return &Issue{Code: BindingIssueUnknown, Reason: "BindingIntegrityUnknown", Message: "the emergency access binding could not be verified"}
}

// Curated role issue reasons. They are reported by reason, not by code.
const (
	RoleIssueSnapshotMissing = "CuratedRoleSnapshotMissing"
	RoleIssueMissing         = "CuratedRoleMissing"
	RoleIssueUIDMismatch     = "CuratedRoleUIDMismatch"
	RoleIssueRulesDrift      = "CuratedRoleRulesDrift"
	RoleIssueUnknown         = "CuratedRoleUnknown"
)

// Request source issue codes.
const (
	SourceIssueReference           = "request_reference"
	SourceIssueMissing             = "request_missing"
	SourceIssueUIDMismatch         = "request_uid_mismatch"
	SourceIssueContentMismatch     = "request_content_mismatch"
	SourceIssueReservationMismatch = "session_reservation_mismatch"
	SourceIssueSessionUIDMismatch  = "session_uid_mismatch"
	SourceIssuePhase               = "request_phase"
	SourceIssueTTLInvalid          = "request_ttl_invalid"
	SourceIssueExpired             = "request_expired"
	SourceIssueApprovalReference   = "approval_reference"
	SourceIssueApprovalMissing     = "approval_missing"
	SourceIssueApprovalUIDMismatch = "approval_uid_mismatch"
	SourceIssueApprovalInvalid     = "approval_invalid"
	SourceIssueUnknown             = "source_unknown"
)
