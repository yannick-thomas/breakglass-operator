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
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

const (
	// RoleBindingKind is the only binding kind the operator creates.
	RoleBindingKind = "RoleBinding"
	// RBACGroup is the API group of RBAC roles and subjects.
	RBACGroup = "rbac.authorization.k8s.io"

	// Finalizer keeps a session until its binding is removed.
	Finalizer = "access.breakglass.io/finalizer"

	// Labels that tie a binding to its session. A session lives in a control
	// namespace and its binding in a target namespace; Kubernetes forbids
	// owner references across namespaces, so the labels name the session's
	// namespace, name, and UID (ADR-004).
	ManagedByLabelKey        = "app.kubernetes.io/managed-by"
	ManagedByLabelValue      = "breakglass-operator"
	SessionLabelKey          = "access.breakglass.io/session"
	SessionNamespaceLabelKey = "access.breakglass.io/session-namespace"
	SessionUIDLabelKey       = "access.breakglass.io/session-uid"

	// Binding names include a short digest of the immutable session UID. This
	// avoids predictable name reuse across delete/recreate cycles while
	// staying within the object-name limit.
	bindingNamePrefix    = "breakglass-"
	bindingUIDHashLength = 12
	maxObjectNameLength  = 253
)

// BindingRef is the authoritative identity of a binding. Once its UID is
// recorded, only an object with exactly this kind, namespace, name, and UID
// may be inspected, promoted, or deleted.
type BindingRef struct {
	Kind      string
	Name      string
	Namespace string
	UID       string
}

// Locates reports whether the reference points at the binding's location,
// ignoring the UID.
func (r *BindingRef) Locates(b Binding) bool {
	return r != nil && r.Kind == RoleBindingKind && b.Kind == RoleBindingKind &&
		r.Name == b.Name && r.Namespace == b.Namespace
}

// BindingRoleRef is the role reference of an RBAC binding.
type BindingRoleRef struct {
	APIGroup string
	Kind     string
	Name     string
}

// BindingSubject is a subject of an RBAC binding.
type BindingSubject struct {
	APIGroup  string
	Kind      string
	Name      string
	Namespace string
}

// Binding is an observed RBAC binding.
type Binding struct {
	Kind      string
	Name      string
	Namespace string
	UID       string
	Labels    map[string]string
	RoleRef   BindingRoleRef
	Subjects  []BindingSubject
	// Version is an opaque optimistic-concurrency token. A write based on this
	// observation fails if the object changed since it was read.
	Version string
}

// Ref returns the binding's identity. A binding without a server-assigned UID
// cannot be tracked and is rejected.
func (b Binding) Ref() (*BindingRef, error) {
	if b.UID == "" {
		return nil, fmt.Errorf("RBAC binding %s/%s returned without a server-assigned UID", b.Namespace, b.Name)
	}
	if b.Kind != RoleBindingKind {
		return nil, errors.New("unsupported RBAC binding kind " + b.Kind)
	}
	return &BindingRef{Kind: RoleBindingKind, Name: b.Name, Namespace: b.Namespace, UID: b.UID}, nil
}

// BindingName derives the deterministic binding name of a session.
func BindingName(sessionName, sessionUID string) string {
	digest := sha256.Sum256([]byte(sessionUID))
	suffix := fmt.Sprintf("-%x", digest[:])[:bindingUIDHashLength+1]
	maxSessionNameLength := maxObjectNameLength - len(bindingNamePrefix) - len(suffix)
	if len(sessionName) > maxSessionNameLength {
		sessionName = sessionName[:maxSessionNameLength]
	}
	sessionName = strings.Trim(sessionName, "-")
	if sessionName == "" {
		sessionName = "session"
	}
	return bindingNamePrefix + sessionName + suffix
}

// ExpectedBindingRef is where the session's binding must be. Its UID is empty;
// the namespace is empty until a grant is resolved.
func (s *Session) ExpectedBindingRef() *BindingRef {
	name := s.Status.BindingName
	if name == "" {
		name = BindingName(s.Name, s.UID)
	}
	namespace := ""
	if s.Status.Grant != nil {
		namespace = s.Status.Grant.TargetNamespace
	}
	return &BindingRef{Kind: RoleBindingKind, Name: name, Namespace: namespace}
}

// RecordedRefIsConsistent reports whether a binding reference has a UID and
// points at the session's expected location.
func (s *Session) RecordedRefIsConsistent(ref *BindingRef) bool {
	if ref == nil || ref.UID == "" {
		return false
	}
	expected := s.ExpectedBindingRef()
	return ref.Kind == expected.Kind && ref.Name == expected.Name && ref.Namespace == expected.Namespace
}

// ExpectedSubject is the one subject the session's binding may have.
// Kubernetes defaults a User subject's API group to the RBAC group, so the
// canonical value is recorded here as well; otherwise that server-side
// defaulting would look like drift.
func (s *Session) ExpectedSubject() BindingSubject {
	return BindingSubject{APIGroup: RBACGroup, Kind: string(s.Spec.Subject.Kind), Name: s.Spec.Subject.Name}
}

// ExpectedRoleRef is the role the session's binding must reference.
func (s *Session) ExpectedRoleRef() BindingRoleRef {
	if s.Status.Grant == nil {
		return BindingRoleRef{}
	}
	return BindingRoleRef{APIGroup: RBACGroup, Kind: s.Status.Grant.RoleRef.Kind, Name: s.Status.Grant.RoleRef.Name}
}

// ManagedLabels are the ownership labels of the session's binding.
func (s *Session) ManagedLabels() map[string]string {
	return map[string]string{
		ManagedByLabelKey:        ManagedByLabelValue,
		SessionLabelKey:          s.Name,
		SessionNamespaceLabelKey: s.Namespace,
		SessionUIDLabelKey:       s.UID,
	}
}

// Owns reports whether the binding is labelled as this session's own. Labels
// prove no more than an owner reference did: anyone who may write bindings in
// the target namespace can set either. Once a UID is recorded, the UID remains
// the authority for safe deletion.
func (s *Session) Owns(b Binding) bool {
	for key, value := range s.ManagedLabels() {
		if b.Labels[key] != value {
			return false
		}
	}
	return true
}

// CheckGrantedBinding verifies an authorizing binding: expected location,
// ownership, role, and exactly the session's subject.
func (s *Session) CheckGrantedBinding(b Binding) *Issue {
	if issue := s.checkBindingMetadata(b); issue != nil {
		return issue
	}
	if len(b.Subjects) != 1 || b.Subjects[0] != s.ExpectedSubject() {
		return &Issue{Code: BindingIssueSubjects, Reason: bindingSubjectsDriftReason, Message: "the RBAC binding subjects differ from the approved session"}
	}
	return nil
}

// CheckReservedBinding verifies a non-authorizing reservation: expected
// location, ownership, role, and no subjects.
func (s *Session) CheckReservedBinding(b Binding) *Issue {
	if issue := s.checkBindingMetadata(b); issue != nil {
		return issue
	}
	if len(b.Subjects) != 0 {
		return &Issue{Code: BindingIssueSubjects, Reason: bindingSubjectsDriftReason, Message: "the reserved RBAC binding unexpectedly has subjects"}
	}
	return nil
}

func (s *Session) checkBindingMetadata(b Binding) *Issue {
	if !s.ExpectedBindingRef().Locates(b) {
		return BindingReferenceInvalid("the RBAC binding kind, name, or namespace differs from the session record")
	}
	if !s.Owns(b) {
		return &Issue{Code: BindingIssueOwnership, Reason: "BindingOwnershipLost", Message: "the RBAC binding no longer has the expected ownership labels"}
	}
	if b.RoleRef != s.ExpectedRoleRef() {
		return &Issue{Code: BindingIssueRoleRef, Reason: "BindingRoleRefDrift", Message: "the RBAC binding role reference differs from the approved session"}
	}
	return nil
}

// IsUnrecordedReservation reports whether a binding found by label search is
// this session's empty-subject reservation, left behind when the status write
// recording its UID failed. Such a binding grants nothing.
func (s *Session) IsUnrecordedReservation(b Binding) bool {
	return b.Name == BindingName(s.Name, s.UID) && len(b.Subjects) == 0 && s.Owns(b)
}

// ManagedSessionRef is the session a managed binding claims to belong to.
type ManagedSessionRef struct {
	Namespace string
	Name      string
	UID       string
}

// ManagedSession reads the session a binding is labelled for. ok is false
// unless the binding carries the managed-by label and a complete session
// identity.
func (b Binding) ManagedSession() (ManagedSessionRef, bool) {
	ref := ManagedSessionRef{
		Namespace: b.Labels[SessionNamespaceLabelKey],
		Name:      b.Labels[SessionLabelKey],
		UID:       b.Labels[SessionUIDLabelKey],
	}
	ok := b.Labels[ManagedByLabelKey] == ManagedByLabelValue && ref.Namespace != "" && ref.Name != "" && ref.UID != ""
	return ref, ok
}

// MayHaveUnrecordedReservation reports whether the session is in the narrow
// state in which an unrecorded reservation can exist: nothing about its
// activation has been persisted yet.
func (s *Session) MayHaveUnrecordedReservation() bool {
	return s.Status.BindingName == "" && s.Status.Grant == nil &&
		s.Status.StartTime == nil && s.Status.ExpiresAt == nil
}
