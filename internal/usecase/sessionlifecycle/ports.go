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

// PolicySource reads the policy objects a grant depends on. Implementations
// must read directly from the API server: a stale cache must never authorize a
// new grant or prolong an active one. Lookups of missing objects return an
// error marked with port.ErrNotFound. Profiles, requests, and approvals are
// read in the namespace of the session being reconciled (ADR-004).
type PolicySource interface {
	Profile(ctx context.Context, name string) (access.Profile, error)
	Role(ctx context.Context, name string) (access.Role, error)
	Request(ctx context.Context, name string) (access.Request, error)
	Approval(ctx context.Context, name string) (access.Approval, error)
	// NamespaceAbsent reports whether a direct read confirms that the
	// namespace no longer exists. Any other outcome, including Forbidden or a
	// terminating namespace, is not evidence of absence.
	NamespaceAbsent(ctx context.Context, namespace string) bool
}

// BindingDraft describes a binding to create.
type BindingDraft struct {
	Name      string
	Namespace string
	Labels    map[string]string
	RoleRef   access.BindingRoleRef
	Subjects  []access.BindingSubject
}

// BindingGateway reads and writes RBAC bindings. Errors are marked with the
// port error kinds the use case distinguishes.
type BindingGateway interface {
	// Create creates the binding; port.ErrAlreadyExists if the name is taken.
	Create(ctx context.Context, draft BindingDraft) (access.Binding, error)
	// Get reads a binding; port.ErrNotFound or port.ErrForbidden.
	Get(ctx context.Context, namespace, name string) (access.Binding, error)
	// SetSubjects replaces the subjects of exactly the observed binding
	// version; a concurrent change fails.
	SetSubjects(ctx context.Context, binding access.Binding, subjects []access.BindingSubject) error
	// Delete deletes the binding only if its UID still matches;
	// port.ErrNotFound, port.ErrConflict, or port.ErrForbidden.
	Delete(ctx context.Context, ref access.BindingRef) error
	// ListManaged lists bindings carrying all labels, directly from the API
	// server. An empty namespace lists all namespaces.
	ListManaged(ctx context.Context, namespace string, labels map[string]string) ([]access.Binding, error)
}

// SessionStore persists a session. It is bound to the session being
// reconciled.
type SessionStore interface {
	UpdateStatus(ctx context.Context, session *access.Session) error
	AddFinalizer(ctx context.Context, session *access.Session) error
	RemoveFinalizer(ctx context.Context, session *access.Session) error
}

// Event types.
const (
	EventNormal  = "Normal"
	EventWarning = "Warning"
)

// Events records human-readable lifecycle events for the session being
// reconciled. Events are operational information, not an audit trail.
type Events interface {
	Event(eventType, reason, messageFmt string, args ...any)
}

// Transition is a lifecycle transition reported to telemetry.
type Transition int

const (
	TransitionActivated Transition = iota
	TransitionDenied
	TransitionExpired
	TransitionRevoked
	TransitionSuspended
)

// BindingOperation is a binding write reported to telemetry.
type BindingOperation int

const (
	OperationReserve BindingOperation = iota
	OperationRecoverReservation
	OperationGrant
	OperationCleanup
)

// Telemetry receives operational signals. It must never be used as an audit
// source or to decide whether access is granted. Implementations derive their
// labels from the session synchronously during the call.
type Telemetry interface {
	Transition(Transition, *access.Session)
	BindingOperation(op BindingOperation, success bool, session *access.Session)
	BindingDrift(*access.Issue, *access.Session)
	CuratedRoleDrift(*access.Issue, *access.Session)
	RequestSourceIntegrity(*access.Issue, *access.Session)
	ExpiryCleanupLag(*access.Session, time.Duration)
}

type noTelemetry struct{}

func (noTelemetry) Transition(Transition, *access.Session)                   {}
func (noTelemetry) BindingOperation(BindingOperation, bool, *access.Session) {}
func (noTelemetry) BindingDrift(*access.Issue, *access.Session)              {}
func (noTelemetry) CuratedRoleDrift(*access.Issue, *access.Session)          {}
func (noTelemetry) RequestSourceIntegrity(*access.Issue, *access.Session)    {}
func (noTelemetry) ExpiryCleanupLag(*access.Session, time.Duration)          {}

type noEvents struct{}

func (noEvents) Event(string, string, string, ...any) {}
