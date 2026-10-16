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

// Package expirysweep removes the bindings of expired sessions independently
// of the session lifecycle (SR-06).
//
// It is a second, deliberately small enforcement point for expiry. It never
// creates, adopts, repairs, or extends access and never writes session state.
// It only deletes the exact binding identity (kind, namespace, name, and UID)
// recorded in the session's status, and only after the expiry plus a grace
// period. A binding that does not match that identity is reported, never
// touched.
//
// A session lives in a control namespace and its binding in a target
// namespace, so no owner reference lets the garbage collector remove a
// binding whose session is gone (ADR-004). The sweep therefore also deletes
// managed bindings whose labelled session no longer exists in its control
// namespace. Such a binding cannot be the recorded binding of any live
// session. A binding labelled for a session outside the control namespaces is
// reported, never touched: the sweep cannot read that session, and the
// guard's control namespaces may simply have drifted from the manager's. A
// managed binding without a complete session identity is ignored: it proves
// nothing about any session, and anyone able to create RoleBindings in a
// target namespace can create one.
//
// Sessions are listed per control namespace and bindings per target
// namespace, so one namespace that cannot be read does not stop the sweep in
// the others. Namespaced RBAC disappears with its namespace, so listing a
// deleted namespace returns Forbidden. Such a namespace counts as empty only
// when a direct read of the Namespace returns NotFound; Forbidden alone, any
// other error, or a terminating namespace is never evidence of absence. A
// namespace that cannot be read and is not confirmed absent is reported as
// unreadable. A control namespace that is unreadable may still hold live
// sessions, so a binding claiming a session there is refused, never deleted
// as an orphan.
package expirysweep

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-logr/logr"

	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/port"
)

// DefaultGrace leaves the session lifecycle time to perform the normal expiry
// cleanup, so the sweep only acts when the controller is behind or down.
const DefaultGrace = 2 * time.Minute

// SessionSource reads sessions as stored by the API server.
type SessionSource interface {
	// List lists the sessions in one namespace. An empty namespace lists all
	// namespaces. A missing permission is reported as port.ErrForbidden.
	List(ctx context.Context, namespace string) ([]access.Session, error)
}

// NamespaceObserver confirms that a namespace no longer exists.
type NamespaceObserver interface {
	// NamespaceAbsent reports true only when a direct read of the Namespace
	// returns NotFound. Forbidden, any other error, and a terminating
	// namespace all report false.
	NamespaceAbsent(ctx context.Context, namespace string) bool
}

// BindingGateway reads and deletes bindings.
type BindingGateway interface {
	// Get returns port.ErrNotFound if the binding does not exist and
	// port.ErrForbidden if it may not be read.
	Get(ctx context.Context, namespace, name string) (access.Binding, error)
	// ListManaged lists the bindings carrying the operator's managed-by
	// label. An empty namespace lists all namespaces. A missing permission
	// is reported as port.ErrForbidden.
	ListManaged(ctx context.Context, namespace string) ([]access.Binding, error)
	// Delete deletes exactly the observed binding: its UID and version must
	// still match. port.ErrNotFound or port.ErrConflict otherwise.
	Delete(ctx context.Context, binding access.Binding) error
}

// Sweeper performs expiry sweeps.
type Sweeper struct {
	Sessions SessionSource
	Bindings BindingGateway
	// Namespaces confirms deleted namespaces. Without it no namespace is
	// ever treated as absent.
	Namespaces NamespaceObserver
	// Grace is the time after expiry before a binding is removed.
	Grace time.Duration
	// Scope restricts the namespaces the sweep acts in.
	Scope access.NamespaceScope
	// Control is the set of namespaces in which sessions may exist. Sessions
	// are listed in each of them, or cluster-wide when it is empty. A binding
	// labelled for a session elsewhere is refused, never deleted.
	Control access.NamespaceScope
	// DryRun reports what would be removed without deleting anything.
	DryRun bool
	Clock  func() time.Time
	Log    logr.Logger
}

// Finding describes one binding the sweep acted on or refused to act on.
type Finding struct {
	Session   string
	Namespace string
	Binding   string
	Reason    string
}

// Report is the result of one sweep.
type Report struct {
	// Removed lists bindings deleted (or, in dry-run mode, due for deletion),
	// both of expired sessions and of sessions that no longer exist.
	Removed []Finding
	// Refused lists bindings that could not be proven to be removable. They
	// need a human; the sweep never resolves them.
	Refused []Finding
	// Ignored lists managed bindings without a complete session identity.
	// They are not counted as failures: such a binding claims no session the
	// sweep could check, and a namespace admin in a target namespace can
	// create one at will, so failing on it would let anyone there keep the
	// guard failing on every run and bury real refusals in noise.
	Ignored []Finding
	// Unreadable lists configured namespaces whose sessions or bindings
	// could not be listed and that are not confirmed absent. The sweep went
	// on in the other namespaces; nothing in these was enforced.
	Unreadable []Finding
}

// Failed reports whether the sweep left anything for a human to look at.
func (r Report) Failed() bool {
	return len(r.Refused) > 0 || len(r.Unreadable) > 0
}

// Sweep inspects every session and every managed binding in scope once. It
// returns an error only when it could not complete; per-binding and
// per-namespace problems are collected in the report.
func (s *Sweeper) Sweep(ctx context.Context) (Report, error) {
	var report Report
	// Managed bindings in every target namespace are listed before any
	// session. The controller creates a session before its binding, so every
	// binding seen here has its session visible in the later session lists,
	// and a session created in between cannot make its brand-new binding look
	// orphaned. Listing sessions first would open exactly that window. The
	// same session lists serve the expiry part, for which the order does not
	// matter.
	managed, err := s.listManaged(ctx, &report)
	if err != nil {
		return report, err
	}
	sessions, unreadableControl, err := s.listSessions(ctx, &report)
	if err != nil {
		return report, err
	}

	// A session is due once now >= expiresAt + grace.
	dueAt := s.now().Add(-s.Grace)
	existing := make(map[access.ManagedSessionRef]struct{}, len(sessions))
	for i := range sessions {
		session := &sessions[i]
		existing[access.ManagedSessionRef{Namespace: session.Namespace, Name: session.Name, UID: session.UID}] = struct{}{}
		if !session.Expired(dueAt) {
			continue
		}
		finding, removed, err := s.enforce(ctx, session)
		if err != nil {
			return report, err
		}
		report.add(finding, removed)
	}
	for _, binding := range managed {
		if err := s.enforceOrphan(ctx, binding, existing, unreadableControl, &report); err != nil {
			return report, err
		}
	}
	return report, nil
}

func (r *Report) add(finding *Finding, removed bool) {
	switch {
	case finding == nil:
	case removed:
		r.Removed = append(r.Removed, *finding)
	default:
		r.Refused = append(r.Refused, *finding)
	}
}

// listManaged lists the managed bindings in the namespaces the sweep may act
// in. Without explicit namespaces it lists cluster-wide, and any error ends
// the sweep: absence cannot be established for "all namespaces".
func (s *Sweeper) listManaged(ctx context.Context, report *Report) ([]access.Binding, error) {
	if !s.Scope.Explicit() {
		managed, err := s.Bindings.ListManaged(ctx, "")
		if err != nil {
			return nil, fmt.Errorf("list managed RoleBindings: %w", err)
		}
		return managed, nil
	}
	var managed []access.Binding
	for _, namespace := range sortedNamespaces(s.Scope) {
		bindings, err := s.Bindings.ListManaged(ctx, namespace)
		if err != nil {
			if _, err := s.isolate(ctx, namespace, "managed RoleBindings", err, report); err != nil {
				return nil, err
			}
			continue
		}
		managed = append(managed, bindings...)
	}
	return managed, nil
}

// listSessions lists the sessions in the control namespaces, or cluster-wide
// when none are configured. It also returns the control namespaces that could
// not be read: they may still hold live sessions.
func (s *Sweeper) listSessions(ctx context.Context, report *Report) ([]access.Session, map[string]struct{}, error) {
	if !s.Control.Explicit() {
		sessions, err := s.Sessions.List(ctx, "")
		if err != nil {
			return nil, nil, fmt.Errorf("list BreakGlassSessions: %w", err)
		}
		return sessions, nil, nil
	}
	var sessions []access.Session
	unreadable := map[string]struct{}{}
	for _, namespace := range sortedNamespaces(s.Control) {
		found, err := s.Sessions.List(ctx, namespace)
		if err != nil {
			skipped, err := s.isolate(ctx, namespace, "BreakGlassSessions", err, report)
			if err != nil {
				return nil, nil, err
			}
			if skipped {
				unreadable[namespace] = struct{}{}
			}
			continue
		}
		sessions = append(sessions, found...)
	}
	return sessions, unreadable, nil
}

// isolate handles a failed list in one configured namespace without stopping
// the sweep in the others. A namespace confirmed absent is empty: its
// namespaced RBAC, and with it the permission to list, went with it. Any
// other failure leaves the namespace unreadable (skipped is true) and
// reported. Only a cancelled or expired context ends the sweep.
func (s *Sweeper) isolate(ctx context.Context, namespace, what string, err error, report *Report) (bool, error) {
	if ctx.Err() != nil {
		return false, fmt.Errorf("list %s in namespace %s: %w", what, namespace, err)
	}
	if errors.Is(err, port.ErrForbidden) && s.namespaceAbsent(ctx, namespace) {
		s.Log.Info("Treated deleted Namespace as empty", "namespace", namespace, "resource", what)
		return false, nil
	}
	s.Log.Error(err, "Could not list resources in Namespace", "namespace", namespace, "resource", what)
	report.Unreadable = append(report.Unreadable, Finding{Namespace: namespace,
		Reason: fmt.Sprintf("could not list %s: %v", what, err)})
	return true, nil
}

func (s *Sweeper) namespaceAbsent(ctx context.Context, namespace string) bool {
	return s.Namespaces != nil && s.Namespaces.NamespaceAbsent(ctx, namespace)
}

func sortedNamespaces(scope access.NamespaceScope) []string {
	namespaces := make([]string, 0, len(scope))
	for namespace := range scope {
		namespaces = append(namespaces, namespace)
	}
	slices.Sort(namespaces)
	return namespaces
}

// enforceOrphan deletes a managed binding whose labelled session no longer
// exists, or exists only as a different object under the same name. existing
// holds the sessions listed after the binding was; unreadableControl the
// control namespaces whose sessions could not be listed.
func (s *Sweeper) enforceOrphan(ctx context.Context, binding access.Binding,
	existing map[access.ManagedSessionRef]struct{}, unreadableControl map[string]struct{}, report *Report) error {
	claimed, ok := binding.ManagedSession()
	if !ok {
		s.Log.Info("Ignored managed RoleBinding without complete BreakGlassSession identity",
			"namespace", binding.Namespace, "roleBinding", binding.Name)
		report.Ignored = append(report.Ignored, Finding{Namespace: binding.Namespace, Binding: binding.Name,
			Reason: "managed binding has no complete session identity"})
		return nil
	}
	if !s.Control.Allows(claimed.Namespace) {
		// The sweep does not read sessions there, so it cannot tell whether
		// the session is live; the control namespaces may have drifted from
		// the manager's.
		report.add(s.refuseOrphan(binding, claimed.Name, "session namespace is outside the control namespaces"), false)
		return nil
	}
	if _, ok := unreadableControl[claimed.Namespace]; ok {
		// The session may be live; the sweep just could not see it.
		report.add(s.refuseOrphan(binding, claimed.Name, "session namespace could not be read"), false)
		return nil
	}
	if _, ok := existing[claimed]; ok {
		return nil
	}

	finding := &Finding{Session: claimed.Name, Namespace: binding.Namespace, Binding: binding.Name, Reason: "session no longer exists"}
	log := s.Log.WithValues("session", claimed.Name, "sessionNamespace", claimed.Namespace,
		"namespace", binding.Namespace, "roleBinding", binding.Name, "uid", binding.UID)
	if s.DryRun {
		log.Info("Would delete RoleBinding of missing BreakGlassSession")
		report.add(finding, true)
		return nil
	}
	err := s.Bindings.Delete(ctx, binding)
	switch {
	case err == nil:
		log.Info("Deleted RoleBinding of missing BreakGlassSession")
		report.add(finding, true)
	case errors.Is(err, port.ErrNotFound):
	case errors.Is(err, port.ErrConflict):
		report.add(s.refuseOrphan(binding, claimed.Name, "binding changed before it could be deleted"), false)
	default:
		return fmt.Errorf("delete RoleBinding %s/%s: %w", binding.Namespace, binding.Name, err)
	}
	return nil
}

func (s *Sweeper) refuseOrphan(binding access.Binding, session, reason string) *Finding {
	s.Log.Info("Refused to delete managed RoleBinding", "session", session,
		"namespace", binding.Namespace, "roleBinding", binding.Name, "reason", reason)
	return &Finding{Session: session, Namespace: binding.Namespace, Binding: binding.Name, Reason: reason}
}

// enforce returns a nil finding when there is nothing left to do, for example
// because the controller already removed the binding.
func (s *Sweeper) enforce(ctx context.Context, session *access.Session) (*Finding, bool, error) {
	ref := session.Status.BindingRef
	if ref == nil {
		// Without a recorded identity nothing can be proven. A terminal session
		// has nothing left to remove; an active one needs a human.
		if session.Status.Phase != access.PhaseActive {
			return nil, false, nil
		}
		return s.refuse(session, "", "", "active session has no recorded binding identity"), false, nil
	}
	if ref.Kind != access.RoleBindingKind || ref.Name == "" || ref.Namespace == "" || ref.UID == "" {
		return s.refuse(session, ref.Namespace, ref.Name, "recorded binding identity is incomplete"), false, nil
	}
	if !s.Scope.Allows(ref.Namespace) {
		return s.refuse(session, ref.Namespace, ref.Name, "binding namespace is outside the allowed target namespaces"), false, nil
	}

	binding, err := s.Bindings.Get(ctx, ref.Namespace, ref.Name)
	switch {
	case err == nil:
	case errors.Is(err, port.ErrNotFound):
		return nil, false, nil
	case errors.Is(err, port.ErrForbidden) && s.namespaceAbsent(ctx, ref.Namespace):
		// The binding went with its namespace.
		return nil, false, nil
	case errors.Is(err, port.ErrForbidden):
		// Typically a target namespace whose RBAC is gone while the
		// namespace itself still exists, for example while terminating.
		return s.refuse(session, ref.Namespace, ref.Name, "binding could not be read"), false, nil
	default:
		return nil, false, fmt.Errorf("get RoleBinding %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	if binding.UID != ref.UID {
		// A same-named object with another UID is not the binding the
		// controller created. Deleting it could hide evidence or break
		// unrelated RBAC.
		return s.refuse(session, ref.Namespace, ref.Name, "live binding UID does not match the recorded UID"), false, nil
	}

	finding := &Finding{Session: session.Name, Namespace: ref.Namespace, Binding: ref.Name, Reason: "session expired"}
	log := s.Log.WithValues("session", session.Name, "namespace", ref.Namespace, "roleBinding", ref.Name,
		"uid", ref.UID, "expiresAt", session.Status.ExpiresAt.UTC().Format(time.RFC3339))
	if s.DryRun {
		log.Info("Would delete RoleBinding of expired BreakGlassSession")
		return finding, true, nil
	}

	err = s.Bindings.Delete(ctx, binding)
	switch {
	case err == nil:
		log.Info("Deleted RoleBinding of expired BreakGlassSession")
		return finding, true, nil
	case errors.Is(err, port.ErrNotFound):
		return nil, false, nil
	case errors.Is(err, port.ErrConflict):
		// Changed between read and delete; the next sweep re-verifies it.
		return s.refuse(session, ref.Namespace, ref.Name, "binding changed before it could be deleted"), false, nil
	default:
		return nil, false, fmt.Errorf("delete RoleBinding %s/%s: %w", ref.Namespace, ref.Name, err)
	}
}

func (s *Sweeper) refuse(session *access.Session, namespace, name, reason string) *Finding {
	s.Log.Info("Refused to delete RoleBinding of expired BreakGlassSession",
		"session", session.Name, "namespace", namespace, "roleBinding", name, "reason", reason)
	return &Finding{Session: session.Name, Namespace: namespace, Binding: name, Reason: reason}
}

func (s *Sweeper) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now()
}
