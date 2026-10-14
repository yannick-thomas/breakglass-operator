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
package expirysweep

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/port"
)

// DefaultGrace leaves the session lifecycle time to perform the normal expiry
// cleanup, so the sweep only acts when the controller is behind or down.
const DefaultGrace = 2 * time.Minute

// SessionSource lists sessions as stored by the API server.
type SessionSource interface {
	List(ctx context.Context) ([]access.Session, error)
}

// BindingGateway reads and deletes bindings.
type BindingGateway interface {
	// Get returns port.ErrNotFound if the binding does not exist.
	Get(ctx context.Context, namespace, name string) (access.Binding, error)
	// Delete deletes exactly the observed binding: its UID and version must
	// still match. port.ErrNotFound or port.ErrConflict otherwise.
	Delete(ctx context.Context, binding access.Binding) error
}

// Sweeper performs expiry sweeps.
type Sweeper struct {
	Sessions SessionSource
	Bindings BindingGateway
	// Grace is the time after expiry before a binding is removed.
	Grace time.Duration
	// Scope restricts the namespaces the sweep acts in.
	Scope access.NamespaceScope
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
	// Removed lists bindings deleted (or, in dry-run mode, due for deletion).
	Removed []Finding
	// Refused lists expired sessions whose binding could not be proven to be
	// the recorded one. They need a human; the sweep never resolves them.
	Refused []Finding
}

// Failed reports whether the sweep left anything for a human to look at.
func (r Report) Failed() bool {
	return len(r.Refused) > 0
}

// Sweep inspects every session once. It returns an error only when it could
// not complete; per-session problems are collected in the report.
func (s *Sweeper) Sweep(ctx context.Context) (Report, error) {
	sessions, err := s.Sessions.List(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("list BreakGlassSessions: %w", err)
	}

	// A session is due once now >= expiresAt + grace.
	dueAt := s.now().Add(-s.Grace)
	var report Report
	for i := range sessions {
		session := &sessions[i]
		if !session.Expired(dueAt) {
			continue
		}
		finding, removed, err := s.enforce(ctx, session)
		if err != nil {
			return report, err
		}
		switch {
		case finding == nil:
		case removed:
			report.Removed = append(report.Removed, *finding)
		default:
			report.Refused = append(report.Refused, *finding)
		}
	}
	return report, nil
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
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, false, nil
		}
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
