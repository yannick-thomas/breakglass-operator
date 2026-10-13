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

// Package expiryguard removes RoleBindings of expired BreakGlassSessions
// independently of the controller manager.
//
// The guard is a second, deliberately small enforcement point for expiry
// (SR-06). It never creates, adopts, repairs, or extends access and never
// writes session state. It only deletes the exact binding identity (kind,
// namespace, name, and UID) that the controller persisted in
// status.bindingRef, and only after status.expiresAt plus a grace period. A
// binding that does not match that identity is reported, never touched.
package expiryguard

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
)

// DefaultGrace leaves the controller time to perform the normal expiry
// cleanup, so the guard only acts when the controller is behind or down.
const DefaultGrace = 2 * time.Minute

const roleBindingKind = "RoleBinding"

// Guard performs expiry sweeps.
type Guard struct {
	Client client.Client
	// Grace is the time after status.expiresAt before the guard acts.
	Grace time.Duration
	// AllowedNamespaces restricts the namespaces the guard acts in. Empty
	// permits all namespaces and mirrors the manager's development default.
	AllowedNamespaces map[string]struct{}
	// DryRun reports what would be removed without deleting anything.
	DryRun bool
	Now    func() time.Time
	Log    logr.Logger
}

// Finding describes one binding the guard acted on or refused to act on.
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
	// the recorded one. They need a human; the guard never resolves them.
	Refused []Finding
}

// Failed reports whether the sweep left anything for a human to look at.
func (r Report) Failed() bool {
	return len(r.Refused) > 0
}

// Sweep inspects every session once. It returns an error only when it could
// not complete the sweep; per-session problems are collected in the report.
func (g *Guard) Sweep(ctx context.Context) (Report, error) {
	var sessions accessv1alpha1.BreakGlassSessionList
	if err := g.Client.List(ctx, &sessions); err != nil {
		return Report{}, fmt.Errorf("list BreakGlassSessions: %w", err)
	}

	now := g.now()
	var report Report
	for i := range sessions.Items {
		session := &sessions.Items[i]
		if !g.due(session, now) {
			continue
		}
		finding, removed, err := g.enforce(ctx, session)
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

func (g *Guard) due(session *accessv1alpha1.BreakGlassSession, now time.Time) bool {
	expiresAt := session.Status.ExpiresAt
	return expiresAt != nil && !now.Before(expiresAt.Add(g.Grace))
}

// enforce returns a nil finding when there is nothing left to do, for example
// because the controller already removed the binding.
func (g *Guard) enforce(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (*Finding, bool, error) {
	ref := session.Status.BindingRef
	if ref == nil {
		// Without a persisted identity nothing can be proven. A terminal session
		// has nothing left to remove; an active one needs a human.
		if session.Status.Phase != accessv1alpha1.PhaseActive {
			return nil, false, nil
		}
		return g.refuse(session, "", "", "active session has no recorded binding identity"), false, nil
	}

	if ref.Kind != roleBindingKind || ref.Name == "" || ref.Namespace == "" || ref.UID == "" {
		return g.refuse(session, ref.Namespace, ref.Name, "recorded binding identity is incomplete"), false, nil
	}
	if !g.namespaceAllowed(ref.Namespace) {
		return g.refuse(session, ref.Namespace, ref.Name, "binding namespace is outside the allowed target namespaces"), false, nil
	}

	binding := &rbacv1.RoleBinding{}
	if err := g.Client.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, binding); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("get RoleBinding %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	if string(binding.UID) != ref.UID {
		// A same-named object with another UID is not the binding the controller
		// created. Deleting it could hide evidence or break unrelated RBAC.
		return g.refuse(session, ref.Namespace, ref.Name, "live binding UID does not match the recorded UID"), false, nil
	}

	finding := &Finding{Session: session.Name, Namespace: ref.Namespace, Binding: ref.Name, Reason: "session expired"}
	log := g.Log.WithValues("session", session.Name, "namespace", ref.Namespace, "roleBinding", ref.Name,
		"uid", ref.UID, "expiresAt", session.Status.ExpiresAt.UTC().Format(time.RFC3339))
	if g.DryRun {
		log.Info("Would delete RoleBinding of expired BreakGlassSession")
		return finding, true, nil
	}

	uid := types.UID(ref.UID)
	err := g.Client.Delete(ctx, binding, client.Preconditions{UID: &uid, ResourceVersion: &binding.ResourceVersion})
	switch {
	case err == nil:
		log.Info("Deleted RoleBinding of expired BreakGlassSession")
		return finding, true, nil
	case apierrors.IsNotFound(err):
		return nil, false, nil
	case apierrors.IsConflict(err):
		// Changed between read and delete; the next sweep re-verifies it.
		return g.refuse(session, ref.Namespace, ref.Name, "binding changed before it could be deleted"), false, nil
	default:
		return nil, false, fmt.Errorf("delete RoleBinding %s/%s: %w", ref.Namespace, ref.Name, err)
	}
}

func (g *Guard) refuse(session *accessv1alpha1.BreakGlassSession, namespace, name, reason string) *Finding {
	g.Log.Info("Refused to delete RoleBinding of expired BreakGlassSession",
		"session", session.Name, "namespace", namespace, "roleBinding", name, "reason", reason)
	return &Finding{Session: session.Name, Namespace: namespace, Binding: name, Reason: reason}
}

func (g *Guard) namespaceAllowed(namespace string) bool {
	if len(g.AllowedNamespaces) == 0 {
		return true
	}
	_, ok := g.AllowedNamespaces[namespace]
	return ok
}

func (g *Guard) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// ParseNamespaces parses a comma-separated namespace list. Empty means all.
func ParseNamespaces(value string) (map[string]struct{}, error) {
	allowed := make(map[string]struct{})
	if value == "" {
		return allowed, nil
	}
	for raw := range strings.SplitSeq(value, ",") {
		namespace := strings.TrimSpace(raw)
		if namespace == "" {
			return nil, fmt.Errorf("namespace list contains an empty namespace")
		}
		if errs := validation.IsDNS1123Label(namespace); len(errs) > 0 {
			return nil, fmt.Errorf("invalid namespace %q: %s", namespace, strings.Join(errs, "; "))
		}
		allowed[namespace] = struct{}{}
	}
	return allowed, nil
}
