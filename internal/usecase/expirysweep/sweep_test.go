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

package expirysweep

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/port"
)

var now = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func forbidden(namespace string) error {
	return port.Mark(port.ErrForbidden, fmt.Errorf("forbidden in namespace %s", namespace))
}

type fakeSessions struct {
	sessions []access.Session
	err      error
	// forbidden lists namespaces whose sessions may not be listed.
	forbidden map[string]bool
	listed    []string
}

func (f *fakeSessions) List(_ context.Context, namespace string) ([]access.Session, error) {
	f.listed = append(f.listed, namespace)
	if f.err != nil {
		return nil, f.err
	}
	if f.forbidden[namespace] {
		return nil, forbidden(namespace)
	}
	var found []access.Session
	for _, session := range f.sessions {
		if namespace == "" || session.Namespace == namespace {
			found = append(found, session)
		}
	}
	return found, nil
}

// fakeNamespaces reports the named namespaces as confirmed absent.
type fakeNamespaces map[string]bool

func (f fakeNamespaces) NamespaceAbsent(_ context.Context, namespace string) bool {
	return f[namespace]
}

type fakeBindings struct {
	objects   map[string]access.Binding
	deleteErr error
	deleted   []string
	// forbidden lists namespaces in which bindings may not be read.
	forbidden map[string]bool
	// afterList runs after ListManaged took its snapshot.
	afterList func()
}

func (f *fakeBindings) Get(_ context.Context, namespace, name string) (access.Binding, error) {
	if f.forbidden[namespace] {
		return access.Binding{}, forbidden(namespace)
	}
	if b, ok := f.objects[namespace+"/"+name]; ok {
		return b, nil
	}
	return access.Binding{}, port.Mark(port.ErrNotFound, fmt.Errorf("binding %s", name))
}

func (f *fakeBindings) ListManaged(_ context.Context, namespace string) ([]access.Binding, error) {
	if f.forbidden[namespace] {
		return nil, forbidden(namespace)
	}
	var managed []access.Binding
	for _, b := range f.objects {
		if b.Labels[access.ManagedByLabelKey] == access.ManagedByLabelValue && (namespace == "" || b.Namespace == namespace) {
			managed = append(managed, b)
		}
	}
	if f.afterList != nil {
		f.afterList()
	}
	return managed, nil
}

func (f *fakeBindings) Delete(_ context.Context, b access.Binding) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, b.Name)
	delete(f.objects, b.Namespace+"/"+b.Name)
	return nil
}

func expired(name string, ago time.Duration) access.Session {
	expiresAt := now.Add(-ago)
	return access.Session{
		Name: name, UID: name + "-uid",
		Status: access.SessionStatus{
			Phase: access.PhaseActive, ExpiresAt: &expiresAt,
			BindingRef: &access.BindingRef{Kind: access.RoleBindingKind, Namespace: "production", Name: "rb-" + name, UID: "uid-" + name},
		},
	}
}

func bindingOf(s access.Session) access.Binding {
	ref := s.Status.BindingRef
	return access.Binding{Kind: access.RoleBindingKind, Namespace: ref.Namespace, Name: ref.Name, UID: ref.UID, Version: "7"}
}

func sweeper(sessions []access.Session, bindings *fakeBindings) *Sweeper {
	return &Sweeper{
		Sessions: &fakeSessions{sessions: sessions}, Bindings: bindings, Grace: DefaultGrace,
		Clock: func() time.Time { return now }, Log: logr.Discard(),
	}
}

func sweep(t *testing.T, s *Sweeper) Report {
	t.Helper()
	report, err := s.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep() error = %v", err)
	}
	return report
}

func TestSweepRemovesOnlyDueBindings(t *testing.T) {
	due, fresh, inGrace := expired("due", 3*time.Minute), expired("fresh", -time.Hour), expired("grace", time.Minute)
	bindings := &fakeBindings{objects: map[string]access.Binding{}}
	for _, s := range []access.Session{due, fresh, inGrace} {
		b := bindingOf(s)
		bindings.objects[b.Namespace+"/"+b.Name] = b
	}

	report := sweep(t, sweeper([]access.Session{due, fresh, inGrace}, bindings))
	if len(report.Removed) != 1 || report.Removed[0].Session != "due" || report.Failed() {
		t.Fatalf("report = %#v, want exactly the due session removed", report)
	}
	if len(bindings.objects) != 2 {
		t.Fatalf("remaining bindings = %d, want 2", len(bindings.objects))
	}
}

func TestSweepRefusesUnprovableBindings(t *testing.T) {
	replaced := expired("replaced", time.Hour)
	foreign := bindingOf(replaced)
	foreign.UID = "someone-elses"

	noRef := expired("noref", time.Hour)
	noRef.Status.BindingRef = nil

	outOfScope := expired("scope", time.Hour)
	outOfScope.Status.BindingRef.Namespace = "kube-system"

	incomplete := expired("incomplete", time.Hour)
	incomplete.Status.BindingRef.UID = ""

	bindings := &fakeBindings{objects: map[string]access.Binding{foreign.Namespace + "/" + foreign.Name: foreign}}
	s := sweeper([]access.Session{replaced, noRef, outOfScope, incomplete}, bindings)
	s.Scope = access.NamespaceScope{"production": {}}

	report := sweep(t, s)
	if len(report.Refused) != 4 || len(report.Removed) != 0 || len(bindings.deleted) != 0 {
		t.Fatalf("report = %#v, deleted = %v, want four refusals and no deletion", report, bindings.deleted)
	}
}

func TestSweepIgnoresTerminalSessionWithoutReference(t *testing.T) {
	s := expired("done", time.Hour)
	s.Status.BindingRef = nil
	s.Status.Phase = access.PhaseExpired
	if report := sweep(t, sweeper([]access.Session{s}, &fakeBindings{objects: map[string]access.Binding{}})); len(report.Refused) != 0 {
		t.Fatalf("report = %#v, want nothing to do", report)
	}
}

func TestSweepTreatsVanishedBindingAsDone(t *testing.T) {
	s := expired("gone", time.Hour)
	bindings := &fakeBindings{
		objects:   map[string]access.Binding{"production/rb-gone": bindingOf(s)},
		deleteErr: port.Mark(port.ErrNotFound, errors.New("gone")),
	}
	if report := sweep(t, sweeper([]access.Session{s}, bindings)); len(report.Removed) != 0 || report.Failed() {
		t.Fatalf("report = %#v, want nothing to report", report)
	}
}

func TestSweepRefusesBindingChangedBeforeDelete(t *testing.T) {
	s := expired("raced", time.Hour)
	bindings := &fakeBindings{
		objects:   map[string]access.Binding{"production/rb-raced": bindingOf(s)},
		deleteErr: port.Mark(port.ErrConflict, errors.New("changed")),
	}
	if report := sweep(t, sweeper([]access.Session{s}, bindings)); !report.Failed() {
		t.Fatalf("report = %#v, want refusal", report)
	}
}

func TestSweepDryRunDeletesNothing(t *testing.T) {
	s := expired("dry", time.Hour)
	bindings := &fakeBindings{objects: map[string]access.Binding{"production/rb-dry": bindingOf(s)}}
	sw := sweeper([]access.Session{s}, bindings)
	sw.DryRun = true
	if report := sweep(t, sw); len(report.Removed) != 1 || len(bindings.deleted) != 0 {
		t.Fatalf("report = %#v, deleted = %v, want planned removal only", report, bindings.deleted)
	}
}

func TestSweepFailsWhenSessionsCannotBeListed(t *testing.T) {
	sw := sweeper(nil, &fakeBindings{})
	sw.Sessions = &fakeSessions{err: errors.New("unavailable")}
	if _, err := sw.Sweep(context.Background()); err == nil {
		t.Fatal("Sweep() error = nil, want error")
	}
}

func managedBinding(session access.Session, namespace, name string) access.Binding {
	return access.Binding{
		Kind: access.RoleBindingKind, Namespace: namespace, Name: name, UID: "uid-" + name, Version: "3",
		Labels: session.ManagedLabels(),
	}
}

func TestSweepRemovesBindingsOfMissingSessions(t *testing.T) {
	live := access.Session{Name: "live", Namespace: "breakglass-access", UID: "live-uid"}
	deleted := access.Session{Name: "deleted", Namespace: "breakglass-access", UID: "deleted-uid"}
	recreated := access.Session{Name: "live", Namespace: "breakglass-access", UID: "old-uid"}

	bindings := &fakeBindings{objects: map[string]access.Binding{}}
	for _, b := range []access.Binding{
		managedBinding(live, "production", "rb-live"),
		managedBinding(deleted, "production", "rb-deleted"),
		managedBinding(recreated, "production", "rb-recreated"),
	} {
		bindings.objects[b.Namespace+"/"+b.Name] = b
	}

	report := sweep(t, sweeper([]access.Session{live}, bindings))
	if len(report.Removed) != 2 || report.Failed() {
		t.Fatalf("report = %#v, want the two orphaned bindings removed", report)
	}
	if _, ok := bindings.objects["production/rb-live"]; !ok || len(bindings.objects) != 1 {
		t.Fatalf("remaining bindings = %v, want only the live session's binding", bindings.objects)
	}
}

func TestSweepIgnoresManagedBindingWithoutSessionIdentity(t *testing.T) {
	incomplete := managedBinding(access.Session{Name: "x", UID: "x-uid"}, "production", "rb-x")
	delete(incomplete.Labels, access.SessionNamespaceLabelKey)
	bindings := &fakeBindings{objects: map[string]access.Binding{"production/rb-x": incomplete}}

	report := sweep(t, sweeper(nil, bindings))
	if report.Failed() || len(report.Ignored) != 1 || len(report.Removed) != 0 || len(bindings.deleted) != 0 {
		t.Fatalf("report = %#v, deleted = %v, want one ignored binding, no failure, no deletion", report, bindings.deleted)
	}
}

func TestSweepRefusesOrphanOfSessionOutsideControlNamespaces(t *testing.T) {
	// The session may well be live: the guard's control namespaces can drift
	// from the manager's, and the sweep does not read sessions elsewhere.
	elsewhere := managedBinding(access.Session{Name: "s", Namespace: "team-b", UID: "s-uid"}, "production", "rb-s")
	bindings := &fakeBindings{objects: map[string]access.Binding{"production/rb-s": elsewhere}}
	sw := sweeper(nil, bindings)
	sw.Control = access.NamespaceScope{"team-a": {}}

	report := sweep(t, sw)
	if !report.Failed() || len(report.Refused) != 1 || len(report.Removed) != 0 || len(bindings.deleted) != 0 {
		t.Fatalf("report = %#v, deleted = %v, want a refusal and no deletion", report, bindings.deleted)
	}
}

func TestSweepListsSessionsAfterBindings(t *testing.T) {
	// A session created after the bindings were listed has its binding
	// created later still; it must never make an earlier binding look
	// orphaned, and its own binding cannot appear in the binding snapshot.
	created := access.Session{Name: "new", Namespace: "breakglass-access", UID: "new-uid"}
	bindings := &fakeBindings{objects: map[string]access.Binding{}}
	b := managedBinding(created, "production", "rb-new")
	bindings.objects[b.Namespace+"/"+b.Name] = b
	sessions := &fakeSessions{}
	// The binding is in the snapshot, so its session was created before the
	// snapshot; it only becomes visible to List if List runs afterwards.
	bindings.afterList = func() { sessions.sessions = []access.Session{created} }
	sw := sweeper(nil, bindings)
	sw.Sessions = sessions

	if report := sweep(t, sw); len(report.Removed) != 0 || len(bindings.deleted) != 0 {
		t.Fatalf("report = %#v, deleted = %v, want the live session's binding kept", report, bindings.deleted)
	}
}

func TestSweepLeavesOrphansOutsideScopeAlone(t *testing.T) {
	orphan := managedBinding(access.Session{Name: "gone", Namespace: "breakglass-access", UID: "gone-uid"}, "kube-system", "rb-gone")
	bindings := &fakeBindings{objects: map[string]access.Binding{"kube-system/rb-gone": orphan}}
	sw := sweeper(nil, bindings)
	sw.Scope = access.NamespaceScope{"production": {}}

	if report := sweep(t, sw); len(report.Removed) != 0 || report.Failed() || len(bindings.deleted) != 0 {
		t.Fatalf("report = %#v, want nothing outside the allowed namespaces touched", report)
	}
}

func TestSweepDryRunKeepsOrphans(t *testing.T) {
	orphan := managedBinding(access.Session{Name: "gone", Namespace: "breakglass-access", UID: "gone-uid"}, "production", "rb-gone")
	bindings := &fakeBindings{objects: map[string]access.Binding{"production/rb-gone": orphan}}
	sw := sweeper(nil, bindings)
	sw.DryRun = true

	if report := sweep(t, sw); len(report.Removed) != 1 || len(bindings.deleted) != 0 {
		t.Fatalf("report = %#v, deleted = %v, want planned removal only", report, bindings.deleted)
	}
}

// add stores bindings in the fake and returns it.
func (f *fakeBindings) add(bindings ...access.Binding) *fakeBindings {
	if f.objects == nil {
		f.objects = map[string]access.Binding{}
	}
	for _, b := range bindings {
		f.objects[b.Namespace+"/"+b.Name] = b
	}
	return f
}

// has reports whether the named binding still exists in production.
func (f *fakeBindings) has(name string) bool {
	_, ok := f.objects["production/"+name]
	return ok
}

func TestSweepTreatsDeletedTargetNamespaceAsEmpty(t *testing.T) {
	// The namespace and with it the guard's RoleBinding-read Role are gone:
	// listing there is Forbidden, the Namespace read is NotFound.
	expiredInDeleted := expired("in-deleted", time.Hour)
	expiredInDeleted.Status.BindingRef.Namespace = "staging"
	orphan := managedBinding(access.Session{Name: "gone", Namespace: "breakglass-access", UID: "gone-uid"}, "production", "rb-gone")
	due := expired("due", time.Hour)
	bindings := (&fakeBindings{forbidden: map[string]bool{"staging": true}}).add(orphan, bindingOf(due))
	sw := sweeper([]access.Session{expiredInDeleted, due}, bindings)
	sw.Scope = access.NamespaceScope{"production": {}, "staging": {}}
	sw.Namespaces = fakeNamespaces{"staging": true}

	report := sweep(t, sw)
	if report.Failed() || len(report.Unreadable) != 0 || len(report.Removed) != 2 {
		t.Fatalf("report = %#v, want the deleted namespace treated as empty and production swept", report)
	}
	if bindings.has("rb-gone") || bindings.has("rb-due") {
		t.Fatalf("remaining bindings = %v, want production swept", bindings.objects)
	}
}

func TestSweepTreatsDeletedControlNamespaceAsEmpty(t *testing.T) {
	live := access.Session{Name: "live", Namespace: "team-a", UID: "live-uid"}
	inDeleted := access.Session{Name: "s", Namespace: "team-b", UID: "s-uid"}
	goneInLive := access.Session{Name: "gone", Namespace: "team-a", UID: "gone-uid"}
	bindings := (&fakeBindings{}).add(
		managedBinding(live, "production", "rb-live"),
		managedBinding(inDeleted, "production", "rb-deleted-ns"),
		managedBinding(goneInLive, "production", "rb-gone"),
	)
	sw := sweeper(nil, bindings)
	sw.Sessions = &fakeSessions{sessions: []access.Session{live}, forbidden: map[string]bool{"team-b": true}}
	sw.Control = access.NamespaceScope{"team-a": {}, "team-b": {}}
	sw.Namespaces = fakeNamespaces{"team-b": true}

	report := sweep(t, sw)
	if report.Failed() || len(report.Removed) != 2 {
		t.Fatalf("report = %#v, want both orphans removed and no failure", report)
	}
	if !bindings.has("rb-live") || len(bindings.objects) != 1 {
		t.Fatalf("remaining bindings = %v, want only the live session's binding", bindings.objects)
	}
}

func TestSweepReportsForbiddenNamespaceThatStillExists(t *testing.T) {
	// Forbidden alone, for example while a namespace is terminating, is not
	// evidence of absence: team-b may still hold live sessions.
	live := access.Session{Name: "live", Namespace: "team-a", UID: "live-uid"}
	unseen := access.Session{Name: "unseen", Namespace: "team-b", UID: "unseen-uid"}
	goneInLive := access.Session{Name: "gone", Namespace: "team-a", UID: "gone-uid"}
	due := expired("due", time.Hour)
	due.Namespace = "team-a"
	unreadableTarget := expired("unreadable-target", time.Hour)
	unreadableTarget.Namespace = "team-a"
	unreadableTarget.Status.BindingRef.Namespace = "staging"
	bindings := (&fakeBindings{forbidden: map[string]bool{"staging": true}}).add(
		managedBinding(live, "production", "rb-live"),
		managedBinding(unseen, "production", "rb-unseen"),
		managedBinding(goneInLive, "production", "rb-gone"),
		bindingOf(due),
	)
	sw := sweeper(nil, bindings)
	sw.Sessions = &fakeSessions{sessions: []access.Session{live, due, unreadableTarget}, forbidden: map[string]bool{"team-b": true}}
	sw.Control = access.NamespaceScope{"team-a": {}, "team-b": {}}
	sw.Scope = access.NamespaceScope{"production": {}, "staging": {}}
	sw.Namespaces = fakeNamespaces{}

	report := sweep(t, sw)
	if !report.Failed() || len(report.Unreadable) != 2 {
		t.Fatalf("report = %#v, want both forbidden namespaces reported unreadable", report)
	}
	if !bindings.has("rb-unseen") || !bindings.has("rb-live") {
		t.Fatalf("remaining bindings = %v, want the binding claiming the unreadable namespace kept", bindings.objects)
	}
	if bindings.has("rb-gone") || bindings.has("rb-due") {
		t.Fatalf("remaining bindings = %v, want the readable namespaces still swept", bindings.objects)
	}
	refused := map[string]string{}
	for _, finding := range report.Refused {
		refused[finding.Binding] = finding.Reason
	}
	if refused["rb-unseen"] != "session namespace could not be read" ||
		refused["rb-unreadable-target"] != "binding could not be read" || len(refused) != 2 {
		t.Fatalf("refused = %v, want the unseen session's binding and the unreadable binding refused", refused)
	}
}

func TestSweepNeverAssumesAbsenceWithoutObserver(t *testing.T) {
	orphan := managedBinding(access.Session{Name: "s", Namespace: "team-b", UID: "s-uid"}, "production", "rb-s")
	bindings := (&fakeBindings{}).add(orphan)
	sw := sweeper(nil, bindings)
	sw.Sessions = &fakeSessions{forbidden: map[string]bool{"team-b": true}}
	sw.Control = access.NamespaceScope{"team-b": {}}

	report := sweep(t, sw)
	if !report.Failed() || len(report.Unreadable) != 1 || len(bindings.deleted) != 0 {
		t.Fatalf("report = %#v, deleted = %v, want an unreadable namespace and no deletion", report, bindings.deleted)
	}
}

func TestSweepFailsWhenClusterWideListIsForbidden(t *testing.T) {
	// Without explicit namespaces absence cannot be established.
	sw := sweeper(nil, &fakeBindings{forbidden: map[string]bool{"": true}})
	sw.Namespaces = fakeNamespaces{"": true}
	if _, err := sw.Sweep(context.Background()); err == nil {
		t.Fatal("Sweep() error = nil, want error")
	}
	sw = sweeper(nil, &fakeBindings{})
	sw.Sessions = &fakeSessions{forbidden: map[string]bool{"": true}}
	sw.Namespaces = fakeNamespaces{"": true}
	if _, err := sw.Sweep(context.Background()); err == nil {
		t.Fatal("Sweep() error = nil, want error")
	}
}

func TestSweepStopsWhenContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sw := sweeper(nil, &fakeBindings{})
	sw.Sessions = &fakeSessions{err: context.Canceled}
	sw.Control = access.NamespaceScope{"team-a": {}}
	if _, err := sw.Sweep(ctx); err == nil {
		t.Fatal("Sweep() error = nil, want error after the context ended")
	}
}

// recordingSessions records each session list in a shared order.
type recordingSessions struct {
	order *[]string
}

func (r recordingSessions) List(_ context.Context, namespace string) ([]access.Session, error) {
	*r.order = append(*r.order, "sessions:"+namespace)
	return nil, nil
}

func TestSweepListsAllTargetNamespacesBeforeSessions(t *testing.T) {
	var order []string
	bindings := &fakeBindings{forbidden: map[string]bool{"staging": true}}
	// afterList does not run for the forbidden namespace.
	bindings.afterList = func() { order = append(order, "bindings") }
	sw := sweeper(nil, bindings)
	sw.Sessions = recordingSessions{order: &order}
	sw.Scope = access.NamespaceScope{"production": {}, "staging": {}, "zeta": {}}
	sw.Control = access.NamespaceScope{"team-a": {}, "team-b": {}}
	sw.Namespaces = fakeNamespaces{"staging": true}

	sweep(t, sw)
	want := []string{"bindings", "bindings", "sessions:team-a", "sessions:team-b"}
	if !slices.Equal(order, want) {
		t.Fatalf("list order = %q, want %q", order, want)
	}
}
