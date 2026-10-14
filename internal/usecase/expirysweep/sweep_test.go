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
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/port"
)

var now = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

type fakeSessions struct {
	sessions []access.Session
	err      error
}

func (f fakeSessions) List(context.Context) ([]access.Session, error) { return f.sessions, f.err }

type fakeBindings struct {
	objects   map[string]access.Binding
	deleteErr error
	deleted   []string
}

func (f *fakeBindings) Get(_ context.Context, namespace, name string) (access.Binding, error) {
	if b, ok := f.objects[namespace+"/"+name]; ok {
		return b, nil
	}
	return access.Binding{}, port.Mark(port.ErrNotFound, fmt.Errorf("binding %s", name))
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
		Sessions: fakeSessions{sessions: sessions}, Bindings: bindings, Grace: DefaultGrace,
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
	sw.Sessions = fakeSessions{err: errors.New("unavailable")}
	if _, err := sw.Sweep(context.Background()); err == nil {
		t.Fatal("Sweep() error = nil, want error")
	}
}
