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

// These tests drive the lifecycle through its ports with in-memory fakes.
// They need no Kubernetes client, API server, or envtest. The Kubernetes
// adapter is covered separately by the controller tests.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/port"
)

var start = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

type fakePolicy struct {
	profiles map[string]access.Profile
	roles    map[string]access.Role
}

func (f *fakePolicy) Profile(_ context.Context, name string) (access.Profile, error) {
	if p, ok := f.profiles[name]; ok {
		return p, nil
	}
	return access.Profile{}, port.Mark(port.ErrNotFound, fmt.Errorf("profile %s", name))
}

func (f *fakePolicy) Role(_ context.Context, name string) (access.Role, error) {
	if r, ok := f.roles[name]; ok {
		return r, nil
	}
	return access.Role{}, port.Mark(port.ErrNotFound, fmt.Errorf("role %s", name))
}

func (f *fakePolicy) Request(context.Context, string) (access.Request, error) {
	return access.Request{}, port.Mark(port.ErrNotFound, fmt.Errorf("request"))
}

func (f *fakePolicy) Approval(context.Context, string) (access.Approval, error) {
	return access.Approval{}, port.Mark(port.ErrNotFound, fmt.Errorf("approval"))
}

func (f *fakePolicy) NamespaceAbsent(context.Context, string) bool { return false }

type fakeBindings struct {
	objects map[string]access.Binding
	nextUID int
}

func key(namespace, name string) string { return namespace + "/" + name }

func (f *fakeBindings) Create(_ context.Context, d BindingDraft) (access.Binding, error) {
	if _, exists := f.objects[key(d.Namespace, d.Name)]; exists {
		return access.Binding{}, port.Mark(port.ErrAlreadyExists, fmt.Errorf("binding %s", d.Name))
	}
	f.nextUID++
	b := access.Binding{
		Kind: access.RoleBindingKind, Name: d.Name, Namespace: d.Namespace,
		UID: fmt.Sprintf("binding-%d", f.nextUID), Labels: d.Labels,
		RoleRef: d.RoleRef, Subjects: d.Subjects, Version: "1",
	}
	f.objects[key(d.Namespace, d.Name)] = b
	return b, nil
}

func (f *fakeBindings) Get(_ context.Context, namespace, name string) (access.Binding, error) {
	if b, ok := f.objects[key(namespace, name)]; ok {
		return b, nil
	}
	return access.Binding{}, port.Mark(port.ErrNotFound, fmt.Errorf("binding %s", name))
}

func (f *fakeBindings) SetSubjects(_ context.Context, b access.Binding, subjects []access.BindingSubject) error {
	stored, ok := f.objects[key(b.Namespace, b.Name)]
	if !ok || stored.UID != b.UID || stored.Version != b.Version {
		return port.Mark(port.ErrConflict, fmt.Errorf("binding %s changed", b.Name))
	}
	stored.Subjects = subjects
	stored.Version += "+"
	f.objects[key(b.Namespace, b.Name)] = stored
	return nil
}

func (f *fakeBindings) Delete(_ context.Context, ref access.BindingRef) error {
	stored, ok := f.objects[key(ref.Namespace, ref.Name)]
	if !ok {
		return port.Mark(port.ErrNotFound, fmt.Errorf("binding %s", ref.Name))
	}
	if stored.UID != ref.UID {
		return port.Mark(port.ErrConflict, fmt.Errorf("binding %s UID changed", ref.Name))
	}
	delete(f.objects, key(ref.Namespace, ref.Name))
	return nil
}

func (f *fakeBindings) ListManaged(context.Context, string, map[string]string) ([]access.Binding, error) {
	return nil, nil
}

type fakeStore struct{ writes int }

func (f *fakeStore) UpdateStatus(context.Context, *access.Session) error { f.writes++; return nil }
func (f *fakeStore) AddFinalizer(_ context.Context, s *access.Session) error {
	s.HasFinalizer = true
	return nil
}
func (f *fakeStore) RemoveFinalizer(_ context.Context, s *access.Session) error {
	s.HasFinalizer = false
	return nil
}

func newFixture() (*Lifecycle, *fakeBindings, *time.Time) {
	now := start
	bindings := &fakeBindings{objects: map[string]access.Binding{}}
	l := &Lifecycle{
		Policy: &fakePolicy{
			profiles: map[string]access.Profile{"observer": {
				Name: "observer", Namespace: "breakglass-access", UID: "profile-uid", RoleRef: access.RoleRef{Kind: access.ClusterRoleKind, Name: "pod-observer"},
				TargetNamespace: "production", MaxDuration: "30m",
			}},
			roles: map[string]access.Role{"pod-observer": {Name: "pod-observer", UID: "role-uid", RulesHash: "hash"}},
		},
		Bindings: bindings,
		Clock:    func() time.Time { return now },
	}
	return l, bindings, &now
}

func newSession() *access.Session {
	return &access.Session{
		Name: "incident", Namespace: "breakglass-access", UID: "session-uid",
		Spec: access.SessionSpec{
			AccessProfile: "observer", AccessProfileUID: "profile-uid",
			Subject:  access.Subject{Kind: access.SubjectKindUser, Name: "jane@example.com"},
			Duration: "20m", Reason: "INC-1092",
		},
	}
}

func reconcile(t *testing.T, l *Lifecycle, s *access.Session, store *fakeStore) Result {
	t.Helper()
	result, err := l.Reconcile(context.Background(), s, store, nil)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	return result
}

func TestActivationReservesBeforeGrantingAndExpires(t *testing.T) {
	l, bindings, now := newFixture()
	s, store := newSession(), &fakeStore{}

	reconcile(t, l, s, store) // finalizer
	reconcile(t, l, s, store) // reserve
	if s.Status.Phase != access.PhasePending || s.Status.BindingRef == nil {
		t.Fatalf("status = %#v, want a recorded reservation", s.Status)
	}
	reserved, _ := bindings.Get(context.Background(), "production", s.Status.BindingRef.Name)
	if len(reserved.Subjects) != 0 {
		t.Fatal("the reservation must not grant access before its UID is persisted")
	}

	result := reconcile(t, l, s, store) // promote
	granted, _ := bindings.Get(context.Background(), "production", s.Status.BindingRef.Name)
	if s.Status.Phase != access.PhaseActive || len(granted.Subjects) != 1 || granted.Subjects[0] != s.ExpectedSubject() {
		t.Fatalf("status = %#v, binding = %#v, want active grant", s.Status, granted)
	}
	if result.RequeueAfter != DefaultIntegrityCheckInterval {
		t.Fatalf("RequeueAfter = %v, want the integrity interval", result.RequeueAfter)
	}

	*now = now.Add(20 * time.Minute)
	reconcile(t, l, s, store)
	if s.Status.Phase != access.PhaseExpired || len(bindings.objects) != 0 {
		t.Fatalf("phase = %s, bindings = %d, want expired and removed", s.Status.Phase, len(bindings.objects))
	}
}

func TestTamperedBindingSuspendsWithoutRepair(t *testing.T) {
	l, bindings, _ := newFixture()
	s, store := newSession(), &fakeStore{}
	for range 3 {
		reconcile(t, l, s, store)
	}

	k := key("production", s.Status.BindingRef.Name)
	tampered := bindings.objects[k]
	tampered.Subjects = append(tampered.Subjects, access.BindingSubject{Kind: "Group", Name: "everyone"})
	bindings.objects[k] = tampered

	reconcile(t, l, s, store)
	if s.Status.Phase != access.PhaseSuspended {
		t.Fatalf("phase = %s, want Suspended", s.Status.Phase)
	}
	if _, exists := bindings.objects[k]; exists {
		t.Fatal("the exact recorded binding must be removed on suspension")
	}
}

func TestReplacementBindingIsNeverDeleted(t *testing.T) {
	l, bindings, now := newFixture()
	s, store := newSession(), &fakeStore{}
	for range 3 {
		reconcile(t, l, s, store)
	}
	k := key("production", s.Status.BindingRef.Name)
	replacement := bindings.objects[k]
	replacement.UID = "someone-elses"
	bindings.objects[k] = replacement

	*now = now.Add(time.Hour)
	reconcile(t, l, s, store)
	if _, exists := bindings.objects[k]; !exists {
		t.Fatal("an object with another UID must never be deleted")
	}
	if c := access.FindCondition(s.Status.Conditions, access.ConditionBindingIntegrity); c == nil || c.Status != access.ConditionFalse {
		t.Fatalf("BindingIntegrity = %#v, want False", c)
	}
}

func TestDeniedProfileNeverCreatesABinding(t *testing.T) {
	l, bindings, _ := newFixture()
	s, store := newSession(), &fakeStore{}
	s.Spec.Duration = "4h"
	reconcile(t, l, s, store)
	reconcile(t, l, s, store)
	if s.Status.Phase != access.PhaseDenied || len(bindings.objects) != 0 {
		t.Fatalf("phase = %s, bindings = %d, want Denied without binding", s.Status.Phase, len(bindings.objects))
	}
}
