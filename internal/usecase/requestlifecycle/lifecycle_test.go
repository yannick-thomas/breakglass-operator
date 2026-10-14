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

package requestlifecycle

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/port"
)

var created = time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)

type fakeApprovals map[string]access.Approval

func (f fakeApprovals) Approval(_ context.Context, name string) (access.Approval, error) {
	if a, ok := f[name]; ok {
		return a, nil
	}
	return access.Approval{}, port.Mark(port.ErrNotFound, fmt.Errorf("approval %s", name))
}

type fakeSessions struct {
	records map[string]SessionRecord
	creates int
}

func (f *fakeSessions) Get(_ context.Context, name string) (SessionRecord, error) {
	if r, ok := f.records[name]; ok {
		return r, nil
	}
	return SessionRecord{}, port.Mark(port.ErrNotFound, fmt.Errorf("session %s", name))
}

func (f *fakeSessions) Create(_ context.Context, name string, spec access.SessionSpec) (SessionRecord, error) {
	f.creates++
	r := SessionRecord{Name: name, UID: "session-uid", RequestRef: spec.RequestRef}
	f.records[name] = r
	return r, nil
}

// fakeStore persists by copying, so "changed" means different from the last
// write, as with the API server.
type fakeStore struct {
	stored *access.RequestStatus
	writes int
}

func (f *fakeStore) UpdateStatusIfChanged(_ context.Context, r *access.Request) (bool, error) {
	if f.stored != nil && fmt.Sprintf("%+v", *f.stored) == fmt.Sprintf("%+v", r.Status) {
		return false, nil
	}
	status := r.Status
	f.stored = &status
	f.writes++
	return true, nil
}

type recordedTransitions []access.RequestPhase

func (r *recordedTransitions) Transition(p access.RequestPhase) { *r = append(*r, p) }

func newRequest() *access.Request {
	return &access.Request{
		Name: "bgr", UID: "request-uid", CreatedAt: created,
		AccessProfile: "observer", AccessProfileUID: "profile-uid",
		Requester: access.Subject{Kind: access.SubjectKindUser, Name: "jane@example.com"},
		Duration:  "20m", Reason: "INC-1092", RequestTTL: "15m",
	}
}

func approvalFor(r *access.Request, decision access.Decision, approver string) access.Approval {
	return access.Approval{
		Name: r.ApprovalName(), UID: "approval-uid", RequestRef: r.Ref(), Decision: decision,
		Approver: access.Subject{Kind: access.SubjectKindUser, Name: approver},
	}
}

type fixture struct {
	lifecycle   *Lifecycle
	sessions    *fakeSessions
	store       *fakeStore
	transitions *recordedTransitions
	now         time.Time
}

func newFixture(approvals fakeApprovals) *fixture {
	f := &fixture{
		sessions:    &fakeSessions{records: map[string]SessionRecord{}},
		store:       &fakeStore{},
		transitions: &recordedTransitions{},
		now:         created.Add(time.Minute),
	}
	f.lifecycle = &Lifecycle{
		Approvals: approvals, Sessions: f.sessions, Telemetry: f.transitions,
		RequestControllerUsername: "system:serviceaccount:breakglass:manager",
		Clock:                     func() time.Time { return f.now },
	}
	return f
}

func (f *fixture) reconcile(t *testing.T, r *access.Request) Result {
	t.Helper()
	result, err := f.lifecycle.Reconcile(context.Background(), r, f.store)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	return result
}

func TestApprovedRequestProvisionsExactlyOneSession(t *testing.T) {
	r := newRequest()
	f := newFixture(fakeApprovals{r.ApprovalName(): approvalFor(r, access.DecisionApproved, "max@example.com")})

	if f.reconcile(t, r); r.Status.Phase != access.RequestPhasePending {
		t.Fatalf("phase = %s, want Pending", r.Status.Phase)
	}
	if result := f.reconcile(t, r); r.Status.Phase != access.RequestPhaseApproved || result.RequeueAfter != ContinueImmediately {
		t.Fatalf("phase = %s, requeue = %v, want Approved and immediate continuation", r.Status.Phase, result.RequeueAfter)
	}
	f.reconcile(t, r)
	if r.Status.Phase != access.RequestPhaseProvisioning || r.Status.SessionRef.Name != access.SessionNameForRequestUID(r.UID) {
		t.Fatalf("status = %#v, want a reserved deterministic session name", r.Status)
	}
	f.reconcile(t, r)
	if r.Status.Phase != access.RequestPhaseSessionCreated || r.Status.SessionRef.UID != "session-uid" {
		t.Fatalf("status = %#v, want SessionCreated with the session UID", r.Status)
	}
	f.reconcile(t, r)
	if f.sessions.creates != 1 {
		t.Fatalf("sessions created = %d, want exactly one", f.sessions.creates)
	}
	want := []access.RequestPhase{access.RequestPhasePending, access.RequestPhaseApproved, access.RequestPhaseProvisioning, access.RequestPhaseSessionCreated}
	if fmt.Sprint(*f.transitions) != fmt.Sprint(want) {
		t.Fatalf("transitions = %v, want %v", *f.transitions, want)
	}
}

func TestDeniedRequestIsTerminal(t *testing.T) {
	r := newRequest()
	f := newFixture(fakeApprovals{r.ApprovalName(): approvalFor(r, access.DecisionDenied, "max@example.com")})
	f.reconcile(t, r)
	f.reconcile(t, r)
	f.reconcile(t, r)
	if r.Status.Phase != access.RequestPhaseDenied || f.sessions.creates != 0 {
		t.Fatalf("phase = %s, sessions = %d, want Denied without session", r.Status.Phase, f.sessions.creates)
	}
}

func TestSelfApprovalFailsTheRequest(t *testing.T) {
	r := newRequest()
	f := newFixture(fakeApprovals{r.ApprovalName(): approvalFor(r, access.DecisionApproved, r.Requester.Name)})
	f.reconcile(t, r)
	f.reconcile(t, r)
	if r.Status.Phase != access.RequestPhaseFailed {
		t.Fatalf("phase = %s, want Failed", r.Status.Phase)
	}
	if c := access.FindCondition(r.Status.Conditions, ConditionProvisioned); c == nil || c.Reason != "InvalidApproval" {
		t.Fatalf("Provisioned = %#v, want InvalidApproval", c)
	}
}

func TestUndecidedRequestExpiresAtItsDeadline(t *testing.T) {
	r := newRequest()
	f := newFixture(fakeApprovals{})
	if result := f.reconcile(t, r); result.RequeueAfter != 14*time.Minute {
		t.Fatalf("requeue = %v, want the remaining decision window", result.RequeueAfter)
	}
	f.now = created.Add(15 * time.Minute)
	if result := f.reconcile(t, r); r.Status.Phase != access.RequestPhaseExpired || result.RequeueAfter != 0 {
		t.Fatalf("phase = %s, requeue = %v, want Expired without requeue", r.Status.Phase, result.RequeueAfter)
	}
	if r.Status.ExpiresAt == nil || !r.Status.ExpiresAt.Equal(created.Add(15*time.Minute)) {
		t.Fatalf("expiresAt = %v, want creation + TTL", r.Status.ExpiresAt)
	}
}

func TestApprovalAfterDeadlineDoesNotProvision(t *testing.T) {
	r := newRequest()
	f := newFixture(fakeApprovals{r.ApprovalName(): approvalFor(r, access.DecisionApproved, "max@example.com")})
	f.reconcile(t, r)
	f.now = created.Add(time.Hour)
	f.reconcile(t, r)
	f.reconcile(t, r)
	if r.Status.Phase != access.RequestPhaseExpired || f.sessions.creates != 0 {
		t.Fatalf("phase = %s, sessions = %d, want Expired without session", r.Status.Phase, f.sessions.creates)
	}
}

func TestInvalidTTLFailsTheRequest(t *testing.T) {
	r := newRequest()
	r.RequestTTL = "0s"
	f := newFixture(fakeApprovals{})
	f.reconcile(t, r)
	if r.Status.Phase != access.RequestPhaseFailed {
		t.Fatalf("phase = %s, want Failed", r.Status.Phase)
	}
}

func TestProvisioningRefusesASessionOfAnotherRequest(t *testing.T) {
	r := newRequest()
	r.Status.Phase = access.RequestPhaseProvisioning
	r.Status.SessionRef = &access.ObjectRef{Name: access.SessionNameForRequestUID(r.UID)}
	f := newFixture(fakeApprovals{})
	f.sessions.records[r.Status.SessionRef.Name] = SessionRecord{
		Name: r.Status.SessionRef.Name, UID: "squatter", RequestRef: &access.ObjectRef{Name: "other", UID: "other-uid"},
	}
	f.reconcile(t, r)
	if r.Status.Phase != access.RequestPhaseFailed {
		t.Fatalf("phase = %s, want Failed", r.Status.Phase)
	}
	if c := access.FindCondition(r.Status.Conditions, ConditionProvisioned); c == nil || c.Reason != "SessionSourceMismatch" {
		t.Fatalf("Provisioned = %#v, want SessionSourceMismatch", c)
	}
}

func TestProvisioningRequiresAControllerIdentity(t *testing.T) {
	r := newRequest()
	r.Status.Phase = access.RequestPhaseApproved
	f := newFixture(fakeApprovals{})
	f.lifecycle.RequestControllerUsername = ""
	f.reconcile(t, r)
	if r.Status.Phase != access.RequestPhaseFailed {
		t.Fatalf("phase = %s, want Failed", r.Status.Phase)
	}
}

type failingStore struct{}

func (failingStore) UpdateStatusIfChanged(context.Context, *access.Request) (bool, error) {
	return false, errors.New("unavailable")
}

func TestStoreFailureIsRetried(t *testing.T) {
	f := newFixture(fakeApprovals{})
	if _, err := f.lifecycle.Reconcile(context.Background(), newRequest(), failingStore{}); err == nil {
		t.Fatal("a failed status write must be returned for retry")
	}
	if len(*f.transitions) != 0 {
		t.Fatal("no transition may be recorded for a write that failed")
	}
}
