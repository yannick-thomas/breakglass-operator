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
	"strings"
	"testing"
	"time"
)

const (
	profileName = "production-pod-observer"
	roleName    = "breakglass-pod-observer"
	requester   = "jane@example.com"
	approver    = "max@example.com"
)

var now = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func validProfile() Profile {
	return Profile{
		Name: profileName, UID: "profile-uid",
		RoleRef:         RoleRef{Kind: ClusterRoleKind, Name: roleName},
		TargetNamespace: "production", MaxDuration: "30m",
	}
}

func directSpec() SessionSpec {
	return SessionSpec{
		AccessProfile: profileName, AccessProfileUID: "profile-uid",
		Subject:  Subject{Kind: SubjectKindUser, Name: requester},
		Duration: "20m", Reason: "INC-1092",
	}
}

func activeSession() *Session {
	grant := NewGrant(validProfile(), Role{Name: roleName, UID: "role-uid", RulesHash: "hash"})
	expires := now.Add(10 * time.Minute)
	return &Session{
		Name: "incident", UID: "session-uid", Spec: directSpec(),
		Status: SessionStatus{Phase: PhaseActive, Grant: &grant, ExpiresAt: &expires},
	}
}

func TestValidateHumanRequester(t *testing.T) {
	for _, tc := range []struct {
		username string
		wantErr  string
	}{
		{requester, ""},
		{"", "no username"},
		{"system:serviceaccount:ns:deployer", "service account"},
		{"system:anonymous", "anonymous"},
		{"system:unauthenticated", "anonymous"},
	} {
		err := ValidateHumanRequester(tc.username)
		if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("ValidateHumanRequester(%q) = %v, want %q", tc.username, err, tc.wantErr)
		}
	}
}

func TestProfileCheckReportsFirstDefectInOrder(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Profile)
		want   ProfileDefect
	}{
		{"valid", func(*Profile) {}, ProfileValid},
		{"role kind", func(p *Profile) { p.RoleRef.Kind = "Role"; p.TargetNamespace = "" }, ProfileRoleRefInvalid},
		{"namespace", func(p *Profile) { p.TargetNamespace = ""; p.MaxDuration = "x" }, ProfileTargetNamespaceMissing},
		{"duration", func(p *Profile) { p.MaxDuration = "0s" }, ProfileMaxDurationInvalid},
		{"mode", func(p *Profile) { p.DeliveryMode = "Magic" }, ProfileDeliveryModeUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := validProfile()
			tc.mutate(&profile)
			maxDuration, defect := profile.Check()
			if defect != tc.want {
				t.Fatalf("defect = %v, want %v", defect, tc.want)
			}
			if (defect == ProfileValid || defect == ProfileDeliveryModeUnsupported) && maxDuration != 30*time.Minute {
				t.Fatalf("maxDuration = %v, want 30m", maxDuration)
			}
		})
	}
}

func TestProfilePermitsOnlyItsDeliveryChannel(t *testing.T) {
	selfService := validProfile()
	approval := validProfile()
	approval.DeliveryMode = DeliveryApprovalRequired
	if !selfService.Permits(ChannelDirect) || selfService.Permits(ChannelApproval) {
		t.Error("an unset delivery mode must permit only direct self-service")
	}
	if approval.Permits(ChannelDirect) || !approval.Permits(ChannelApproval) {
		t.Error("ApprovalRequired must permit only the approval workflow")
	}
}

func TestNamespaceScope(t *testing.T) {
	if !NamespaceScope(nil).Allows("anything") {
		t.Error("an empty scope is the all-namespaces development default")
	}
	scope := NamespaceScope{"production": {}}
	if !scope.Allows("production") || scope.Allows("kube-system") {
		t.Error("an explicit scope must allow only its namespaces")
	}
}

func TestValidateSessionSpec(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*SessionSpec)
		max     time.Duration
		wantErr string
	}{
		{name: "valid", mutate: func(*SessionSpec) {}},
		{name: "unparseable", mutate: func(s *SessionSpec) { s.Duration = "soon" }, wantErr: "not a valid Go duration"},
		{name: "zero", mutate: func(s *SessionSpec) { s.Duration = "0s" }, wantErr: "greater than zero"},
		{name: "manager maximum", mutate: func(*SessionSpec) {}, max: time.Minute, wantErr: "configured maximum"},
		{name: "profile UID", mutate: func(s *SessionSpec) { s.AccessProfileUID = "" }, wantErr: "accessProfileUID are required"},
		{name: "group subject", mutate: func(s *SessionSpec) { s.Subject.Kind = SubjectKindGroup }, wantErr: "authenticated User"},
		{name: "namespaced user", mutate: func(s *SessionSpec) { s.Subject.Namespace = "ns" }, wantErr: "subject.namespace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := directSpec()
			tc.mutate(&spec)
			_, err := ValidateSessionSpec(spec, tc.max)
			assertErr(t, err, tc.wantErr)
		})
	}
}

func TestCheckProfileForSession(t *testing.T) {
	approvalProfile := validProfile()
	approvalProfile.DeliveryMode = DeliveryApprovalRequired
	approvalSpec := directSpec()
	approvalSpec.RequestRef = &ObjectRef{Name: "bgr", UID: "bgr-uid"}
	for _, tc := range []struct {
		name     string
		spec     SessionSpec
		profile  Profile
		duration time.Duration
		scope    NamespaceScope
		wantErr  string
	}{
		{name: "valid", spec: directSpec(), profile: validProfile(), duration: 20 * time.Minute},
		{name: "recreated profile", spec: directSpec(), profile: Profile{Name: profileName, UID: "other"}, wantErr: "no longer matches"},
		{name: "approval profile used directly", spec: directSpec(), profile: approvalProfile, wantErr: "requires the approval workflow"},
		{name: "self-service profile via workflow", spec: approvalSpec, profile: validProfile(), wantErr: "does not authorize a controller-sourced"},
		{name: "too long", spec: directSpec(), profile: validProfile(), duration: time.Hour, wantErr: "exceeds AccessProfile maximum"},
		{name: "out of scope", spec: directSpec(), profile: validProfile(), scope: NamespaceScope{"staging": {}}, wantErr: "outside this manager's allowed namespace set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertErr(t, CheckProfileForSession(tc.spec, tc.duration, tc.profile, tc.scope), tc.wantErr)
		})
	}
}

func TestBindingNameIsDeterministicBoundedAndUIDSpecific(t *testing.T) {
	name := BindingName("incident", "uid-a")
	if name != BindingName("incident", "uid-a") || name == BindingName("incident", "uid-b") {
		t.Fatal("binding name must be deterministic per UID and differ across UIDs")
	}
	if long := BindingName(strings.Repeat("a", 300), "uid"); len(long) > maxObjectNameLength {
		t.Fatalf("binding name length = %d", len(long))
	}
	if got := BindingName("---", "uid"); !strings.HasPrefix(got, "breakglass-session-") {
		t.Fatalf("binding name for a dash-only session = %q", got)
	}
}

func ownedBinding(s *Session, subjects ...BindingSubject) Binding {
	ref := s.ExpectedBindingRef()
	return Binding{
		Kind: RoleBindingKind, Name: ref.Name, Namespace: ref.Namespace, UID: "binding-uid",
		Labels:        s.ManagedLabels(),
		SessionOwners: []SessionOwner{{Name: s.Name, UID: s.UID}},
		RoleRef:       s.ExpectedRoleRef(),
		Subjects:      subjects,
	}
}

func TestBindingChecks(t *testing.T) {
	s := activeSession()
	granted := ownedBinding(s, s.ExpectedSubject())
	if issue := s.CheckGrantedBinding(granted); issue != nil {
		t.Fatalf("granted binding rejected: %#v", issue)
	}
	if issue := s.CheckReservedBinding(ownedBinding(s)); issue != nil {
		t.Fatalf("reservation rejected: %#v", issue)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*Binding)
		code   string
	}{
		{"moved", func(b *Binding) { b.Namespace = "other" }, BindingIssueReference},
		{"foreign owner", func(b *Binding) { b.SessionOwners = []SessionOwner{{Name: s.Name, UID: "other"}} }, BindingIssueOwnership},
		{"label removed", func(b *Binding) { b.Labels = map[string]string{} }, BindingIssueOwnership},
		{"role swapped", func(b *Binding) { b.RoleRef.Name = "cluster-admin" }, BindingIssueRoleRef},
		{"subject added", func(b *Binding) { b.Subjects = append(b.Subjects, BindingSubject{Kind: "Group", Name: "devs"}) }, BindingIssueSubjects},
		{"subject removed", func(b *Binding) { b.Subjects = nil }, BindingIssueSubjects},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := ownedBinding(s, s.ExpectedSubject())
			tc.mutate(&b)
			if issue := s.CheckGrantedBinding(b); issue == nil || issue.Code != tc.code {
				t.Fatalf("issue = %#v, want code %q", issue, tc.code)
			}
		})
	}
	if issue := s.CheckReservedBinding(granted); issue == nil || issue.Code != BindingIssueSubjects {
		t.Fatalf("a reservation with subjects must be rejected, got %#v", issue)
	}
}

func TestBindingRefRequiresServerUID(t *testing.T) {
	if _, err := (Binding{Kind: RoleBindingKind, Name: "b", Namespace: "ns"}).Ref(); err == nil {
		t.Fatal("a binding without UID must not become a tracked reference")
	}
	ref, err := (Binding{Kind: RoleBindingKind, Name: "b", Namespace: "ns", UID: "u"}).Ref()
	if err != nil || ref.UID != "u" || ref.Kind != RoleBindingKind {
		t.Fatalf("Ref() = %#v, %v", ref, err)
	}
}

func TestUnrecordedReservationRecovery(t *testing.T) {
	s := &Session{Name: "incident", UID: "session-uid"}
	if !s.MayHaveUnrecordedReservation() {
		t.Fatal("a session without persisted activation may have an unrecorded reservation")
	}
	reservation := Binding{
		Kind: RoleBindingKind, Name: BindingName(s.Name, s.UID), Namespace: "production", UID: "b",
		Labels: s.ManagedLabels(), SessionOwners: []SessionOwner{{Name: s.Name, UID: s.UID}},
	}
	if !s.IsUnrecordedReservation(reservation) {
		t.Fatal("exact empty-subject reservation not recognized")
	}
	reservation.Subjects = []BindingSubject{{Kind: "User", Name: requester}}
	if s.IsUnrecordedReservation(reservation) {
		t.Fatal("an authorizing binding must never be recovered without a recorded UID")
	}
}

func TestProfileIssueFailsClosedOnDrift(t *testing.T) {
	s := activeSession()
	if issue := s.ProfileIssue(validProfile(), nil); issue != nil {
		t.Fatalf("unchanged profile rejected: %#v", issue)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Profile)
		scope  NamespaceScope
		reason string
	}{
		{"recreated", func(p *Profile) { p.UID = "new" }, nil, "AccessProfileUIDMismatch"},
		{"invalid", func(p *Profile) { p.MaxDuration = "" }, nil, "AccessProfileInvalid"},
		{"out of scope", func(*Profile) {}, NamespaceScope{"staging": {}}, "AccessProfileOutOfScope"},
		{"role changed", func(p *Profile) { p.RoleRef.Name = "other" }, nil, "AccessProfilePolicyDrift"},
		{"mode changed", func(p *Profile) { p.DeliveryMode = DeliveryApprovalRequired }, nil, "AccessProfileDeliveryModeDrift"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := validProfile()
			tc.mutate(&p)
			if issue := s.ProfileIssue(p, tc.scope); issue == nil || issue.Reason != tc.reason {
				t.Fatalf("issue = %#v, want %q", issue, tc.reason)
			}
		})
	}
	s.Spec.AccessProfileUID = "tampered"
	if issue := s.ProfileSnapshotIssue(); issue == nil || issue.Reason != "AccessProfileSnapshotMismatch" {
		t.Fatalf("snapshot mismatch not detected: %#v", issue)
	}
}

func TestRoleIssue(t *testing.T) {
	s := activeSession()
	if issue := s.RoleIssue(Role{UID: "role-uid", RulesHash: "hash"}); issue != nil {
		t.Fatalf("unchanged role rejected: %#v", issue)
	}
	if issue := s.RoleIssue(Role{UID: "other", RulesHash: "hash"}); issue == nil || issue.Reason != RoleIssueUIDMismatch {
		t.Fatalf("recreated role not detected: %#v", issue)
	}
	if issue := s.RoleIssue(Role{UID: "role-uid", RulesHash: "wider"}); issue == nil || issue.Reason != RoleIssueRulesDrift {
		t.Fatalf("rule drift not detected: %#v", issue)
	}
	s.Status.Grant.RoleRulesHash = ""
	if issue := s.RoleSnapshotIssue(); issue == nil || issue.Reason != RoleIssueSnapshotMissing {
		t.Fatalf("incomplete snapshot not detected: %#v", issue)
	}
}

func sourcedSession() (*Session, Request, Approval) {
	s := activeSession()
	s.Spec.RequestRef = &ObjectRef{Name: "bgr", UID: "bgr-uid"}
	request := Request{
		Name: "bgr", UID: "bgr-uid", CreatedAt: now.Add(-time.Minute),
		AccessProfile: s.Spec.AccessProfile, AccessProfileUID: s.Spec.AccessProfileUID,
		Requester: s.Spec.Subject, Duration: s.Spec.Duration, Reason: s.Spec.Reason, RequestTTL: "15m",
		Status: RequestStatus{
			Phase:       RequestPhaseSessionCreated,
			SessionRef:  &ObjectRef{Name: s.Name, UID: s.UID},
			ApprovalRef: &ObjectRef{Name: ApprovalNameForRequestUID("bgr-uid"), UID: "approval-uid"},
		},
	}
	approval := Approval{
		Name: request.ApprovalName(), UID: "approval-uid", RequestRef: request.Ref(),
		Decision: DecisionApproved, Approver: Subject{Kind: SubjectKindUser, Name: approver},
	}
	return s, request, approval
}

func TestSourceRequestIssue(t *testing.T) {
	s, request, _ := sourcedSession()
	if issue := s.SourceRequestIssue(request, now); issue != nil {
		t.Fatalf("valid source rejected: %#v", issue)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Session, *Request)
		code   string
	}{
		{"recreated request", func(_ *Session, r *Request) { r.UID = "other" }, SourceIssueUIDMismatch},
		{"different intent", func(_ *Session, r *Request) { r.Duration = "4h" }, SourceIssueContentMismatch},
		{"other session reserved", func(_ *Session, r *Request) { r.Status.SessionRef.Name = "other" }, SourceIssueReservationMismatch},
		{"other session UID", func(_ *Session, r *Request) { r.Status.SessionRef.UID = "other" }, SourceIssueSessionUIDMismatch},
		{"provisioning without UID is fine", func(_ *Session, r *Request) {
			r.Status.Phase = RequestPhaseProvisioning
			r.Status.SessionRef.UID = ""
		}, ""},
		{"wrong phase", func(_ *Session, r *Request) { r.Status.Phase = RequestPhasePending }, SourceIssuePhase},
		{"invalid TTL", func(_ *Session, r *Request) { r.RequestTTL = "0s" }, SourceIssueTTLInvalid},
		{"expired before activation", func(s *Session, r *Request) {
			s.Status.Phase = PhasePending
			r.CreatedAt = now.Add(-time.Hour)
		}, SourceIssueExpired},
		{"expired after activation is fine", func(_ *Session, r *Request) { r.CreatedAt = now.Add(-time.Hour) }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, r, _ := sourcedSession()
			tc.mutate(s, &r)
			issue := s.SourceRequestIssue(r, now)
			if tc.code == "" && issue != nil || tc.code != "" && (issue == nil || issue.Code != tc.code) {
				t.Fatalf("issue = %#v, want code %q", issue, tc.code)
			}
		})
	}
}

func TestSourceApprovalIssue(t *testing.T) {
	_, request, approval := sourcedSession()
	if issue := SourceApprovalRefIssue(request); issue != nil {
		t.Fatalf("valid approval reference rejected: %#v", issue)
	}
	if issue := SourceApprovalIssue(request, approval); issue != nil {
		t.Fatalf("valid approval rejected: %#v", issue)
	}
	request.Status.ApprovalRef.Name = "chosen-by-attacker"
	if issue := SourceApprovalRefIssue(request); issue == nil || issue.Code != SourceIssueApprovalReference {
		t.Fatalf("non-deterministic approval slot accepted: %#v", issue)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*Approval)
		code   string
	}{
		{"recreated", func(a *Approval) { a.UID = "other" }, SourceIssueApprovalUIDMismatch},
		{"self approval", func(a *Approval) { a.Approver.Name = requester }, SourceIssueApprovalInvalid},
		{"denied", func(a *Approval) { a.Decision = DecisionDenied }, SourceIssueApprovalInvalid},
		{"other request", func(a *Approval) { a.RequestRef.UID = "other" }, SourceIssueApprovalInvalid},
		{"group approver", func(a *Approval) { a.Approver.Kind = SubjectKindGroup }, SourceIssueApprovalInvalid},
		{"anonymous approver", func(a *Approval) { a.Approver.Name = "" }, SourceIssueApprovalInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, r, a := sourcedSession()
			tc.mutate(&a)
			if issue := SourceApprovalIssue(r, a); issue == nil || issue.Code != tc.code {
				t.Fatalf("issue = %#v, want code %q", issue, tc.code)
			}
		})
	}
}

func TestApprovalDecidesFor(t *testing.T) {
	_, request, approval := sourcedSession()
	approval.Decision = DecisionDenied
	if !approval.DecidesFor(request) || approval.Approves(request) {
		t.Fatal("a denial is a valid decision, but not an approval")
	}
	approval.Decision = "Maybe"
	if approval.DecidesFor(request) {
		t.Fatal("an unsupported decision must not count")
	}
}

func TestRequestDeadline(t *testing.T) {
	r := Request{CreatedAt: now, RequestTTL: "15m"}
	if !r.DecisionOpen(now.Add(14*time.Minute)) || r.DecisionOpen(now.Add(15*time.Minute)) {
		t.Fatal("the decision window must close exactly at creation + TTL")
	}
	r.RequestTTL = "-1m"
	if _, ok := r.Deadline(); ok || r.DecisionOpen(now) {
		t.Fatal("an invalid TTL must close the decision window")
	}
}

func TestRequestPhaseTerminal(t *testing.T) {
	for _, phase := range []RequestPhase{RequestPhaseDenied, RequestPhaseExpired, RequestPhaseSessionCreated, RequestPhaseFailed} {
		if !phase.Terminal() {
			t.Errorf("%s must be terminal", phase)
		}
	}
	for _, phase := range []RequestPhase{"", RequestPhasePending, RequestPhaseApproved, RequestPhaseProvisioning} {
		if phase.Terminal() {
			t.Errorf("%q must not be terminal", phase)
		}
	}
}

func TestSessionPhaseTerminal(t *testing.T) {
	for _, phase := range []SessionPhase{PhaseExpired, PhaseDenied, PhaseSuspended, PhaseRevoked} {
		if !phase.Terminal() {
			t.Errorf("%s must be terminal", phase)
		}
	}
	if PhasePending.Terminal() || PhaseActive.Terminal() {
		t.Error("pending and active sessions are not terminal")
	}
}

func TestSetConditionKeepsTransitionTimeUnlessStatusChanges(t *testing.T) {
	var conditions []Condition
	SetCondition(&conditions, Condition{Type: "Ready", Status: ConditionTrue, Reason: "A"}, now)
	SetCondition(&conditions, Condition{Type: "Ready", Status: ConditionTrue, Reason: "B"}, now.Add(time.Minute))
	if got := FindCondition(conditions, "Ready"); got.LastTransitionTime != now || got.Reason != "B" {
		t.Fatalf("condition = %#v, want unchanged transition time and updated reason", got)
	}
	SetCondition(&conditions, Condition{Type: "Ready", Status: ConditionFalse, Reason: "C"}, now.Add(2*time.Minute))
	if got := FindCondition(conditions, "Ready"); got.LastTransitionTime != now.Add(2*time.Minute) || len(conditions) != 1 {
		t.Fatalf("condition = %#v, want new transition time", got)
	}
}

func TestRequeueAfter(t *testing.T) {
	if got := RequeueAfter(now, now.Add(time.Hour), time.Minute); got != time.Minute {
		t.Errorf("long remaining time = %v, want the integrity interval", got)
	}
	if got := RequeueAfter(now, now.Add(10*time.Second), time.Minute); got != 10*time.Second {
		t.Errorf("short remaining time = %v, want the expiry", got)
	}
	if got := RequeueAfter(now, now.Add(-time.Second), time.Minute); got <= 0 {
		t.Errorf("elapsed expiry = %v, must stay positive", got)
	}
}

func assertErr(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

func TestParseNamespaceScope(t *testing.T) {
	scope, err := ParseNamespaceScope("production, staging")
	if err != nil || len(scope) != 2 || !scope.Allows("staging") || scope.Allows("kube-system") {
		t.Fatalf("ParseNamespaceScope() = %v, %v", scope, err)
	}
	if scope, err := ParseNamespaceScope(""); err != nil || scope.Explicit() {
		t.Fatalf("empty value must be the all-namespaces default, got %v, %v", scope, err)
	}
	for value, want := range map[string]string{
		"production,,staging":   "empty namespace",
		"Production":            "invalid namespace",
		"-leading":              "invalid namespace",
		strings.Repeat("a", 64): "invalid namespace",
	} {
		if _, err := ParseNamespaceScope(value); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseNamespaceScope(%q) error = %v, want %q", value, err, want)
		}
	}
}
