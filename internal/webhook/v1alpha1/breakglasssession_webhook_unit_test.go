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

package v1alpha1

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	breakglassmetrics "github.com/yannick-thomas/breakglass-operator/internal/metrics"
)

func TestDefaulterOverwritesClientSuppliedSubjectAndProfileUID(t *testing.T) {
	profile := testAccessProfile()
	reader := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithObjects(profile).Build()
	defaulter := &BreakGlassSessionDefaulter{ProfileReader: reader}
	session := testSessionRequest()
	session.Spec.Subject = accessv1alpha1.SubjectReference{Kind: accessv1alpha1.SubjectKindUser, Name: "attacker@example.com"}
	session.Spec.AccessProfileUID = "forged"

	if err := defaulter.Default(requestContext("engineer@example.com"), session); err != nil {
		t.Fatalf("Default() error = %v", err)
	}
	if session.Spec.Subject.Name != "engineer@example.com" || session.Spec.Subject.Kind != accessv1alpha1.SubjectKindUser {
		t.Fatalf("Default() subject = %#v, want authenticated requester", session.Spec.Subject)
	}
	if session.Spec.AccessProfileUID != string(profile.UID) {
		t.Fatalf("Default() accessProfileUID = %q, want %q", session.Spec.AccessProfileUID, profile.UID)
	}
}

func TestValidatorRequiresAuthenticatedProfileUse(t *testing.T) {
	profile := testAccessProfile()
	reader := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithObjects(profile).Build()

	tests := []struct {
		name     string
		mutate   func(*accessv1alpha1.BreakGlassSession)
		reviewer fakeReviewer
		wantErr  string
	}{
		{
			name:     "allows a matching requester with use permission",
			reviewer: fakeReviewer{allowed: true},
		},
		{
			name: "rejects spoofed subject even when profile use is allowed",
			mutate: func(session *accessv1alpha1.BreakGlassSession) {
				session.Spec.Subject.Name = "another-engineer@example.com"
			},
			reviewer: fakeReviewer{allowed: true},
			wantErr:  "authenticated requester",
		},
		{
			name:     "rejects denied profile use",
			reviewer: fakeReviewer{allowed: false},
			wantErr:  "not authorized",
		},
		{
			name: "rejects a duration above the profile limit",
			mutate: func(session *accessv1alpha1.BreakGlassSession) {
				session.Spec.Duration = "2h"
			},
			reviewer: fakeReviewer{allowed: true},
			wantErr:  "exceeds AccessProfile maximum",
		},
		{
			name: "rejects stale profile UID",
			mutate: func(session *accessv1alpha1.BreakGlassSession) {
				session.Spec.AccessProfileUID = "replaced-profile-uid"
			},
			reviewer: fakeReviewer{allowed: true},
			wantErr:  "does not match",
		},
		{
			name:     "fails closed on reviewer error",
			reviewer: fakeReviewer{err: errors.New("API unavailable")},
			wantErr:  "evaluate AccessProfile use authorization",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := testSessionRequest()
			if test.mutate != nil {
				test.mutate(session)
			}
			validator := &BreakGlassSessionValidator{ProfileReader: reader, Reviewer: test.reviewer}
			_, err := validator.ValidateCreate(requestContext("engineer@example.com"), session)
			if test.wantErr == "" && err != nil {
				t.Fatalf("ValidateCreate() error = %v, want nil", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("ValidateCreate() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestValidatorRejectsProfileOutsideAllowedNamespaces(t *testing.T) {
	profile := testAccessProfile()
	reader := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithObjects(profile).Build()
	validator := &BreakGlassSessionValidator{
		ProfileReader:           reader,
		Reviewer:                fakeReviewer{allowed: true},
		AllowedTargetNamespaces: map[string]struct{}{"staging": {}},
	}

	_, err := validator.ValidateCreate(requestContext("engineer@example.com"), testSessionRequest())
	if err == nil || !strings.Contains(err.Error(), "outside this manager's allowed namespace set") {
		t.Fatalf("ValidateCreate() error = %v, want out-of-scope denial", err)
	}
}

func TestValidatorAllowsOnlyOneWayRevocation(t *testing.T) {
	validator := &BreakGlassSessionValidator{}
	oldSession := testSessionRequest()
	newSession := oldSession.DeepCopy()
	newSession.Spec.Revoked = true
	if _, err := validator.ValidateUpdate(context.Background(), oldSession, newSession); err != nil {
		t.Fatalf("ValidateUpdate() revocation error = %v", err)
	}

	newSession = oldSession.DeepCopy()
	newSession.Spec.AccessProfile = "another-profile"
	if _, err := validator.ValidateUpdate(context.Background(), oldSession, newSession); err == nil {
		t.Fatal("ValidateUpdate() allowed profile change")
	}

	oldSession.Spec.Revoked = true
	newSession = oldSession.DeepCopy()
	newSession.Spec.Revoked = false
	if _, err := validator.ValidateUpdate(context.Background(), oldSession, newSession); err == nil {
		t.Fatal("ValidateUpdate() allowed revocation reversal")
	}
}

func TestDefaulterRejectsWorkloadIdentity(t *testing.T) {
	profile := testAccessProfile()
	reader := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithObjects(profile).Build()
	defaulter := &BreakGlassSessionDefaulter{ProfileReader: reader}
	err := defaulter.Default(requestContext("system:serviceaccount:production:deployer"), testSessionRequest())
	if err == nil || !strings.Contains(err.Error(), "service account") {
		t.Fatalf("Default() error = %v, want service account rejection", err)
	}
}

func TestValidatorAcceptsOnlyTheReservedControllerSourcedSession(t *testing.T) {
	now := time.Now()
	profile := testApprovalAccessProfile()
	request := testPendingApprovalRequest(now)
	request.Status.Phase = accessv1alpha1.RequestPhaseProvisioning
	request.Status.ApprovalRef = &accessv1alpha1.BreakGlassObjectReference{Name: accessv1alpha1.ApprovalNameForRequestUID(string(request.UID)), UID: "approval-uid"}
	request.Status.SessionRef = &accessv1alpha1.BreakGlassObjectReference{Name: accessv1alpha1.SessionNameForRequestUID(string(request.UID))}
	approval := testApprovalForRequest(request)
	approval.UID = "approval-uid"
	reader := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithObjects(profile, request, approval).Build()
	controllerUsername := "system:serviceaccount:breakglass-operator-system:breakglass-operator-controller-manager"

	newSession := func() *accessv1alpha1.BreakGlassSession {
		return &accessv1alpha1.BreakGlassSession{
			ObjectMeta: metav1.ObjectMeta{Name: request.Status.SessionRef.Name},
			Spec: accessv1alpha1.BreakGlassSessionSpec{
				AccessProfile:    request.Spec.AccessProfile,
				AccessProfileUID: request.Spec.AccessProfileUID,
				Subject:          request.Spec.Requester,
				Duration:         request.Spec.Duration,
				Reason:           request.Spec.Reason,
				RequestRef:       &accessv1alpha1.BreakGlassRequestReference{Name: request.Name, UID: string(request.UID)},
			},
		}
	}

	tests := []struct {
		name     string
		username string
		mutate   func(*accessv1alpha1.BreakGlassSession)
		wantErr  string
	}{
		{name: "allows only the exact configured controller", username: controllerUsername},
		{name: "rejects another service account", username: "system:serviceaccount:production:deployer", wantErr: "configured request controller"},
		{
			name:     "rejects a session with changed request fields",
			username: controllerUsername,
			mutate: func(session *accessv1alpha1.BreakGlassSession) {
				session.Spec.Duration = "30m"
			},
			wantErr: "must exactly match",
		},
		{
			name:     "rejects a session with another name",
			username: controllerUsername,
			mutate: func(session *accessv1alpha1.BreakGlassSession) {
				session.Name = "a-second-session"
			},
			wantErr: "has not reserved",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validator := &BreakGlassSessionValidator{
				ProfileReader:             reader,
				RequestReader:             reader,
				ApprovalReader:            reader,
				RequestControllerUsername: controllerUsername,
			}
			session := newSession()
			if test.mutate != nil {
				test.mutate(session)
			}
			_, err := validator.ValidateCreate(requestContext(test.username), session)
			if test.wantErr == "" && err != nil {
				t.Fatalf("ValidateCreate() error = %v, want nil", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("ValidateCreate() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestValidatorRejectsDirectSessionForApprovalRequiredProfile(t *testing.T) {
	profile := testApprovalAccessProfile()
	reader := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithObjects(profile).Build()
	validator := &BreakGlassSessionValidator{ProfileReader: reader, Reviewer: fakeReviewer{allowed: true}}
	_, err := validator.ValidateCreate(requestContext("engineer@example.com"), testSessionRequest())
	if err == nil || !strings.Contains(err.Error(), "requires the approval workflow") {
		t.Fatalf("ValidateCreate() error = %v, want approval-only denial", err)
	}
}

func TestAdmissionMetricsRecordTerminalOutcomes(t *testing.T) {
	profile := testAccessProfile()
	reader := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithObjects(profile).Build()
	recorder := &recordingAdmissionRecorder{}

	defaulter := &BreakGlassSessionDefaulter{ProfileReader: reader, Metrics: recorder}
	session := testSessionRequest()
	if err := defaulter.Default(requestContext("engineer@example.com"), session); err != nil {
		t.Fatalf("Default() error = %v", err)
	}
	assertAdmissionDecisions(t, recorder, nil)

	validator := &BreakGlassSessionValidator{ProfileReader: reader, Reviewer: fakeReviewer{allowed: true}, Metrics: recorder}
	if _, err := validator.ValidateCreate(requestContext("engineer@example.com"), session); err != nil {
		t.Fatalf("ValidateCreate() error = %v", err)
	}
	assertAdmissionDecisions(t, recorder, []admissionDecision{{
		operation: breakglassmetrics.AdmissionOperationCreate,
		outcome:   breakglassmetrics.AdmissionOutcomeAllowed,
	}})

	denied := &BreakGlassSessionValidator{ProfileReader: reader, Reviewer: fakeReviewer{allowed: false}, Metrics: recorder}
	if _, err := denied.ValidateCreate(requestContext("engineer@example.com"), testSessionRequest()); err == nil {
		t.Fatal("ValidateCreate() allowed an unauthorized profile use")
	}
	assertAdmissionDecisions(t, recorder, []admissionDecision{
		{operation: breakglassmetrics.AdmissionOperationCreate, outcome: breakglassmetrics.AdmissionOutcomeAllowed},
		{operation: breakglassmetrics.AdmissionOperationCreate, outcome: breakglassmetrics.AdmissionOutcomeDenied},
	})

	failing := &BreakGlassSessionValidator{ProfileReader: reader, Reviewer: fakeReviewer{err: errors.New("API unavailable")}, Metrics: recorder}
	if _, err := failing.ValidateCreate(requestContext("engineer@example.com"), testSessionRequest()); err == nil {
		t.Fatal("ValidateCreate() succeeded when authorization infrastructure failed")
	}
	assertAdmissionDecisions(t, recorder, []admissionDecision{
		{operation: breakglassmetrics.AdmissionOperationCreate, outcome: breakglassmetrics.AdmissionOutcomeAllowed},
		{operation: breakglassmetrics.AdmissionOperationCreate, outcome: breakglassmetrics.AdmissionOutcomeDenied},
		{operation: breakglassmetrics.AdmissionOperationCreate, outcome: breakglassmetrics.AdmissionOutcomeError},
	})

	oldSession := testSessionRequest()
	if _, err := validator.ValidateUpdate(context.Background(), oldSession, oldSession.DeepCopy()); err != nil {
		t.Fatalf("ValidateUpdate() error = %v", err)
	}
	changedSession := oldSession.DeepCopy()
	changedSession.Spec.Reason = "a different reason"
	if _, err := validator.ValidateUpdate(context.Background(), oldSession, changedSession); err == nil {
		t.Fatal("ValidateUpdate() allowed an immutable field change")
	}
	assertAdmissionDecisions(t, recorder, []admissionDecision{
		{operation: breakglassmetrics.AdmissionOperationCreate, outcome: breakglassmetrics.AdmissionOutcomeAllowed},
		{operation: breakglassmetrics.AdmissionOperationCreate, outcome: breakglassmetrics.AdmissionOutcomeDenied},
		{operation: breakglassmetrics.AdmissionOperationCreate, outcome: breakglassmetrics.AdmissionOutcomeError},
		{operation: breakglassmetrics.AdmissionOperationUpdate, outcome: breakglassmetrics.AdmissionOutcomeAllowed},
		{operation: breakglassmetrics.AdmissionOperationUpdate, outcome: breakglassmetrics.AdmissionOutcomeDenied},
	})

	if err := defaulter.Default(requestContext("system:serviceaccount:production:deployer"), testSessionRequest()); err == nil {
		t.Fatal("Default() allowed a workload identity")
	}
	if err := defaulter.Default(context.Background(), testSessionRequest()); err == nil {
		t.Fatal("Default() accepted a missing admission request")
	}
	unconfigured := &BreakGlassSessionDefaulter{Metrics: recorder}
	if err := unconfigured.Default(requestContext("engineer@example.com"), testSessionRequest()); err == nil {
		t.Fatal("Default() accepted an unconfigured profile reader")
	}
	assertAdmissionDecisions(t, recorder, []admissionDecision{
		{operation: breakglassmetrics.AdmissionOperationCreate, outcome: breakglassmetrics.AdmissionOutcomeAllowed},
		{operation: breakglassmetrics.AdmissionOperationCreate, outcome: breakglassmetrics.AdmissionOutcomeDenied},
		{operation: breakglassmetrics.AdmissionOperationCreate, outcome: breakglassmetrics.AdmissionOutcomeError},
		{operation: breakglassmetrics.AdmissionOperationUpdate, outcome: breakglassmetrics.AdmissionOutcomeAllowed},
		{operation: breakglassmetrics.AdmissionOperationUpdate, outcome: breakglassmetrics.AdmissionOutcomeDenied},
		{operation: breakglassmetrics.AdmissionOperationCreate, outcome: breakglassmetrics.AdmissionOutcomeDenied},
		{operation: breakglassmetrics.AdmissionOperationCreate, outcome: breakglassmetrics.AdmissionOutcomeError},
		{operation: breakglassmetrics.AdmissionOperationCreate, outcome: breakglassmetrics.AdmissionOutcomeError},
	})
}

type fakeReviewer struct {
	allowed bool
	err     error
}

type admissionDecision struct {
	operation breakglassmetrics.AdmissionOperation
	outcome   breakglassmetrics.AdmissionOutcome
}

type recordingAdmissionRecorder struct {
	decisions []admissionDecision
}

func (r *recordingAdmissionRecorder) RecordAdmissionRequest(operation breakglassmetrics.AdmissionOperation, outcome breakglassmetrics.AdmissionOutcome) {
	r.decisions = append(r.decisions, admissionDecision{operation: operation, outcome: outcome})
}

func assertAdmissionDecisions(t *testing.T, recorder *recordingAdmissionRecorder, want []admissionDecision) {
	t.Helper()
	if len(recorder.decisions) != len(want) {
		t.Fatalf("admission decisions = %#v, want %#v", recorder.decisions, want)
	}
	for i := range want {
		if recorder.decisions[i] != want[i] {
			t.Fatalf("admission decision %d = %#v, want %#v", i, recorder.decisions[i], want[i])
		}
	}
}

func (f fakeReviewer) CanUse(_ context.Context, _ authenticationv1.UserInfo, _ string) (bool, error) {
	return f.allowed, f.err
}

func requestContext(username string) context.Context {
	return admission.NewContextWithRequest(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{UserInfo: authenticationv1.UserInfo{Username: username}},
	})
}

func testAccessProfile() *accessv1alpha1.AccessProfile {
	return &accessv1alpha1.AccessProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "production-pod-observer", UID: types.UID("profile-uid")},
		Spec: accessv1alpha1.AccessProfileSpec{
			RoleRef:         accessv1alpha1.RoleReference{Kind: "ClusterRole", Name: "breakglass-pod-observer"},
			TargetNamespace: "production",
			MaxDuration:     "30m",
		},
	}
}

func testSessionRequest() *accessv1alpha1.BreakGlassSession {
	return &accessv1alpha1.BreakGlassSession{
		Spec: accessv1alpha1.BreakGlassSessionSpec{
			AccessProfile:    "production-pod-observer",
			AccessProfileUID: "profile-uid",
			Subject: accessv1alpha1.SubjectReference{
				Kind: accessv1alpha1.SubjectKindUser,
				Name: "engineer@example.com",
			},
			Duration: "15m",
			Reason:   "Investigating active production incident",
		},
	}
}

func webhookTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := accessv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add access API to scheme: %v", err)
	}
	return scheme
}
