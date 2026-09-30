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

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
)

func TestApprovalDefaulterStampsTheOnlyDecisionSlotAndApprover(t *testing.T) {
	now := time.Date(2026, time.September, 29, 12, 0, 0, 0, time.UTC)
	request := testPendingApprovalRequest(now)
	reader := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithObjects(request).Build()
	approval := &accessv1alpha1.BreakGlassApproval{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "attacker-"},
		Spec: accessv1alpha1.BreakGlassApprovalSpec{
			RequestRef: accessv1alpha1.BreakGlassRequestReference{Name: request.Name, UID: "forged"},
			Decision:   accessv1alpha1.ApprovalDecisionApproved,
			Approver:   accessv1alpha1.SubjectReference{Kind: accessv1alpha1.SubjectKindUser, Name: "attacker@example.com"},
		},
	}

	defaulter := &BreakGlassApprovalDefaulter{RequestReader: reader}
	if err := defaulter.Default(requestContext("approver@example.com"), approval); err != nil {
		t.Fatalf("Default() error = %v", err)
	}
	if approval.Name != accessv1alpha1.ApprovalNameForRequestUID(string(request.UID)) || approval.GenerateName != "" {
		t.Fatalf("approval metadata = name %q generateName %q, want deterministic slot", approval.Name, approval.GenerateName)
	}
	if approval.Spec.RequestRef.UID != string(request.UID) {
		t.Fatalf("request UID = %q, want %q", approval.Spec.RequestRef.UID, request.UID)
	}
	if approval.Spec.Approver != (accessv1alpha1.SubjectReference{Kind: accessv1alpha1.SubjectKindUser, Name: "approver@example.com"}) {
		t.Fatalf("approver = %#v, want authenticated approver", approval.Spec.Approver)
	}
}

func TestApprovalValidatorRejectsUnsafeDecisions(t *testing.T) {
	now := time.Date(2026, time.September, 29, 12, 0, 0, 0, time.UTC)
	profile := testApprovalAccessProfile()
	request := testPendingApprovalRequest(now)
	reader := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithObjects(profile, request).Build()

	tests := []struct {
		name     string
		username string
		mutate   func(*accessv1alpha1.BreakGlassApproval, *accessv1alpha1.BreakGlassRequest)
		reviewer fakeApprovalReviewer
		wantErr  string
	}{
		{name: "allows an independent authorized approver", username: "approver@example.com", reviewer: fakeApprovalReviewer{allowed: true}},
		{
			name:     "rejects self approval",
			username: "engineer@example.com",
			mutate: func(approval *accessv1alpha1.BreakGlassApproval, _ *accessv1alpha1.BreakGlassRequest) {
				approval.Spec.Approver.Name = "engineer@example.com"
			},
			reviewer: fakeApprovalReviewer{allowed: true},
			wantErr:  "may not approve",
		},
		{
			name:     "rejects stale request UID",
			username: "approver@example.com",
			mutate: func(approval *accessv1alpha1.BreakGlassApproval, _ *accessv1alpha1.BreakGlassRequest) {
				approval.Spec.RequestRef.UID = "recreated-request"
			},
			reviewer: fakeApprovalReviewer{allowed: true},
			wantErr:  "does not match",
		},
		{name: "rejects missing approval permission", username: "approver@example.com", reviewer: fakeApprovalReviewer{allowed: false}, wantErr: "not authorized"},
		{name: "fails closed on approval authorization error", username: "approver@example.com", reviewer: fakeApprovalReviewer{err: errors.New("API unavailable")}, wantErr: "evaluate AccessProfile approval authorization"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			approval := testApprovalForRequest(request)
			if test.mutate != nil {
				test.mutate(approval, request)
			}
			validator := &BreakGlassApprovalValidator{
				RequestReader: reader,
				ProfileReader: reader,
				Reviewer:      test.reviewer,
				Clock:         func() time.Time { return now },
			}
			_, err := validator.ValidateCreate(requestContext(test.username), approval)
			if test.wantErr == "" && err != nil {
				t.Fatalf("ValidateCreate() error = %v, want nil", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("ValidateCreate() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestApprovalValidatorRejectsExpiredOrNonDeterministicDecisionSlots(t *testing.T) {
	now := time.Date(2026, time.September, 29, 12, 0, 0, 0, time.UTC)
	profile := testApprovalAccessProfile()
	request := testPendingApprovalRequest(now.Add(-16 * time.Minute))
	reader := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithObjects(profile, request).Build()
	validator := &BreakGlassApprovalValidator{
		RequestReader: reader,
		ProfileReader: reader,
		Reviewer:      fakeApprovalReviewer{allowed: true},
		Clock:         func() time.Time { return now },
	}
	approval := testApprovalForRequest(request)
	if _, err := validator.ValidateCreate(requestContext("approver@example.com"), approval); err == nil || !strings.Contains(err.Error(), "has expired") {
		t.Fatalf("ValidateCreate() error = %v, want expiry denial", err)
	}

	request = testPendingApprovalRequest(now)
	reader = fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithObjects(profile, request).Build()
	validator.RequestReader = reader
	validator.ProfileReader = reader
	approval = testApprovalForRequest(request)
	approval.Name = "second-decision"
	if _, err := validator.ValidateCreate(requestContext("approver@example.com"), approval); err == nil || !strings.Contains(err.Error(), "deterministic slot") {
		t.Fatalf("ValidateCreate() error = %v, want deterministic-slot denial", err)
	}
}

func TestApprovalIsAppendOnly(t *testing.T) {
	approval := testApprovalForRequest(testPendingApprovalRequest(time.Now()))
	validator := &BreakGlassApprovalValidator{}
	if _, err := validator.ValidateUpdate(context.Background(), approval, approval.DeepCopy()); err != nil {
		t.Fatalf("ValidateUpdate() error = %v", err)
	}
	updated := approval.DeepCopy()
	updated.Spec.Decision = accessv1alpha1.ApprovalDecisionDenied
	if _, err := validator.ValidateUpdate(context.Background(), approval, updated); err == nil {
		t.Fatal("ValidateUpdate() allowed decision mutation")
	}
	if _, err := validator.ValidateDelete(context.Background(), approval); err == nil {
		t.Fatal("ValidateDelete() allowed deletion")
	}
}

type fakeApprovalReviewer struct {
	allowed bool
	err     error
}

func (f fakeApprovalReviewer) CanApprove(_ context.Context, _ authenticationv1.UserInfo, _ string) (bool, error) {
	return f.allowed, f.err
}

func testPendingApprovalRequest(now time.Time) *accessv1alpha1.BreakGlassRequest {
	return &accessv1alpha1.BreakGlassRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "request-incident",
			UID:               types.UID("request-uid"),
			CreationTimestamp: metav1.NewTime(now),
		},
		Spec: accessv1alpha1.BreakGlassRequestSpec{
			AccessProfile:    "production-pod-observer",
			AccessProfileUID: "profile-uid",
			Requester:        accessv1alpha1.SubjectReference{Kind: accessv1alpha1.SubjectKindUser, Name: "engineer@example.com"},
			Duration:         "15m",
			RequestTTL:       "15m",
			Reason:           "Investigating active production incident",
		},
		Status: accessv1alpha1.BreakGlassRequestStatus{Phase: accessv1alpha1.RequestPhasePending},
	}
}

func testApprovalForRequest(request *accessv1alpha1.BreakGlassRequest) *accessv1alpha1.BreakGlassApproval {
	return &accessv1alpha1.BreakGlassApproval{
		ObjectMeta: metav1.ObjectMeta{Name: accessv1alpha1.ApprovalNameForRequestUID(string(request.UID))},
		Spec: accessv1alpha1.BreakGlassApprovalSpec{
			RequestRef: accessv1alpha1.BreakGlassRequestReference{Name: request.Name, UID: string(request.UID)},
			Decision:   accessv1alpha1.ApprovalDecisionApproved,
			Approver:   accessv1alpha1.SubjectReference{Kind: accessv1alpha1.SubjectKindUser, Name: "approver@example.com"},
		},
	}
}
