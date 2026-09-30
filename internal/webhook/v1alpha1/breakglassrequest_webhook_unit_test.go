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

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	breakglassmetrics "github.com/yannick-thomas/breakglass-operator/internal/metrics"
)

func TestRequestDefaulterOverwritesClientSuppliedIdentityAndProfileUID(t *testing.T) {
	profile := testApprovalAccessProfile()
	reader := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithObjects(profile).Build()
	request := testBreakGlassRequest()
	request.Spec.Requester.Name = "attacker@example.com"
	request.Spec.AccessProfileUID = "forged"

	defaulter := &BreakGlassRequestDefaulter{ProfileReader: reader, RequestTTL: 15 * time.Minute}
	if err := defaulter.Default(requestContext("engineer@example.com"), request); err != nil {
		t.Fatalf("Default() error = %v", err)
	}
	if request.Spec.Requester != (accessv1alpha1.SubjectReference{Kind: accessv1alpha1.SubjectKindUser, Name: "engineer@example.com"}) {
		t.Fatalf("Default() requester = %#v, want authenticated requester", request.Spec.Requester)
	}
	if request.Spec.AccessProfileUID != string(profile.UID) {
		t.Fatalf("Default() accessProfileUID = %q, want %q", request.Spec.AccessProfileUID, profile.UID)
	}
	if request.Spec.RequestTTL != "15m0s" {
		t.Fatalf("Default() requestTTL = %q, want 15m0s", request.Spec.RequestTTL)
	}
}

func TestRequestValidatorEnforcesTheSessionProfileBoundary(t *testing.T) {
	profile := testApprovalAccessProfile()
	reader := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithObjects(profile).Build()

	tests := []struct {
		name     string
		mutate   func(*accessv1alpha1.BreakGlassRequest)
		reviewer fakeReviewer
		allowed  map[string]struct{}
		wantErr  string
	}{
		{
			name:     "allows a current in-scope profile with use permission",
			reviewer: fakeReviewer{allowed: true},
		},
		{
			name:     "rejects a profile outside the manager namespace boundary",
			allowed:  map[string]struct{}{"staging": {}},
			reviewer: fakeReviewer{allowed: true},
			wantErr:  "outside this manager's allowed namespace set",
		},
		{
			name: "rejects an invalid profile UID",
			mutate: func(request *accessv1alpha1.BreakGlassRequest) {
				request.Spec.AccessProfileUID = "replaced-profile-uid"
			},
			reviewer: fakeReviewer{allowed: true},
			wantErr:  "does not match",
		},
		{
			name: "rejects a duration above the profile maximum",
			mutate: func(request *accessv1alpha1.BreakGlassRequest) {
				request.Spec.Duration = "2h"
			},
			reviewer: fakeReviewer{allowed: true},
			wantErr:  "exceeds AccessProfile maximum",
		},
		{
			name:     "rejects missing profile use permission",
			reviewer: fakeReviewer{allowed: false},
			wantErr:  "not authorized",
		},
		{
			name:     "fails closed when authorization cannot be evaluated",
			reviewer: fakeReviewer{err: errors.New("API unavailable")},
			wantErr:  "evaluate AccessProfile use authorization",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := testBreakGlassRequest()
			if test.mutate != nil {
				test.mutate(request)
			}
			validator := &BreakGlassRequestValidator{
				ProfileReader:           reader,
				Reviewer:                test.reviewer,
				AllowedTargetNamespaces: test.allowed,
				RequestTTL:              15 * time.Minute,
			}
			_, err := validator.ValidateCreate(requestContext("engineer@example.com"), request)
			if test.wantErr == "" && err != nil {
				t.Fatalf("ValidateCreate() error = %v, want nil", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("ValidateCreate() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestRequestAdmissionMetricsRecordTerminalOutcomes(t *testing.T) {
	profile := testApprovalAccessProfile()
	reader := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithObjects(profile).Build()
	recorder := &recordingAdmissionRecorder{}

	validator := &BreakGlassRequestValidator{
		ProfileReader: reader,
		Reviewer:      fakeReviewer{allowed: true},
		Metrics:       recorder,
		RequestTTL:    15 * time.Minute,
	}
	if _, err := validator.ValidateCreate(requestContext("engineer@example.com"), testBreakGlassRequest()); err != nil {
		t.Fatalf("ValidateCreate() error = %v", err)
	}

	denied := &BreakGlassRequestValidator{
		ProfileReader: reader,
		Reviewer:      fakeReviewer{allowed: false},
		Metrics:       recorder,
		RequestTTL:    15 * time.Minute,
	}
	if _, err := denied.ValidateCreate(requestContext("engineer@example.com"), testBreakGlassRequest()); err == nil {
		t.Fatal("ValidateCreate() allowed an unauthorized profile use")
	}

	failing := &BreakGlassRequestValidator{
		ProfileReader: reader,
		Reviewer:      fakeReviewer{err: errors.New("API unavailable")},
		Metrics:       recorder,
		RequestTTL:    15 * time.Minute,
	}
	if _, err := failing.ValidateCreate(requestContext("engineer@example.com"), testBreakGlassRequest()); err == nil {
		t.Fatal("ValidateCreate() succeeded when authorization infrastructure failed")
	}

	oldRequest := testBreakGlassRequest()
	if _, err := validator.ValidateUpdate(context.Background(), oldRequest, oldRequest.DeepCopy()); err != nil {
		t.Fatalf("ValidateUpdate() error = %v", err)
	}
	changedRequest := oldRequest.DeepCopy()
	changedRequest.Spec.Reason = "a changed incident reason"
	if _, err := validator.ValidateUpdate(context.Background(), oldRequest, changedRequest); err == nil {
		t.Fatal("ValidateUpdate() allowed a spec change")
	}

	assertAdmissionDecisions(t, recorder, []admissionDecision{
		{operation: breakglassmetrics.AdmissionOperationCreate, outcome: breakglassmetrics.AdmissionOutcomeAllowed},
		{operation: breakglassmetrics.AdmissionOperationCreate, outcome: breakglassmetrics.AdmissionOutcomeDenied},
		{operation: breakglassmetrics.AdmissionOperationCreate, outcome: breakglassmetrics.AdmissionOutcomeError},
		{operation: breakglassmetrics.AdmissionOperationUpdate, outcome: breakglassmetrics.AdmissionOutcomeAllowed},
		{operation: breakglassmetrics.AdmissionOperationUpdate, outcome: breakglassmetrics.AdmissionOutcomeDenied},
	})
}

func TestRequestDefaulterFailsClosedForAWorkloadIdentity(t *testing.T) {
	profile := testApprovalAccessProfile()
	reader := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithObjects(profile).Build()
	defaulter := &BreakGlassRequestDefaulter{ProfileReader: reader, RequestTTL: 15 * time.Minute}

	err := defaulter.Default(requestContext("system:serviceaccount:production:deployer"), testBreakGlassRequest())
	if err == nil || !strings.Contains(err.Error(), "service account") {
		t.Fatalf("Default() error = %v, want service account rejection", err)
	}
}

func testBreakGlassRequest() *accessv1alpha1.BreakGlassRequest {
	return &accessv1alpha1.BreakGlassRequest{
		Spec: accessv1alpha1.BreakGlassRequestSpec{
			AccessProfile:    "production-pod-observer",
			AccessProfileUID: "profile-uid",
			Requester: accessv1alpha1.SubjectReference{
				Kind: accessv1alpha1.SubjectKindUser,
				Name: "engineer@example.com",
			},
			Duration:   "15m",
			RequestTTL: "15m0s",
			Reason:     "Investigating active production incident",
		},
	}
}

func testApprovalAccessProfile() *accessv1alpha1.AccessProfile {
	profile := testAccessProfile()
	profile.Spec.DeliveryMode = accessv1alpha1.AccessDeliveryModeApprovalRequired
	return profile
}
