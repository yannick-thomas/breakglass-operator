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
	"strings"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
)

// controlOnly accepts access objects only in testControlNamespace.
var controlOnly = access.Placement{Control: access.NamespaceScope{testControlNamespace: {}}}

func TestAdmissionRejectsAccessObjectsOutsideControlNamespaces(t *testing.T) {
	ctx := requestContext("engineer@example.com")
	reader := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithObjects(testAccessProfile()).Build()

	session := testSessionRequest()
	session.Namespace = "production"
	request := testBreakGlassRequest()
	request.Namespace = "production"
	approval := testApprovalForRequest(testPendingApprovalRequest(time.Now()))
	approval.Namespace = "production"

	for name, err := range map[string]error{
		"session defaulter":  (&BreakGlassSessionDefaulter{ProfileReader: reader, Placement: controlOnly}).Default(ctx, session.DeepCopy()),
		"request defaulter":  (&BreakGlassRequestDefaulter{ProfileReader: reader, Placement: controlOnly, RequestTTL: time.Minute}).Default(ctx, request.DeepCopy()),
		"approval defaulter": (&BreakGlassApprovalDefaulter{RequestReader: reader, Placement: controlOnly}).Default(requestContext("approver@example.com"), approval.DeepCopy()),
		"session validator":  second((&BreakGlassSessionValidator{ProfileReader: reader, Reviewer: fakeReviewer{allowed: true}, Placement: controlOnly}).ValidateCreate(ctx, session)),
		"request validator":  second((&BreakGlassRequestValidator{ProfileReader: reader, Reviewer: fakeReviewer{allowed: true}, Placement: controlOnly, RequestTTL: 15 * time.Minute}).ValidateCreate(ctx, request)),
		"approval validator": second((&BreakGlassApprovalValidator{RequestReader: reader, ProfileReader: reader, Reviewer: fakeApprovalReviewer{allowed: true}, Placement: controlOnly}).ValidateCreate(requestContext("approver@example.com"), approval)),
	} {
		if err == nil || !strings.Contains(err.Error(), "must be created in a control namespace") {
			t.Errorf("%s error = %v, want control-namespace rejection", name, err)
		}
	}
}

func TestAdmissionRejectsProfileThatGrantsInAControlNamespace(t *testing.T) {
	ownNamespace := testAccessProfile()
	ownNamespace.Spec.TargetNamespace = testControlNamespace
	otherControl := testAccessProfile()
	otherControl.Spec.TargetNamespace = "team-b-access"
	placement := access.Placement{Control: access.NamespaceScope{testControlNamespace: {}, "team-b-access": {}}}

	for name, tc := range map[string]struct {
		profile   *accessv1alpha1.AccessProfile
		placement access.Placement
		wantErr   string
	}{
		"own namespace":             {ownNamespace, access.Placement{}, "not a valid curated namespaced policy"},
		"another control namespace": {otherControl, placement, "targets control namespace"},
	} {
		t.Run(name, func(t *testing.T) {
			reader := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithObjects(tc.profile).Build()
			validator := &BreakGlassSessionValidator{ProfileReader: reader, Reviewer: fakeReviewer{allowed: true}, Placement: tc.placement}
			_, err := validator.ValidateCreate(requestContext("engineer@example.com"), testSessionRequest())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateCreate() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestAdmissionResolvesProfilesOnlyInTheObjectsNamespace(t *testing.T) {
	elsewhere := testAccessProfile()
	elsewhere.Namespace = "team-b-access"
	reader := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithObjects(elsewhere).Build()

	_, err := (&BreakGlassSessionValidator{ProfileReader: reader, Reviewer: fakeReviewer{allowed: true}}).
		ValidateCreate(requestContext("engineer@example.com"), testSessionRequest())
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("ValidateCreate() error = %v, want a profile of another namespace to be invisible", err)
	}
}

func TestSubjectAccessReviewCarriesTheProfileNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := authorizationv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	var reviewed *authorizationv1.ResourceAttributes
	c := interceptor.NewClient(fake.NewClientBuilder().WithScheme(scheme).Build(), interceptor.Funcs{
		Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
			review := obj.(*authorizationv1.SubjectAccessReview)
			reviewed = review.Spec.ResourceAttributes
			review.Status.Allowed = true
			return nil
		},
	})
	reviewer := KubernetesSubjectAccessReviewer{Client: c}
	user := authenticationv1.UserInfo{Username: "engineer@example.com"}

	if allowed, err := reviewer.CanApprove(context.Background(), user, testControlNamespace, "production-pod-observer"); err != nil || !allowed {
		t.Fatalf("CanApprove() = %v, %v", allowed, err)
	}
	if reviewed == nil || reviewed.Namespace != testControlNamespace || reviewed.Name != "production-pod-observer" || reviewed.Verb != "approve" {
		t.Fatalf("reviewed attributes = %#v, want approve on the named profile in its namespace", reviewed)
	}
	if _, err := reviewer.CanUse(context.Background(), user, "", "production-pod-observer"); err == nil {
		t.Fatal("CanUse() without a namespace must fail instead of asking about a cluster-wide permission")
	}
}

func second[T any](_ T, err error) error {
	return err
}
