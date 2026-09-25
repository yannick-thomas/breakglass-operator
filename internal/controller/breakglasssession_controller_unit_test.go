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

package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
)

func TestValidateSession(t *testing.T) {
	t.Parallel()

	base := testSession()
	tests := []struct {
		name    string
		mutate  func(*accessv1alpha1.BreakGlassSession)
		wantErr string
	}{
		{name: "accepts valid request"},
		{
			name: "rejects zero duration",
			mutate: func(session *accessv1alpha1.BreakGlassSession) {
				session.Spec.Duration = "0s"
			},
			wantErr: "greater than zero",
		},
		{
			name: "enforces maximum duration",
			mutate: func(session *accessv1alpha1.BreakGlassSession) {
				session.Spec.Duration = "2h"
			},
			wantErr: "configured maximum",
		},
		{
			name: "requires an explicit service account namespace",
			mutate: func(session *accessv1alpha1.BreakGlassSession) {
				session.Spec.Subject = accessv1alpha1.SubjectReference{
					Kind: accessv1alpha1.SubjectKindServiceAccount,
					Name: "deployer",
				}
			},
			wantErr: "must specify subject.namespace",
		},
		{
			name: "rejects a Role for cluster-wide access",
			mutate: func(session *accessv1alpha1.BreakGlassSession) {
				session.Spec.TargetNamespace = ""
				session.Spec.RoleRef.Kind = "Role"
			},
			wantErr: "must reference a ClusterRole",
		},
	}

	reconciler := &BreakGlassSessionReconciler{MaxSessionDuration: time.Hour}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := base.DeepCopy()
			if test.mutate != nil {
				test.mutate(session)
			}

			_, err := reconciler.validateSession(session)
			if test.wantErr == "" && err != nil {
				t.Fatalf("validateSession() error = %v, want nil", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("validateSession() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestEnsureBindingRefusesToAdoptNameCollision(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	session := testSession()
	existing := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "breakglass-incident",
			Namespace:       "default",
			ResourceVersion: "1",
		},
	}
	reconciler := &BreakGlassSessionReconciler{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build(),
		Scheme: scheme,
	}

	err := reconciler.ensureBinding(context.Background(), session)
	if err == nil || !strings.Contains(err.Error(), "refusing to adopt existing RoleBinding") {
		t.Fatalf("ensureBinding() error = %v, want a collision refusal", err)
	}
}

func TestEnsureBindingLabelsAndDeletesOnlyItsOwnBinding(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	session := testSession()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := &BreakGlassSessionReconciler{Client: client, Scheme: scheme}

	if err := reconciler.ensureBinding(context.Background(), session); err != nil {
		t.Fatalf("ensureBinding() error = %v", err)
	}

	binding := &rbacv1.RoleBinding{}
	key := types.NamespacedName{Name: "breakglass-incident", Namespace: "default"}
	if err := client.Get(context.Background(), key, binding); err != nil {
		t.Fatalf("get created RoleBinding: %v", err)
	}
	if !isManagedBindingForSession(binding.Labels, session) {
		t.Fatalf("created binding labels = %#v, want session ownership labels", binding.Labels)
	}
	if len(binding.OwnerReferences) != 1 || binding.OwnerReferences[0].UID != session.UID {
		t.Fatalf("created binding owner references = %#v, want session UID %s", binding.OwnerReferences, session.UID)
	}

	if err := reconciler.cleanupBinding(context.Background(), session); err != nil {
		t.Fatalf("cleanupBinding() error = %v", err)
	}
	if err := client.Get(context.Background(), key, binding); err == nil {
		t.Fatal("cleanupBinding() left the managed RoleBinding behind")
	}
}

func testSession() *accessv1alpha1.BreakGlassSession {
	return &accessv1alpha1.BreakGlassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "incident", UID: types.UID("session-uid")},
		Spec: accessv1alpha1.BreakGlassSessionSpec{
			Subject: accessv1alpha1.SubjectReference{
				Kind: accessv1alpha1.SubjectKindUser,
				Name: "engineer@example.com",
			},
			RoleRef:         accessv1alpha1.RoleReference{Kind: "ClusterRole", Name: "edit"},
			TargetNamespace: "default",
			Duration:        "30m",
			Reason:          "Investigating an active production incident",
		},
	}
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := rbacv1.AddToScheme(scheme); err != nil {
		t.Fatalf("add RBAC scheme: %v", err)
	}
	if err := accessv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add BreakGlassSession scheme: %v", err)
	}
	return scheme
}
