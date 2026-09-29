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
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
)

func TestAccessProfileReconcileReportsReadiness(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		mutate     func(*accessv1alpha1.AccessProfile)
		objects    []client.Object
		allowed    map[string]struct{}
		wantStatus metav1.ConditionStatus
		wantReason string
	}{
		{
			name:       "marks a usable profile ready",
			objects:    []client.Object{testClusterRole()},
			wantStatus: metav1.ConditionTrue,
			wantReason: "Ready",
		},
		{
			name: "rejects invalid maximum duration",
			mutate: func(profile *accessv1alpha1.AccessProfile) {
				profile.Spec.MaxDuration = "0s"
			},
			wantStatus: metav1.ConditionFalse,
			wantReason: "InvalidDuration",
		},
		{
			name:       "reports a missing curated role",
			wantStatus: metav1.ConditionFalse,
			wantReason: "ClusterRoleMissing",
		},
		{
			name:       "reports a namespace outside manager scope",
			objects:    []client.Object{testClusterRole()},
			allowed:    map[string]struct{}{"staging": {}},
			wantStatus: metav1.ConditionFalse,
			wantReason: "NamespaceOutOfScope",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			profile := testAccessProfileForReadiness()
			if test.mutate != nil {
				test.mutate(profile)
			}
			objects := append([]client.Object{profile}, test.objects...)
			reconciler := &AccessProfileReconciler{
				Client:                  newTestClient(testScheme(t), objects...),
				AllowedTargetNamespaces: test.allowed,
			}

			if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(profile)}); err != nil {
				t.Fatalf("Reconcile() error = %v", err)
			}

			updated := &accessv1alpha1.AccessProfile{}
			if err := reconciler.Get(context.Background(), client.ObjectKeyFromObject(profile), updated); err != nil {
				t.Fatalf("get AccessProfile after Reconcile(): %v", err)
			}
			if updated.Status.ObservedGeneration != profile.Generation {
				t.Fatalf("observedGeneration = %d, want %d", updated.Status.ObservedGeneration, profile.Generation)
			}
			if !hasCondition(updated.Status.Conditions, AccessProfileReadyCondition, test.wantStatus, test.wantReason) {
				t.Fatalf("conditions = %#v, want %s=%s (%s)", updated.Status.Conditions, AccessProfileReadyCondition, test.wantStatus, test.wantReason)
			}
			for _, condition := range updated.Status.Conditions {
				if condition.Type == AccessProfileReadyCondition && condition.ObservedGeneration != profile.Generation {
					t.Fatalf("ready condition observedGeneration = %d, want %d", condition.ObservedGeneration, profile.Generation)
				}
			}
		})
	}
}

func TestAccessProfileReconcileRequeuesMissingCuratedRole(t *testing.T) {
	t.Parallel()

	profile := testAccessProfileForReadiness()
	reconciler := &AccessProfileReconciler{
		Client: newTestClient(testScheme(t), profile),
	}

	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(profile)})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != ProfileReadinessRetryInterval {
		t.Fatalf("RequeueAfter = %s, want %s", result.RequeueAfter, ProfileReadinessRetryInterval)
	}
}

func testAccessProfileForReadiness() *accessv1alpha1.AccessProfile {
	return &accessv1alpha1.AccessProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "production-pod-observer",
			UID:        types.UID("profile-uid"),
			Generation: 7,
		},
		Spec: accessv1alpha1.AccessProfileSpec{
			RoleRef:         accessv1alpha1.RoleReference{Kind: "ClusterRole", Name: "breakglass-pod-observer"},
			TargetNamespace: "production",
			MaxDuration:     "30m",
		},
	}
}

func testClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "breakglass-pod-observer", UID: types.UID("role-uid")},
	}
}
