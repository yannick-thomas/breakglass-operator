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
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	breakglassmetrics "github.com/yannick-thomas/breakglass-operator/internal/metrics"
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
			name: "rejects a non-user subject",
			mutate: func(session *accessv1alpha1.BreakGlassSession) {
				session.Spec.Subject = accessv1alpha1.SubjectReference{
					Kind: accessv1alpha1.SubjectKindServiceAccount,
					Name: "deployer",
				}
			},
			wantErr: "authenticated User",
		},
		{
			name: "requires a server-assigned profile UID",
			mutate: func(session *accessv1alpha1.BreakGlassSession) {
				session.Spec.AccessProfileUID = ""
			},
			wantErr: "accessProfile and server-assigned",
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

func TestInitialReconcileRequeuesAfterAddingFinalizer(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	session := testSession()
	session.Status = accessv1alpha1.BreakGlassSessionStatus{}
	reconciler := &BreakGlassSessionReconciler{
		Client: newTestClient(scheme, session),
		Scheme: scheme,
	}

	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(session)})
	if err != nil {
		t.Fatalf("initial Reconcile() error = %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("initial Reconcile() result = %#v, want an explicit requeue after finalizer update", result)
	}

	updated := &accessv1alpha1.BreakGlassSession{}
	if err := reconciler.Get(context.Background(), client.ObjectKeyFromObject(session), updated); err != nil {
		t.Fatalf("get session after initial Reconcile(): %v", err)
	}
	if !controllerutil.ContainsFinalizer(updated, BreakGlassFinalizer) {
		t.Fatalf("session finalizers = %#v, want %q", updated.Finalizers, BreakGlassFinalizer)
	}
}

func TestReconcileExpiresPersistedSessionAfterControllerRestart(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	session := testSession()
	profile, role := activationPolicyObjects()
	testClient := newTestClient(scheme, session, profile, role)
	reconciler := &BreakGlassSessionReconciler{Client: testClient, Scheme: scheme}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(session)}

	// Activate the session, then discard this reconciler instance. The next
	// reconcile must use only the persisted status and still revoke access.
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("add finalizer Reconcile() error = %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("reserve binding Reconcile() error = %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("activate reserved binding Reconcile() error = %v", err)
	}

	active := &accessv1alpha1.BreakGlassSession{}
	if err := testClient.Get(context.Background(), request.NamespacedName, active); err != nil {
		t.Fatalf("get active session: %v", err)
	}
	if active.Status.Phase != accessv1alpha1.PhaseActive || active.Status.BindingRef == nil {
		t.Fatalf("activated session status = %#v, want active session with binding reference", active.Status)
	}
	bindingName := active.Status.BindingRef.Name
	expiredAt := metav1.NewTime(time.Now().Add(-time.Second))
	active.Status.ExpiresAt = &expiredAt
	if err := testClient.Status().Update(context.Background(), active); err != nil {
		t.Fatalf("persist elapsed expiry: %v", err)
	}

	restartedReconciler := &BreakGlassSessionReconciler{Client: testClient, Scheme: scheme}
	if _, err := restartedReconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("post-restart expiry Reconcile() error = %v", err)
	}

	expired := &accessv1alpha1.BreakGlassSession{}
	if err := testClient.Get(context.Background(), request.NamespacedName, expired); err != nil {
		t.Fatalf("get expired session: %v", err)
	}
	if expired.Status.Phase != accessv1alpha1.PhaseExpired {
		t.Fatalf("session phase = %q, want %q", expired.Status.Phase, accessv1alpha1.PhaseExpired)
	}
	binding := &rbacv1.RoleBinding{}
	if err := testClient.Get(context.Background(), types.NamespacedName{Name: bindingName, Namespace: "default"}, binding); err == nil {
		t.Fatal("expired session left its RoleBinding behind after controller restart")
	}
}

func TestReconcileCleansUnrecordedBindingWhenPolicyDisappearsAfterStatusWriteFailure(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	session := testSession()
	session.Status = accessv1alpha1.BreakGlassSessionStatus{}
	profile, role := activationPolicyObjects()
	testClient := newStatusFailingTestClient(scheme, session, profile, role)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(session)}
	reconciler := &BreakGlassSessionReconciler{
		Client:                  testClient,
		Scheme:                  scheme,
		AllowedTargetNamespaces: map[string]struct{}{"default": {}},
	}

	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("add finalizer Reconcile() error = %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err == nil {
		t.Fatal("activation Reconcile() error = nil, want injected status failure")
	}

	bindingKey := types.NamespacedName{Name: bindingNameForSession(session), Namespace: "default"}
	reservedBinding := &rbacv1.RoleBinding{}
	if err := testClient.Get(context.Background(), bindingKey, reservedBinding); err != nil {
		t.Fatalf("get unrecorded RoleBinding after status failure: %v", err)
	}
	if len(reservedBinding.Subjects) != 0 {
		t.Fatalf("unrecorded binding subjects = %#v, want an empty non-authorizing reservation", reservedBinding.Subjects)
	}
	if err := testClient.Delete(context.Background(), profile); err != nil {
		t.Fatalf("delete profile after status failure: %v", err)
	}

	// Simulate the next work item being handled by a fresh process. Policy
	// resolution now denies the session, so terminal cleanup must discover and
	// delete the exact binding created before status persistence failed.
	restartedReconciler := &BreakGlassSessionReconciler{
		Client:                  testClient,
		Scheme:                  scheme,
		AllowedTargetNamespaces: map[string]struct{}{"default": {}},
	}
	if _, err := restartedReconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("post-policy-loss Reconcile() error = %v", err)
	}

	denied := &accessv1alpha1.BreakGlassSession{}
	if err := testClient.Get(context.Background(), request.NamespacedName, denied); err != nil {
		t.Fatalf("get denied session: %v", err)
	}
	if denied.Status.Phase != accessv1alpha1.PhaseDenied {
		t.Fatalf("session phase = %q, want %q", denied.Status.Phase, accessv1alpha1.PhaseDenied)
	}
	remainingBinding := &rbacv1.RoleBinding{}
	if err := testClient.Get(context.Background(), bindingKey, remainingBinding); err == nil {
		t.Fatalf("denied session left its unrecorded RoleBinding behind: labels=%#v ownerReferences=%#v", remainingBinding.Labels, remainingBinding.OwnerReferences)
	}
}

func TestCleanupNeverRecoversAnUnrecordedAuthorizingBinding(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	session := testSession()
	session.Status = accessv1alpha1.BreakGlassSessionStatus{}
	forged := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingNameForSession(session),
			Namespace: "default",
			UID:       types.UID("forged-binding-uid"),
			Labels:    managedBindingLabels(session),
		},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: clusterRoleKind, Name: "breakglass-pod-observer"},
		Subjects: []rbacv1.Subject{expectedSubject(session)},
	}
	if err := controllerutil.SetControllerReference(session, forged, scheme); err != nil {
		t.Fatalf("set forged binding owner reference: %v", err)
	}
	testClient := newTestClient(scheme, session, forged)
	reconciler := &BreakGlassSessionReconciler{Client: testClient, Scheme: scheme}

	cleanup, err := reconciler.cleanupBindingWithResult(context.Background(), session)
	if err != nil {
		t.Fatalf("cleanupBindingWithResult() error = %v", err)
	}
	if cleanup.Deleted || cleanup.IntegrityIssue != nil {
		t.Fatalf("cleanup result = %#v, want no unrecorded authorizing-binding action", cleanup)
	}
	if err := testClient.Get(context.Background(), client.ObjectKeyFromObject(forged), &rbacv1.RoleBinding{}); err != nil {
		t.Fatalf("unrecorded authorizing RoleBinding was deleted: %v", err)
	}
}

func TestReconcileFinalizesPendingSessionAfterSubjectPromotionStatusInterruption(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	session := testSession()
	session.Status = accessv1alpha1.BreakGlassSessionStatus{}
	profile, role := activationPolicyObjects()
	testClient := newTestClient(scheme, session, profile, role)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(session)}
	reconciler := &BreakGlassSessionReconciler{Client: testClient, Scheme: scheme}

	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("add finalizer Reconcile() error = %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("reserve binding Reconcile() error = %v", err)
	}

	pending := &accessv1alpha1.BreakGlassSession{}
	if err := testClient.Get(context.Background(), request.NamespacedName, pending); err != nil {
		t.Fatalf("get pending session: %v", err)
	}
	if pending.Status.Phase != accessv1alpha1.PhasePending || pending.Status.BindingRef == nil {
		t.Fatalf("reserved session status = %#v, want pending session with binding reference", pending.Status)
	}
	binding := &rbacv1.RoleBinding{}
	if err := testClient.Get(context.Background(), types.NamespacedName{
		Name: pending.Status.BindingRef.Name, Namespace: pending.Status.BindingRef.Namespace,
	}, binding); err != nil {
		t.Fatalf("get reserved binding: %v", err)
	}
	binding.Subjects = []rbacv1.Subject{expectedSubject(pending)}
	if err := testClient.Update(context.Background(), binding); err != nil {
		t.Fatalf("simulate successful subject promotion: %v", err)
	}

	// The manager can crash after this RBAC update but before its Active status
	// write returns. The recorded UID lets a new manager finish status without
	// recreating or mutating a replacement binding.
	restartedReconciler := &BreakGlassSessionReconciler{Client: testClient, Scheme: scheme}
	if _, err := restartedReconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("finalize pending session Reconcile() error = %v", err)
	}
	active := &accessv1alpha1.BreakGlassSession{}
	if err := testClient.Get(context.Background(), request.NamespacedName, active); err != nil {
		t.Fatalf("get active session: %v", err)
	}
	if active.Status.Phase != accessv1alpha1.PhaseActive || active.Status.BindingRef == nil {
		t.Fatalf("finalized session status = %#v, want active UID-tracked session", active.Status)
	}
}

func TestReconcileDeletionCleansUnrecordedBindingAfterStatusWriteFailure(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	session := testSession()
	session.Status = accessv1alpha1.BreakGlassSessionStatus{}
	profile, role := activationPolicyObjects()
	testClient := newStatusFailingTestClient(scheme, session, profile, role)
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(session)}
	reconciler := &BreakGlassSessionReconciler{Client: testClient, Scheme: scheme}

	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("add finalizer Reconcile() error = %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err == nil {
		t.Fatal("activation Reconcile() error = nil, want injected status failure")
	}

	bindingKey := types.NamespacedName{Name: bindingNameForSession(session), Namespace: "default"}
	if err := testClient.Get(context.Background(), bindingKey, &rbacv1.RoleBinding{}); err != nil {
		t.Fatalf("get unrecorded RoleBinding after status failure: %v", err)
	}
	stored := &accessv1alpha1.BreakGlassSession{}
	if err := testClient.Get(context.Background(), request.NamespacedName, stored); err != nil {
		t.Fatalf("get session for deletion: %v", err)
	}
	if err := testClient.Delete(context.Background(), stored); err != nil {
		t.Fatalf("delete session: %v", err)
	}

	// The finalizer must not assume a nil status.bindingRef means no binding was
	// ever created: the persisted object contains none after the injected error.
	restartedReconciler := &BreakGlassSessionReconciler{Client: testClient, Scheme: scheme}
	if _, err := restartedReconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatalf("deletion Reconcile() error = %v", err)
	}
	if err := testClient.Get(context.Background(), request.NamespacedName, &accessv1alpha1.BreakGlassSession{}); err == nil {
		t.Fatal("session finalizer remained after cleanup of the unrecorded binding")
	}
	remainingBinding := &rbacv1.RoleBinding{}
	if err := testClient.Get(context.Background(), bindingKey, remainingBinding); err == nil {
		t.Fatalf("deleted session left its unrecorded RoleBinding behind: labels=%#v ownerReferences=%#v", remainingBinding.Labels, remainingBinding.OwnerReferences)
	}
}

func TestReconcileDeniesBindingNameCollisionWithoutChangingExistingBinding(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	session := testSession()
	session.Finalizers = []string{BreakGlassFinalizer}
	profile, role := activationPolicyObjects()
	existing := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingNameForSession(session),
			Namespace: "default",
			UID:       types.UID("unrelated-binding-uid"),
		},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "unrelated-role"},
		Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "unrelated@example.com", APIGroup: rbacv1.GroupName}},
	}
	testClient := newTestClient(scheme, session, profile, role, existing)
	reconciler := &BreakGlassSessionReconciler{Client: testClient, Scheme: scheme}

	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(session)}); err != nil {
		t.Fatalf("collision Reconcile() error = %v", err)
	}

	updated := &accessv1alpha1.BreakGlassSession{}
	if err := testClient.Get(context.Background(), client.ObjectKeyFromObject(session), updated); err != nil {
		t.Fatalf("get denied session: %v", err)
	}
	if updated.Status.Phase != accessv1alpha1.PhaseDenied {
		t.Fatalf("session phase = %q, want %q", updated.Status.Phase, accessv1alpha1.PhaseDenied)
	}
	if !hasCondition(updated.Status.Conditions, BindingIntegrityCondition, metav1.ConditionFalse, "BindingCollision") {
		t.Fatalf("session conditions = %#v, want BindingCollision integrity condition", updated.Status.Conditions)
	}

	got := &rbacv1.RoleBinding{}
	key := client.ObjectKeyFromObject(existing)
	if err := testClient.Get(context.Background(), key, got); err != nil {
		t.Fatalf("get pre-existing binding: %v", err)
	}
	if got.UID != existing.UID || got.RoleRef != existing.RoleRef || len(got.Subjects) != 1 || got.Subjects[0].Name != "unrelated@example.com" {
		t.Fatalf("existing RoleBinding was modified during collision handling: %#v", got)
	}
}

func TestResolveAccessGrantUsesImmutableProfileSnapshot(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	profile := &accessv1alpha1.AccessProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "production-pod-observer", UID: types.UID("profile-uid")},
		Spec: accessv1alpha1.AccessProfileSpec{
			RoleRef:         accessv1alpha1.RoleReference{Kind: "ClusterRole", Name: "breakglass-pod-observer"},
			TargetNamespace: "default",
			MaxDuration:     "1h",
		},
	}
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "breakglass-pod-observer", UID: types.UID("role-uid")},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch"},
		}},
	}
	reconciler := &BreakGlassSessionReconciler{
		Client:             newTestClient(scheme, profile, role),
		MaxSessionDuration: 2 * time.Hour,
	}

	tests := []struct {
		name    string
		mutate  func(*accessv1alpha1.BreakGlassSession)
		wantErr string
	}{
		{name: "resolves the curated namespaced grant"},
		{
			name: "rejects a stale profile UID",
			mutate: func(session *accessv1alpha1.BreakGlassSession) {
				session.Spec.AccessProfileUID = "replacement-uid"
			},
			wantErr: "no longer matches",
		},
		{
			name: "enforces the profile maximum duration",
			mutate: func(session *accessv1alpha1.BreakGlassSession) {
				session.Spec.Duration = "90m"
			},
			wantErr: "exceeds AccessProfile maximum",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := testSession()
			if test.mutate != nil {
				test.mutate(session)
			}
			grant, duration, err := reconciler.resolveAccessGrant(context.Background(), session)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("resolveAccessGrant() error = %v", err)
				}
				if grant.TargetNamespace != "default" || grant.RoleRef.Name != "breakglass-pod-observer" || grant.RoleUID != "role-uid" || grant.RoleRulesHash != curatedRoleRulesHash(role.Rules) || duration != 30*time.Minute {
					t.Fatalf("resolveAccessGrant() = (%#v, %s), want profile snapshot", grant, duration)
				}
				return
			}
			if err == nil || !isRequestDenied(err) || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("resolveAccessGrant() error = %v, want denied error containing %q", err, test.wantErr)
			}
		})
	}
}

func TestVerifyCuratedRoleDetectsRuleDrift(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "breakglass-pod-observer", UID: types.UID("role-uid")},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods", "secrets"},
			Verbs:     []string{"get", "list"},
		}},
	}
	session := testSession()
	session.Status.Grant.RoleUID = "role-uid"
	session.Status.Grant.RoleRulesHash = curatedRoleRulesHash([]rbacv1.PolicyRule{{
		APIGroups: []string{""},
		Resources: []string{"pods"},
		Verbs:     []string{"get", "list"},
	}})
	reconciler := &BreakGlassSessionReconciler{Client: newTestClient(scheme, role)}

	issue, err := reconciler.verifyCuratedRole(context.Background(), session)
	if err != nil {
		t.Fatalf("verifyCuratedRole() error = %v", err)
	}
	if issue == nil || issue.ConditionReason != "CuratedRoleRulesDrift" {
		t.Fatalf("verifyCuratedRole() issue = %#v, want CuratedRoleRulesDrift", issue)
	}
}

func TestCuratedRoleRulesHashIgnoresRuleAndValueOrder(t *testing.T) {
	t.Parallel()

	first := []rbacv1.PolicyRule{
		{APIGroups: []string{"apps", ""}, Resources: []string{"deployments", "pods"}, Verbs: []string{"watch", "get"}},
		{APIGroups: []string{""}, Resources: []string{"events"}, Verbs: []string{"list"}},
	}
	second := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"events"}, Verbs: []string{"list"}},
		{APIGroups: []string{"", "apps"}, Resources: []string{"pods", "deployments"}, Verbs: []string{"get", "watch"}},
	}
	if got, want := curatedRoleRulesHash(first), curatedRoleRulesHash(second); got != want {
		t.Fatalf("curatedRoleRulesHash() = %q, want canonical hash %q", got, want)
	}
}

func TestResolveAccessGrantRejectsProfileOutsideAllowedNamespaces(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	profile := &accessv1alpha1.AccessProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "production-pod-observer", UID: types.UID("profile-uid")},
		Spec: accessv1alpha1.AccessProfileSpec{
			RoleRef:         accessv1alpha1.RoleReference{Kind: "ClusterRole", Name: "breakglass-pod-observer"},
			TargetNamespace: "production",
			MaxDuration:     "1h",
		},
	}
	reconciler := &BreakGlassSessionReconciler{
		Client:                  newTestClient(scheme, profile),
		MaxSessionDuration:      2 * time.Hour,
		AllowedTargetNamespaces: map[string]struct{}{"staging": {}},
	}

	_, _, err := reconciler.resolveAccessGrant(context.Background(), testSession())
	if err == nil || !isRequestDenied(err) || !strings.Contains(err.Error(), "outside this manager's allowed namespace set") {
		t.Fatalf("resolveAccessGrant() error = %v, want out-of-scope denial", err)
	}
}

func TestEnsureBindingRefusesToAdoptNameCollision(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	session := testSession()
	bindingName := bindingNameForSession(session)
	existing := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:            bindingName,
			Namespace:       "default",
			ResourceVersion: "1",
		},
	}
	reconciler := &BreakGlassSessionReconciler{
		Client: newTestClient(scheme, existing),
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
	bindingName := bindingNameForSession(session)
	testClient := newTestClient(scheme)
	reconciler := &BreakGlassSessionReconciler{Client: testClient, Scheme: scheme}

	if err := reconciler.ensureBinding(context.Background(), session); err != nil {
		t.Fatalf("ensureBinding() error = %v", err)
	}

	binding := &rbacv1.RoleBinding{}
	key := types.NamespacedName{Name: bindingName, Namespace: "default"}
	if err := testClient.Get(context.Background(), key, binding); err != nil {
		t.Fatalf("get created RoleBinding: %v", err)
	}
	if !isManagedBindingForSession(binding, session) {
		t.Fatalf("created binding labels = %#v, want session ownership labels", binding.Labels)
	}
	if len(binding.OwnerReferences) != 1 || binding.OwnerReferences[0].UID != session.UID {
		t.Fatalf("created binding owner references = %#v, want session UID %s", binding.OwnerReferences, session.UID)
	}
	if len(binding.Subjects) != 1 || binding.Subjects[0].APIGroup != rbacv1.GroupName {
		t.Fatalf("created binding subjects = %#v, want canonical User API group %q", binding.Subjects, rbacv1.GroupName)
	}
	if session.Status.BindingRef == nil || session.Status.BindingRef.UID != string(binding.UID) {
		t.Fatalf("session bindingRef = %#v, want server UID %q", session.Status.BindingRef, binding.UID)
	}

	if err := reconciler.cleanupBinding(context.Background(), session); err != nil {
		t.Fatalf("cleanupBinding() error = %v", err)
	}
	if err := testClient.Get(context.Background(), key, binding); err == nil {
		t.Fatal("cleanupBinding() left the managed RoleBinding behind")
	}
}

func TestBindingLabelRemovalIsDetectedAndExactBindingIsCleanedUp(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	session := testSession()
	bindingName := bindingNameForSession(session)
	testClient := newTestClient(scheme, session.DeepCopy())
	reconciler := &BreakGlassSessionReconciler{Client: testClient, Scheme: scheme}

	if err := reconciler.ensureBinding(context.Background(), session); err != nil {
		t.Fatalf("ensureBinding() error = %v", err)
	}

	key := types.NamespacedName{Name: bindingName, Namespace: "default"}
	binding := &rbacv1.RoleBinding{}
	if err := testClient.Get(context.Background(), key, binding); err != nil {
		t.Fatalf("get created RoleBinding: %v", err)
	}
	binding.Labels = nil
	if err := testClient.Update(context.Background(), binding); err != nil {
		t.Fatalf("remove binding labels: %v", err)
	}

	requests := reconciler.findSessionForBinding(context.Background(), binding)
	if len(requests) != 1 || requests[0].Name != session.Name {
		t.Fatalf("findSessionForBinding() = %#v, want request for %q", requests, session.Name)
	}
	issue, err := reconciler.verifyBindingIntegrity(context.Background(), session)
	if err != nil {
		t.Fatalf("verifyBindingIntegrity() after label removal error = %v", err)
	}
	if issue == nil || issue.Code != "ownership" {
		t.Fatalf("verifyBindingIntegrity() issue = %#v, want ownership drift", issue)
	}
	cleanup, err := reconciler.cleanupBindingWithResult(context.Background(), session)
	if err != nil {
		t.Fatalf("cleanupBindingWithResult() after label removal error = %v", err)
	}
	if !cleanup.Deleted || cleanup.IntegrityIssue != nil {
		t.Fatalf("cleanup result = %#v, want exact binding deletion", cleanup)
	}
	if err := testClient.Get(context.Background(), key, binding); err == nil {
		t.Fatal("cleanupBindingWithResult() left the exact UID-tracked RoleBinding behind")
	}
}

func TestCleanupNeverDeletesAReplacementBinding(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	session := testSession()
	session.Status.BindingName = "breakglass-incident"
	session.Status.BindingRef = &accessv1alpha1.BindingReference{
		Kind:      "RoleBinding",
		Name:      "breakglass-incident",
		Namespace: "default",
		UID:       "original-binding-uid",
	}
	replacement := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "breakglass-incident",
			Namespace: "default",
			UID:       types.UID("replacement-binding-uid"),
		},
	}
	testClient := newTestClient(scheme, replacement)
	reconciler := &BreakGlassSessionReconciler{Client: testClient, Scheme: scheme}

	cleanup, err := reconciler.cleanupBindingWithResult(context.Background(), session)
	if err != nil {
		t.Fatalf("cleanupBindingWithResult() error = %v", err)
	}
	if cleanup.IntegrityIssue == nil || cleanup.IntegrityIssue.Code != "uid_mismatch" {
		t.Fatalf("cleanup result = %#v, want UID mismatch", cleanup)
	}

	got := &rbacv1.RoleBinding{}
	if err := testClient.Get(context.Background(), types.NamespacedName{Name: replacement.Name, Namespace: replacement.Namespace}, got); err != nil {
		t.Fatalf("replacement binding was deleted: %v", err)
	}
	if got.UID != replacement.UID {
		t.Fatalf("replacement UID = %q, want %q", got.UID, replacement.UID)
	}
}

func TestReconcileRevocationRecordsCleanupUIDMismatch(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	session := testSession()
	session.Spec.Revoked = true
	session.Finalizers = []string{BreakGlassFinalizer}
	session.Status.BindingName = bindingNameForSession(session)
	session.Status.BindingRef = &accessv1alpha1.BindingReference{
		Kind:      roleBindingKind,
		Name:      session.Status.BindingName,
		Namespace: "default",
		UID:       "original-binding-uid",
	}
	replacement := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      session.Status.BindingName,
			Namespace: "default",
			UID:       types.UID("replacement-binding-uid"),
		},
	}
	recorder := &recordingMetrics{}
	testClient := newTestClient(scheme, session, replacement)
	reconciler := &BreakGlassSessionReconciler{Client: testClient, Scheme: scheme, Metrics: recorder}

	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(session)}); err != nil {
		t.Fatalf("revocation Reconcile() error = %v", err)
	}
	if len(recorder.driftReasons) != 1 || recorder.driftReasons[0] != breakglassmetrics.DriftUIDMismatch {
		t.Fatalf("recorded cleanup drift = %#v, want uid mismatch", recorder.driftReasons)
	}
	if err := testClient.Get(context.Background(), client.ObjectKeyFromObject(replacement), &rbacv1.RoleBinding{}); err != nil {
		t.Fatalf("replacement RoleBinding was deleted: %v", err)
	}
}

func TestVerifyBindingIntegrityDetectsSubjectDrift(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	session := testSession()
	bindingName := bindingNameForSession(session)
	testClient := newTestClient(scheme)
	reconciler := &BreakGlassSessionReconciler{Client: testClient, Scheme: scheme}

	if err := reconciler.ensureBinding(context.Background(), session); err != nil {
		t.Fatalf("ensureBinding() error = %v", err)
	}
	binding := &rbacv1.RoleBinding{}
	key := types.NamespacedName{Name: bindingName, Namespace: "default"}
	if err := testClient.Get(context.Background(), key, binding); err != nil {
		t.Fatalf("get binding: %v", err)
	}
	binding.Subjects = append(binding.Subjects, rbacv1.Subject{Kind: rbacv1.UserKind, Name: "unexpected@example.com"})
	if err := testClient.Update(context.Background(), binding); err != nil {
		t.Fatalf("drift binding subjects: %v", err)
	}

	issue, err := reconciler.verifyBindingIntegrity(context.Background(), session)
	if err != nil {
		t.Fatalf("verifyBindingIntegrity() error = %v", err)
	}
	if issue == nil || issue.Code != "subjects" {
		t.Fatalf("verifyBindingIntegrity() issue = %#v, want subjects drift", issue)
	}
}

func TestActiveRequeueUsesPeriodicIntegrityInterval(t *testing.T) {
	t.Parallel()

	reconciler := &BreakGlassSessionReconciler{IntegrityCheckInterval: 5 * time.Second}
	expiresAt := time.Now().Add(30 * time.Minute)
	if requeue := reconciler.activeRequeueAfter(expiresAt); requeue > 5*time.Second || requeue < 4*time.Second {
		t.Fatalf("activeRequeueAfter() = %s, want approximately 5s", requeue)
	}
}

func TestActiveRequeueAfterElapsedExpiryStaysPositive(t *testing.T) {
	t.Parallel()

	reconciler := &BreakGlassSessionReconciler{}
	if requeue := reconciler.activeRequeueAfter(time.Now().Add(-time.Millisecond)); requeue <= 0 || requeue > 10*time.Millisecond {
		t.Fatalf("activeRequeueAfter() = %s, want a short positive retry after elapsed expiry", requeue)
	}
}

func TestBindingNameIncludesSessionUIDAndFitsKubernetesLimit(t *testing.T) {
	t.Parallel()

	session := testSession()
	session.Name = strings.Repeat("a", 253)
	first := bindingNameForSession(session)
	if len(first) > maxKubernetesNameSize {
		t.Fatalf("bindingNameForSession() length = %d, want at most %d", len(first), maxKubernetesNameSize)
	}
	if !strings.HasPrefix(first, bindingNamePrefix) {
		t.Fatalf("bindingNameForSession() = %q, want prefix %q", first, bindingNamePrefix)
	}

	second := session.DeepCopy()
	second.UID = types.UID("replacement-session-uid")
	if got := bindingNameForSession(second); got == first {
		t.Fatalf("bindingNameForSession() reused %q after a session UID change", got)
	}
}

func TestRecordBindingDriftPreservesStableReasons(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code string
		want breakglassmetrics.BindingDriftReason
	}{
		{code: "binding_reference", want: breakglassmetrics.DriftBindingReference},
		{code: "missing_expiry", want: breakglassmetrics.DriftMissingExpiry},
		{code: "integrity_unknown", want: breakglassmetrics.DriftIntegrityUnknown},
	}

	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			recorder := &recordingMetrics{}
			reconciler := &BreakGlassSessionReconciler{Metrics: recorder}
			reconciler.recordBindingDrift(&bindingIntegrityIssue{Code: test.code}, testSession())
			if len(recorder.driftReasons) != 1 || recorder.driftReasons[0] != test.want {
				t.Fatalf("recorded drift reasons = %#v, want %q", recorder.driftReasons, test.want)
			}
		})
	}
}

func TestFindSessionsForAccessProfileUsesProfileFieldIndex(t *testing.T) {
	t.Parallel()

	sessionForProfile := testSession()
	sessionForProfile.Name = "profile-match"
	sessionForProfile.UID = types.UID("profile-match-uid")
	otherSession := testSession()
	otherSession.Name = "profile-mismatch"
	otherSession.UID = types.UID("profile-mismatch-uid")
	otherSession.Spec.AccessProfile = "staging-pod-observer"

	reconciler := &BreakGlassSessionReconciler{
		Client: newTestClient(testScheme(t), sessionForProfile, otherSession),
	}
	profile := &accessv1alpha1.AccessProfile{ObjectMeta: metav1.ObjectMeta{Name: sessionForProfile.Spec.AccessProfile}}

	requests := reconciler.findSessionsForAccessProfile(context.Background(), profile)
	if len(requests) != 1 || requests[0].NamespacedName != client.ObjectKeyFromObject(sessionForProfile) {
		t.Fatalf("findSessionsForAccessProfile() = %#v, want only %s", requests, client.ObjectKeyFromObject(sessionForProfile))
	}
}

func TestReconcileSuspendsAnActiveSessionWhenItsApprovalSourceDisappears(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	session := testSession()
	session.Finalizers = []string{BreakGlassFinalizer}
	session.Spec.RequestRef = &accessv1alpha1.BreakGlassRequestReference{Name: "incident-request", UID: "request-uid"}
	profile, role := activationPolicyObjects()
	profile.Spec.DeliveryMode = accessv1alpha1.AccessDeliveryModeApprovalRequired
	request, approval := requestSourceObjects(session)
	testClient := newTestClient(scheme, session, profile, role, request, approval)
	reconciler := &BreakGlassSessionReconciler{Client: testClient, Scheme: scheme}
	key := client.ObjectKeyFromObject(session)

	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reserve request-sourced session: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("activate request-sourced session: %v", err)
	}
	active := &accessv1alpha1.BreakGlassSession{}
	if err := testClient.Get(context.Background(), key, active); err != nil {
		t.Fatalf("get active request-sourced session: %v", err)
	}
	if active.Status.Phase != accessv1alpha1.PhaseActive || active.Status.BindingRef == nil {
		t.Fatalf("active request-sourced session = %#v, want active session with binding reference", active.Status)
	}

	if err := testClient.Delete(context.Background(), request); err != nil {
		t.Fatalf("delete source request: %v", err)
	}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile after source request deletion: %v", err)
	}

	suspended := &accessv1alpha1.BreakGlassSession{}
	if err := testClient.Get(context.Background(), key, suspended); err != nil {
		t.Fatalf("get suspended session: %v", err)
	}
	if suspended.Status.Phase != accessv1alpha1.PhaseSuspended {
		t.Fatalf("session phase = %q, want %q", suspended.Status.Phase, accessv1alpha1.PhaseSuspended)
	}
	if !hasCondition(suspended.Status.Conditions, RequestSourceCondition, metav1.ConditionFalse, "RequestMissing") {
		t.Fatalf("session conditions = %#v, want RequestMissing source condition", suspended.Status.Conditions)
	}
	if err := testClient.Get(context.Background(), types.NamespacedName{Name: active.Status.BindingRef.Name, Namespace: active.Status.BindingRef.Namespace}, &rbacv1.RoleBinding{}); err == nil {
		t.Fatal("suspended request-sourced session left its RoleBinding behind")
	}
}

func TestFindSessionsForBreakGlassRequestUsesSourceFieldIndex(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	session := testSession()
	session.Spec.RequestRef = &accessv1alpha1.BreakGlassRequestReference{Name: "incident-request", UID: "request-uid"}
	otherSession := testSession()
	otherSession.Name = "unrelated-session"
	otherSession.Spec.RequestRef = &accessv1alpha1.BreakGlassRequestReference{Name: "other-request", UID: "other-request-uid"}
	reconciler := &BreakGlassSessionReconciler{Client: newTestClient(scheme, session, otherSession)}

	requests := reconciler.findSessionsForBreakGlassRequest(context.Background(), &accessv1alpha1.BreakGlassRequest{ObjectMeta: metav1.ObjectMeta{Name: "incident-request"}})
	if len(requests) != 1 || requests[0].Name != session.Name {
		t.Fatalf("source request watch mapped %#v, want only %q", requests, session.Name)
	}
}

func TestAccessProfileWatchPredicateSkipsStatusOnlyUpdates(t *testing.T) {
	t.Parallel()

	profile := &accessv1alpha1.AccessProfile{ObjectMeta: metav1.ObjectMeta{Name: "production-pod-observer", Generation: 1}}
	profilePredicate := predicate.GenerationChangedPredicate{}
	if profilePredicate.Update(event.UpdateEvent{ObjectOld: profile, ObjectNew: profile.DeepCopy()}) {
		t.Fatal("GenerationChangedPredicate accepted a status-only AccessProfile update")
	}

	policyUpdate := profile.DeepCopy()
	policyUpdate.Generation = 2
	if !profilePredicate.Update(event.UpdateEvent{ObjectOld: profile, ObjectNew: policyUpdate}) {
		t.Fatal("GenerationChangedPredicate rejected an AccessProfile policy update")
	}
	if !profilePredicate.Delete(event.DeleteEvent{Object: profile}) {
		t.Fatal("GenerationChangedPredicate rejected an AccessProfile deletion")
	}
}

func activationPolicyObjects() (*accessv1alpha1.AccessProfile, *rbacv1.ClusterRole) {
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "breakglass-pod-observer", UID: types.UID("role-uid")},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch"},
		}},
	}
	profile := &accessv1alpha1.AccessProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "production-pod-observer", UID: types.UID("profile-uid")},
		Spec: accessv1alpha1.AccessProfileSpec{
			RoleRef:         accessv1alpha1.RoleReference{Kind: "ClusterRole", Name: role.Name},
			TargetNamespace: "default",
			MaxDuration:     "1h",
		},
	}
	return profile, role
}

func hasCondition(conditions []metav1.Condition, conditionType string, status metav1.ConditionStatus, reason string) bool {
	for _, condition := range conditions {
		if condition.Type == conditionType && condition.Status == status && condition.Reason == reason {
			return true
		}
	}
	return false
}

func testSession() *accessv1alpha1.BreakGlassSession {
	return &accessv1alpha1.BreakGlassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "incident", UID: types.UID("session-uid")},
		Spec: accessv1alpha1.BreakGlassSessionSpec{
			AccessProfile:    "production-pod-observer",
			AccessProfileUID: "profile-uid",
			Subject: accessv1alpha1.SubjectReference{
				Kind: accessv1alpha1.SubjectKindUser,
				Name: "engineer@example.com",
			},
			Duration: "30m",
			Reason:   "Investigating an active production incident",
		},
		Status: accessv1alpha1.BreakGlassSessionStatus{
			Grant: &accessv1alpha1.ResolvedAccess{
				AccessProfile:    "production-pod-observer",
				AccessProfileUID: "profile-uid",
				RoleRef:          accessv1alpha1.RoleReference{Kind: "ClusterRole", Name: "breakglass-pod-observer"},
				RoleUID:          "role-uid",
				RoleRulesHash:    curatedRoleRulesHash(nil),
				TargetNamespace:  "default",
			},
		},
	}
}

func requestSourceObjects(session *accessv1alpha1.BreakGlassSession) (*accessv1alpha1.BreakGlassRequest, *accessv1alpha1.BreakGlassApproval) {
	request := &accessv1alpha1.BreakGlassRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:              session.Spec.RequestRef.Name,
			UID:               types.UID(session.Spec.RequestRef.UID),
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Minute)),
		},
		Spec: accessv1alpha1.BreakGlassRequestSpec{
			AccessProfile:    session.Spec.AccessProfile,
			AccessProfileUID: session.Spec.AccessProfileUID,
			Requester:        session.Spec.Subject,
			Duration:         session.Spec.Duration,
			RequestTTL:       "15m",
			Reason:           session.Spec.Reason,
		},
		Status: accessv1alpha1.BreakGlassRequestStatus{
			Phase:       accessv1alpha1.RequestPhaseSessionCreated,
			ApprovalRef: &accessv1alpha1.BreakGlassObjectReference{Name: accessv1alpha1.ApprovalNameForRequestUID(session.Spec.RequestRef.UID), UID: "approval-uid"},
			SessionRef:  &accessv1alpha1.BreakGlassObjectReference{Name: session.Name, UID: string(session.UID)},
		},
	}
	approval := &accessv1alpha1.BreakGlassApproval{
		ObjectMeta: metav1.ObjectMeta{Name: request.Status.ApprovalRef.Name, UID: types.UID(request.Status.ApprovalRef.UID)},
		Spec: accessv1alpha1.BreakGlassApprovalSpec{
			RequestRef: accessv1alpha1.BreakGlassRequestReference{Name: request.Name, UID: string(request.UID)},
			Decision:   accessv1alpha1.ApprovalDecisionApproved,
			Approver:   accessv1alpha1.SubjectReference{Kind: accessv1alpha1.SubjectKindUser, Name: "approver@example.com"},
		},
	}
	return request, approval
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := rbacv1.AddToScheme(scheme); err != nil {
		t.Fatalf("add RBAC scheme: %v", err)
	}
	if err := accessv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add BreakGlassSession scheme: %v", err)
	}
	return scheme
}

// The controller-runtime fake client intentionally does not emulate API-server
// UID allocation. Give created RBAC bindings deterministic server-style UIDs so
// unit tests exercise the same status.bindingRef invariant as envtest.
func newTestClient(scheme *runtime.Scheme, objects ...client.Object) client.Client {
	raw := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&accessv1alpha1.BreakGlassSession{}, &accessv1alpha1.AccessProfile{}, &accessv1alpha1.BreakGlassRequest{}).
		WithIndex(&accessv1alpha1.BreakGlassSession{}, accessProfileField, accessProfileNameIndex).
		WithIndex(&accessv1alpha1.BreakGlassSession{}, requestSourceField, requestSourceNameIndex).
		WithObjects(objects...).
		Build()
	return interceptor.NewClient(raw, interceptor.Funcs{
		Create: func(ctx context.Context, next client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if obj.GetUID() == "" {
				obj.SetUID(types.UID("server-uid-" + obj.GetName()))
			}
			return next.Create(ctx, obj, opts...)
		},
	})
}

// newStatusFailingTestClient simulates the sole persistence failure that can
// occur after the API server accepts a RoleBinding create but before the
// controller records its UID in BreakGlassSession status.
func newStatusFailingTestClient(scheme *runtime.Scheme, objects ...client.Object) client.Client {
	raw := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&accessv1alpha1.BreakGlassSession{}, &accessv1alpha1.AccessProfile{}, &accessv1alpha1.BreakGlassRequest{}).
		WithIndex(&accessv1alpha1.BreakGlassSession{}, accessProfileField, accessProfileNameIndex).
		WithIndex(&accessv1alpha1.BreakGlassSession{}, requestSourceField, requestSourceNameIndex).
		WithObjects(objects...).
		Build()
	failStatusUpdate := true
	return interceptor.NewClient(raw, interceptor.Funcs{
		Create: func(ctx context.Context, next client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if obj.GetUID() == "" {
				obj.SetUID(types.UID("server-uid-" + obj.GetName()))
			}
			return next.Create(ctx, obj, opts...)
		},
		SubResourceUpdate: func(ctx context.Context, next client.Client, subResource string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if subResource == "status" && failStatusUpdate {
				if _, ok := obj.(*accessv1alpha1.BreakGlassSession); ok {
					failStatusUpdate = false
					return errors.New("injected BreakGlassSession status write failure")
				}
			}
			return next.SubResource(subResource).Update(ctx, obj, opts...)
		},
	})
}

type recordingMetrics struct {
	operations            []bindingOperationRecord
	driftReasons          []breakglassmetrics.BindingDriftReason
	curatedRoleDrifts     []breakglassmetrics.CuratedRoleDriftReason
	requestSourceFailures []breakglassmetrics.RequestSourceIntegrityReason
}

func (r *recordingMetrics) RecordTransition(breakglassmetrics.LifecycleTransition, breakglassmetrics.Scope) {
}

func (r *recordingMetrics) RecordBindingDrift(reason breakglassmetrics.BindingDriftReason, _ breakglassmetrics.Scope) {
	r.driftReasons = append(r.driftReasons, reason)
}

func (r *recordingMetrics) RecordCuratedRoleDrift(reason breakglassmetrics.CuratedRoleDriftReason, _ breakglassmetrics.Scope) {
	r.curatedRoleDrifts = append(r.curatedRoleDrifts, reason)
}

func (r *recordingMetrics) RecordRequestSourceIntegrity(reason breakglassmetrics.RequestSourceIntegrityReason, _ breakglassmetrics.Scope) {
	r.requestSourceFailures = append(r.requestSourceFailures, reason)
}

type bindingOperationRecord struct {
	operation breakglassmetrics.BindingOperation
	result    breakglassmetrics.BindingOperationResult
}

func (r *recordingMetrics) RecordBindingOperation(operation breakglassmetrics.BindingOperation, result breakglassmetrics.BindingOperationResult, _ breakglassmetrics.Scope) {
	r.operations = append(r.operations, bindingOperationRecord{operation, result})
}

func (r *recordingMetrics) ObserveExpiryCleanupLag(breakglassmetrics.Scope, time.Duration) {}

func TestPendingReservationCannotOutliveRequestDeadline(t *testing.T) {
	t.Parallel()
	for _, alreadyPromoted := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty reservation", true: "promotion before interrupted status write"}[alreadyPromoted], func(t *testing.T) {
			session := testSession()
			session.Finalizers = []string{BreakGlassFinalizer}
			session.Spec.RequestRef = &accessv1alpha1.BreakGlassRequestReference{Name: "request", UID: "request-uid"}
			request, approval := requestSourceObjects(session)
			profile, role := activationPolicyObjects()
			profile.Spec.DeliveryMode = accessv1alpha1.AccessDeliveryModeApprovalRequired
			r := &BreakGlassSessionReconciler{Client: newTestClient(testScheme(t), session, request, approval, profile, role), Scheme: testScheme(t)}
			ctx := context.Background()
			key := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(session)}
			if _, err := r.Reconcile(ctx, key); err != nil {
				t.Fatal(err)
			}
			if err := r.Get(ctx, key.NamespacedName, session); err != nil {
				t.Fatal(err)
			}
			if session.Status.Phase != accessv1alpha1.PhasePending || session.Status.ExpiresAt == nil {
				t.Fatal("expected persisted reservation")
			}
			bindingKey := client.ObjectKey{Name: session.Status.BindingRef.Name, Namespace: session.Status.BindingRef.Namespace}
			if alreadyPromoted {
				binding := &rbacv1.RoleBinding{}
				if err := r.Get(ctx, bindingKey, binding); err != nil {
					t.Fatal(err)
				}
				binding.Subjects = []rbacv1.Subject{expectedSubject(session)}
				if err := r.Update(ctx, binding); err != nil {
					t.Fatal(err)
				}
			}
			// Advance only the fake request's server timestamp; the grant TTL is still live.
			if err := r.Get(ctx, client.ObjectKeyFromObject(request), request); err != nil {
				t.Fatal(err)
			}
			request.CreationTimestamp = metav1.NewTime(time.Now().Add(-time.Hour))
			if err := r.Update(ctx, request); err != nil {
				t.Fatal(err)
			}
			restarted := &BreakGlassSessionReconciler{Client: r.Client, Scheme: r.Scheme}
			if _, err := restarted.Reconcile(ctx, key); err != nil {
				t.Fatal(err)
			}
			if err := r.Get(ctx, key.NamespacedName, session); err != nil {
				t.Fatal(err)
			}
			if !hasCondition(session.Status.Conditions, RequestSourceCondition, metav1.ConditionFalse, "RequestExpired") {
				t.Fatalf("status: %#v", session.Status)
			}
			if err := r.Get(ctx, bindingKey, &rbacv1.RoleBinding{}); !apierrors.IsNotFound(err) {
				t.Fatalf("binding remains: %v", err)
			}
		})
	}
}

func TestActiveSessionUsesGrantDeadlineInsteadOfRequestDeadline(t *testing.T) {
	t.Parallel()
	session := testSession()
	request := &accessv1alpha1.BreakGlassRequest{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour))}, Spec: accessv1alpha1.BreakGlassRequestSpec{RequestTTL: "15m"}}
	session.Status.Phase = accessv1alpha1.PhaseActive
	if issue := validateRequestDecisionDeadline(request, session); issue != nil {
		t.Fatalf("active session rejected: %#v", issue)
	}
}

func TestCleanupDriftRecordedOnlyAfterFinalizerWrite(t *testing.T) {
	t.Parallel()
	session := testSession()
	session.Finalizers = []string{BreakGlassFinalizer}
	session.DeletionTimestamp = &metav1.Time{Time: time.Now()}
	session.Status.BindingRef = expectedBindingReference(session)
	session.Status.BindingRef.UID = "missing-binding-uid"
	base := newTestClient(testScheme(t), session)
	fail := true
	c := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{Update: func(ctx context.Context, next client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
		if fail {
			fail = false
			return apierrors.NewConflict(accessv1alpha1.GroupVersion.WithResource("breakglasssessions").GroupResource(), obj.GetName(), errors.New("injected conflict"))
		}
		return next.Update(ctx, obj, opts...)
	}})
	metrics := &recordingMetrics{}
	r := &BreakGlassSessionReconciler{Client: c, Scheme: testScheme(t), Metrics: metrics}
	key := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(session)}
	if _, err := r.Reconcile(context.Background(), key); !apierrors.IsConflict(err) {
		t.Fatalf("want conflict, got %v", err)
	}
	if len(metrics.driftReasons) != 0 {
		t.Fatal("metric recorded before durable finalizer removal")
	}
	if _, err := r.Reconcile(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if len(metrics.driftReasons) != 1 {
		t.Fatalf("drift counted %d times", len(metrics.driftReasons))
	}
}

func TestReservationAndPromotionMetricsAreSeparate(t *testing.T) {
	t.Parallel()
	session := testSession()
	session.Finalizers = []string{BreakGlassFinalizer}
	profile, role := activationPolicyObjects()
	base := newTestClient(testScheme(t), session, profile, role)
	fail := true
	c := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{Update: func(ctx context.Context, next client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
		if _, ok := obj.(*rbacv1.RoleBinding); ok && fail {
			fail = false
			return errors.New("promotion failed")
		}
		return next.Update(ctx, obj, opts...)
	}})
	metrics := &recordingMetrics{}
	r := &BreakGlassSessionReconciler{Client: c, Scheme: testScheme(t), Metrics: metrics}
	key := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(session)}
	if _, err := r.Reconcile(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if len(metrics.operations) != 1 || metrics.operations[0].operation != breakglassmetrics.BindingOperationReserve {
		t.Fatalf("reservation metrics: %#v", metrics.operations)
	}
	if _, err := r.Reconcile(context.Background(), key); err == nil {
		t.Fatal("expected promotion failure")
	}
	if _, err := r.Reconcile(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	want := []bindingOperationRecord{{breakglassmetrics.BindingOperationReserve, breakglassmetrics.BindingOperationSuccess}, {breakglassmetrics.BindingOperationGrant, breakglassmetrics.BindingOperationError}, {breakglassmetrics.BindingOperationGrant, breakglassmetrics.BindingOperationSuccess}}
	if len(metrics.operations) != len(want) {
		t.Fatalf("metrics: %#v", metrics.operations)
	}
	for i := range want {
		if metrics.operations[i] != want[i] {
			t.Fatalf("metrics: %#v", metrics.operations)
		}
	}
}

func TestForbiddenCleanupRequiresConfirmedNamespaceAbsence(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"get", "delete", "list"} {
		for _, state := range []string{"absent", "present", "terminating", "recreated", "unreadable"} {
			t.Run(mode+"/"+state, func(t *testing.T) {
				ctx := context.Background()
				session := testSession()
				session.Finalizers = []string{BreakGlassFinalizer}
				session.DeletionTimestamp = &metav1.Time{Time: time.Now()}
				session.Status.BindingRef = expectedBindingReference(session)
				session.Status.BindingRef.UID = "binding-uid"
				binding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: session.Status.BindingRef.Name, Namespace: "default", UID: "binding-uid"}}
				if mode == "list" {
					session.Status = accessv1alpha1.BreakGlassSessionStatus{}
				}
				objects := []client.Object{session, binding}
				if state != "absent" && state != "unreadable" {
					ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default", UID: types.UID(state)}}
					if state == "terminating" {
						ns.DeletionTimestamp = &metav1.Time{Time: time.Now()}
						ns.Finalizers = []string{"test"}
					}
					objects = append(objects, ns)
				}
				denied := apierrors.NewForbidden(rbacv1.Resource("rolebindings"), binding.Name, errors.New("namespace RBAC removed"))
				base := newTestClient(testScheme(t), objects...)
				c := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
					Get: func(ctx context.Context, next client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
						if _, ok := obj.(*rbacv1.RoleBinding); ok && mode == "get" {
							return denied
						}
						if _, ok := obj.(*corev1.Namespace); ok && state == "unreadable" {
							return errors.New("namespace read unavailable")
						}
						return next.Get(ctx, key, obj, opts...)
					},
					Delete: func(ctx context.Context, next client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
						if _, ok := obj.(*rbacv1.RoleBinding); ok {
							return denied
						}
						return next.Delete(ctx, obj, opts...)
					},
					List: func(ctx context.Context, next client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
						if _, ok := list.(*rbacv1.RoleBindingList); ok {
							return denied
						}
						return next.List(ctx, list, opts...)
					},
				})
				r := &BreakGlassSessionReconciler{Client: c, APIReader: c, AllowedTargetNamespaces: map[string]struct{}{"default": {}}}
				_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(session)})
				if state == "absent" {
					if err != nil {
						t.Fatal(err)
					}
					if err := base.Get(ctx, client.ObjectKeyFromObject(session), &accessv1alpha1.BreakGlassSession{}); !apierrors.IsNotFound(err) {
						t.Fatalf("finalizer remains: %v", err)
					}
				} else {
					if !apierrors.IsForbidden(err) {
						t.Fatalf("want original Forbidden, got %v", err)
					}
					if err := base.Get(ctx, client.ObjectKeyFromObject(session), session); err != nil {
						t.Fatal(err)
					}
					if !controllerutil.ContainsFinalizer(session, BreakGlassFinalizer) {
						t.Fatal("unsafe finalizer removal")
					}
				}
			})
		}
	}
}

func TestNamespaceAbsenceUsesDirectReaderAndAllowedScope(t *testing.T) {
	t.Parallel()
	scheme := testScheme(t)
	stale := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	r := &BreakGlassSessionReconciler{
		Client: newTestClient(scheme, stale), APIReader: newTestClient(scheme),
		AllowedTargetNamespaces: map[string]struct{}{"default": {}},
	}
	if !r.namespaceConfirmedAbsent(context.Background(), "default") {
		t.Fatal("stale cache must not override direct absence")
	}
	if r.namespaceConfirmedAbsent(context.Background(), "other") {
		t.Fatal("must not recover outside the allowed scope")
	}
	// Conversely, a cache miss must never override an existing live namespace.
	r.Client, r.APIReader = newTestClient(scheme), newTestClient(scheme, stale)
	if r.namespaceConfirmedAbsent(context.Background(), "default") {
		t.Fatal("cache miss is not proof of namespace deletion")
	}
}

func TestRecoveredReservationDoesNotReportGrantOrRestore(t *testing.T) {
	t.Parallel()
	metrics := &recordingMetrics{}
	r := &BreakGlassSessionReconciler{Client: newTestClient(testScheme(t)), Scheme: testScheme(t), Metrics: metrics}
	session := testSession()
	for range 2 {
		if _, err := r.ensureReservedBindingReference(context.Background(), session); err != nil {
			t.Fatal(err)
		}
	}
	if len(metrics.operations) != 2 || metrics.operations[0].operation != breakglassmetrics.BindingOperationReserve ||
		metrics.operations[1].operation != breakglassmetrics.BindingOperationRecoverReservation {
		t.Fatalf("metrics: %#v", metrics.operations)
	}
}
