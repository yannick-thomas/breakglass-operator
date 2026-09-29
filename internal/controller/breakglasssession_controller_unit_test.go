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
		t.Fatalf("activate Reconcile() error = %v", err)
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
	client := newTestClient(scheme)
	reconciler := &BreakGlassSessionReconciler{Client: client, Scheme: scheme}

	if err := reconciler.ensureBinding(context.Background(), session); err != nil {
		t.Fatalf("ensureBinding() error = %v", err)
	}

	binding := &rbacv1.RoleBinding{}
	key := types.NamespacedName{Name: bindingName, Namespace: "default"}
	if err := client.Get(context.Background(), key, binding); err != nil {
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
	if err := client.Get(context.Background(), key, binding); err == nil {
		t.Fatal("cleanupBinding() left the managed RoleBinding behind")
	}
}

func TestBindingLabelRemovalIsDetectedAndExactBindingIsCleanedUp(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	session := testSession()
	bindingName := bindingNameForSession(session)
	client := newTestClient(scheme, session.DeepCopy())
	reconciler := &BreakGlassSessionReconciler{Client: client, Scheme: scheme}

	if err := reconciler.ensureBinding(context.Background(), session); err != nil {
		t.Fatalf("ensureBinding() error = %v", err)
	}

	key := types.NamespacedName{Name: bindingName, Namespace: "default"}
	binding := &rbacv1.RoleBinding{}
	if err := client.Get(context.Background(), key, binding); err != nil {
		t.Fatalf("get created RoleBinding: %v", err)
	}
	binding.Labels = nil
	if err := client.Update(context.Background(), binding); err != nil {
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
	if err := client.Get(context.Background(), key, binding); err == nil {
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
	client := newTestClient(scheme, replacement)
	reconciler := &BreakGlassSessionReconciler{Client: client, Scheme: scheme}

	cleanup, err := reconciler.cleanupBindingWithResult(context.Background(), session)
	if err != nil {
		t.Fatalf("cleanupBindingWithResult() error = %v", err)
	}
	if cleanup.IntegrityIssue == nil || cleanup.IntegrityIssue.Code != "uid_mismatch" {
		t.Fatalf("cleanup result = %#v, want UID mismatch", cleanup)
	}

	got := &rbacv1.RoleBinding{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: replacement.Name, Namespace: replacement.Namespace}, got); err != nil {
		t.Fatalf("replacement binding was deleted: %v", err)
	}
	if got.UID != replacement.UID {
		t.Fatalf("replacement UID = %q, want %q", got.UID, replacement.UID)
	}
}

func TestVerifyBindingIntegrityDetectsSubjectDrift(t *testing.T) {
	t.Parallel()

	scheme := testScheme(t)
	session := testSession()
	bindingName := bindingNameForSession(session)
	client := newTestClient(scheme)
	reconciler := &BreakGlassSessionReconciler{Client: client, Scheme: scheme}

	if err := reconciler.ensureBinding(context.Background(), session); err != nil {
		t.Fatalf("ensureBinding() error = %v", err)
	}
	binding := &rbacv1.RoleBinding{}
	key := types.NamespacedName{Name: bindingName, Namespace: "default"}
	if err := client.Get(context.Background(), key, binding); err != nil {
		t.Fatalf("get binding: %v", err)
	}
	binding.Subjects = append(binding.Subjects, rbacv1.Subject{Kind: rbacv1.UserKind, Name: "unexpected@example.com"})
	if err := client.Update(context.Background(), binding); err != nil {
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

// The controller-runtime fake client intentionally does not emulate API-server
// UID allocation. Give created RBAC bindings deterministic server-style UIDs so
// unit tests exercise the same status.bindingRef invariant as envtest.
func newTestClient(scheme *runtime.Scheme, objects ...client.Object) client.Client {
	raw := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&accessv1alpha1.BreakGlassSession{}, &accessv1alpha1.AccessProfile{}).
		WithIndex(&accessv1alpha1.BreakGlassSession{}, accessProfileField, accessProfileNameIndex).
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

type recordingMetrics struct {
	driftReasons      []breakglassmetrics.BindingDriftReason
	curatedRoleDrifts []breakglassmetrics.CuratedRoleDriftReason
}

func (r *recordingMetrics) RecordTransition(breakglassmetrics.LifecycleTransition, breakglassmetrics.Scope) {
}

func (r *recordingMetrics) RecordBindingDrift(reason breakglassmetrics.BindingDriftReason, _ breakglassmetrics.Scope) {
	r.driftReasons = append(r.driftReasons, reason)
}

func (r *recordingMetrics) RecordCuratedRoleDrift(reason breakglassmetrics.CuratedRoleDriftReason, _ breakglassmetrics.Scope) {
	r.curatedRoleDrifts = append(r.curatedRoleDrifts, reason)
}

func (r *recordingMetrics) RecordBindingOperation(breakglassmetrics.BindingOperation, breakglassmetrics.BindingOperationResult, breakglassmetrics.Scope) {
}

func (r *recordingMetrics) ObserveExpiryCleanupLag(breakglassmetrics.Scope, time.Duration) {}
