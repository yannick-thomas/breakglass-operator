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

package expiryguard

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/adapter/apiconv"
	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/expirysweep"
)

const (
	testNamespace    = "production"
	controlNamespace = "breakglass-access"
	bindingUID       = "binding-uid"
)

var now = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func TestSweepDeletesExactBindingAfterGrace(t *testing.T) {
	t.Parallel()
	session, binding := expiredSession("s1", now.Add(-3*time.Minute))
	c := newClient(t, session, binding)

	report := sweep(t, New(c, nil))

	if len(report.Removed) != 1 || report.Failed() {
		t.Fatalf("report = %#v, want one removal and no refusal", report)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(binding), &rbacv1.RoleBinding{}); !apierrors.IsNotFound(err) {
		t.Fatalf("binding still present: %v", err)
	}
}

func TestSweepLeavesBindingWithinGrace(t *testing.T) {
	t.Parallel()
	session, binding := expiredSession("s1", now.Add(-time.Minute))
	c := newClient(t, session, binding)

	report := sweep(t, New(c, nil))

	if len(report.Removed) != 0 || report.Failed() {
		t.Fatalf("report = %#v, want nothing to do", report)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(binding), &rbacv1.RoleBinding{}); err != nil {
		t.Fatalf("binding removed within grace: %v", err)
	}
}

func TestSweepIgnoresSessionsWithoutExpiry(t *testing.T) {
	t.Parallel()
	session, binding := expiredSession("s1", now)
	session.Status.ExpiresAt = nil
	c := newClient(t, session, binding)

	if report := sweep(t, New(c, nil)); len(report.Removed) != 0 || report.Failed() {
		t.Fatalf("report = %#v, want nothing to do", report)
	}
}

func TestSweepRefusesReplacementBinding(t *testing.T) {
	t.Parallel()
	session, binding := expiredSession("s1", now.Add(-time.Hour))
	binding.UID = "replacement-uid"
	c := newClient(t, session, binding)

	report := sweep(t, New(c, nil))

	if !report.Failed() || len(report.Removed) != 0 {
		t.Fatalf("report = %#v, want refusal", report)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(binding), &rbacv1.RoleBinding{}); err != nil {
		t.Fatalf("replacement binding was touched: %v", err)
	}
}

func TestSweepRefusesNamespaceOutsideAllowList(t *testing.T) {
	t.Parallel()
	session, binding := expiredSession("s1", now.Add(-time.Hour))
	c := newClient(t, session, binding)

	report := sweep(t, withScope(New(c, nil), access.NamespaceScope{"staging": {}}))

	if !report.Failed() {
		t.Fatalf("report = %#v, want refusal", report)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(binding), &rbacv1.RoleBinding{}); err != nil {
		t.Fatalf("binding outside allow list was touched: %v", err)
	}
}

func TestSweepTreatsMissingBindingAsDone(t *testing.T) {
	t.Parallel()
	session, _ := expiredSession("s1", now.Add(-time.Hour))
	report := sweep(t, New(newClient(t, session), nil))
	if len(report.Removed) != 0 || report.Failed() {
		t.Fatalf("report = %#v, want nothing to do", report)
	}
}

func TestSweepRefusesActiveSessionWithoutBindingIdentity(t *testing.T) {
	t.Parallel()
	active, _ := expiredSession("active", now.Add(-time.Hour))
	active.Status.BindingRef = nil
	expired, _ := expiredSession("expired", now.Add(-time.Hour))
	expired.Status.BindingRef = nil
	expired.Status.Phase = accessv1alpha1.PhaseExpired

	report := sweep(t, New(newClient(t, active, expired), nil))

	if len(report.Refused) != 1 || report.Refused[0].Session != "active" {
		t.Fatalf("report = %#v, want one refusal for the active session", report)
	}
}

func TestSweepDryRunDeletesNothing(t *testing.T) {
	t.Parallel()
	session, binding := expiredSession("s1", now.Add(-time.Hour))
	c := newClient(t, session, binding)

	report := sweep(t, dryRun(New(c, nil)))

	if len(report.Removed) != 1 {
		t.Fatalf("report = %#v, want one planned removal", report)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(binding), &rbacv1.RoleBinding{}); err != nil {
		t.Fatalf("dry run deleted the binding: %v", err)
	}
}

func TestSweepDeletesWithUIDPrecondition(t *testing.T) {
	t.Parallel()
	session, binding := expiredSession("s1", now.Add(-time.Hour))
	var preconditions *metav1.Preconditions
	c := interceptor.NewClient(newClient(t, session, binding), interceptor.Funcs{
		Delete: func(ctx context.Context, next client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			options := &client.DeleteOptions{}
			options.ApplyOptions(opts)
			preconditions = options.Preconditions
			return next.Delete(ctx, obj, opts...)
		},
	})

	sweep(t, New(c, nil))

	if preconditions == nil || preconditions.UID == nil || *preconditions.UID != types.UID(bindingUID) {
		t.Fatalf("delete preconditions = %#v, want recorded UID", preconditions)
	}
}

func TestSweepReportsConflictAsRefusal(t *testing.T) {
	t.Parallel()
	session, binding := expiredSession("s1", now.Add(-time.Hour))
	c := interceptor.NewClient(newClient(t, session, binding), interceptor.Funcs{
		Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
			return apierrors.NewConflict(rbacv1.Resource("rolebindings"), binding.Name, errors.New("changed"))
		},
	})

	if report := sweep(t, New(c, nil)); !report.Failed() {
		t.Fatalf("report = %#v, want refusal", report)
	}
}

func TestSweepFailsWhenSessionsCannotBeListed(t *testing.T) {
	t.Parallel()
	c := interceptor.NewClient(newClient(t), interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errors.New("unavailable")
		},
	})
	guard := New(c, nil)
	guard.Clock = func() time.Time { return now }
	guard.Log = logr.Discard()
	if _, err := guard.Sweep(context.Background()); err == nil {
		t.Fatal("Sweep() error = nil, want error")
	}
}

func withScope(guard *expirysweep.Sweeper, scope access.NamespaceScope) *expirysweep.Sweeper {
	guard.Scope = scope
	return guard
}

func dryRun(guard *expirysweep.Sweeper) *expirysweep.Sweeper {
	guard.DryRun = true
	return guard
}

func sweep(t *testing.T, guard *expirysweep.Sweeper) expirysweep.Report {
	t.Helper()
	guard.Clock = func() time.Time { return now }
	guard.Log = logr.Discard()
	report, err := guard.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep() error = %v", err)
	}
	return report
}

func expiredSession(name string, expiresAt time.Time) (*accessv1alpha1.BreakGlassSession, *rbacv1.RoleBinding) {
	expiry := metav1.NewTime(expiresAt)
	bindingName := "breakglass-" + name
	session := &accessv1alpha1.BreakGlassSession{
		ObjectMeta: metav1.ObjectMeta{Namespace: controlNamespace, Name: name, UID: types.UID(name + "-uid")},
		Status: accessv1alpha1.BreakGlassSessionStatus{
			Phase:     accessv1alpha1.PhaseActive,
			ExpiresAt: &expiry,
			BindingRef: &accessv1alpha1.BindingReference{
				Kind: access.RoleBindingKind, Namespace: testNamespace, Name: bindingName, UID: bindingUID,
			},
		},
	}
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: bindingName, Namespace: testNamespace, UID: bindingUID,
			Labels: apiconv.ToDomainSession(session).ManagedLabels(),
		},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "pod-observer"},
		Subjects: []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: "oidc:jane@example.com"}},
	}
	return session, binding
}

func newClient(t *testing.T, objects ...client.Object) client.WithWatch {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := accessv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).
		WithStatusSubresource(&accessv1alpha1.BreakGlassSession{}).Build()
}

func TestSweepDeletesBindingOfDeletedSession(t *testing.T) {
	t.Parallel()
	_, binding := expiredSession("gone", now.Add(time.Hour))
	c := newClient(t, binding)

	report := sweep(t, New(c, access.NamespaceScope{controlNamespace: {}}))

	if len(report.Removed) != 1 || report.Removed[0].Reason != "session no longer exists" || report.Failed() {
		t.Fatalf("report = %#v, want the orphaned binding removed", report)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(binding), &rbacv1.RoleBinding{}); !apierrors.IsNotFound(err) {
		t.Fatalf("orphaned binding still present: %v", err)
	}
}

func TestSweepKeepsBindingOfLiveSession(t *testing.T) {
	t.Parallel()
	session, binding := expiredSession("live", now.Add(time.Hour))
	c := newClient(t, session, binding)

	if report := sweep(t, New(c, access.NamespaceScope{controlNamespace: {}})); len(report.Removed) != 0 || report.Failed() {
		t.Fatalf("report = %#v, want nothing to do", report)
	}
}

func TestSweepRefusesBindingOfSessionOutsideControlNamespaces(t *testing.T) {
	t.Parallel()
	// The guard's control namespaces have drifted from the manager's: the
	// session in team-b is live, but the guard does not read team-b.
	session, binding := expiredSession("elsewhere", now.Add(time.Hour))
	session.Namespace = "team-b"
	binding.Labels = apiconv.ToDomainSession(session).ManagedLabels()
	c := newClient(t, session, binding)

	report := sweep(t, New(c, access.NamespaceScope{controlNamespace: {}}))

	if !report.Failed() || len(report.Refused) != 1 || len(report.Removed) != 0 {
		t.Fatalf("report = %#v, want a refusal and no removal", report)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(binding), &rbacv1.RoleBinding{}); err != nil {
		t.Fatalf("binding of a session outside the control namespaces was touched: %v", err)
	}
}

func TestSweepIgnoresManagedBindingWithoutSessionIdentity(t *testing.T) {
	t.Parallel()
	_, binding := expiredSession("forged", now.Add(time.Hour))
	binding.Labels = map[string]string{access.ManagedByLabelKey: access.ManagedByLabelValue}
	c := newClient(t, binding)

	report := sweep(t, New(c, access.NamespaceScope{controlNamespace: {}}))

	if report.Failed() || len(report.Ignored) != 1 || len(report.Removed) != 0 {
		t.Fatalf("report = %#v, want one ignored binding and no failure", report)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(binding), &rbacv1.RoleBinding{}); err != nil {
		t.Fatalf("binding without session identity was touched: %v", err)
	}
}

func TestSweepListsBindingsBeforeSessions(t *testing.T) {
	t.Parallel()
	var order []string
	c := interceptor.NewClient(newClient(t), interceptor.Funcs{
		List: func(ctx context.Context, next client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			switch list.(type) {
			case *rbacv1.RoleBindingList:
				order = append(order, "bindings")
			case *accessv1alpha1.BreakGlassSessionList:
				order = append(order, "sessions")
			}
			return next.List(ctx, list, opts...)
		},
		Get: func(ctx context.Context, next client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*accessv1alpha1.BreakGlassSession); ok {
				t.Errorf("Get(BreakGlassSession %s): want sessions only listed", key)
			}
			return next.Get(ctx, key, obj, opts...)
		},
	})

	sweep(t, New(c, access.NamespaceScope{controlNamespace: {}}))

	if len(order) != 2 || order[0] != "bindings" || order[1] != "sessions" {
		t.Fatalf("list order = %q, want managed bindings listed once before sessions", order)
	}
}

func TestSweepListsSessionsOnlyInControlNamespaces(t *testing.T) {
	t.Parallel()
	var namespaces []string
	c := interceptor.NewClient(newClient(t), interceptor.Funcs{
		List: func(ctx context.Context, next client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*accessv1alpha1.BreakGlassSessionList); ok {
				options := &client.ListOptions{}
				options.ApplyOptions(opts)
				namespaces = append(namespaces, options.Namespace)
			}
			return next.List(ctx, list, opts...)
		},
	})

	sweep(t, New(c, access.NamespaceScope{"team-b": {}, controlNamespace: {}}))

	if len(namespaces) != 2 || namespaces[0] != controlNamespace || namespaces[1] != "team-b" {
		t.Fatalf("listed sessions in %q, want exactly the control namespaces", namespaces)
	}
}

// forbidLists makes listing the given kind Forbidden in the given namespaces,
// as when the guard's namespaced Role went with its namespace.
func forbidLists[L client.ObjectList](c client.WithWatch, namespaces ...string) client.WithWatch {
	return interceptor.NewClient(c, interceptor.Funcs{
		List: func(ctx context.Context, next client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			options := &client.ListOptions{}
			options.ApplyOptions(opts)
			if _, ok := list.(L); ok && slices.Contains(namespaces, options.Namespace) {
				return apierrors.NewForbidden(rbacv1.Resource("rolebindings"), "", errors.New("no permission"))
			}
			return next.List(ctx, list, opts...)
		},
	})
}

func namespace(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func terminating(name string) *corev1.Namespace {
	ns := namespace(name)
	ns.Finalizers = []string{"kubernetes"}
	ns.DeletionTimestamp = &metav1.Time{Time: now}
	return ns
}

func orphanIn(sessionNamespace, name string) *rbacv1.RoleBinding {
	session, binding := expiredSession(name, now.Add(time.Hour))
	session.Namespace = sessionNamespace
	binding.Name, binding.UID = "rb-"+name, types.UID("uid-"+name)
	binding.Labels = apiconv.ToDomainSession(session).ManagedLabels()
	return binding
}

func exists(t *testing.T, c client.Client, obj client.Object) bool {
	t.Helper()
	err := c.Get(context.Background(), client.ObjectKeyFromObject(obj), &rbacv1.RoleBinding{})
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	return err == nil
}

func TestSweepTreatsDeletedTargetNamespaceAsEmpty(t *testing.T) {
	t.Parallel()
	orphan := orphanIn(controlNamespace, "gone")
	// staging was deleted: no Namespace, and listing there is Forbidden.
	c := forbidLists[*rbacv1.RoleBindingList](newClient(t, namespace(testNamespace), namespace(controlNamespace), orphan), "staging")

	report := sweep(t, withScope(New(c, access.NamespaceScope{controlNamespace: {}}),
		access.NamespaceScope{testNamespace: {}, "staging": {}}))

	if report.Failed() || len(report.Removed) != 1 {
		t.Fatalf("report = %#v, want the deleted namespace treated as empty and production swept", report)
	}
	if exists(t, c, orphan) {
		t.Fatal("orphaned binding in production still present")
	}
}

func TestSweepTreatsDeletedControlNamespaceAsEmpty(t *testing.T) {
	t.Parallel()
	live, liveBinding := expiredSession("live", now.Add(time.Hour))
	inDeleted := orphanIn("team-b", "in-deleted")
	goneInLive := orphanIn(controlNamespace, "gone")
	c := forbidLists[*accessv1alpha1.BreakGlassSessionList](
		newClient(t, namespace(testNamespace), namespace(controlNamespace), live, liveBinding, inDeleted, goneInLive), "team-b")

	report := sweep(t, New(c, access.NamespaceScope{controlNamespace: {}, "team-b": {}}))

	if report.Failed() || len(report.Removed) != 2 {
		t.Fatalf("report = %#v, want both orphans removed and no failure", report)
	}
	if exists(t, c, inDeleted) || exists(t, c, goneInLive) || !exists(t, c, liveBinding) {
		t.Fatal("want only the live session's binding kept")
	}
}

func TestSweepReportsForbiddenNamespaceThatStillExists(t *testing.T) {
	t.Parallel()
	unseen := orphanIn("team-b", "unseen")
	goneInLive := orphanIn(controlNamespace, "gone")
	// team-b is terminating: its Role is gone, but sessions may still exist.
	c := forbidLists[*accessv1alpha1.BreakGlassSessionList](
		newClient(t, namespace(testNamespace), namespace(controlNamespace), terminating("team-b"), unseen, goneInLive), "team-b")

	report := sweep(t, New(c, access.NamespaceScope{controlNamespace: {}, "team-b": {}}))

	if !report.Failed() || len(report.Unreadable) != 1 || report.Unreadable[0].Namespace != "team-b" {
		t.Fatalf("report = %#v, want team-b reported unreadable", report)
	}
	if len(report.Refused) != 1 || report.Refused[0].Binding != unseen.Name {
		t.Fatalf("report = %#v, want the binding claiming team-b refused", report)
	}
	if !exists(t, c, unseen) {
		t.Fatal("binding claiming a session in an unreadable control namespace was deleted")
	}
	if exists(t, c, goneInLive) {
		t.Fatal("readable control namespace was not swept")
	}
}

func TestNamespaceAbsentOnlyOnNotFound(t *testing.T) {
	t.Parallel()
	failGet := func(err error) client.WithWatch {
		return interceptor.NewClient(newClient(t), interceptor.Funcs{
			Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
				return err
			},
		})
	}
	for _, tc := range []struct {
		name   string
		reader client.Reader
		absent bool
	}{
		{"not found", newClient(t), true},
		{"exists", newClient(t, namespace("team-b")), false},
		{"terminating", newClient(t, terminating("team-b")), false},
		{"forbidden", failGet(apierrors.NewForbidden(corev1.Resource("namespaces"), "team-b", errors.New("no permission"))), false},
		{"unavailable", failGet(errors.New("unavailable")), false},
	} {
		if got := (namespaceObserver{Reader: tc.reader}).NamespaceAbsent(context.Background(), "team-b"); got != tc.absent {
			t.Errorf("%s: NamespaceAbsent() = %t, want %t", tc.name, got, tc.absent)
		}
	}
}
