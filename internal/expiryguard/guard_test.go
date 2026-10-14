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
	"testing"
	"time"

	"github.com/go-logr/logr"
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
	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/expirysweep"
)

const (
	testNamespace = "production"
	bindingUID    = "binding-uid"
)

var now = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func TestSweepDeletesExactBindingAfterGrace(t *testing.T) {
	t.Parallel()
	session, binding := expiredSession("s1", now.Add(-3*time.Minute))
	c := newClient(t, session, binding)

	report := sweep(t, New(c))

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

	report := sweep(t, New(c))

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

	if report := sweep(t, New(c)); len(report.Removed) != 0 || report.Failed() {
		t.Fatalf("report = %#v, want nothing to do", report)
	}
}

func TestSweepRefusesReplacementBinding(t *testing.T) {
	t.Parallel()
	session, binding := expiredSession("s1", now.Add(-time.Hour))
	binding.UID = "replacement-uid"
	c := newClient(t, session, binding)

	report := sweep(t, New(c))

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

	report := sweep(t, withScope(New(c), access.NamespaceScope{"staging": {}}))

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
	report := sweep(t, New(newClient(t, session)))
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

	report := sweep(t, New(newClient(t, active, expired)))

	if len(report.Refused) != 1 || report.Refused[0].Session != "active" {
		t.Fatalf("report = %#v, want one refusal for the active session", report)
	}
}

func TestSweepDryRunDeletesNothing(t *testing.T) {
	t.Parallel()
	session, binding := expiredSession("s1", now.Add(-time.Hour))
	c := newClient(t, session, binding)

	report := sweep(t, dryRun(New(c)))

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

	sweep(t, New(c))

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

	if report := sweep(t, New(c)); !report.Failed() {
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
	guard := New(c)
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
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(name + "-uid")},
		Status: accessv1alpha1.BreakGlassSessionStatus{
			Phase:     accessv1alpha1.PhaseActive,
			ExpiresAt: &expiry,
			BindingRef: &accessv1alpha1.BindingReference{
				Kind: access.RoleBindingKind, Namespace: testNamespace, Name: bindingName, UID: bindingUID,
			},
		},
	}
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: bindingName, Namespace: testNamespace, UID: bindingUID},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "pod-observer"},
		Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: "oidc:jane@example.com"}},
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
