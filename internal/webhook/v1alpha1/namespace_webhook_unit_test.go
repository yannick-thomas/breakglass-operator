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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
)

func controlNamespaceSession(name string, deleting bool) *accessv1alpha1.BreakGlassSession {
	session := &accessv1alpha1.BreakGlassSession{
		ObjectMeta: metav1.ObjectMeta{Namespace: testControlNamespace, Name: name},
	}
	if deleting {
		now := metav1.Now()
		session.DeletionTimestamp = &now
		session.Finalizers = []string{"access.breakglass.io/rolebinding-cleanup"}
	}
	return session
}

func TestControlNamespaceDeletionRequiresDrainedSessions(t *testing.T) {
	ctx := context.Background()
	live := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testControlNamespace}}
	terminating := live.DeepCopy()
	terminating.Status.Phase = corev1.NamespaceTerminating
	withSessions := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).
		WithObjects(controlNamespaceSession("active", false), controlNamespaceSession("cleaning-up", true)).Build()
	drained := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).Build()
	failing := fake.NewClientBuilder().WithScheme(webhookTestScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errors.New("connection refused")
		},
	}).Build()

	for _, tc := range []struct {
		name      string
		reader    client.Reader
		namespace *corev1.Namespace
		wantErr   string
		internal  bool
	}{
		// A session already being deleted still holds a finalizer that needs
		// the manager's rights in this namespace, so it blocks as well.
		{name: "live and deleting sessions", reader: withSessions, namespace: live,
			wantErr: `still holds 2 BreakGlassSession(s) (active, cleaning-up)`},
		{name: "drained", reader: drained, namespace: live},
		{name: "read failure fails closed", reader: failing, namespace: live,
			wantErr: "list BreakGlassSessions", internal: true},
		{name: "missing reader fails closed", namespace: live, wantErr: "not configured", internal: true},
		{name: "already terminating", namespace: terminating},
		{name: "not a control namespace", namespace: &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			validator := &ControlNamespaceValidator{SessionReader: tc.reader, Placement: controlOnly}
			_, err := validator.ValidateDelete(ctx, tc.namespace)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected denial: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
			if apierrors.IsInternalError(err) != tc.internal {
				t.Fatalf("internal error = %v, want %v", apierrors.IsInternalError(err), tc.internal)
			}
		})
	}
}
