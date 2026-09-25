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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
)

var _ = Describe("BreakGlassSession Controller", func() {
	Context("When reconciling a BreakGlassSession", func() {
		const resourceName = "test-incident-session"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name: resourceName,
		}

		BeforeEach(func() {
			session := &accessv1alpha1.BreakGlassSession{
				ObjectMeta: metav1.ObjectMeta{
					Name: resourceName,
				},
				Spec: accessv1alpha1.BreakGlassSessionSpec{
					Subject: accessv1alpha1.SubjectReference{
						Kind: accessv1alpha1.SubjectKindUser,
						Name: "dev@example.com",
					},
					RoleRef: accessv1alpha1.RoleReference{
						Kind: "ClusterRole",
						Name: "edit",
					},
					TargetNamespace: "default",
					Duration:        "30m",
					Reason:          "Debugging production outage",
				},
			}
			err := k8sClient.Get(ctx, typeNamespacedName, &accessv1alpha1.BreakGlassSession{})
			if err != nil && errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, session)).To(Succeed())
			}
		})

		AfterEach(func() {
			session := &accessv1alpha1.BreakGlassSession{}
			err := k8sClient.Get(ctx, typeNamespacedName, session)
			if err == nil {
				// Reconciler cleanup
				reconciler := &BreakGlassSessionReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				}
				_ = k8sClient.Delete(ctx, session)
				_, _ = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			}
		})

		It("should successfully reconcile the session and activate access", func() {
			reconciler := &BreakGlassSessionReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// First reconcile adds finalizer
			result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile creates binding and activates
			result, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			// Verify status
			updatedSession := &accessv1alpha1.BreakGlassSession{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedSession)).To(Succeed())
			Expect(updatedSession.Status.Phase).To(Equal(accessv1alpha1.PhaseActive))
			Expect(updatedSession.Status.ExpiresAt).NotTo(BeNil())
			Expect(updatedSession.Status.BindingName).To(Equal("breakglass-test-incident-session"))
		})
	})
})
