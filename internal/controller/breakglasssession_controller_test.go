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
	rbacv1 "k8s.io/api/rbac/v1"
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
			role := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "breakglass-pod-observer"},
				Rules: []rbacv1.PolicyRule{{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get", "list", "watch"},
				}},
			}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: role.Name}, &rbacv1.ClusterRole{})
			if err != nil && errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, role)).To(Succeed())
			}

			profile := &accessv1alpha1.AccessProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "production-pod-observer"},
				Spec: accessv1alpha1.AccessProfileSpec{
					RoleRef:         accessv1alpha1.RoleReference{Kind: "ClusterRole", Name: "breakglass-pod-observer"},
					TargetNamespace: "default",
					MaxDuration:     "30m",
				},
			}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: profile.Name}, &accessv1alpha1.AccessProfile{})
			if err != nil && errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, profile)).To(Succeed())
			}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: profile.Name}, profile)).To(Succeed())

			session := &accessv1alpha1.BreakGlassSession{
				ObjectMeta: metav1.ObjectMeta{
					Name: resourceName,
				},
				Spec: accessv1alpha1.BreakGlassSessionSpec{
					AccessProfile:    profile.Name,
					AccessProfileUID: string(profile.UID),
					Subject: accessv1alpha1.SubjectReference{
						Kind: accessv1alpha1.SubjectKindUser,
						Name: "dev@example.com",
					},
					Duration: "30m",
					Reason:   "Debugging production outage",
				},
			}
			err = k8sClient.Get(ctx, typeNamespacedName, &accessv1alpha1.BreakGlassSession{})
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
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile reserves a non-authorizing binding and records its UID.
			result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			// Third reconcile grants the subject only after the binding UID is durable.
			result, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			// Verify status
			updatedSession := &accessv1alpha1.BreakGlassSession{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedSession)).To(Succeed())
			Expect(updatedSession.Status.Phase).To(Equal(accessv1alpha1.PhaseActive))
			Expect(updatedSession.Status.ExpiresAt).NotTo(BeNil())
			Expect(updatedSession.Status.BindingName).To(Equal(bindingNameForSession(updatedSession)))
			Expect(updatedSession.Status.BindingRef).NotTo(BeNil())
			Expect(updatedSession.Status.BindingRef.Kind).To(Equal("RoleBinding"))
			Expect(updatedSession.Status.BindingRef.Name).To(Equal(updatedSession.Status.BindingName))
			Expect(updatedSession.Status.Grant).NotTo(BeNil())
			Expect(updatedSession.Status.Grant.TargetNamespace).To(Equal("default"))
			Expect(updatedSession.Status.BindingRef.Namespace).To(Equal(updatedSession.Status.Grant.TargetNamespace))
			Expect(updatedSession.Status.Conditions).To(ContainElement(SatisfyAll(
				HaveField("Type", Equal(AccessGrantedCondition)),
				HaveField("Status", Equal(metav1.ConditionTrue)),
			)))

			binding := &rbacv1.RoleBinding{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      updatedSession.Status.BindingName,
				Namespace: updatedSession.Status.Grant.TargetNamespace,
			}, binding)).To(Succeed())
			Expect(binding.Labels).To(HaveKeyWithValue(SessionUIDLabelKey, string(updatedSession.UID)))
			Expect(binding.OwnerReferences).To(HaveLen(1))
			owner := binding.OwnerReferences[0]
			Expect(owner.UID).To(Equal(updatedSession.UID))
			Expect(owner.Controller).NotTo(BeNil())
			Expect(*owner.Controller).To(BeTrue())
			Expect(updatedSession.Status.BindingRef.UID).To(Equal(string(binding.UID)))
		})
	})
})
