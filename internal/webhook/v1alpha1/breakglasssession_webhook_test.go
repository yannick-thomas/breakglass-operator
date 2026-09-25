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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
)

var _ = Describe("BreakGlassSession Webhook", func() {
	It("attributes the authenticated requester and snapshots the profile UID", func() {
		profile := &accessv1alpha1.AccessProfile{
			ObjectMeta: metav1.ObjectMeta{Name: "webhook-production-pod-observer"},
			Spec: accessv1alpha1.AccessProfileSpec{
				RoleRef:         accessv1alpha1.RoleReference{Kind: "ClusterRole", Name: "breakglass-pod-observer"},
				TargetNamespace: "default",
				MaxDuration:     "30m",
			},
		}
		Expect(k8sClient.Create(ctx, profile)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, profile) })
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(profile), profile)).To(Succeed())

		request := &accessv1alpha1.BreakGlassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "webhook-requester-attribution"},
			Spec: accessv1alpha1.BreakGlassSessionSpec{
				AccessProfile: "webhook-production-pod-observer",
				Subject: accessv1alpha1.SubjectReference{
					Kind: accessv1alpha1.SubjectKindUser,
					Name: "client-supplied@example.com",
				},
				Duration: "15m",
				Reason:   "Verify admission requester attribution",
			},
		}
		Expect(k8sClient.Create(ctx, request)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, request) })

		stored := &accessv1alpha1.BreakGlassSession{}
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(request), stored)).To(Succeed())
		Expect(stored.Spec.Subject.Kind).To(Equal(accessv1alpha1.SubjectKindUser))
		Expect(stored.Spec.Subject.Name).NotTo(BeEmpty())
		Expect(stored.Spec.Subject.Name).NotTo(Equal("client-supplied@example.com"))
		Expect(stored.Spec.AccessProfileUID).To(Equal(string(profile.UID)))
	})
})
