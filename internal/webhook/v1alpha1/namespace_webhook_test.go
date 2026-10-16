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
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
)

var _ = Describe("Control namespace Webhook", func() {
	It("denies deleting a control namespace until its sessions are gone", func() {
		control := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "webhook-drain"}}
		Expect(k8sClient.Create(ctx, control)).To(Succeed())

		profile := &accessv1alpha1.AccessProfile{
			ObjectMeta: metav1.ObjectMeta{Namespace: control.Name, Name: "drain-pod-observer"},
			Spec: accessv1alpha1.AccessProfileSpec{
				RoleRef:         accessv1alpha1.RoleReference{Kind: "ClusterRole", Name: "breakglass-pod-observer"},
				TargetNamespace: "default",
				MaxDuration:     "30m",
			},
		}
		Expect(k8sClient.Create(ctx, profile)).To(Succeed())
		session := &accessv1alpha1.BreakGlassSession{
			ObjectMeta: metav1.ObjectMeta{Namespace: control.Name, Name: "drain-session"},
			Spec: accessv1alpha1.BreakGlassSessionSpec{
				AccessProfile: profile.Name,
				Subject:       accessv1alpha1.SubjectReference{Kind: accessv1alpha1.SubjectKindUser, Name: "jane@example.com"},
				Duration:      "15m",
				Reason:        "Verify the control namespace drain check",
			},
		}
		Expect(k8sClient.Create(ctx, session)).To(Succeed())

		err := k8sClient.Delete(ctx, control)
		Expect(err).To(HaveOccurred())
		Expect(apierrors.IsForbidden(err)).To(BeTrue(), "unexpected error: %v", err)
		Expect(err.Error()).To(ContainSubstring(`still holds 1 BreakGlassSession(s) (drain-session)`))

		Expect(k8sClient.Delete(ctx, session)).To(Succeed())
		Eventually(func() bool {
			return apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(session), session))
		}).Should(BeTrue())
		Expect(k8sClient.Delete(ctx, control)).To(Succeed())
	})
})
