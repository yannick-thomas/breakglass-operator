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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
)

// controlNamespaceWebhookPath serves the drain check for control namespaces.
const controlNamespaceWebhookPath = "/validate-core-v1-namespace"

// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglasssessions,verbs=list

// SetupControlNamespaceWebhookWithManager installs the drain check for
// control namespaces: a control namespace may be deleted only after its
// sessions are gone, because the manager's rights on them may be granted by
// RBAC in that namespace (ADR-004). Sessions are listed from the API server,
// not the cache, and the webhook fails closed.
func SetupControlNamespaceWebhookWithManager(mgr ctrl.Manager, placement access.Placement) error {
	return ctrl.NewWebhookManagedBy(mgr, &corev1.Namespace{}).
		WithValidator(&ControlNamespaceValidator{
			SessionReader: mgr.GetAPIReader(),
			Placement:     placement,
		}).
		WithValidatorCustomPath(controlNamespaceWebhookPath).
		Complete()
}

// The webhook configuration is scoped to the control namespaces by a
// namespaceSelector in each installer (Helm, Kustomize overlays), so its
// fail-closed policy never blocks the deletion of an unrelated namespace.
// +kubebuilder:webhook:path=/validate-core-v1-namespace,mutating=false,failurePolicy=fail,sideEffects=None,timeoutSeconds=5,groups="",resources=namespaces,verbs=delete,versions=v1,name=vcontrolnamespace-v1.kb.io,admissionReviewVersions=v1

// ControlNamespaceValidator denies the deletion of a control namespace that
// still holds BreakGlassSessions.
type ControlNamespaceValidator struct {
	// SessionReader must read the API server directly (not a cache): a
	// stale empty list would admit a deletion that strands a session.
	SessionReader client.Reader
	Placement     access.Placement
}

var _ admission.Validator[*corev1.Namespace] = (*ControlNamespaceValidator)(nil)

// ValidateCreate admits every creation; the webhook is registered for DELETE only.
func (v *ControlNamespaceValidator) ValidateCreate(context.Context, *corev1.Namespace) (admission.Warnings, error) {
	return nil, nil
}

// ValidateUpdate admits every update; the webhook is registered for DELETE only.
func (v *ControlNamespaceValidator) ValidateUpdate(context.Context, *corev1.Namespace, *corev1.Namespace) (admission.Warnings, error) {
	return nil, nil
}

// ValidateDelete lists the namespace's sessions and applies the domain drain
// rule. Any read failure denies the deletion.
func (v *ControlNamespaceValidator) ValidateDelete(ctx context.Context, namespace *corev1.Namespace) (admission.Warnings, error) {
	terminating := !namespace.DeletionTimestamp.IsZero() || namespace.Status.Phase == corev1.NamespaceTerminating
	if !v.Placement.NamespaceDeletionNeedsDrain(namespace.Name, terminating) {
		return nil, nil
	}
	if v.SessionReader == nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("BreakGlassSession reader is not configured"))
	}
	sessions := &accessv1alpha1.BreakGlassSessionList{}
	if err := v.SessionReader.List(ctx, sessions, client.InNamespace(namespace.Name)); err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("list BreakGlassSessions before deleting control namespace %q: %w", namespace.Name, err))
	}
	names := make([]string, 0, len(sessions.Items))
	for i := range sessions.Items {
		names = append(names, sessions.Items[i].Name)
	}
	return nil, v.Placement.CheckNamespaceDeletion(namespace.Name, terminating, names)
}
