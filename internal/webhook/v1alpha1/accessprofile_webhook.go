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

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/adapter/apiconv"
	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	breakglassmetrics "github.com/yannick-thomas/breakglass-operator/internal/metrics"
)

// SetupAccessProfileWebhookWithManager installs the placement boundary for
// profiles: a profile can only be created in a control namespace and only
// for an allowed target namespace that is not a control namespace (ADR-004).
// Without it, placement would be enforced only when a profile is used.
func SetupAccessProfileWebhookWithManager(mgr ctrl.Manager, placement access.Placement) error {
	return ctrl.NewWebhookManagedBy(mgr, &accessv1alpha1.AccessProfile{}).
		WithValidator(&AccessProfileValidator{Placement: placement, Metrics: breakglassmetrics.DefaultRecorder}).
		Complete()
}

// The spec is immutable (CEL), so creation is the only point where placement
// can change; updates and deletes are not intercepted and never depend on
// admission availability.
// +kubebuilder:webhook:path=/validate-access-breakglass-io-v1alpha1-accessprofile,mutating=false,failurePolicy=fail,sideEffects=None,timeoutSeconds=5,groups=access.breakglass.io,resources=accessprofiles,verbs=create,versions=v1alpha1,name=vaccessprofile-v1alpha1.kb.io,admissionReviewVersions=v1

// AccessProfileValidator applies the domain profile and placement rules when
// a profile is created.
type AccessProfileValidator struct {
	Placement access.Placement
	Metrics   breakglassmetrics.AdmissionRecorder
}

var _ admission.Validator[*accessv1alpha1.AccessProfile] = (*AccessProfileValidator)(nil)

// ValidateCreate rejects a profile outside the control namespaces, one that
// grants in its own or another control namespace, one targeting a namespace
// outside the allowed set, and one that fails the semantic profile rules.
func (v *AccessProfileValidator) ValidateCreate(_ context.Context, obj *accessv1alpha1.AccessProfile) (warnings admission.Warnings, err error) {
	defer func() {
		recordAdmissionDecision(v.Metrics, breakglassmetrics.AdmissionOperationCreate, admissionOutcomeForError(err))
	}()
	return nil, v.Placement.AdmitProfile(apiconv.ToDomainProfile(obj))
}

// ValidateUpdate admits every update; the webhook is registered for CREATE only.
func (v *AccessProfileValidator) ValidateUpdate(context.Context, *accessv1alpha1.AccessProfile, *accessv1alpha1.AccessProfile) (admission.Warnings, error) {
	return nil, nil
}

// ValidateDelete admits every deletion; the webhook is registered for CREATE only.
func (v *AccessProfileValidator) ValidateDelete(context.Context, *accessv1alpha1.AccessProfile) (admission.Warnings, error) {
	return nil, nil
}
