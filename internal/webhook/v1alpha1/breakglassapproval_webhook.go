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
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	breakglassmetrics "github.com/yannick-thomas/breakglass-operator/internal/metrics"
)

// ProfileApprovalReviewer performs the profile-scoped authorization decision
// for an authenticated approver.
type ProfileApprovalReviewer interface {
	CanApprove(context.Context, authenticationUserInfo, string) (bool, error)
}

// authenticationUserInfo aliases the Kubernetes admission identity used by
// SubjectAccessReview without making approval API callers depend on internals.
// It remains an alias so KubernetesSubjectAccessReviewer satisfies the
// interface directly.
type authenticationUserInfo = authenticationv1.UserInfo

// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglassrequests,verbs=get

// SetupBreakGlassApprovalWebhookWithManager installs the append-only human
// approval boundary. The request controller later consumes only an admission-
// verified approval; it never treats an arbitrary CR as a grant command.
func SetupBreakGlassApprovalWebhookWithManager(mgr ctrl.Manager, allowedTargetNamespaces map[string]struct{}) error {
	return ctrl.NewWebhookManagedBy(mgr, &accessv1alpha1.BreakGlassApproval{}).
		WithDefaulter(&BreakGlassApprovalDefaulter{RequestReader: mgr.GetAPIReader(), Metrics: breakglassmetrics.DefaultRecorder}).
		WithValidator(&BreakGlassApprovalValidator{
			RequestReader:           mgr.GetAPIReader(),
			ProfileReader:           mgr.GetAPIReader(),
			Reviewer:                KubernetesSubjectAccessReviewer{Client: mgr.GetClient()},
			Metrics:                 breakglassmetrics.DefaultRecorder,
			AllowedTargetNamespaces: allowedTargetNamespaces,
		}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-access-breakglass-io-v1alpha1-breakglassapproval,mutating=true,failurePolicy=fail,sideEffects=None,timeoutSeconds=5,groups=access.breakglass.io,resources=breakglassapprovals,verbs=create,versions=v1alpha1,name=mbreakglassapproval-v1alpha1.kb.io,admissionReviewVersions=v1
type BreakGlassApprovalDefaulter struct {
	RequestReader client.Reader
	Metrics       breakglassmetrics.AdmissionRecorder
}

// Default overwrites the user-controlled approver reference. The validator
// repeats the request lookup because admission mutations are not authority.
func (d *BreakGlassApprovalDefaulter) Default(ctx context.Context, obj *accessv1alpha1.BreakGlassApproval) (err error) {
	defer func() {
		if err != nil {
			recordAdmissionDecision(d.Metrics, breakglassmetrics.AdmissionOperationCreate, admissionOutcomeForError(err))
		}
	}()

	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return &admissionInternalError{err: fmt.Errorf("read authenticated admission approver: %w", err)}
	}
	if err := validateHumanRequester(req.UserInfo); err != nil {
		return err
	}
	if obj.Spec.RequestRef.Name == "" {
		return fmt.Errorf("requestRef.name is required")
	}
	if d.RequestReader == nil {
		return &admissionInternalError{err: fmt.Errorf("BreakGlassRequest reader is not configured")}
	}
	request := &accessv1alpha1.BreakGlassRequest{}
	if err := d.RequestReader.Get(ctx, client.ObjectKey{Name: obj.Spec.RequestRef.Name}, request); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("BreakGlassRequest %q does not exist", obj.Spec.RequestRef.Name)
		}
		return apierrors.NewInternalError(fmt.Errorf("read BreakGlassRequest for admission: %w", err))
	}
	if request.UID == "" {
		return apierrors.NewInternalError(fmt.Errorf("BreakGlassRequest %q has no server-assigned UID", request.Name))
	}
	obj.Spec.RequestRef.UID = string(request.UID)
	obj.Spec.Approver = accessv1alpha1.SubjectReference{
		Kind: accessv1alpha1.SubjectKindUser,
		Name: req.UserInfo.Username,
	}
	obj.Name = accessv1alpha1.ApprovalNameForRequestUID(string(request.UID))
	obj.GenerateName = ""
	return nil
}

// +kubebuilder:webhook:path=/validate-access-breakglass-io-v1alpha1-breakglassapproval,mutating=false,failurePolicy=fail,sideEffects=None,timeoutSeconds=5,groups=access.breakglass.io,resources=breakglassapprovals,verbs=create;update;delete,versions=v1alpha1,name=vbreakglassapproval-v1alpha1.kb.io,admissionReviewVersions=v1
type BreakGlassApprovalValidator struct {
	RequestReader           client.Reader
	ProfileReader           client.Reader
	Reviewer                ProfileApprovalReviewer
	Metrics                 breakglassmetrics.AdmissionRecorder
	AllowedTargetNamespaces map[string]struct{}
	Clock                   func() time.Time
}

func (v *BreakGlassApprovalValidator) ValidateCreate(ctx context.Context, obj *accessv1alpha1.BreakGlassApproval) (warnings admission.Warnings, err error) {
	defer func() {
		recordAdmissionDecision(v.Metrics, breakglassmetrics.AdmissionOperationCreate, admissionOutcomeForError(err))
	}()

	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("read authenticated admission approver: %w", err))
	}
	if err := validateHumanRequester(req.UserInfo); err != nil {
		return nil, err
	}
	if obj.Spec.Approver.Kind != accessv1alpha1.SubjectKindUser || obj.Spec.Approver.Name != req.UserInfo.Username || obj.Spec.Approver.Namespace != "" {
		return nil, fmt.Errorf("approver must be the authenticated requester")
	}
	if obj.Spec.Decision != accessv1alpha1.ApprovalDecisionApproved && obj.Spec.Decision != accessv1alpha1.ApprovalDecisionDenied {
		return nil, fmt.Errorf("decision must be Approved or Denied")
	}
	request, err := v.loadPendingRequest(ctx, obj.Spec.RequestRef)
	if err != nil {
		return nil, err
	}
	if request.Spec.Requester.Name == req.UserInfo.Username {
		return nil, fmt.Errorf("requester may not approve their own BreakGlassRequest")
	}
	if obj.Name != accessv1alpha1.ApprovalNameForRequestUID(string(request.UID)) {
		return nil, fmt.Errorf("approval name does not match the deterministic slot for this BreakGlassRequest")
	}
	profileValidator := &BreakGlassSessionValidator{
		ProfileReader:           v.ProfileReader,
		AllowedTargetNamespaces: v.AllowedTargetNamespaces,
	}
	profile, _, err := profileValidator.loadAndValidateProfile(ctx, request.Spec.AccessProfile)
	if err != nil {
		return nil, err
	}
	if string(profile.UID) != request.Spec.AccessProfileUID {
		return nil, fmt.Errorf("BreakGlassRequest accessProfileUID does not match the current AccessProfile")
	}
	if profile.Spec.EffectiveDeliveryMode() != accessv1alpha1.AccessDeliveryModeApprovalRequired {
		return nil, fmt.Errorf("AccessProfile %q does not require the approval workflow", profile.Name)
	}
	if v.Reviewer == nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("SubjectAccessReview reviewer is not configured"))
	}
	allowed, err := v.Reviewer.CanApprove(ctx, req.UserInfo, profile.Name)
	if err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("evaluate AccessProfile approval authorization: %w", err))
	}
	if !allowed {
		return nil, fmt.Errorf("approver is not authorized to approve AccessProfile %q", profile.Name)
	}
	return nil, nil
}

func (v *BreakGlassApprovalValidator) ValidateUpdate(_ context.Context, oldObj, newObj *accessv1alpha1.BreakGlassApproval) (warnings admission.Warnings, err error) {
	defer func() {
		recordAdmissionDecision(v.Metrics, breakglassmetrics.AdmissionOperationUpdate, admissionOutcomeForError(err))
	}()
	if oldObj.Spec != newObj.Spec {
		return nil, fmt.Errorf("BreakGlassApproval spec is immutable")
	}
	return nil, nil
}

// ValidateDelete makes decisions append-only. Retention policy may later add a
// controller-owned archival path; a requester or approver must not be able to
// erase the object that the controller used for a grant decision.
func (v *BreakGlassApprovalValidator) ValidateDelete(_ context.Context, _ *accessv1alpha1.BreakGlassApproval) (warnings admission.Warnings, err error) {
	defer func() {
		recordAdmissionDecision(v.Metrics, breakglassmetrics.AdmissionOperationUpdate, admissionOutcomeForError(err))
	}()
	return nil, fmt.Errorf("BreakGlassApproval is append-only and cannot be deleted")
}

func (v *BreakGlassApprovalValidator) loadPendingRequest(ctx context.Context, ref accessv1alpha1.BreakGlassRequestReference) (*accessv1alpha1.BreakGlassRequest, error) {
	if ref.Name == "" || ref.UID == "" {
		return nil, fmt.Errorf("requestRef name and UID are required")
	}
	if v.RequestReader == nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("BreakGlassRequest reader is not configured"))
	}
	request := &accessv1alpha1.BreakGlassRequest{}
	if err := v.RequestReader.Get(ctx, client.ObjectKey{Name: ref.Name}, request); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("BreakGlassRequest %q does not exist", ref.Name)
		}
		return nil, apierrors.NewInternalError(fmt.Errorf("read BreakGlassRequest for approval: %w", err))
	}
	if string(request.UID) != ref.UID {
		return nil, fmt.Errorf("requestRef UID does not match the current BreakGlassRequest")
	}
	if request.Status.Phase != accessv1alpha1.RequestPhasePending {
		return nil, fmt.Errorf("BreakGlassRequest %q is not awaiting approval", request.Name)
	}
	requestTTL, err := time.ParseDuration(request.Spec.RequestTTL)
	if err != nil || requestTTL <= 0 {
		return nil, fmt.Errorf("BreakGlassRequest %q has no valid immutable request TTL", request.Name)
	}
	if !v.now().Before(request.CreationTimestamp.Add(requestTTL)) {
		return nil, fmt.Errorf("BreakGlassRequest %q has expired", request.Name)
	}
	return request, nil
}

func (v *BreakGlassApprovalValidator) now() time.Time {
	if v.Clock != nil {
		return v.Clock()
	}
	return time.Now()
}
