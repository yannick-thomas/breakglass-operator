package v1alpha1

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
)

func SetupBreakGlassRequestWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &accessv1alpha1.BreakGlassRequest{}).
		WithDefaulter(&BreakGlassRequestDefaulter{ProfileReader: mgr.GetAPIReader()}).
		WithValidator(&BreakGlassRequestValidator{ProfileReader: mgr.GetAPIReader(), Reviewer: KubernetesSubjectAccessReviewer{Client: mgr.GetClient()}}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-access-breakglass-io-v1alpha1-breakglassrequest,mutating=true,failurePolicy=fail,sideEffects=None,groups=access.breakglass.io,resources=breakglassrequests,verbs=create,versions=v1alpha1,name=mbreakglassrequest-v1alpha1.kb.io,admissionReviewVersions=v1
type BreakGlassRequestDefaulter struct{ ProfileReader client.Reader }

func (d *BreakGlassRequestDefaulter) Default(ctx context.Context, obj *accessv1alpha1.BreakGlassRequest) error {
	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return err
	}
	if err := validateHumanRequester(req.UserInfo); err != nil {
		return err
	}
	p := &accessv1alpha1.AccessProfile{}
	if err := d.ProfileReader.Get(ctx, client.ObjectKey{Name: obj.Spec.AccessProfile}, p); err != nil {
		return fmt.Errorf("read AccessProfile: %w", err)
	}
	obj.Spec.Requester = accessv1alpha1.SubjectReference{Kind: accessv1alpha1.SubjectKindUser, Name: req.UserInfo.Username}
	obj.Spec.AccessProfileUID = string(p.UID)
	return nil
}

// +kubebuilder:webhook:path=/validate-access-breakglass-io-v1alpha1-breakglassrequest,mutating=false,failurePolicy=fail,sideEffects=None,groups=access.breakglass.io,resources=breakglassrequests,verbs=create;update,versions=v1alpha1,name=vbreakglassrequest-v1alpha1.kb.io,admissionReviewVersions=v1
type BreakGlassRequestValidator struct {
	ProfileReader client.Reader
	Reviewer      SubjectAccessReviewer
}

func (v *BreakGlassRequestValidator) ValidateCreate(ctx context.Context, obj *accessv1alpha1.BreakGlassRequest) (admission.Warnings, error) {
	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateHumanRequester(req.UserInfo); err != nil {
		return nil, err
	}
	if obj.Spec.Requester.Kind != accessv1alpha1.SubjectKindUser || obj.Spec.Requester.Name != req.UserInfo.Username {
		return nil, fmt.Errorf("requester must be the authenticated requester")
	}
	p := &accessv1alpha1.AccessProfile{}
	if err := v.ProfileReader.Get(ctx, client.ObjectKey{Name: obj.Spec.AccessProfile}, p); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("AccessProfile %q does not exist", obj.Spec.AccessProfile)
		}
		return nil, err
	}
	if obj.Spec.AccessProfileUID != string(p.UID) {
		return nil, fmt.Errorf("accessProfileUID does not match the current AccessProfile")
	}
	duration, err := time.ParseDuration(obj.Spec.Duration)
	if err != nil || duration <= 0 {
		return nil, fmt.Errorf("duration must be a positive Go duration")
	}
	maxDuration, err := time.ParseDuration(p.Spec.MaxDuration)
	if err != nil || maxDuration <= 0 || duration > maxDuration {
		return nil, fmt.Errorf("duration exceeds AccessProfile maximum")
	}
	allowed, err := v.Reviewer.CanUse(ctx, req.UserInfo, p.Name)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, fmt.Errorf("requester is not authorized to use AccessProfile %q", p.Name)
	}
	return nil, nil
}
func (v *BreakGlassRequestValidator) ValidateUpdate(_ context.Context, oldObj, newObj *accessv1alpha1.BreakGlassRequest) (admission.Warnings, error) {
	if oldObj.Spec != newObj.Spec {
		return nil, fmt.Errorf("BreakGlassRequest spec is immutable")
	}
	return nil, nil
}
func (v *BreakGlassRequestValidator) ValidateDelete(context.Context, *accessv1alpha1.BreakGlassRequest) (admission.Warnings, error) {
	return nil, nil
}
