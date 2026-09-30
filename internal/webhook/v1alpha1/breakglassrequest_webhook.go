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
	breakglassmetrics "github.com/yannick-thomas/breakglass-operator/internal/metrics"
)

// SetupBreakGlassRequestWebhookWithManager installs the request admission
// boundary with the same target-namespace constraint as direct sessions. A
// request must not be able to select a profile that this manager would later
// refuse to grant.
func SetupBreakGlassRequestWebhookWithManager(
	mgr ctrl.Manager,
	allowedTargetNamespaces map[string]struct{},
	requestTTL time.Duration,
) error {
	return ctrl.NewWebhookManagedBy(mgr, &accessv1alpha1.BreakGlassRequest{}).
		WithDefaulter(&BreakGlassRequestDefaulter{ProfileReader: mgr.GetAPIReader(), Metrics: breakglassmetrics.DefaultRecorder, RequestTTL: requestTTL}).
		WithValidator(&BreakGlassRequestValidator{
			ProfileReader:           mgr.GetAPIReader(),
			Reviewer:                KubernetesSubjectAccessReviewer{Client: mgr.GetClient()},
			Metrics:                 breakglassmetrics.DefaultRecorder,
			AllowedTargetNamespaces: allowedTargetNamespaces,
			RequestTTL:              requestTTL,
		}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-access-breakglass-io-v1alpha1-breakglassrequest,mutating=true,failurePolicy=fail,sideEffects=None,groups=access.breakglass.io,resources=breakglassrequests,verbs=create,versions=v1alpha1,name=mbreakglassrequest-v1alpha1.kb.io,admissionReviewVersions=v1
type BreakGlassRequestDefaulter struct {
	ProfileReader client.Reader
	Metrics       breakglassmetrics.AdmissionRecorder
	RequestTTL    time.Duration
}

func (d *BreakGlassRequestDefaulter) Default(ctx context.Context, obj *accessv1alpha1.BreakGlassRequest) (err error) {
	defer func() {
		if err != nil {
			recordAdmissionDecision(d.Metrics, breakglassmetrics.AdmissionOperationCreate, admissionOutcomeForError(err))
		}
	}()

	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return &admissionInternalError{err: fmt.Errorf("read authenticated admission requester: %w", err)}
	}
	if err := validateHumanRequester(req.UserInfo); err != nil {
		return err
	}
	if obj.Spec.AccessProfile == "" {
		return fmt.Errorf("accessProfile is required")
	}
	if d.ProfileReader == nil {
		return &admissionInternalError{err: fmt.Errorf("AccessProfile reader is not configured")}
	}
	if d.RequestTTL <= 0 {
		return &admissionInternalError{err: fmt.Errorf("request TTL is not configured")}
	}
	p := &accessv1alpha1.AccessProfile{}
	if err := d.ProfileReader.Get(ctx, client.ObjectKey{Name: obj.Spec.AccessProfile}, p); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("AccessProfile %q does not exist", obj.Spec.AccessProfile)
		}
		return apierrors.NewInternalError(fmt.Errorf("read AccessProfile for admission: %w", err))
	}
	if p.UID == "" {
		return apierrors.NewInternalError(fmt.Errorf("AccessProfile %q has no server-assigned UID", p.Name))
	}
	obj.Spec.Requester = accessv1alpha1.SubjectReference{Kind: accessv1alpha1.SubjectKindUser, Name: req.UserInfo.Username}
	obj.Spec.AccessProfileUID = string(p.UID)
	obj.Spec.RequestTTL = d.RequestTTL.String()
	return nil
}

// +kubebuilder:webhook:path=/validate-access-breakglass-io-v1alpha1-breakglassrequest,mutating=false,failurePolicy=fail,sideEffects=None,groups=access.breakglass.io,resources=breakglassrequests,verbs=create;update,versions=v1alpha1,name=vbreakglassrequest-v1alpha1.kb.io,admissionReviewVersions=v1
type BreakGlassRequestValidator struct {
	ProfileReader           client.Reader
	Reviewer                SubjectAccessReviewer
	Metrics                 breakglassmetrics.AdmissionRecorder
	AllowedTargetNamespaces map[string]struct{}
	RequestTTL              time.Duration
}

func (v *BreakGlassRequestValidator) ValidateCreate(ctx context.Context, obj *accessv1alpha1.BreakGlassRequest) (warnings admission.Warnings, err error) {
	defer func() {
		recordAdmissionDecision(v.Metrics, breakglassmetrics.AdmissionOperationCreate, admissionOutcomeForError(err))
	}()

	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("read authenticated admission requester: %w", err))
	}
	if err := validateHumanRequester(req.UserInfo); err != nil {
		return nil, err
	}
	if obj.Spec.Requester.Kind != accessv1alpha1.SubjectKindUser || obj.Spec.Requester.Name != req.UserInfo.Username {
		return nil, fmt.Errorf("requester must be the authenticated requester")
	}
	profileValidator := &BreakGlassSessionValidator{
		ProfileReader:           v.ProfileReader,
		AllowedTargetNamespaces: v.AllowedTargetNamespaces,
	}
	p, maxDuration, err := profileValidator.loadAndValidateProfile(ctx, obj.Spec.AccessProfile)
	if err != nil {
		return nil, err
	}
	if obj.Spec.AccessProfileUID != string(p.UID) {
		return nil, fmt.Errorf("accessProfileUID does not match the current AccessProfile")
	}
	if p.Spec.EffectiveDeliveryMode() != accessv1alpha1.AccessDeliveryModeApprovalRequired {
		return nil, fmt.Errorf("AccessProfile %q does not require the approval workflow", p.Name)
	}
	if v.RequestTTL <= 0 {
		return nil, apierrors.NewInternalError(fmt.Errorf("request TTL is not configured"))
	}
	if obj.Spec.RequestTTL != v.RequestTTL.String() {
		return nil, fmt.Errorf("requestTTL does not match the current manager policy")
	}
	duration, err := time.ParseDuration(obj.Spec.Duration)
	if err != nil || duration <= 0 {
		return nil, fmt.Errorf("duration must be a positive Go duration")
	}
	if duration > maxDuration {
		return nil, fmt.Errorf("duration exceeds AccessProfile maximum")
	}
	if v.Reviewer == nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("SubjectAccessReview reviewer is not configured"))
	}
	allowed, err := v.Reviewer.CanUse(ctx, req.UserInfo, p.Name)
	if err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("evaluate AccessProfile use authorization: %w", err))
	}
	if !allowed {
		return nil, fmt.Errorf("requester is not authorized to use AccessProfile %q", p.Name)
	}
	return nil, nil
}
func (v *BreakGlassRequestValidator) ValidateUpdate(_ context.Context, oldObj, newObj *accessv1alpha1.BreakGlassRequest) (warnings admission.Warnings, err error) {
	defer func() {
		recordAdmissionDecision(v.Metrics, breakglassmetrics.AdmissionOperationUpdate, admissionOutcomeForError(err))
	}()

	if oldObj.Spec != newObj.Spec {
		return nil, fmt.Errorf("BreakGlassRequest spec is immutable")
	}
	return nil, nil
}
func (v *BreakGlassRequestValidator) ValidateDelete(context.Context, *accessv1alpha1.BreakGlassRequest) (admission.Warnings, error) {
	return nil, nil
}
