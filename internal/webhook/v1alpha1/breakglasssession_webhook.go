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
	"fmt"
	"strings"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	breakglassmetrics "github.com/yannick-thomas/breakglass-operator/internal/metrics"
)

// nolint:unused
// breakglasssessionlog is the package logger for admission decisions. Never
// log request reasons or identities at a verbosity intended for shared logs.
var breakglasssessionlog = logf.Log.WithName("breakglasssession-resource")

// +kubebuilder:rbac:groups=access.breakglass.io,resources=accessprofiles,verbs=get
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create

// SetupBreakGlassSessionWebhookWithManager registers the required mutating and
// validating admission endpoints. GetAPIReader deliberately bypasses the
// cache: authorization must evaluate the profile currently stored by the API
// server, not a stale cache entry.
func SetupBreakGlassSessionWebhookWithManager(
	mgr ctrl.Manager,
	allowedTargetNamespaces map[string]struct{},
	requestControllerUsername string,
) error {
	return ctrl.NewWebhookManagedBy(mgr, &accessv1alpha1.BreakGlassSession{}).
		WithValidator(&BreakGlassSessionValidator{
			ProfileReader:             mgr.GetAPIReader(),
			RequestReader:             mgr.GetAPIReader(),
			ApprovalReader:            mgr.GetAPIReader(),
			Reviewer:                  KubernetesSubjectAccessReviewer{Client: mgr.GetClient()},
			Metrics:                   breakglassmetrics.DefaultRecorder,
			AllowedTargetNamespaces:   allowedTargetNamespaces,
			RequestControllerUsername: requestControllerUsername,
		}).
		WithDefaulter(&BreakGlassSessionDefaulter{
			ProfileReader:             mgr.GetAPIReader(),
			Metrics:                   breakglassmetrics.DefaultRecorder,
			RequestControllerUsername: requestControllerUsername,
		}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-access-breakglass-io-v1alpha1-breakglasssession,mutating=true,failurePolicy=fail,sideEffects=None,timeoutSeconds=5,groups=access.breakglass.io,resources=breakglasssessions,verbs=create,versions=v1alpha1,name=mbreakglasssession-v1alpha1.kb.io,admissionReviewVersions=v1

// BreakGlassSessionDefaulter stamps a self-service request with the only
// trusted subject: the user authenticated by the Kubernetes API server. It
// deliberately overwrites any client-provided value rather than validating it.
type BreakGlassSessionDefaulter struct {
	ProfileReader             client.Reader
	Metrics                   breakglassmetrics.AdmissionRecorder
	RequestControllerUsername string
}

// Default implements admission.Defaulter. controller-runtime places the
// AdmissionRequest in ctx, including its authenticated UserInfo.
// A successful mutation is not counted here because ValidateCreate records
// the terminal admission decision. Mutation failures are terminal because the
// validating webhook will not receive that request.
func (d *BreakGlassSessionDefaulter) Default(ctx context.Context, obj *accessv1alpha1.BreakGlassSession) (err error) {
	defer func() {
		if err != nil {
			recordAdmissionDecision(d.Metrics, breakglassmetrics.AdmissionOperationCreate, admissionOutcomeForError(err))
		}
	}()

	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return &admissionInternalError{err: fmt.Errorf("read authenticated admission requester: %w", err)}
	}
	if obj.Spec.RequestRef != nil {
		if d.RequestControllerUsername == "" || req.UserInfo.Username != d.RequestControllerUsername {
			return fmt.Errorf("request-sourced sessions may only be created by the configured request controller")
		}
		return nil
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

	profile := &accessv1alpha1.AccessProfile{}
	if err := d.ProfileReader.Get(ctx, client.ObjectKey{Name: obj.Spec.AccessProfile}, profile); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("AccessProfile %q does not exist", obj.Spec.AccessProfile)
		}
		return apierrors.NewInternalError(fmt.Errorf("read AccessProfile for admission: %w", err))
	}
	if profile.UID == "" {
		return apierrors.NewInternalError(fmt.Errorf("AccessProfile %q has no server-assigned UID", profile.Name))
	}

	obj.Spec.Subject = accessv1alpha1.SubjectReference{
		Kind: accessv1alpha1.SubjectKindUser,
		Name: req.UserInfo.Username,
	}
	obj.Spec.AccessProfileUID = string(profile.UID)
	return nil
}

// +kubebuilder:webhook:path=/validate-access-breakglass-io-v1alpha1-breakglasssession,mutating=false,failurePolicy=fail,sideEffects=None,timeoutSeconds=5,groups=access.breakglass.io,resources=breakglasssessions,verbs=create;update,versions=v1alpha1,name=vbreakglasssession-v1alpha1.kb.io,admissionReviewVersions=v1

// SubjectAccessReviewer makes profile-use authorization independently
// testable. It must authorize the original requester, not the manager Service
// Account that executes the webhook.
type SubjectAccessReviewer interface {
	CanUse(context.Context, authenticationv1.UserInfo, string) (bool, error)
}

// KubernetesSubjectAccessReviewer performs a real SubjectAccessReview through
// the Kubernetes API.
type KubernetesSubjectAccessReviewer struct {
	Client client.Client
}

func (r KubernetesSubjectAccessReviewer) CanUse(ctx context.Context, user authenticationv1.UserInfo, profile string) (bool, error) {
	return r.canAccessProfile(ctx, user, profile, "use")
}

// CanApprove verifies the custom, profile-scoped approval verb. Keeping this
// distinct from use prevents a requester from approving their own access just
// because they may start a direct self-service session.
func (r KubernetesSubjectAccessReviewer) CanApprove(ctx context.Context, user authenticationv1.UserInfo, profile string) (bool, error) {
	return r.canAccessProfile(ctx, user, profile, "approve")
}

func (r KubernetesSubjectAccessReviewer) canAccessProfile(ctx context.Context, user authenticationv1.UserInfo, profile, verb string) (bool, error) {
	if r.Client == nil {
		return false, fmt.Errorf("SubjectAccessReview client is not configured")
	}
	extra := make(map[string]authorizationv1.ExtraValue, len(user.Extra))
	for key, value := range user.Extra {
		extra[key] = authorizationv1.ExtraValue(value)
	}
	sar := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   user.Username,
			UID:    user.UID,
			Groups: user.Groups,
			Extra:  extra,
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Group:    accessv1alpha1.GroupVersion.Group,
				Version:  accessv1alpha1.GroupVersion.Version,
				Resource: "accessprofiles",
				Verb:     verb,
				Name:     profile,
			},
		},
	}
	if err := r.Client.Create(ctx, sar); err != nil {
		return false, err
	}
	if sar.Status.EvaluationError != "" {
		return false, fmt.Errorf("SubjectAccessReview evaluation failed")
	}
	return sar.Status.Allowed, nil
}

// BreakGlassSessionValidator validates the fully-mutated session and enforces
// the profile-specific custom RBAC verb "use" at creation time.
type BreakGlassSessionValidator struct {
	ProfileReader             client.Reader
	RequestReader             client.Reader
	ApprovalReader            client.Reader
	Reviewer                  SubjectAccessReviewer
	Metrics                   breakglassmetrics.AdmissionRecorder
	AllowedTargetNamespaces   map[string]struct{}
	RequestControllerUsername string
}

// ValidateCreate rejects a request unless its persisted subject exactly equals
// the authenticated requester, its profile UID is current, its duration fits
// the profile, and Kubernetes authorizes use of that named profile.
func (v *BreakGlassSessionValidator) ValidateCreate(ctx context.Context, obj *accessv1alpha1.BreakGlassSession) (warnings admission.Warnings, err error) {
	defer func() {
		recordAdmissionDecision(v.Metrics, breakglassmetrics.AdmissionOperationCreate, admissionOutcomeForError(err))
	}()

	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("read authenticated admission requester: %w", err))
	}
	if obj.Spec.RequestRef != nil {
		return nil, v.validateRequestSourcedSession(ctx, req.UserInfo, obj)
	}
	if err := validateHumanRequester(req.UserInfo); err != nil {
		return nil, err
	}
	if obj.Spec.Subject.Kind != accessv1alpha1.SubjectKindUser || obj.Spec.Subject.Name != req.UserInfo.Username || obj.Spec.Subject.Namespace != "" {
		return nil, fmt.Errorf("subject must be the authenticated requester")
	}

	profile, maxDuration, err := v.loadAndValidateProfile(ctx, obj.Spec.AccessProfile)
	if err != nil {
		return nil, err
	}
	if string(profile.UID) != obj.Spec.AccessProfileUID {
		return nil, fmt.Errorf("accessProfileUID does not match the current AccessProfile")
	}
	if profile.Spec.EffectiveDeliveryMode() != accessv1alpha1.AccessDeliveryModeSelfService {
		return nil, fmt.Errorf("AccessProfile %q requires the approval workflow", profile.Name)
	}
	duration, err := time.ParseDuration(obj.Spec.Duration)
	if err != nil || duration <= 0 {
		return nil, fmt.Errorf("duration must be a positive Go duration")
	}
	if duration > maxDuration {
		return nil, fmt.Errorf("duration %s exceeds AccessProfile maximum of %s", duration, maxDuration)
	}
	if v.Reviewer == nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("SubjectAccessReview reviewer is not configured"))
	}
	allowed, err := v.Reviewer.CanUse(ctx, req.UserInfo, profile.Name)
	if err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("evaluate AccessProfile use authorization: %w", err))
	}
	if !allowed {
		return nil, fmt.Errorf("requester is not authorized to use AccessProfile %q", profile.Name)
	}
	return nil, nil
}

// ValidateUpdate permits only metadata/status activity and one-way revocation.
// The controller itself updates finalizers and status under its own identity,
// so profile-use authorization is intentionally a CREATE-only decision.
func (v *BreakGlassSessionValidator) ValidateUpdate(_ context.Context, oldObj, newObj *accessv1alpha1.BreakGlassSession) (warnings admission.Warnings, err error) {
	defer func() {
		recordAdmissionDecision(v.Metrics, breakglassmetrics.AdmissionOperationUpdate, admissionOutcomeForError(err))
	}()

	oldSpec, newSpec := oldObj.Spec, newObj.Spec
	if oldSpec.AccessProfile != newSpec.AccessProfile ||
		oldSpec.AccessProfileUID != newSpec.AccessProfileUID ||
		oldSpec.Subject != newSpec.Subject ||
		oldSpec.Duration != newSpec.Duration ||
		oldSpec.Reason != newSpec.Reason ||
		!requestReferencesEqual(oldSpec.RequestRef, newSpec.RequestRef) {
		return nil, fmt.Errorf("access request fields are immutable")
	}
	if oldSpec.Revoked && !newSpec.Revoked {
		return nil, fmt.Errorf("revoked cannot be changed from true to false")
	}
	return nil, nil
}

// validateRequestSourcedSession is the only admission path for a workload
// identity. It is deliberately narrow: the manager must present the exact
// configured ServiceAccount identity and may create only the session name
// reserved by a current, approved request.
func (v *BreakGlassSessionValidator) validateRequestSourcedSession(
	ctx context.Context,
	user authenticationv1.UserInfo,
	obj *accessv1alpha1.BreakGlassSession,
) error {
	if v.RequestControllerUsername == "" || user.Username != v.RequestControllerUsername {
		return fmt.Errorf("request-sourced sessions may only be created by the configured request controller")
	}
	request, err := v.loadRequestForSourcedSession(ctx, obj.Spec.RequestRef)
	if err != nil {
		return err
	}
	if err := validateRequestSessionReservation(request, obj); err != nil {
		return err
	}
	if err := validateRequestTTL(request); err != nil {
		return err
	}
	if err := v.validateRequestApproval(ctx, request); err != nil {
		return err
	}
	if err := validateSessionMatchesRequest(obj, request); err != nil {
		return err
	}
	return v.validateRequestProfile(ctx, request)
}

func (v *BreakGlassSessionValidator) loadRequestForSourcedSession(
	ctx context.Context,
	ref *accessv1alpha1.BreakGlassRequestReference,
) (*accessv1alpha1.BreakGlassRequest, error) {
	if ref == nil || ref.Name == "" || ref.UID == "" {
		return nil, fmt.Errorf("requestRef name and UID are required for a controller-sourced session")
	}
	if v.RequestReader == nil || v.ApprovalReader == nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("request or approval reader is not configured"))
	}
	request := &accessv1alpha1.BreakGlassRequest{}
	if err := v.RequestReader.Get(ctx, client.ObjectKey{Name: ref.Name}, request); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("BreakGlassRequest %q does not exist", ref.Name)
		}
		return nil, apierrors.NewInternalError(fmt.Errorf("read BreakGlassRequest for session admission: %w", err))
	}
	if string(request.UID) != ref.UID {
		return nil, fmt.Errorf("requestRef UID does not match the current BreakGlassRequest")
	}
	return request, nil
}

func validateRequestSessionReservation(request *accessv1alpha1.BreakGlassRequest, session *accessv1alpha1.BreakGlassSession) error {
	if request.Status.Phase != accessv1alpha1.RequestPhaseProvisioning || request.Status.SessionRef == nil ||
		request.Status.SessionRef.Name != session.Name || request.Status.SessionRef.UID != "" {
		return fmt.Errorf("BreakGlassRequest %q has not reserved this session for provisioning", request.Name)
	}
	return nil
}

func validateRequestTTL(request *accessv1alpha1.BreakGlassRequest) error {
	requestTTL, err := time.ParseDuration(request.Spec.RequestTTL)
	if err != nil || requestTTL <= 0 {
		return fmt.Errorf("BreakGlassRequest %q has no valid immutable request TTL", request.Name)
	}
	if !time.Now().Before(request.CreationTimestamp.Add(requestTTL)) {
		return fmt.Errorf("BreakGlassRequest %q has expired", request.Name)
	}
	return nil
}

func (v *BreakGlassSessionValidator) validateRequestApproval(ctx context.Context, request *accessv1alpha1.BreakGlassRequest) error {
	if request.Status.ApprovalRef == nil || request.Status.ApprovalRef.Name == "" || request.Status.ApprovalRef.UID == "" {
		return fmt.Errorf("BreakGlassRequest %q has no verified approval reference", request.Name)
	}
	approval := &accessv1alpha1.BreakGlassApproval{}
	if err := v.ApprovalReader.Get(ctx, client.ObjectKey{Name: request.Status.ApprovalRef.Name}, approval); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("BreakGlassApproval %q does not exist", request.Status.ApprovalRef.Name)
		}
		return apierrors.NewInternalError(fmt.Errorf("read BreakGlassApproval for session admission: %w", err))
	}
	if string(approval.UID) != request.Status.ApprovalRef.UID ||
		approval.Spec.Decision != accessv1alpha1.ApprovalDecisionApproved ||
		approval.Spec.RequestRef.Name != request.Name || approval.Spec.RequestRef.UID != string(request.UID) ||
		approval.Spec.Approver.Kind != accessv1alpha1.SubjectKindUser ||
		approval.Spec.Approver.Name == request.Spec.Requester.Name {
		return fmt.Errorf("BreakGlassRequest %q approval reference is not a valid independent approval", request.Name)
	}
	return nil
}

func validateSessionMatchesRequest(session *accessv1alpha1.BreakGlassSession, request *accessv1alpha1.BreakGlassRequest) error {
	if session.Spec.AccessProfile != request.Spec.AccessProfile ||
		session.Spec.AccessProfileUID != request.Spec.AccessProfileUID ||
		session.Spec.Subject != request.Spec.Requester ||
		session.Spec.Duration != request.Spec.Duration ||
		session.Spec.Reason != request.Spec.Reason {
		return fmt.Errorf("controller-sourced session fields must exactly match the approved BreakGlassRequest")
	}
	return nil
}

func (v *BreakGlassSessionValidator) validateRequestProfile(ctx context.Context, request *accessv1alpha1.BreakGlassRequest) error {
	profile, maxDuration, err := v.loadAndValidateProfile(ctx, request.Spec.AccessProfile)
	if err != nil {
		return err
	}
	if string(profile.UID) != request.Spec.AccessProfileUID {
		return fmt.Errorf("BreakGlassRequest accessProfileUID does not match the current AccessProfile")
	}
	if profile.Spec.EffectiveDeliveryMode() != accessv1alpha1.AccessDeliveryModeApprovalRequired {
		return fmt.Errorf("AccessProfile %q does not require the approval workflow", profile.Name)
	}
	duration, err := time.ParseDuration(request.Spec.Duration)
	if err != nil || duration <= 0 || duration > maxDuration {
		return fmt.Errorf("BreakGlassRequest duration is no longer valid for the current AccessProfile")
	}
	return nil
}

func requestReferencesEqual(left, right *accessv1alpha1.BreakGlassRequestReference) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

// ValidateDelete performs no extra policy check. Kubernetes RBAC governs who
// can delete a session; its finalizer safely removes only the UID-recorded
// binding.
func (v *BreakGlassSessionValidator) ValidateDelete(_ context.Context, _ *accessv1alpha1.BreakGlassSession) (admission.Warnings, error) {
	return nil, nil
}

func (v *BreakGlassSessionValidator) loadAndValidateProfile(ctx context.Context, name string) (*accessv1alpha1.AccessProfile, time.Duration, error) {
	if name == "" {
		return nil, 0, fmt.Errorf("accessProfile is required")
	}
	if v.ProfileReader == nil {
		return nil, 0, apierrors.NewInternalError(fmt.Errorf("AccessProfile reader is not configured"))
	}
	profile := &accessv1alpha1.AccessProfile{}
	if err := v.ProfileReader.Get(ctx, client.ObjectKey{Name: name}, profile); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, 0, fmt.Errorf("AccessProfile %q does not exist", name)
		}
		return nil, 0, apierrors.NewInternalError(fmt.Errorf("read AccessProfile for admission: %w", err))
	}
	if profile.Spec.RoleRef.Kind != "ClusterRole" || profile.Spec.RoleRef.Name == "" || profile.Spec.TargetNamespace == "" {
		return nil, 0, fmt.Errorf("AccessProfile %q is not a valid curated namespaced policy", name)
	}
	if !targetNamespaceAllowed(profile.Spec.TargetNamespace, v.AllowedTargetNamespaces) {
		return nil, 0, fmt.Errorf("AccessProfile %q targets namespace %q outside this manager's allowed namespace set", name, profile.Spec.TargetNamespace)
	}
	maxDuration, err := time.ParseDuration(profile.Spec.MaxDuration)
	if err != nil || maxDuration <= 0 {
		return nil, 0, fmt.Errorf("AccessProfile %q has an invalid positive maxDuration", name)
	}
	return profile, maxDuration, nil
}

func targetNamespaceAllowed(namespace string, allowed map[string]struct{}) bool {
	if len(allowed) == 0 {
		return true
	}
	_, found := allowed[namespace]
	return found
}

func validateHumanRequester(user authenticationv1.UserInfo) error {
	if user.Username == "" {
		return fmt.Errorf("authenticated requester has no username")
	}
	if strings.HasPrefix(user.Username, "system:serviceaccount:") {
		return fmt.Errorf("service account requesters are not supported by self-service BreakGlassSession")
	}
	if user.Username == "system:anonymous" || user.Username == "system:unauthenticated" {
		return fmt.Errorf("anonymous requesters are not supported")
	}
	return nil
}

// admissionInternalError marks errors caused by the admission transport or
// webhook infrastructure while preserving the error text returned to callers.
// Policy rejections deliberately remain ordinary errors and are counted as
// denied rather than error.
type admissionInternalError struct {
	err error
}

func (e *admissionInternalError) Error() string {
	return e.err.Error()
}

func (e *admissionInternalError) Unwrap() error {
	return e.err
}

func admissionOutcomeForError(err error) breakglassmetrics.AdmissionOutcome {
	if err == nil {
		return breakglassmetrics.AdmissionOutcomeAllowed
	}

	var internalErr *admissionInternalError
	if errors.As(err, &internalErr) || apierrors.IsInternalError(err) {
		return breakglassmetrics.AdmissionOutcomeError
	}
	return breakglassmetrics.AdmissionOutcomeDenied
}

func recordAdmissionDecision(recorder breakglassmetrics.AdmissionRecorder, operation breakglassmetrics.AdmissionOperation, outcome breakglassmetrics.AdmissionOutcome) {
	if recorder != nil {
		recorder.RecordAdmissionRequest(operation, outcome)
	}
}
