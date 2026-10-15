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

// This file keeps the controller tests written against the API types. Each
// helper translates to the domain and calls the production use case or domain
// function, so the tests keep exercising production behavior end to end.

import (
	"context"
	"errors"
	"fmt"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/adapter/apiconv"
	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/port"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/requestlifecycle"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/sessionlifecycle"
)

const (
	bindingNamePrefix      = "breakglass-"
	maxKubernetesNameSize  = 253
	clusterRoleKind        = access.ClusterRoleKind
	curatedClusterRoleKind = access.ClusterRoleKind
	roleBindingKind        = access.RoleBindingKind

	requestTransitionRequeueDelay = requestlifecycle.ContinueImmediately
)

type bindingIntegrityIssue struct {
	Code            string
	ConditionReason string
	Message         string
}

type curatedRoleIssue = bindingIntegrityIssue

type requestSourceIssue = bindingIntegrityIssue

type bindingCleanupResult struct {
	Deleted        bool
	IntegrityIssue *bindingIntegrityIssue
}

func fromDomainIssue(issue *access.Issue) *bindingIntegrityIssue {
	if issue == nil {
		return nil
	}
	return &bindingIntegrityIssue{Code: issue.Code, ConditionReason: issue.Reason, Message: issue.Message}
}

func bindingNameForSession(session *accessv1alpha1.BreakGlassSession) string {
	return access.BindingName(session.Name, string(session.UID))
}

func managedBindingLabels(session *accessv1alpha1.BreakGlassSession) map[string]string {
	return apiconv.ToDomainSession(session).ManagedLabels()
}

func expectedSubject(session *accessv1alpha1.BreakGlassSession) rbacv1.Subject {
	return apiconv.ToAPISubjects([]access.BindingSubject{apiconv.ToDomainSession(session).ExpectedSubject()})[0]
}

func expectedBindingReference(session *accessv1alpha1.BreakGlassSession) *accessv1alpha1.BindingReference {
	return apiconv.ToAPIBindingRef(apiconv.ToDomainSession(session).ExpectedBindingRef())
}

func isManagedBindingForSession(obj client.Object, session *accessv1alpha1.BreakGlassSession) bool {
	rb, ok := obj.(*rbacv1.RoleBinding)
	return ok && apiconv.ToDomainSession(session).Owns(apiconv.ToDomainBinding(rb))
}

func isRequestDenied(err error) bool {
	return sessionlifecycle.IsDenied(err)
}

func validateRequestDecisionDeadline(request *accessv1alpha1.BreakGlassRequest, session *accessv1alpha1.BreakGlassSession) *requestSourceIssue {
	return fromDomainIssue(apiconv.ToDomainSession(session).DecisionDeadlineIssue(apiconv.ToDomainRequest(request), time.Now()))
}

func (r *BreakGlassSessionReconciler) validateSession(session *accessv1alpha1.BreakGlassSession) (time.Duration, error) {
	return access.ValidateSessionSpec(apiconv.ToDomainSession(session).Spec, r.MaxSessionDuration)
}

func (r *BreakGlassSessionReconciler) resolveAccessGrant(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (*accessv1alpha1.ResolvedAccess, time.Duration, error) {
	grant, duration, err := r.lifecycle(session.Namespace).ResolveGrant(ctx, apiconv.ToDomainSession(session))
	return apiconv.ToAPIGrant(grant), duration, err
}

func (r *BreakGlassSessionReconciler) verifyCuratedRole(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (*curatedRoleIssue, error) {
	issue, err := r.lifecycle(session.Namespace).VerifyCuratedRole(ctx, apiconv.ToDomainSession(session))
	return fromDomainIssue(issue), err
}

func (r *BreakGlassSessionReconciler) verifyBindingIntegrity(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (*bindingIntegrityIssue, error) {
	issue, err := r.lifecycle(session.Namespace).VerifyBinding(ctx, apiconv.ToDomainSession(session))
	return fromDomainIssue(issue), err
}

func (r *BreakGlassSessionReconciler) activeRequeueAfter(expiresAt time.Time) time.Duration {
	return r.lifecycle("").RequeueAfter(expiresAt)
}

func (r *BreakGlassSessionReconciler) namespaceConfirmedAbsent(ctx context.Context, namespace string) bool {
	return r.lifecycle("").NamespaceConfirmedAbsent(ctx, namespace)
}

func (r *BreakGlassSessionReconciler) ensureReservedBindingReference(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (*accessv1alpha1.BindingReference, error) {
	ref, err := r.lifecycle(session.Namespace).ReserveBinding(ctx, apiconv.ToDomainSession(session))
	return apiconv.ToAPIBindingRef(ref), err
}

func (r *BreakGlassSessionReconciler) cleanupBindingWithResult(ctx context.Context, session *accessv1alpha1.BreakGlassSession) (bindingCleanupResult, error) {
	s := apiconv.ToDomainSession(session)
	result, err := r.lifecycle(session.Namespace).CleanupBinding(ctx, s)
	session.Status.BindingRef = apiconv.ToAPIBindingRef(s.Status.BindingRef)
	session.Status.BindingName = s.Status.BindingName
	return bindingCleanupResult{Deleted: result.Deleted, IntegrityIssue: fromDomainIssue(result.Issue)}, err
}

func (r *BreakGlassSessionReconciler) cleanupBinding(ctx context.Context, session *accessv1alpha1.BreakGlassSession) error {
	_, err := r.cleanupBindingWithResult(ctx, session)
	return err
}

func (r *BreakGlassSessionReconciler) recordBindingDrift(issue *bindingIntegrityIssue, session *accessv1alpha1.BreakGlassSession) {
	if r.Metrics == nil || issue == nil {
		return
	}
	lifecycleTelemetry{recorder: r.Metrics}.BindingDrift(&access.Issue{Code: issue.Code}, apiconv.ToDomainSession(session))
}

// ensureBinding creates an already authorizing binding, as the activation of
// earlier releases did. Production activation reserves first and promotes
// after the UID is persisted; tests use this to set up an active grant.
func (r *BreakGlassSessionReconciler) ensureBinding(ctx context.Context, session *accessv1alpha1.BreakGlassSession) error {
	s := apiconv.ToDomainSession(session)
	expected := s.ExpectedBindingRef()
	if expected.Namespace == "" || s.Status.Grant == nil {
		return errors.New("cannot create a binding without a resolved namespaced AccessProfile grant")
	}
	gateway := roleBindingGateway{Client: r.Client, Lister: r.policyReader()}
	binding, err := gateway.Create(ctx, sessionlifecycle.BindingDraft{
		Name:      expected.Name,
		Namespace: expected.Namespace,
		Labels:    s.ManagedLabels(),
		RoleRef:   s.ExpectedRoleRef(),
		Subjects:  []access.BindingSubject{s.ExpectedSubject()},
	})
	if errors.Is(err, port.ErrAlreadyExists) {
		binding, err = gateway.Get(ctx, expected.Namespace, expected.Name)
		if err == nil {
			if issue := s.CheckGrantedBinding(binding); issue != nil {
				return fmt.Errorf("refusing to adopt existing RoleBinding %s/%s: %s", binding.Namespace, binding.Name, issue.Code)
			}
		}
	}
	if err != nil {
		return err
	}
	ref, err := binding.Ref()
	if err != nil {
		return err
	}
	session.Status.BindingName = ref.Name
	session.Status.BindingRef = apiconv.ToAPIBindingRef(ref)
	return nil
}
