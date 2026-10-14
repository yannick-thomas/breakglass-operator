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

// Package apiconv translates between the Kubernetes API types and the domain,
// and classifies API errors for the use-case ports. It is shared by all
// adapters: reconcilers, admission webhooks, and the expiry guard.
package apiconv

import (
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/port"
)

// SessionKind is the kind of the BreakGlassSession API type.
const SessionKind = "BreakGlassSession"

// The translation is lossless for every field the domain reads or writes;
// fields the domain does not know are left untouched on the API object.

func ToDomainSession(obj *accessv1alpha1.BreakGlassSession) *access.Session {
	return &access.Session{
		Name:         obj.Name,
		UID:          string(obj.UID),
		Generation:   obj.Generation,
		Deleting:     !obj.DeletionTimestamp.IsZero(),
		HasFinalizer: controllerutil.ContainsFinalizer(obj, access.Finalizer),
		Spec: access.SessionSpec{
			AccessProfile:    obj.Spec.AccessProfile,
			AccessProfileUID: obj.Spec.AccessProfileUID,
			Subject:          ToDomainSubject(obj.Spec.Subject),
			Duration:         obj.Spec.Duration,
			Reason:           obj.Spec.Reason,
			RequestRef:       ToDomainRequestRef(obj.Spec.RequestRef),
			Revoked:          obj.Spec.Revoked,
		},
		Status: access.SessionStatus{
			Phase:       access.SessionPhase(obj.Status.Phase),
			StartTime:   ToDomainTime(obj.Status.StartTime),
			ExpiresAt:   ToDomainTime(obj.Status.ExpiresAt),
			BindingName: obj.Status.BindingName,
			BindingRef:  ToDomainBindingRef(obj.Status.BindingRef),
			Grant:       ToDomainGrant(obj.Status.Grant),
			Conditions:  ToDomainConditions(obj.Status.Conditions),
		},
	}
}

// ApplySessionStatus writes the domain status onto the API object.
func ApplySessionStatus(s *access.Session, obj *accessv1alpha1.BreakGlassSession) {
	obj.Status.Phase = accessv1alpha1.SessionPhase(s.Status.Phase)
	obj.Status.StartTime = ToAPITime(s.Status.StartTime)
	obj.Status.ExpiresAt = ToAPITime(s.Status.ExpiresAt)
	obj.Status.BindingName = s.Status.BindingName
	obj.Status.BindingRef = ToAPIBindingRef(s.Status.BindingRef)
	obj.Status.Grant = ToAPIGrant(s.Status.Grant)
	obj.Status.Conditions = ToAPIConditions(s.Status.Conditions)
}

func ToDomainSubject(s accessv1alpha1.SubjectReference) access.Subject {
	return access.Subject{Kind: access.SubjectKind(s.Kind), Name: s.Name, Namespace: s.Namespace}
}

func ToDomainRequestRef(ref *accessv1alpha1.BreakGlassRequestReference) *access.ObjectRef {
	if ref == nil {
		return nil
	}
	return &access.ObjectRef{Name: ref.Name, UID: ref.UID}
}

func ToDomainObjectRef(ref *accessv1alpha1.BreakGlassObjectReference) *access.ObjectRef {
	if ref == nil {
		return nil
	}
	return &access.ObjectRef{Name: ref.Name, UID: ref.UID}
}

func ToAPIObjectRef(ref *access.ObjectRef) *accessv1alpha1.BreakGlassObjectReference {
	if ref == nil {
		return nil
	}
	return &accessv1alpha1.BreakGlassObjectReference{Name: ref.Name, UID: ref.UID}
}

func ToDomainTime(t *metav1.Time) *time.Time {
	if t == nil {
		return nil
	}
	value := t.Time
	return &value
}

func ToAPITime(t *time.Time) *metav1.Time {
	if t == nil {
		return nil
	}
	value := metav1.NewTime(*t)
	return &value
}

func ToDomainBindingRef(ref *accessv1alpha1.BindingReference) *access.BindingRef {
	if ref == nil {
		return nil
	}
	return &access.BindingRef{Kind: ref.Kind, Name: ref.Name, Namespace: ref.Namespace, UID: ref.UID}
}

func ToAPIBindingRef(ref *access.BindingRef) *accessv1alpha1.BindingReference {
	if ref == nil {
		return nil
	}
	return &accessv1alpha1.BindingReference{Kind: ref.Kind, Name: ref.Name, Namespace: ref.Namespace, UID: ref.UID}
}

func ToDomainGrant(grant *accessv1alpha1.ResolvedAccess) *access.Grant {
	if grant == nil {
		return nil
	}
	return &access.Grant{
		AccessProfile:    grant.AccessProfile,
		AccessProfileUID: grant.AccessProfileUID,
		RoleRef:          access.RoleRef{Kind: grant.RoleRef.Kind, Name: grant.RoleRef.Name},
		RoleUID:          grant.RoleUID,
		RoleRulesHash:    grant.RoleRulesHash,
		TargetNamespace:  grant.TargetNamespace,
	}
}

func ToAPIGrant(grant *access.Grant) *accessv1alpha1.ResolvedAccess {
	if grant == nil {
		return nil
	}
	return &accessv1alpha1.ResolvedAccess{
		AccessProfile:    grant.AccessProfile,
		AccessProfileUID: grant.AccessProfileUID,
		RoleRef:          accessv1alpha1.RoleReference{Kind: grant.RoleRef.Kind, Name: grant.RoleRef.Name},
		RoleUID:          grant.RoleUID,
		RoleRulesHash:    grant.RoleRulesHash,
		TargetNamespace:  grant.TargetNamespace,
	}
}

func ToDomainConditions(conditions []metav1.Condition) []access.Condition {
	if conditions == nil {
		return nil
	}
	result := make([]access.Condition, len(conditions))
	for i, c := range conditions {
		result[i] = access.Condition{
			Type:               c.Type,
			Status:             access.ConditionStatus(c.Status),
			ObservedGeneration: c.ObservedGeneration,
			LastTransitionTime: c.LastTransitionTime.Time,
			Reason:             c.Reason,
			Message:            c.Message,
		}
	}
	return result
}

func ToAPIConditions(conditions []access.Condition) []metav1.Condition {
	if conditions == nil {
		return nil
	}
	result := make([]metav1.Condition, len(conditions))
	for i, c := range conditions {
		result[i] = metav1.Condition{
			Type:               c.Type,
			Status:             metav1.ConditionStatus(c.Status),
			ObservedGeneration: c.ObservedGeneration,
			LastTransitionTime: metav1.NewTime(c.LastTransitionTime),
			Reason:             c.Reason,
			Message:            c.Message,
		}
	}
	return result
}

func ToDomainProfile(p *accessv1alpha1.AccessProfile) access.Profile {
	return access.Profile{
		Name:            p.Name,
		UID:             string(p.UID),
		RoleRef:         access.RoleRef{Kind: p.Spec.RoleRef.Kind, Name: p.Spec.RoleRef.Name},
		TargetNamespace: p.Spec.TargetNamespace,
		MaxDuration:     p.Spec.MaxDuration,
		DeliveryMode:    access.DeliveryMode(p.Spec.DeliveryMode),
	}
}

func ToDomainRequest(r *accessv1alpha1.BreakGlassRequest) access.Request {
	return access.Request{
		Name:             r.Name,
		UID:              string(r.UID),
		Generation:       r.Generation,
		CreatedAt:        r.CreationTimestamp.Time,
		AccessProfile:    r.Spec.AccessProfile,
		AccessProfileUID: r.Spec.AccessProfileUID,
		Requester:        ToDomainSubject(r.Spec.Requester),
		Duration:         r.Spec.Duration,
		Reason:           r.Spec.Reason,
		RequestTTL:       r.Spec.RequestTTL,
		Status: access.RequestStatus{
			Phase:              access.RequestPhase(r.Status.Phase),
			ObservedGeneration: r.Status.ObservedGeneration,
			ExpiresAt:          ToDomainTime(r.Status.ExpiresAt),
			ApprovalRef:        ToDomainObjectRef(r.Status.ApprovalRef),
			SessionRef:         ToDomainObjectRef(r.Status.SessionRef),
			Conditions:         ToDomainConditions(r.Status.Conditions),
		},
	}
}

func ToAPIRequestStatus(status access.RequestStatus) accessv1alpha1.BreakGlassRequestStatus {
	return accessv1alpha1.BreakGlassRequestStatus{
		Phase:              accessv1alpha1.RequestPhase(status.Phase),
		ObservedGeneration: status.ObservedGeneration,
		ExpiresAt:          ToAPITime(status.ExpiresAt),
		ApprovalRef:        ToAPIObjectRef(status.ApprovalRef),
		SessionRef:         ToAPIObjectRef(status.SessionRef),
		Conditions:         ToAPIConditions(status.Conditions),
	}
}

func ToDomainApproval(a *accessv1alpha1.BreakGlassApproval) access.Approval {
	return access.Approval{
		Name:       a.Name,
		UID:        string(a.UID),
		RequestRef: access.ObjectRef{Name: a.Spec.RequestRef.Name, UID: a.Spec.RequestRef.UID},
		Decision:   access.Decision(a.Spec.Decision),
		Approver:   ToDomainSubject(a.Spec.Approver),
	}
}

// ToDomainBinding observes a RoleBinding. Only controller owner references to
// a BreakGlassSession are reported; other owners prove nothing.
func ToDomainBinding(rb *rbacv1.RoleBinding) access.Binding {
	binding := access.Binding{
		Kind:      access.RoleBindingKind,
		Name:      rb.Name,
		Namespace: rb.Namespace,
		UID:       string(rb.UID),
		Labels:    rb.Labels,
		RoleRef:   access.BindingRoleRef{APIGroup: rb.RoleRef.APIGroup, Kind: rb.RoleRef.Kind, Name: rb.RoleRef.Name},
		Version:   rb.ResourceVersion,
	}
	for _, owner := range rb.OwnerReferences {
		if IsSessionControllerOwner(owner) {
			binding.SessionOwners = append(binding.SessionOwners, access.SessionOwner{Name: owner.Name, UID: string(owner.UID)})
		}
	}
	if rb.Subjects != nil {
		binding.Subjects = make([]access.BindingSubject, len(rb.Subjects))
		for i, s := range rb.Subjects {
			binding.Subjects[i] = access.BindingSubject{APIGroup: s.APIGroup, Kind: s.Kind, Name: s.Name, Namespace: s.Namespace}
		}
	}
	return binding
}

func ToAPISubjects(subjects []access.BindingSubject) []rbacv1.Subject {
	if subjects == nil {
		return nil
	}
	result := make([]rbacv1.Subject, len(subjects))
	for i, s := range subjects {
		result[i] = rbacv1.Subject{APIGroup: s.APIGroup, Kind: s.Kind, Name: s.Name, Namespace: s.Namespace}
	}
	return result
}

func IsSessionControllerOwner(owner metav1.OwnerReference) bool {
	return owner.APIVersion == accessv1alpha1.GroupVersion.String() &&
		owner.Kind == SessionKind &&
		owner.Controller != nil && *owner.Controller
}

func SessionControllerOwner(owner access.SessionOwner) metav1.OwnerReference {
	controller := true
	return metav1.OwnerReference{
		APIVersion:         accessv1alpha1.GroupVersion.String(),
		Kind:               SessionKind,
		Name:               owner.Name,
		UID:                types.UID(owner.UID),
		Controller:         &controller,
		BlockOwnerDeletion: &controller,
	}
}

// Classify marks Kubernetes API errors with the port error kinds that use
// cases distinguish. The original error is preserved.
func Classify(err error) error {
	switch {
	case err == nil:
		return nil
	case apierrors.IsNotFound(err):
		return port.Mark(port.ErrNotFound, err)
	case apierrors.IsAlreadyExists(err):
		return port.Mark(port.ErrAlreadyExists, err)
	case apierrors.IsConflict(err):
		return port.Mark(port.ErrConflict, err)
	case apierrors.IsForbidden(err):
		return port.Mark(port.ErrForbidden, err)
	default:
		return err
	}
}
