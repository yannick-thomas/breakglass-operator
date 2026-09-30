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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// SessionPhase defines the current lifecycle phase of a BreakGlassSession
// +kubebuilder:validation:Enum=Pending;Active;Suspended;Denied;Expired;Revoked
type SessionPhase string

const (
	PhasePending   SessionPhase = "Pending"
	PhaseActive    SessionPhase = "Active"
	PhaseSuspended SessionPhase = "Suspended"
	PhaseDenied    SessionPhase = "Denied"
	PhaseExpired   SessionPhase = "Expired"
	PhaseRevoked   SessionPhase = "Revoked"
)

// SubjectKind defines the type of subject (User, Group, ServiceAccount)
// +kubebuilder:validation:Enum=User;Group;ServiceAccount
type SubjectKind string

const (
	SubjectKindUser           SubjectKind = "User"
	SubjectKindGroup          SubjectKind = "Group"
	SubjectKindServiceAccount SubjectKind = "ServiceAccount"
)

// SubjectReference specifies the subject receiving the privileged access
type SubjectReference struct {
	// Kind of the subject (User, Group, ServiceAccount)
	// +kubebuilder:validation:Required
	Kind SubjectKind `json:"kind"`

	// Name of the subject (e.g. email, username, serviceaccount name)
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Namespace of the subject (only relevant when Kind is ServiceAccount)
	// +optional
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace"`
}

// RoleReference specifies the Role or ClusterRole being granted
type RoleReference struct {
	// Kind of the role (ClusterRole or Role)
	// +kubebuilder:validation:Enum=Role;ClusterRole
	// +kubebuilder:default=ClusterRole
	Kind string `json:"kind"`

	// Name of the Role or ClusterRole
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// BreakGlassSessionSpec defines an immutable self-service JIT request.
//
// The request intentionally contains no role or target namespace. Those
// privileged choices belong to the administrator-owned AccessProfile. The
// admission webhook writes subject and accessProfileUID from the authenticated
// API request and the controller verifies the resulting profile snapshot.
// The only permitted client transition is early revocation.
//
// This is an intentionally breaking v1alpha1 API change from the original
// free-form roleRef/targetNamespace model. Existing grants should be allowed
// to expire or be revoked before upgrading.
// +kubebuilder:validation:XValidation:rule="self.accessProfile == oldSelf.accessProfile",message="accessProfile is immutable"
// +kubebuilder:validation:XValidation:rule="self.accessProfileUID == oldSelf.accessProfileUID",message="accessProfileUID is immutable"
// +kubebuilder:validation:XValidation:rule="self.subject == oldSelf.subject",message="subject is immutable"
// +kubebuilder:validation:XValidation:rule="self.duration == oldSelf.duration",message="duration is immutable"
// +kubebuilder:validation:XValidation:rule="self.reason == oldSelf.reason",message="reason is immutable"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.requestRef) ? !has(self.requestRef) : has(self.requestRef) && self.requestRef == oldSelf.requestRef",message="requestRef is immutable"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.revoked) || !oldSelf.revoked || (has(self.revoked) && self.revoked)",message="revoked cannot be changed from true to false"
// +kubebuilder:validation:XValidation:rule="self.subject.kind == 'User' && (!has(self.subject.namespace) || size(self.subject.namespace) == 0)",message="v1alpha1 self-service sessions may only grant the authenticated User requester"
type BreakGlassSessionSpec struct {
	// AccessProfile is the fixed, administrator-owned access policy to use.
	// The requester requires the custom RBAC verb "use" on this named profile.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	AccessProfile string `json:"accessProfile"`

	// AccessProfileUID is written by the mutating admission webhook from the
	// selected profile's server-assigned UID. It prevents a delete/recreate of
	// the same profile name from silently changing a pending request.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	AccessProfileUID string `json:"accessProfileUID"`

	// Subject is written by the mutating admission webhook from the
	// authenticated API requester. Client-supplied values are overwritten and
	// v1alpha1 supports only a self-service User grant.
	// +kubebuilder:validation:Required
	Subject SubjectReference `json:"subject"`

	// Duration is the lifespan of this break-glass session (e.g. "30m", "1h", "2h30m").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$`
	Duration string `json:"duration"`

	// Reason explains why this emergency access is needed (audit trail).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=5
	// +kubebuilder:validation:MaxLength=1024
	Reason string `json:"reason"`

	// RequestRef is present only for the approval workflow. The session webhook
	// accepts it only from the configured request controller after it verifies
	// the exact request UID, approval state, deadline, and reserved session
	// name. Self-service users cannot set this field.
	// +optional
	RequestRef *BreakGlassRequestReference `json:"requestRef,omitempty"`

	// Revoked allows manual revocation before the duration expires.
	// +optional
	Revoked bool `json:"revoked,omitempty"`
}

// ResolvedAccess is the immutable, controller-recorded profile snapshot used
// for an active grant. It leaves a durable audit record and prevents later
// profile changes or replacement from altering the bound RBAC role or scope.
type ResolvedAccess struct {
	// AccessProfile is the selected policy name.
	AccessProfile string `json:"accessProfile"`

	// AccessProfileUID is the UID of the policy that was authorized and resolved.
	AccessProfileUID string `json:"accessProfileUID"`

	// RoleRef is the profile's curated ClusterRole.
	RoleRef RoleReference `json:"roleRef"`

	// RoleUID is the server-assigned UID of the curated ClusterRole when the
	// grant was activated. A role recreated under the same name is not trusted.
	// Sessions created before this field existed are suspended fail-closed during
	// their next integrity check.
	// +optional
	RoleUID string `json:"roleUID,omitempty"`

	// RoleRulesHash is a canonical SHA-256 digest of the curated ClusterRole's
	// rules when the grant was activated. A changed rule set suspends the grant.
	// +optional
	RoleRulesHash string `json:"roleRulesHash,omitempty"`

	// TargetNamespace is the profile's fixed namespace.
	TargetNamespace string `json:"targetNamespace"`
}

// BindingReference is the immutable, server-assigned identity of the
// RoleBinding created for a session. The controller uses its UID as the
// authoritative ownership proof after activation: a different object with the
// same name must never be repaired, adopted, or deleted.
type BindingReference struct {
	// Kind is RoleBinding. ClusterRoleBinding is deliberately not supported by
	// the AccessProfile-based v1alpha1 API.
	// +kubebuilder:validation:Enum=RoleBinding
	Kind string `json:"kind"`

	// Name is the RBAC binding name.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace is the fixed namespace of the profile's RoleBinding.
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`

	// UID is the server-assigned UID of the created binding.
	// +kubebuilder:validation:MinLength=1
	UID string `json:"uid"`
}

// BreakGlassSessionStatus defines the observed state of BreakGlassSession.
type BreakGlassSessionStatus struct {
	// Phase is the current lifecycle state (Pending, Active, Suspended, Denied, Expired, Revoked)
	// +optional
	Phase SessionPhase `json:"phase,omitempty"`

	// StartTime is when the session became active
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// ExpiresAt is the calculated expiration time
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`

	// BindingName is the name of the created RoleBinding.
	// +optional
	BindingName string `json:"bindingName,omitempty"`

	// BindingRef is the authoritative identity of the RBAC binding created for
	// this session. Once present, the controller only acts on an object that
	// matches this kind, namespace, name, and UID exactly.
	// +optional
	BindingRef *BindingReference `json:"bindingRef,omitempty"`

	// Grant is the immutable profile snapshot resolved when the session became
	// active. A missing or mismatched profile snapshot is fail-closed.
	// +optional
	Grant *ResolvedAccess `json:"grant,omitempty"`

	// Conditions represent the latest available observations of the session's state.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=bgs
// +kubebuilder:printcolumn:name="Subject",type="string",JSONPath=".spec.subject.name",description="Authenticated requester granted access"
// +kubebuilder:printcolumn:name="Profile",type="string",JSONPath=".spec.accessProfile",description="Administrator-owned access profile"
// +kubebuilder:printcolumn:name="Role",type="string",JSONPath=".status.grant.roleRef.name",description="Resolved curated role"
// +kubebuilder:printcolumn:name="Target-NS",type="string",JSONPath=".status.grant.targetNamespace",description="Resolved fixed target namespace"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase",description="Session phase"
// +kubebuilder:printcolumn:name="Expires-At",type="string",JSONPath=".status.expiresAt",description="Session expiry timestamp"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// BreakGlassSession is the Schema for the breakglasssessions API
type BreakGlassSession struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of BreakGlassSession
	// +required
	Spec BreakGlassSessionSpec `json:"spec"`

	// status defines the observed state of BreakGlassSession
	// +optional
	Status BreakGlassSessionStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// BreakGlassSessionList contains a list of BreakGlassSession
type BreakGlassSessionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []BreakGlassSession `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &BreakGlassSession{}, &BreakGlassSessionList{})
		return nil
	})
}
