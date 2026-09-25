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
// +kubebuilder:validation:Enum=Pending;Active;Expired;Revoked
type SessionPhase string

const (
	PhasePending SessionPhase = "Pending"
	PhaseActive  SessionPhase = "Active"
	PhaseExpired SessionPhase = "Expired"
	PhaseRevoked SessionPhase = "Revoked"
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
	Name string `json:"name"`

	// Namespace of the subject (only relevant when Kind is ServiceAccount)
	// +optional
	Namespace string `json:"namespace,omitempty"`
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
	Name string `json:"name"`
}

// BreakGlassSessionSpec defines the desired state of BreakGlassSession
type BreakGlassSessionSpec struct {
	// Subject specifies who gets access
	// +kubebuilder:validation:Required
	Subject SubjectReference `json:"subject"`

	// RoleRef specifies which Role or ClusterRole to bind
	// +kubebuilder:validation:Required
	RoleRef RoleReference `json:"roleRef"`

	// TargetNamespace specifies the namespace where the role is bound.
	// If omitted or empty, access is granted cluster-wide via ClusterRoleBinding.
	// If set, access is granted only within that namespace via RoleBinding.
	// +optional
	TargetNamespace string `json:"targetNamespace,omitempty"`

	// Duration is the lifespan of this break-glass session (e.g. "30m", "1h", "2h30m").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$`
	Duration string `json:"duration"`

	// Reason explains why this emergency access is needed (audit trail).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=5
	Reason string `json:"reason"`

	// Revoked allows manual revocation before the duration expires.
	// +optional
	Revoked bool `json:"revoked,omitempty"`
}

// BreakGlassSessionStatus defines the observed state of BreakGlassSession.
type BreakGlassSessionStatus struct {
	// Phase is the current lifecycle state (Pending, Active, Expired, Revoked)
	// +optional
	Phase SessionPhase `json:"phase,omitempty"`

	// StartTime is when the session became active
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// ExpiresAt is the calculated expiration time
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`

	// BindingName is the name of the created RoleBinding or ClusterRoleBinding
	// +optional
	BindingName string `json:"bindingName,omitempty"`

	// Conditions represent the latest available observations of the session's state.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=bgs
// +kubebuilder:printcolumn:name="Subject",type="string",JSONPath=".spec.subject.name",description="Subject granted access"
// +kubebuilder:printcolumn:name="Role",type="string",JSONPath=".spec.roleRef.name",description="Role granted"
// +kubebuilder:printcolumn:name="Target-NS",type="string",JSONPath=".spec.targetNamespace",description="Target namespace (empty = cluster-wide)"
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
