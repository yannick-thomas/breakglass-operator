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

// AccessProfileSpec is an administrator-owned, fixed access policy.
//
// Each profile deliberately resolves to one namespaced RBAC grant.  A requester
// selects a profile; they never select a role, a target namespace, or another
// subject.  Granting the custom RBAC verb "use" on a particular AccessProfile
// is therefore the authorization boundary for a self-service session.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="AccessProfile policy fields are immutable; create a new, versioned profile instead"
// +kubebuilder:validation:XValidation:rule="self.roleRef.kind == 'ClusterRole'",message="v1alpha1 AccessProfiles may reference only curated ClusterRoles"
type AccessProfileSpec struct {
	// RoleRef is the pre-approved Role or ClusterRole to bind in targetNamespace.
	// A ClusterRole is still bound with a namespaced RoleBinding; it does not make
	// the resulting grant cluster-wide.
	// +kubebuilder:validation:Required
	RoleRef RoleReference `json:"roleRef"`

	// TargetNamespace is the only namespace in which this profile can grant
	// access. Cluster-wide profiles are intentionally out of scope for this API.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	TargetNamespace string `json:"targetNamespace"`

	// MaxDuration is the longest permitted session duration for this profile,
	// expressed as a Go duration such as "30m" or "1h".
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$`
	MaxDuration string `json:"maxDuration"`
}

// AccessProfileStatus reports whether the policy can be activated by this
// manager. It is controller-owned; a Ready condition does not make the policy
// an authorization decision for a particular requester.
type AccessProfileStatus struct {
	// ObservedGeneration is the most recent generation evaluated by the
	// AccessProfile controller.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions describe whether the role, duration, and manager namespace
	// scope make this profile usable.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=ap
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Role",type="string",JSONPath=".spec.roleRef.name",description="Pre-approved Role or ClusterRole"
// +kubebuilder:printcolumn:name="Target-NS",type="string",JSONPath=".spec.targetNamespace",description="Only namespace this profile can grant in"
// +kubebuilder:printcolumn:name="Max-Duration",type="string",JSONPath=".spec.maxDuration",description="Maximum permitted session duration"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status",description="Whether the manager can activate this profile"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// AccessProfile is the Schema for the accessprofiles API
type AccessProfile struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of AccessProfile
	// +required
	Spec AccessProfileSpec `json:"spec"`

	// status reports controller-observed readiness for this profile.
	// +optional
	Status AccessProfileStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AccessProfileList contains a list of AccessProfile
type AccessProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []AccessProfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &AccessProfile{}, &AccessProfileList{})
		return nil
	})
}
