package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// BreakGlassRequestSpec is untrusted requester intent. Admission snapshots the
// authenticated requester and the selected AccessProfile UID.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="BreakGlassRequest spec is immutable"
type BreakGlassRequestSpec struct {
	// +kubebuilder:validation:Required
	AccessProfile string `json:"accessProfile"`
	// +kubebuilder:validation:Required
	AccessProfileUID string `json:"accessProfileUID"`
	// +kubebuilder:validation:Required
	Requester SubjectReference `json:"requester"`
	// +kubebuilder:validation:Required
	Duration string `json:"duration"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=5
	Reason string `json:"reason"`
}

type BreakGlassRequestStatus struct {
	Phase string `json:"phase,omitempty"`
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=bgr
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Requester",type="string",JSONPath=".spec.requester.name",description="Authenticated requester"
// +kubebuilder:printcolumn:name="Profile",type="string",JSONPath=".spec.accessProfile",description="Requested profile"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase",description="Approval lifecycle phase"
type BreakGlassRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitzero"`
	Spec              BreakGlassRequestSpec   `json:"spec"`
	Status            BreakGlassRequestStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type BreakGlassRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []BreakGlassRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &BreakGlassRequest{}, &BreakGlassRequestList{})
		return nil
	})
}
