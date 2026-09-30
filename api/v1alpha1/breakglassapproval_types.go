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

// ApprovalDecision is an immutable human decision on a request.
// +kubebuilder:validation:Enum=Approved;Denied
type ApprovalDecision string

const (
	ApprovalDecisionApproved ApprovalDecision = "Approved"
	ApprovalDecisionDenied   ApprovalDecision = "Denied"
)

// BreakGlassApprovalSpec is an append-only, authenticated approval decision.
// The webhook stamps Approver from Kubernetes admission identity and verifies
// RequestRef against the current request UID and expiry.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="BreakGlassApproval spec is immutable"
type BreakGlassApprovalSpec struct {
	// +kubebuilder:validation:Required
	RequestRef BreakGlassRequestReference `json:"requestRef"`
	// +kubebuilder:validation:Required
	Decision ApprovalDecision `json:"decision"`
	// Approver is overwritten by the mutating webhook from the authenticated
	// Kubernetes user. A requester can never nominate a different approver.
	// +kubebuilder:validation:Required
	Approver SubjectReference `json:"approver"`
	// Comment is optional audit context. It must never contain credentials or
	// be used as a Prometheus label.
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	Comment string `json:"comment,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=bga
// +kubebuilder:printcolumn:name="Request",type="string",JSONPath=".spec.requestRef.name",description="Approved request"
// +kubebuilder:printcolumn:name="Decision",type="string",JSONPath=".spec.decision",description="Immutable decision"
// +kubebuilder:printcolumn:name="Approver",type="string",JSONPath=".spec.approver.name",description="Authenticated approver"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
type BreakGlassApproval struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitzero"`
	Spec              BreakGlassApprovalSpec `json:"spec"`
}

// +kubebuilder:object:root=true
type BreakGlassApprovalList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []BreakGlassApproval `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &BreakGlassApproval{}, &BreakGlassApprovalList{})
		return nil
	})
}
