package v1alpha1

import (
	"crypto/sha256"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// BreakGlassRequestSpec is untrusted requester intent. Admission snapshots the
// authenticated requester and the selected AccessProfile UID. It deliberately
// omits a role and target namespace: those choices remain owned by the
// administrator-managed AccessProfile.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="BreakGlassRequest spec is immutable"
type BreakGlassRequestSpec struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	AccessProfile string `json:"accessProfile"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	AccessProfileUID string `json:"accessProfileUID"`
	// +kubebuilder:validation:Required
	Requester SubjectReference `json:"requester"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$`
	Duration string `json:"duration"`
	// RequestTTL is overwritten by admission from the manager configuration.
	// It snapshots the server policy that determines the request deadline, so
	// approval and provisioning never depend on a later asynchronous status
	// write or a changed manager flag.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$`
	RequestTTL string `json:"requestTTL"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=5
	// +kubebuilder:validation:MaxLength=1024
	Reason string `json:"reason"`
}

// RequestPhase is the controller-owned lifecycle of a BreakGlassRequest.
// Values are intentionally distinct from BreakGlassSession phases: a request
// records intent and approval, while a session records an actual RBAC grant.
// +kubebuilder:validation:Enum=Pending;Approved;Denied;Expired;Provisioning;SessionCreated;Failed
type RequestPhase string

const (
	RequestPhasePending        RequestPhase = "Pending"
	RequestPhaseApproved       RequestPhase = "Approved"
	RequestPhaseDenied         RequestPhase = "Denied"
	RequestPhaseExpired        RequestPhase = "Expired"
	RequestPhaseProvisioning   RequestPhase = "Provisioning"
	RequestPhaseSessionCreated RequestPhase = "SessionCreated"
	RequestPhaseFailed         RequestPhase = "Failed"
)

// BreakGlassRequestReference identifies one immutable request instance. The
// UID prevents a delete/recreate under the same name from being approved or
// provisioned by mistake.
type BreakGlassRequestReference struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	UID string `json:"uid"`
}

// BreakGlassObjectReference identifies an immutable controller-recorded
// approval or session. It intentionally omits arbitrary API group and kind:
// each status field has a single, fixed resource type.
type BreakGlassObjectReference struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// UID is empty only while the controller reserves a deterministic session
	// name before creating it. Once a reference is persisted as terminal, the
	// UID is required and prevents same-name adoption.
	// +optional
	UID string `json:"uid,omitempty"`
}

type BreakGlassRequestStatus struct {
	// Phase is written only by the request controller. A new request is
	// Pending; it must never be treated as access until SessionCreated is
	// persisted with a verified session reference.
	// +optional
	Phase RequestPhase `json:"phase,omitempty"`
	// ObservedGeneration is the generation from which the controller derived
	// the status. It makes stale UI/API reads detectable without exposing
	// request-specific data in metrics.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// ExpiresAt is the controller-recorded deadline for a decision. The
	// approval controller must fail closed after this timestamp.
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
	// ApprovalRef is the one decision selected by the request controller. It
	// is immutable after the request leaves Pending and provides an audit link
	// without copying the approver identity into a metric label.
	// +optional
	ApprovalRef *BreakGlassObjectReference `json:"approvalRef,omitempty"`
	// SessionRef is reserved before the controller creates the final session,
	// then completed with the server-assigned UID. The session admission
	// webhook accepts a controller-sourced grant only for this exact reference.
	// +optional
	SessionRef *BreakGlassObjectReference `json:"sessionRef,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
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

// ApprovalNameForRequestUID returns the one deterministic approval object
// name for a request. A Kubernetes create conflict therefore serializes
// concurrent approve/deny attempts without giving the controller a
// nondeterministic "first list result wins" policy.
func ApprovalNameForRequestUID(uid string) string {
	sum := sha256.Sum256([]byte(uid))
	return fmt.Sprintf("breakglass-approval-%x", sum[:8])
}

// SessionNameForRequestUID returns the controller-reserved session name for a
// request. It contains only a digest of the request UID, never a requester,
// profile, ticket, or incident reason.
func SessionNameForRequestUID(uid string) string {
	sum := sha256.Sum256([]byte(uid))
	return fmt.Sprintf("breakglass-request-%x", sum[:8])
}
