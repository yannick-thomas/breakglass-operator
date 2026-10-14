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

package access

import (
	"crypto/sha256"
	"fmt"
	"time"
)

// ObjectRef identifies an object by name and server-assigned UID. A name alone
// is never proof of identity: objects can be deleted and recreated.
type ObjectRef struct {
	Name string
	UID  string
}

// Complete reports whether both name and UID are known.
func (r ObjectRef) Complete() bool {
	return r.Name != "" && r.UID != ""
}

// RequestPhase is the lifecycle state of an approval-workflow request.
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

// Terminal reports whether no further transition is possible.
func (p RequestPhase) Terminal() bool {
	switch p {
	case RequestPhaseDenied, RequestPhaseExpired, RequestPhaseSessionCreated, RequestPhaseFailed:
		return true
	default:
		return false
	}
}

// Request is untrusted access intent that needs an independent decision.
type Request struct {
	Name       string
	UID        string
	Generation int64
	CreatedAt  time.Time

	AccessProfile    string
	AccessProfileUID string
	Requester        Subject
	Duration         string
	Reason           string
	RequestTTL       string

	Status RequestStatus
}

// RequestStatus is the controller-owned state of a request.
type RequestStatus struct {
	Phase              RequestPhase
	ObservedGeneration int64
	ExpiresAt          *time.Time
	ApprovalRef        *ObjectRef
	SessionRef         *ObjectRef
	Conditions         []Condition
}

// Ref returns the request's identity.
func (r Request) Ref() ObjectRef {
	return ObjectRef{Name: r.Name, UID: r.UID}
}

// Deadline is the end of the decision window: the server creation time plus
// the request TTL snapshotted at admission. ok is false when the TTL is not a
// positive duration, which makes the request unusable.
func (r Request) Deadline() (deadline time.Time, ok bool) {
	ttl, ok := ParsePositiveDuration(r.RequestTTL)
	if !ok {
		return time.Time{}, false
	}
	return r.CreatedAt.Add(ttl), true
}

// DecisionOpen reports whether the request may still be decided or consumed.
func (r Request) DecisionOpen(now time.Time) bool {
	deadline, ok := r.Deadline()
	return ok && now.Before(deadline)
}

// MatchesSession reports whether a session carries exactly the approved
// request's access intent.
func (r Request) MatchesSession(spec SessionSpec) bool {
	return spec.AccessProfile == r.AccessProfile &&
		spec.AccessProfileUID == r.AccessProfileUID &&
		spec.Subject == r.Requester &&
		spec.Duration == r.Duration &&
		spec.Reason == r.Reason
}

// ReservesForProvisioning reports whether the request is provisioning and
// has reserved exactly this session name, before the session's UID is known.
// Only then may the request controller create that session.
func (r Request) ReservesForProvisioning(sessionName string) bool {
	ref := r.Status.SessionRef
	return r.Status.Phase == RequestPhaseProvisioning && ref != nil && ref.Name == sessionName && ref.UID == ""
}

// ApprovalName is the one deterministic name an approval for this request
// may have. A single slot makes duplicate or competing decisions impossible.
func (r Request) ApprovalName() string {
	return ApprovalNameForRequestUID(r.UID)
}

// ApprovalNameForRequestUID derives the deterministic approval name.
func ApprovalNameForRequestUID(uid string) string {
	sum := sha256.Sum256([]byte(uid))
	return fmt.Sprintf("breakglass-approval-%x", sum[:8])
}

// SessionNameForRequestUID derives the one session name the request
// controller may create for a request.
func SessionNameForRequestUID(uid string) string {
	sum := sha256.Sum256([]byte(uid))
	return fmt.Sprintf("breakglass-request-%x", sum[:8])
}

// Decision is the outcome an approver records.
type Decision string

const (
	DecisionApproved Decision = "Approved"
	DecisionDenied   Decision = "Denied"
)

// Approval is an append-only decision on one request.
type Approval struct {
	Name       string
	UID        string
	RequestRef ObjectRef
	Decision   Decision
	Approver   Subject
}

// DecidesFor reports whether the approval is a valid decision on exactly this
// request by an independent person: it cites the request's name and UID, its
// approver is a named user other than the requester, and its decision is one
// of the supported outcomes.
func (a Approval) DecidesFor(r Request) bool {
	return a.RequestRef == r.Ref() &&
		a.Approver.Kind == SubjectKindUser && a.Approver.Name != "" &&
		a.Approver.Name != r.Requester.Name &&
		(a.Decision == DecisionApproved || a.Decision == DecisionDenied)
}

// Approves reports whether the approval is an independent approval of the
// request.
func (a Approval) Approves(r Request) bool {
	return a.DecidesFor(r) && a.Decision == DecisionApproved
}
