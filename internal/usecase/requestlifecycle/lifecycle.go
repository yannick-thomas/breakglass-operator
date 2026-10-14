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

// Package requestlifecycle is the use case that carries untrusted access
// intent through an independent decision to exactly one session.
//
// It never creates a RoleBinding. The session lifecycle stays the only path
// that turns a validated session into a grant (ADR-001).
package requestlifecycle

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/port"
)

// Condition types recorded on a request.
const (
	ConditionAwaitingApproval = "AwaitingApproval"
	ConditionProvisioned      = "Provisioned"
)

// ContinueImmediately is the requeue delay after a durable intermediate step.
// It continues the state machine without depending on the watch delivering
// the controller's own write.
const ContinueImmediately = time.Nanosecond

// ApprovalSource reads the approval in a request's deterministic slot;
// port.ErrNotFound if none exists yet.
type ApprovalSource interface {
	Approval(ctx context.Context, name string) (access.Approval, error)
}

// SessionRecord is what the request lifecycle needs to know about a session.
type SessionRecord struct {
	Name       string
	UID        string
	RequestRef *access.ObjectRef
}

// SessionGateway reads and creates sessions.
type SessionGateway interface {
	// Get returns port.ErrNotFound if the session does not exist.
	Get(ctx context.Context, name string) (SessionRecord, error)
	Create(ctx context.Context, name string, spec access.SessionSpec) (SessionRecord, error)
}

// RequestStore persists request status.
type RequestStore interface {
	// UpdateStatusIfChanged writes the status only if it differs from the
	// stored one. It reports false without error when nothing was written,
	// including after a write conflict; the next reconciliation retries.
	UpdateStatusIfChanged(ctx context.Context, request *access.Request) (bool, error)
}

// Telemetry receives phase transitions. It is optional.
type Telemetry interface {
	Transition(access.RequestPhase)
}

// Lifecycle reconciles requests.
type Lifecycle struct {
	Approvals ApprovalSource
	Sessions  SessionGateway
	Telemetry Telemetry
	// RequestControllerUsername is the identity admission accepts for
	// request-sourced sessions. Provisioning is disabled when it is empty.
	RequestControllerUsername string
	Clock                     func() time.Time
}

// Result tells the caller when to reconcile the request again.
type Result struct {
	RequeueAfter time.Duration
}

// Reconcile advances a request by one durable step. The deadline is derived
// from the server creation time and the admission-snapshotted TTL, never from
// status, and every unconsumed request expires once it passes.
func (l *Lifecycle) Reconcile(ctx context.Context, req *access.Request, store RequestStore) (Result, error) {
	deadline, ok := req.Deadline()
	if !ok {
		return Result{}, l.markFailed(ctx, req, store, "InvalidRequestTTL", "The immutable request TTL is not a positive duration")
	}
	now := l.now()
	if req.Status.Phase.Terminal() {
		return Result{}, nil
	}
	previous := req.Status.Phase
	if req.Status.ExpiresAt == nil || !req.Status.ExpiresAt.Equal(deadline) {
		req.Status.ExpiresAt = &deadline
	}

	switch {
	case !now.Before(deadline):
		req.Status.Phase = access.RequestPhaseExpired
		l.setCondition(req, ConditionAwaitingApproval, access.ConditionFalse, "RequestExpired", "The request expired before it was consumed by a session")
	case req.Status.Phase == "":
		req.Status.Phase = access.RequestPhasePending
		l.setCondition(req, ConditionAwaitingApproval, access.ConditionTrue, "AwaitingApproval", "The request is valid and awaits an approval decision")
	case req.Status.Phase == access.RequestPhasePending:
		approval, err := l.decisionFor(ctx, req)
		if err != nil {
			return Result{}, l.markFailed(ctx, req, store, "InvalidApproval", "The deterministic approval slot is not a valid independent decision")
		}
		if approval != nil {
			l.recordDecision(req, approval)
		}
	case req.Status.Phase == access.RequestPhaseApproved:
		if l.RequestControllerUsername == "" {
			return Result{}, l.markFailed(ctx, req, store, "ControllerIdentityNotConfigured", "The request controller identity is not configured")
		}
		req.Status.Phase = access.RequestPhaseProvisioning
		req.Status.SessionRef = &access.ObjectRef{Name: access.SessionNameForRequestUID(req.UID)}
		l.setCondition(req, ConditionProvisioned, access.ConditionUnknown, "SessionReserved", "The controller reserved the one session name for this request")
	case req.Status.Phase == access.RequestPhaseProvisioning:
		if err := l.provision(ctx, req, store); err != nil {
			return Result{}, err
		}
	}
	req.Status.ObservedGeneration = req.Generation

	updated, err := store.UpdateStatusIfChanged(ctx, req)
	if err != nil {
		return Result{}, err
	}
	changed := updated && previous != req.Status.Phase
	if changed {
		l.transition(req.Status.Phase)
	}
	if req.Status.Phase == access.RequestPhaseExpired {
		return Result{}, nil
	}
	// Approval and provisioning are persisted one step at a time for crash
	// safety, so those intermediate transitions continue immediately. Pending
	// is event-driven: the approval watch wakes the controller.
	if changed && (req.Status.Phase == access.RequestPhaseApproved || req.Status.Phase == access.RequestPhaseProvisioning) {
		return Result{RequeueAfter: ContinueImmediately}, nil
	}
	return Result{RequeueAfter: deadline.Sub(now)}, nil
}

// decisionFor returns the decision in the request's deterministic slot, nil
// if there is none yet, or an error if the slot holds anything other than a
// valid independent decision on exactly this request.
func (l *Lifecycle) decisionFor(ctx context.Context, req *access.Request) (*access.Approval, error) {
	approval, err := l.Approvals.Approval(ctx, req.ApprovalName())
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if !approval.DecidesFor(*req) {
		return nil, fmt.Errorf("BreakGlassApproval %q is not a valid independent decision", approval.Name)
	}
	return &approval, nil
}

func (l *Lifecycle) recordDecision(req *access.Request, approval *access.Approval) {
	req.Status.ApprovalRef = &access.ObjectRef{Name: approval.Name, UID: approval.UID}
	switch approval.Decision {
	case access.DecisionDenied:
		req.Status.Phase = access.RequestPhaseDenied
		l.setCondition(req, ConditionAwaitingApproval, access.ConditionFalse, "Denied", "An authorized approver denied this request")
	case access.DecisionApproved:
		req.Status.Phase = access.RequestPhaseApproved
		l.setCondition(req, ConditionAwaitingApproval, access.ConditionFalse, "Approved", "An authorized approver accepted this request")
	}
}

// provision creates the reserved session, or confirms that an earlier attempt
// created it, and records its server-assigned UID.
func (l *Lifecycle) provision(ctx context.Context, req *access.Request, store RequestStore) error {
	ref := req.Status.SessionRef
	if ref == nil || ref.Name == "" || ref.UID != "" {
		return l.markFailed(ctx, req, store, "InvalidSessionReservation", "The request has no valid controller-reserved session name")
	}
	session, err := l.Sessions.Get(ctx, ref.Name)
	if err != nil {
		if !errors.Is(err, port.ErrNotFound) {
			return err
		}
		requestRef := req.Ref()
		session, err = l.Sessions.Create(ctx, ref.Name, access.SessionSpec{
			AccessProfile:    req.AccessProfile,
			AccessProfileUID: req.AccessProfileUID,
			Subject:          req.Requester,
			Duration:         req.Duration,
			Reason:           req.Reason,
			RequestRef:       &requestRef,
		})
		if err != nil {
			return err
		}
	}
	if session.RequestRef == nil || *session.RequestRef != req.Ref() {
		return l.markFailed(ctx, req, store, "SessionSourceMismatch", "The reserved session name belongs to a different request")
	}
	if session.UID == "" {
		return fmt.Errorf("created BreakGlassSession %q has no server-assigned UID", session.Name)
	}
	ref.UID = session.UID
	req.Status.Phase = access.RequestPhaseSessionCreated
	l.setCondition(req, ConditionProvisioned, access.ConditionTrue, "SessionCreated", "The controller created the reserved session object")
	return nil
}

// markFailed makes the request terminally Failed and persists that at once.
func (l *Lifecycle) markFailed(ctx context.Context, req *access.Request, store RequestStore, reason, message string) error {
	previous := req.Status.Phase
	req.Status.Phase = access.RequestPhaseFailed
	req.Status.ObservedGeneration = req.Generation
	l.setCondition(req, ConditionProvisioned, access.ConditionFalse, reason, message)
	updated, err := store.UpdateStatusIfChanged(ctx, req)
	if err != nil {
		return err
	}
	if updated && previous != req.Status.Phase {
		l.transition(access.RequestPhaseFailed)
	}
	return nil
}

func (l *Lifecycle) setCondition(req *access.Request, conditionType string, status access.ConditionStatus, reason, message string) {
	access.SetCondition(&req.Status.Conditions, access.Condition{
		Type:               conditionType,
		Status:             status,
		ObservedGeneration: req.Generation,
		Reason:             reason,
		Message:            message,
	}, l.now())
}

func (l *Lifecycle) transition(phase access.RequestPhase) {
	if l.Telemetry != nil {
		l.Telemetry.Transition(phase)
	}
}

func (l *Lifecycle) now() time.Time {
	if l.Clock != nil {
		return l.Clock()
	}
	return time.Now()
}
