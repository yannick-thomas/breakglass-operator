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

package sessionlifecycle

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/port"
)

// deniedError marks a semantic failure that is persisted as Denied instead of
// retried. Connectivity failures are not wrapped and stay retryable.
type deniedError struct{ err error }

func (e *deniedError) Error() string { return e.err.Error() }
func (e *deniedError) Unwrap() error { return e.err }

func denied(err error) error { return &deniedError{err: err} }

// IsDenied reports whether err is a policy denial rather than a transient
// failure.
func IsDenied(err error) bool {
	var d *deniedError
	return errors.As(err, &d)
}

// ResolveGrant validates the session against its profile and curated role and
// returns the immutable snapshot used for the whole session. The profile UID
// is checked in addition to its name, so delete and recreate cannot change
// what a request was authorized for.
func (l *Lifecycle) ResolveGrant(ctx context.Context, s *access.Session) (*access.Grant, time.Duration, error) {
	duration, err := access.ValidateSessionSpec(s.Spec, l.MaxSessionDuration)
	if err != nil {
		return nil, 0, denied(err)
	}
	profile, err := l.Policy.Profile(ctx, s.Spec.AccessProfile)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, 0, denied(fmt.Errorf("AccessProfile %q does not exist", s.Spec.AccessProfile))
		}
		return nil, 0, err
	}
	if err := access.CheckProfileForSession(s.Spec, duration, profile, l.placement()); err != nil {
		return nil, 0, denied(err)
	}
	role, err := l.Policy.Role(ctx, profile.RoleRef.Name)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, 0, denied(fmt.Errorf("curated ClusterRole %q does not exist", profile.RoleRef.Name))
		}
		return nil, 0, err
	}
	if role.UID == "" {
		return nil, 0, denied(fmt.Errorf("curated ClusterRole %q has no server-assigned UID", role.Name))
	}
	grant := access.NewGrant(profile, role)
	return &grant, duration, nil
}

// verifyProfile confirms that the grant still refers to precisely the
// immutable policy it was authorized against.
func (l *Lifecycle) verifyProfile(ctx context.Context, s *access.Session) (*access.Issue, error) {
	if issue := s.ProfileSnapshotIssue(); issue != nil {
		return issue, nil
	}
	profile, err := l.Policy.Profile(ctx, s.Status.Grant.AccessProfile)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return access.ProfileMissing(), nil
		}
		return nil, err
	}
	return s.ProfileIssue(profile, l.placement()), nil
}

// VerifyCuratedRole reads the curated role directly on every integrity check.
// This avoids a broad ClusterRole watch: role names are profile-controlled and
// stay explicitly enumerated in the manager's RBAC.
func (l *Lifecycle) VerifyCuratedRole(ctx context.Context, s *access.Session) (*access.Issue, error) {
	if issue := s.RoleSnapshotIssue(); issue != nil {
		return issue, nil
	}
	role, err := l.Policy.Role(ctx, s.Status.Grant.RoleRef.Name)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return access.RoleMissing(), nil
		}
		return nil, err
	}
	return s.RoleIssue(role), nil
}

// verifyRequestSource re-checks every persisted link in the approval path
// with direct reads. It runs before a request-sourced session first creates a
// binding and on every later integrity check.
func (l *Lifecycle) verifyRequestSource(ctx context.Context, s *access.Session) (*access.Issue, error) {
	if issue := s.SourceReferenceIssue(); issue != nil {
		return issue, nil
	}
	request, err := l.Policy.Request(ctx, s.Spec.RequestRef.Name)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return access.SourceRequestMissing(), nil
		}
		return nil, err
	}
	if issue := s.SourceRequestIssue(request, l.now()); issue != nil {
		return issue, nil
	}
	if issue := access.SourceApprovalRefIssue(request); issue != nil {
		return issue, nil
	}
	approval, err := l.Policy.Approval(ctx, request.Status.ApprovalRef.Name)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return access.SourceApprovalMissing(), nil
		}
		return nil, err
	}
	return access.SourceApprovalIssue(request, approval), nil
}

// VerifyBinding checks that the recorded binding still exists with its UID
// and exactly the approved content.
func (l *Lifecycle) VerifyBinding(ctx context.Context, s *access.Session) (*access.Issue, error) {
	ref := s.Status.BindingRef
	if !s.RecordedRefIsConsistent(ref) {
		return access.BindingReferenceInvalid("the recorded emergency access binding identity is invalid"), nil
	}
	binding, err := l.getBinding(ctx, ref)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return access.BindingMissing(), nil
		}
		return nil, err
	}
	if binding.UID != ref.UID {
		return access.BindingUIDMismatch(), nil
	}
	return s.CheckGrantedBinding(binding), nil
}

// bindingForPromotion verifies the recorded UID before the one-way promotion
// of a reservation. If an earlier promotion succeeded but its status write
// failed, the expected subject is already present: that is accepted, so the
// session can become Active without touching a replacement object.
func (l *Lifecycle) bindingForPromotion(ctx context.Context, s *access.Session) (access.Binding, bool, *access.Issue, error) {
	ref := s.Status.BindingRef
	if !s.RecordedRefIsConsistent(ref) {
		return access.Binding{}, false, access.BindingReferenceInvalid("the recorded reserved binding identity is invalid"), nil
	}
	binding, err := l.Bindings.Get(ctx, ref.Namespace, ref.Name)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return access.Binding{}, false, access.BindingMissing(), nil
		}
		return access.Binding{}, false, nil, err
	}
	if binding.UID != ref.UID {
		return access.Binding{}, false, access.BindingUIDMismatch(), nil
	}
	reservationIssue := s.CheckReservedBinding(binding)
	if reservationIssue == nil {
		return binding, false, nil, nil
	}
	if s.CheckGrantedBinding(binding) == nil {
		return binding, true, nil, nil
	}
	return access.Binding{}, false, reservationIssue, nil
}

// discoverBindingRef supports the one-way migration of sessions created by
// earlier releases. It never recreates or adopts an ambiguous object.
func (l *Lifecycle) discoverBindingRef(ctx context.Context, s *access.Session) (*access.BindingRef, *access.Issue, error) {
	binding, err := l.getBinding(ctx, s.ExpectedBindingRef())
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, access.BindingMissing(), nil
		}
		return nil, nil, err
	}
	if issue := s.CheckGrantedBinding(binding); issue != nil {
		return nil, issue, nil
	}
	ref, err := binding.Ref()
	if err != nil {
		return nil, access.BindingReferenceInvalid("the emergency access binding has no server-assigned UID"), nil
	}
	return ref, nil, nil
}

func (l *Lifecycle) getBinding(ctx context.Context, ref *access.BindingRef) (access.Binding, error) {
	if ref == nil {
		return access.Binding{}, errors.New("cannot get a nil RBAC binding reference")
	}
	if ref.Kind != access.RoleBindingKind || ref.Namespace == "" {
		return access.Binding{}, fmt.Errorf("unsupported RBAC binding kind %q", ref.Kind)
	}
	return l.Bindings.Get(ctx, ref.Namespace, ref.Name)
}
