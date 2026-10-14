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

	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/port"
)

// bindingCollisionError means the binding name is held by an object this
// session cannot prove to be its own.
type bindingCollisionError struct{ message string }

func (e *bindingCollisionError) Error() string { return e.message }

// IsBindingCollision reports whether err is a refused name collision.
func IsBindingCollision(err error) bool {
	var collision *bindingCollisionError
	return errors.As(err, &collision)
}

// CleanupResult reports what a cleanup did.
type CleanupResult struct {
	Deleted bool
	// Issue is set when the binding could not be safely removed, for example
	// because a replacement object now uses its name.
	Issue *access.Issue
}

// ReserveBinding creates the session's binding without subjects. It is a
// durable, non-authorizing reservation: its UID must be persisted before the
// subject may be added. An existing binding is recovered only if it is this
// session's exact reservation.
func (l *Lifecycle) ReserveBinding(ctx context.Context, s *access.Session) (*access.BindingRef, error) {
	expected := s.ExpectedBindingRef()
	if expected.Namespace == "" || s.Status.Grant == nil {
		return nil, errors.New("cannot reserve a binding without a resolved namespaced AccessProfile grant")
	}
	created, err := l.Bindings.Create(ctx, BindingDraft{
		Name:      expected.Name,
		Namespace: expected.Namespace,
		Labels:    s.ManagedLabels(),
		Owner:     access.SessionOwner{Name: s.Name, UID: s.UID},
		RoleRef:   s.ExpectedRoleRef(),
	})
	if err == nil {
		l.telemetry().BindingOperation(OperationReserve, true, s)
		return created.Ref()
	}
	if !errors.Is(err, port.ErrAlreadyExists) {
		l.telemetry().BindingOperation(OperationReserve, false, s)
		return nil, err
	}

	existing, err := l.Bindings.Get(ctx, expected.Namespace, expected.Name)
	if err != nil {
		l.telemetry().BindingOperation(OperationReserve, false, s)
		return nil, err
	}
	if issue := s.CheckReservedBinding(existing); issue != nil {
		l.telemetry().BindingOperation(OperationReserve, false, s)
		return nil, &bindingCollisionError{message: fmt.Sprintf("refusing to adopt existing RoleBinding %s/%s: %s", existing.Namespace, existing.Name, issue.Code)}
	}
	l.telemetry().BindingOperation(OperationRecoverReservation, true, s)
	return existing.Ref()
}

// CleanupBinding deletes only a binding whose ownership is proven. Normally
// that proof is the UID recorded at reservation. The only unrecorded recovery
// permitted is an empty-subject reservation, which cannot authorize access; a
// live binding is never removed without its persisted UID.
//
// For a legacy active session it may record a discovered binding reference on
// s; the caller persists it with its next status write.
func (l *Lifecycle) CleanupBinding(ctx context.Context, s *access.Session) (CleanupResult, error) {
	ref := s.Status.BindingRef
	unrecorded := false
	if ref == nil {
		// Recover a narrow empty-subject reservation left by a failed status
		// checkpoint. This never adopts an authorizing binding.
		recovered, issue, err := l.findUnrecordedReservation(ctx, s)
		if err != nil {
			return CleanupResult{}, err
		}
		if issue != nil {
			return CleanupResult{Issue: issue}, nil
		}
		if recovered != nil {
			ref = recovered
			unrecorded = true
		}
	}

	if ref == nil {
		// A never-activated session has nothing to clean up. A legacy active
		// session with a secure grant gets the strict one-way reference
		// migration; a free-form pre-profile session is never guessed at.
		if s.Status.StartTime == nil && s.Status.ExpiresAt == nil {
			return CleanupResult{}, nil
		}
		if s.Status.Grant == nil {
			return CleanupResult{Issue: access.BindingReferenceInvalid("active session has no secure profile snapshot or binding identity")}, nil
		}
		discovered, issue, err := l.discoverBindingRef(ctx, s)
		if err != nil {
			return CleanupResult{}, err
		}
		if issue != nil {
			return CleanupResult{Issue: issue}, nil
		}
		s.Status.BindingRef = discovered
		s.Status.BindingName = discovered.Name
		ref = discovered
	}

	if ref.UID == "" || (!unrecorded && !s.RecordedRefIsConsistent(ref)) {
		return CleanupResult{Issue: access.BindingReferenceInvalid("the recorded emergency access binding identity is invalid")}, nil
	}

	binding, err := l.getBinding(ctx, ref)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return CleanupResult{Issue: access.BindingMissing()}, nil
		}
		if errors.Is(err, port.ErrForbidden) && l.NamespaceConfirmedAbsent(ctx, ref.Namespace) {
			return CleanupResult{}, nil
		}
		return CleanupResult{}, err
	}
	if binding.UID != ref.UID {
		l.telemetry().BindingOperation(OperationCleanup, false, s)
		return CleanupResult{Issue: access.BindingUIDMismatch()}, nil
	}

	if err := l.Bindings.Delete(ctx, *ref); err != nil {
		switch {
		case errors.Is(err, port.ErrForbidden) && l.NamespaceConfirmedAbsent(ctx, ref.Namespace):
			return CleanupResult{}, nil
		case errors.Is(err, port.ErrNotFound):
			return CleanupResult{Issue: access.BindingMissing()}, nil
		case errors.Is(err, port.ErrConflict):
			l.telemetry().BindingOperation(OperationCleanup, false, s)
			return CleanupResult{Issue: access.BindingChangedBeforeDelete()}, nil
		default:
			l.telemetry().BindingOperation(OperationCleanup, false, s)
			return CleanupResult{}, err
		}
	}
	l.telemetry().BindingOperation(OperationCleanup, true, s)
	return CleanupResult{Deleted: true}, nil
}

// NamespaceConfirmedAbsent is a narrow recovery for namespaced RBAC that
// disappeared with its namespace. Forbidden alone, or a terminating
// namespace, is never evidence of cleanup; only a direct NotFound for a
// namespace this manager explicitly serves is. A recreated namespace fails
// closed.
func (l *Lifecycle) NamespaceConfirmedAbsent(ctx context.Context, namespace string) bool {
	if _, explicit := l.Scope[namespace]; !explicit {
		return false
	}
	return l.Policy.NamespaceAbsent(ctx, namespace)
}

// findUnrecordedReservation discovers only an empty-subject reservation made
// in the window between creating it and persisting its UID. The namespace
// cannot be recovered from blank status, so the high-entropy session UID label
// is searched and the deterministic name and owner reference corroborate it.
// A namespaced manager searches only its configured namespaces and needs no
// broader binding permissions than the grant path itself.
//
// The result is not written back: callers use it only for an immediate
// UID-precondition cleanup on a terminal path.
func (l *Lifecycle) findUnrecordedReservation(ctx context.Context, s *access.Session) (*access.BindingRef, *access.Issue, error) {
	if !s.MayHaveUnrecordedReservation() {
		return nil, nil, nil
	}
	labels := s.ManagedLabels()
	var bindings []access.Binding
	if !l.Scope.Explicit() {
		found, err := l.Bindings.ListManaged(ctx, "", labels)
		if err != nil {
			return nil, nil, err
		}
		bindings = found
	} else {
		for namespace := range l.Scope {
			found, err := l.Bindings.ListManaged(ctx, namespace, labels)
			if err != nil {
				if errors.Is(err, port.ErrForbidden) && l.NamespaceConfirmedAbsent(ctx, namespace) {
					continue
				}
				return nil, nil, err
			}
			bindings = append(bindings, found...)
		}
	}

	var matching []*access.BindingRef
	for _, binding := range bindings {
		if !s.IsUnrecordedReservation(binding) {
			continue
		}
		ref, err := binding.Ref()
		if err != nil {
			return nil, access.BindingReferenceInvalid("a managed emergency access binding has no server-assigned UID"), nil
		}
		matching = append(matching, ref)
	}
	switch len(matching) {
	case 0:
		return nil, nil, nil
	case 1:
		return matching[0], nil, nil
	default:
		return nil, access.BindingReferenceInvalid("multiple managed RoleBindings match an unrecorded emergency access session"), nil
	}
}
