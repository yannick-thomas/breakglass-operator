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
	"fmt"
	"slices"
	"strings"
)

// maxListedSessions bounds the session names quoted in a denial message.
const maxListedSessions = 5

// CheckNamespaceDeletion decides whether a namespace may be deleted. A
// control namespace must be drained first: it may be deleted only while it
// holds no BreakGlassSession (ADR-004).
//
// Every session counts, including one that is already being deleted. A
// session's finalizer is removed only by the manager after it deleted the
// session's RoleBinding, and the manager's rights on sessions may be granted
// by a Role in that very namespace. Namespace deletion would remove that Role
// while the finalizer still holds the session, so the manager could no longer
// finish the cleanup and the namespace would never finish deleting.
//
// A namespace that is already terminating is not blocked again: its deletion
// was admitted before, and a repeated delete request changes nothing.
// Namespaces outside the control namespaces are never blocked. sessions are
// the names of the sessions in the namespace.
func (p Placement) CheckNamespaceDeletion(namespace string, terminating bool, sessions []string) error {
	if !p.NamespaceDeletionNeedsDrain(namespace, terminating) || len(sessions) == 0 {
		return nil
	}
	names := slices.Sorted(slices.Values(sessions))
	listed := strings.Join(names[:min(len(names), maxListedSessions)], ", ")
	if more := len(names) - maxListedSessions; more > 0 {
		listed += fmt.Sprintf(" and %d more", more)
	}
	return fmt.Errorf("control namespace %q still holds %d BreakGlassSession(s) (%s); "+
		"revoke or delete them and wait until they are gone, so the operator can remove their "+
		"RoleBindings, before deleting the namespace", namespace, len(names), listed)
}

// NamespaceDeletionNeedsDrain reports whether CheckNamespaceDeletion depends on
// the namespace's sessions, so adapters read them only when they matter.
func (p Placement) NamespaceDeletionNeedsDrain(namespace string, terminating bool) bool {
	return p.AllowsControl(namespace) && !terminating
}
