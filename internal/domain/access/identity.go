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
	"errors"
	"strings"
)

// SubjectKind is the kind of identity that receives access.
type SubjectKind string

const (
	SubjectKindUser           SubjectKind = "User"
	SubjectKindGroup          SubjectKind = "Group"
	SubjectKindServiceAccount SubjectKind = "ServiceAccount"
)

// Subject identifies a requester, approver, or access recipient.
type Subject struct {
	Kind      SubjectKind
	Name      string
	Namespace string
}

// IsUser reports whether the subject is a named, non-namespaced user.
func (s Subject) IsUser() bool {
	return s.Kind == SubjectKindUser && s.Name != "" && s.Namespace == ""
}

// Is reports whether the subject is exactly the user with the given name.
func (s Subject) Is(username string) bool {
	return s.IsUser() && s.Name == username
}

const serviceAccountUserPrefix = "system:serviceaccount:"

var (
	errNoUsername       = errors.New("authenticated requester has no username")
	errServiceAccount   = errors.New("service account requesters are not supported by self-service BreakGlassSession")
	errAnonymousRequest = errors.New("anonymous requesters are not supported")
)

// ValidateHumanRequester rejects identities that cannot represent a person:
// an empty username, a ServiceAccount, or an anonymous user. Emergency access
// is for people; workloads must never request it for themselves.
func ValidateHumanRequester(username string) error {
	switch {
	case username == "":
		return errNoUsername
	case strings.HasPrefix(username, serviceAccountUserPrefix):
		return errServiceAccount
	case username == "system:anonymous" || username == "system:unauthenticated":
		return errAnonymousRequest
	default:
		return nil
	}
}
