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
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ClusterRoleKind is the only role kind a profile may grant: a curated,
// administrator-owned ClusterRole bound in one namespace.
const ClusterRoleKind = "ClusterRole"

// DeliveryMode decides how a profile may be obtained.
type DeliveryMode string

const (
	DeliverySelfService      DeliveryMode = "SelfService"
	DeliveryApprovalRequired DeliveryMode = "ApprovalRequired"
)

// Channel is the path through which a session was requested.
type Channel int

const (
	// ChannelDirect is a self-service session created by its subject.
	ChannelDirect Channel = iota
	// ChannelApproval is a session the request controller created from an
	// independently approved BreakGlassRequest.
	ChannelApproval
)

// RoleRef names the curated role a profile grants.
type RoleRef struct {
	Kind string
	Name string
}

// Profile is an administrator-owned, immutable access policy.
type Profile struct {
	Name            string
	UID             string
	RoleRef         RoleRef
	TargetNamespace string
	MaxDuration     string
	DeliveryMode    DeliveryMode
}

// EffectiveDeliveryMode applies the documented default: an unset mode is
// self-service.
func (p Profile) EffectiveDeliveryMode() DeliveryMode {
	if p.DeliveryMode == "" {
		return DeliverySelfService
	}
	return p.DeliveryMode
}

// Permits reports whether the profile may be obtained through the channel.
func (p Profile) Permits(channel Channel) bool {
	switch channel {
	case ChannelDirect:
		return p.EffectiveDeliveryMode() == DeliverySelfService
	case ChannelApproval:
		return p.EffectiveDeliveryMode() == DeliveryApprovalRequired
	default:
		return false
	}
}

// ProfileDefect is the first semantic problem found in a profile.
type ProfileDefect int

const (
	ProfileValid ProfileDefect = iota
	ProfileRoleRefInvalid
	ProfileTargetNamespaceMissing
	ProfileMaxDurationInvalid
	ProfileDeliveryModeUnsupported
)

// Check validates the profile in a fixed order and returns its maximum
// duration. The duration is valid whenever the defect is ProfileValid or
// ProfileDeliveryModeUnsupported, which lets callers that report delivery-mode
// mismatches separately still use it.
func (p Profile) Check() (time.Duration, ProfileDefect) {
	if p.RoleRef.Kind != ClusterRoleKind || p.RoleRef.Name == "" {
		return 0, ProfileRoleRefInvalid
	}
	if p.TargetNamespace == "" {
		return 0, ProfileTargetNamespaceMissing
	}
	maxDuration, ok := ParsePositiveDuration(p.MaxDuration)
	if !ok {
		return 0, ProfileMaxDurationInvalid
	}
	if mode := p.EffectiveDeliveryMode(); mode != DeliverySelfService && mode != DeliveryApprovalRequired {
		return maxDuration, ProfileDeliveryModeUnsupported
	}
	return maxDuration, ProfileValid
}

// DefectError describes a profile defect for a lifecycle denial.
func (p Profile) DefectError(defect ProfileDefect) error {
	switch defect {
	case ProfileValid:
		return nil
	case ProfileRoleRefInvalid:
		return fmt.Errorf("AccessProfile %q must reference a curated ClusterRole", p.Name)
	case ProfileTargetNamespaceMissing:
		return fmt.Errorf("AccessProfile %q must specify a targetNamespace", p.Name)
	case ProfileMaxDurationInvalid:
		return fmt.Errorf("AccessProfile %q has an invalid positive maxDuration", p.Name)
	default:
		return fmt.Errorf("AccessProfile %q has an unsupported delivery mode", p.Name)
	}
}

// NamespaceScope is the set of namespaces a manager may grant access in. An
// empty scope permits every namespace and is the development default.
type NamespaceScope map[string]struct{}

// Allows reports whether access may be granted in the namespace.
func (s NamespaceScope) Allows(namespace string) bool {
	if len(s) == 0 {
		return true
	}
	_, ok := s[namespace]
	return ok
}

// dnsLabel is the RFC 1123 label syntax of Kubernetes namespace names.
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

const maxNamespaceLength = 63

// ParseNamespaceScope parses a comma-separated namespace list. An empty value
// is the all-namespaces development default.
func ParseNamespaceScope(value string) (NamespaceScope, error) {
	scope := NamespaceScope{}
	if value == "" {
		return scope, nil
	}
	for raw := range strings.SplitSeq(value, ",") {
		namespace := strings.TrimSpace(raw)
		if namespace == "" {
			return nil, errors.New("contains an empty namespace")
		}
		if len(namespace) > maxNamespaceLength || !dnsLabel.MatchString(namespace) {
			return nil, fmt.Errorf("contains invalid namespace %q: must be a lowercase RFC 1123 label of at most %d characters", namespace, maxNamespaceLength)
		}
		scope[namespace] = struct{}{}
	}
	return scope, nil
}

// Explicit reports whether the scope names its namespaces, as opposed to the
// all-namespaces development default.
func (s NamespaceScope) Explicit() bool {
	return len(s) > 0
}

// ParsePositiveDuration parses a Go duration that must be greater than zero.
func ParsePositiveDuration(value string) (time.Duration, bool) {
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}
