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

// Profile is an administrator-owned, immutable access policy. It lives in a
// control namespace and grants in exactly one other namespace.
type Profile struct {
	Name            string
	Namespace       string
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
	ProfileTargetIsControlNamespace
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
	if p.TargetNamespace == p.Namespace {
		return 0, ProfileTargetIsControlNamespace
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
	case ProfileTargetIsControlNamespace:
		return fmt.Errorf("AccessProfile %q must not grant access in its own namespace", p.Name)
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

// Placement separates the control namespaces, which hold access objects, from
// the target namespaces, in which sessions grant access (ADR-004). A person
// who can write access objects must never thereby gain a grant location, and a
// grant must never land where the evidence of other grants is kept.
type Placement struct {
	Control NamespaceScope
	Target  NamespaceScope
}

// Validate rejects a manager configuration that cannot keep control and
// target namespaces apart: explicit target namespaces without explicit
// control namespaces, or a namespace that is both. The all-namespaces
// development default is checked per profile instead.
func (p Placement) Validate() error {
	if p.Target.Explicit() && !p.Control.Explicit() {
		return errors.New("explicit target namespaces require explicit control namespaces")
	}
	if !p.Control.Explicit() || !p.Target.Explicit() {
		return nil
	}
	for namespace := range p.Control {
		if _, ok := p.Target[namespace]; ok {
			return fmt.Errorf("namespace %q must not be both a control and a target namespace", namespace)
		}
	}
	return nil
}

// AllowsControl reports whether access objects may live in the namespace.
func (p Placement) AllowsControl(namespace string) bool {
	return namespace != "" && p.Control.Allows(namespace)
}

// AdmitProfile decides whether a profile may be created. It applies the
// same semantic and placement rules that later decide whether the profile
// may be used, so a profile outside the control namespaces, or one granting
// in a namespace this manager does not serve, is rejected when it is written
// rather than only when someone tries to use it. It returns a denial reason.
func (p Placement) AdmitProfile(profile Profile) error {
	if _, defect := profile.Check(); defect != ProfileValid {
		return profile.DefectError(defect)
	}
	return p.CheckProfile(profile)
}

// CheckProfile decides whether a profile may be used at all: it must live in
// a control namespace and grant in an allowed target namespace that is not a
// control namespace. It returns a denial reason.
func (p Placement) CheckProfile(profile Profile) error {
	if !p.AllowsControl(profile.Namespace) {
		return fmt.Errorf("AccessProfile %q is not in a control namespace of this manager", profile.Name)
	}
	if !p.Target.Allows(profile.TargetNamespace) {
		return fmt.Errorf("AccessProfile %q targets namespace %q outside this manager's allowed namespace set", profile.Name, profile.TargetNamespace)
	}
	if p.Control.Explicit() && p.Control.Allows(profile.TargetNamespace) {
		return fmt.Errorf("AccessProfile %q targets control namespace %q", profile.Name, profile.TargetNamespace)
	}
	return nil
}

// ParsePositiveDuration parses a Go duration that must be greater than zero.
func ParsePositiveDuration(value string) (time.Duration, bool) {
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}
