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

// Package profilereadiness evaluates, before an incident, whether this
// manager could activate sessions for an AccessProfile. It neither authorizes
// users nor changes a profile.
package profilereadiness

import (
	"context"
	"errors"
	"fmt"

	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/port"
)

// Reasons reported on the Ready condition.
const (
	ReasonReady                  = "Ready"
	ReasonInvalidRoleReference   = "InvalidRoleReference"
	ReasonInvalidTargetNamespace = "InvalidTargetNamespace"
	ReasonInvalidDuration        = "InvalidDuration"
	ReasonInvalidDeliveryMode    = "InvalidDeliveryMode"
	ReasonNamespaceOutOfScope    = "NamespaceOutOfScope"
	ReasonClusterRoleMissing     = "ClusterRoleMissing"
	ReasonClusterRoleNotReady    = "ClusterRoleNotReady"
	ReasonClusterRoleCheckFailed = "ClusterRoleCheckFailed"
)

// RoleSource reads a curated role directly from the API server;
// port.ErrNotFound if it does not exist.
type RoleSource interface {
	Role(ctx context.Context, name string) (access.Role, error)
}

// Readiness is the evaluated Ready condition.
type Readiness struct {
	Status  access.ConditionStatus
	Reason  string
	Message string
}

// Evaluator evaluates profile readiness.
type Evaluator struct {
	Roles     RoleSource
	Placement access.Placement
}

// Evaluate returns the readiness of the profile. Invalid configuration is
// False without error; a failed role read is Unknown with the error, so the
// caller retries.
func (e Evaluator) Evaluate(ctx context.Context, profile access.Profile) (Readiness, error) {
	switch _, defect := profile.Check(); defect {
	case access.ProfileRoleRefInvalid:
		return notReady(ReasonInvalidRoleReference, "The profile must reference a named curated ClusterRole"), nil
	case access.ProfileTargetNamespaceMissing:
		return notReady(ReasonInvalidTargetNamespace, "The profile must specify a target namespace"), nil
	case access.ProfileTargetIsControlNamespace:
		return notReady(ReasonInvalidTargetNamespace, "The profile must not grant access in its own namespace"), nil
	case access.ProfileMaxDurationInvalid:
		return notReady(ReasonInvalidDuration, "The profile must specify a positive maximum duration"), nil
	case access.ProfileDeliveryModeUnsupported:
		return notReady(ReasonInvalidDeliveryMode, "The profile must specify a supported access delivery mode"), nil
	}
	if err := e.Placement.CheckProfile(profile); err != nil {
		return notReady(ReasonNamespaceOutOfScope, err.Error()), nil
	}

	role, err := e.Roles.Role(ctx, profile.RoleRef.Name)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return notReady(ReasonClusterRoleMissing, fmt.Sprintf("Referenced ClusterRole %q does not exist", profile.RoleRef.Name)), nil
		}
		return Readiness{Status: access.ConditionUnknown, Reason: ReasonClusterRoleCheckFailed, Message: "Could not verify the referenced ClusterRole"}, err
	}
	if role.UID == "" {
		return notReady(ReasonClusterRoleNotReady, fmt.Sprintf("Referenced ClusterRole %q has no server-assigned UID", role.Name)), nil
	}
	return Readiness{Status: access.ConditionTrue, Reason: ReasonReady, Message: "The profile can be activated by this manager"}, nil
}

func notReady(reason, message string) Readiness {
	return Readiness{Status: access.ConditionFalse, Reason: reason, Message: message}
}
