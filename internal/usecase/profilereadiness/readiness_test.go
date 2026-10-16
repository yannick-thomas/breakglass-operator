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

package profilereadiness

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/port"
)

type fakeRoles struct {
	roles map[string]access.Role
	err   error
}

func (f fakeRoles) Role(_ context.Context, name string) (access.Role, error) {
	if f.err != nil {
		return access.Role{}, f.err
	}
	if r, ok := f.roles[name]; ok {
		return r, nil
	}
	return access.Role{}, port.Mark(port.ErrNotFound, fmt.Errorf("role %s", name))
}

func profile() access.Profile {
	return access.Profile{
		Name: "observer", Namespace: "breakglass-access", UID: "uid", RoleRef: access.RoleRef{Kind: access.ClusterRoleKind, Name: "pod-observer"},
		TargetNamespace: "production", MaxDuration: "30m",
	}
}

func TestEvaluate(t *testing.T) {
	existing := fakeRoles{roles: map[string]access.Role{"pod-observer": {Name: "pod-observer", UID: "role-uid"}}}
	for _, tc := range []struct {
		name      string
		mutate    func(*access.Profile)
		roles     fakeRoles
		placement access.Placement
		status    access.ConditionStatus
		reason    string
	}{
		{"ready", func(*access.Profile) {}, existing, access.Placement{}, access.ConditionTrue, ReasonReady},
		{"role kind", func(p *access.Profile) { p.RoleRef.Kind = "Role" }, existing, access.Placement{}, access.ConditionFalse, ReasonInvalidRoleReference},
		{"namespace", func(p *access.Profile) { p.TargetNamespace = "" }, existing, access.Placement{}, access.ConditionFalse, ReasonInvalidTargetNamespace},
		{"duration", func(p *access.Profile) { p.MaxDuration = "forever" }, existing, access.Placement{}, access.ConditionFalse, ReasonInvalidDuration},
		{"mode", func(p *access.Profile) { p.DeliveryMode = "Magic" }, existing, access.Placement{}, access.ConditionFalse, ReasonInvalidDeliveryMode},
		{"own namespace", func(p *access.Profile) { p.TargetNamespace = p.Namespace }, existing, access.Placement{}, access.ConditionFalse, ReasonInvalidTargetNamespace},
		{"scope", func(*access.Profile) {}, existing, access.Placement{Target: access.NamespaceScope{"staging": {}}}, access.ConditionFalse, ReasonNamespaceOutOfScope},
		{"outside control namespaces", func(*access.Profile) {}, existing, access.Placement{Control: access.NamespaceScope{"team-b": {}}}, access.ConditionFalse, ReasonNamespaceOutOfScope},
		{"role missing", func(*access.Profile) {}, fakeRoles{}, access.Placement{}, access.ConditionFalse, ReasonClusterRoleMissing},
		{"role without UID", func(*access.Profile) {}, fakeRoles{roles: map[string]access.Role{"pod-observer": {Name: "pod-observer"}}}, access.Placement{}, access.ConditionFalse, ReasonClusterRoleNotReady},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := profile()
			tc.mutate(&p)
			got, err := Evaluator{Roles: tc.roles, Placement: tc.placement}.Evaluate(context.Background(), p)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got.Status != tc.status || got.Reason != tc.reason {
				t.Fatalf("Evaluate() = %#v, want %s/%s", got, tc.status, tc.reason)
			}
		})
	}
}

func TestEvaluateReportsUnknownOnReadFailure(t *testing.T) {
	got, err := Evaluator{Roles: fakeRoles{err: errors.New("unavailable")}}.Evaluate(context.Background(), profile())
	if err == nil || got.Status != access.ConditionUnknown || got.Reason != ReasonClusterRoleCheckFailed {
		t.Fatalf("Evaluate() = %#v, %v, want Unknown with error for retry", got, err)
	}
}
