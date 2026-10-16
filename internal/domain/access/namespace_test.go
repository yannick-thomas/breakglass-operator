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

import "testing"

func TestCheckNamespaceDeletionRequiresDrainedControlNamespace(t *testing.T) {
	explicit := Placement{Control: NamespaceScope{controlNS: {}}, Target: NamespaceScope{"production": {}}}
	many := []string{"s7", "s6", "s5", "s4", "s3", "s2", "s1"}
	for _, tc := range []struct {
		name        string
		placement   Placement
		namespace   string
		terminating bool
		sessions    []string
		wantErr     string
	}{
		{name: "drained control namespace", placement: explicit, namespace: controlNS},
		{name: "session left", placement: explicit, namespace: controlNS, sessions: []string{"b", "a"},
			wantErr: `control namespace "breakglass-access" still holds 2 BreakGlassSession(s) (a, b); revoke or delete them`},
		{name: "names are bounded", placement: explicit, namespace: controlNS, sessions: many,
			wantErr: "(s1, s2, s3, s4, s5 and 2 more)"},
		{name: "target namespace is not guarded", placement: explicit, namespace: "production", sessions: []string{"a"}},
		{name: "other namespace is not guarded", placement: explicit, namespace: "team-b", sessions: []string{"a"}},
		{name: "development default guards every namespace", placement: Placement{}, namespace: "team-b",
			sessions: []string{"a"}, wantErr: "still holds 1 BreakGlassSession(s)"},
		{name: "already terminating", placement: explicit, namespace: controlNS, terminating: true, sessions: []string{"a"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertErr(t, tc.placement.CheckNamespaceDeletion(tc.namespace, tc.terminating, tc.sessions), tc.wantErr)
		})
	}
}

func TestNamespaceDeletionNeedsDrainOnlyForLiveControlNamespaces(t *testing.T) {
	explicit := Placement{Control: NamespaceScope{controlNS: {}}}
	if !explicit.NamespaceDeletionNeedsDrain(controlNS, false) {
		t.Fatal("a live control namespace must be drained before deletion")
	}
	if explicit.NamespaceDeletionNeedsDrain(controlNS, true) || explicit.NamespaceDeletionNeedsDrain("production", false) {
		t.Fatal("terminating and non-control namespaces need no session read")
	}
}
