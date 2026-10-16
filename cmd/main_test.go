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

package main

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/cache"

	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
)

const productionNamespace = "production"

func TestParseNamespaceFlag(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    map[string]struct{}
		wantErr string
	}{
		{name: "empty permits the development default", want: map[string]struct{}{}},
		{name: "one namespace", value: productionNamespace, want: map[string]struct{}{productionNamespace: {}}},
		{
			name:  "multiple namespaces ignore surrounding whitespace",
			value: productionNamespace + ", staging",
			want:  map[string]struct{}{productionNamespace: {}, "staging": {}},
		},
		{
			name:    "rejects empty item and names the flag",
			value:   "production,,staging",
			wantErr: "allowed-target-namespaces contains an empty namespace",
		},
		{name: "rejects invalid namespace", value: "Production", wantErr: "invalid namespace"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseNamespaceFlag("allowed-target-namespaces", test.value)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("parseNamespaceFlag(%q) error = %v, want substring %q", test.value, err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseNamespaceFlag(%q) error = %v", test.value, err)
			}
			if len(got) != len(test.want) {
				t.Fatalf("parseNamespaceFlag(%q) = %#v, want %#v", test.value, got, test.want)
			}
			for namespace := range test.want {
				if _, ok := got[namespace]; !ok {
					t.Fatalf("parseNamespaceFlag(%q) = %#v, missing %q", test.value, got, namespace)
				}
			}
		})
	}
}

func TestCacheOptionsScopesEachKindToItsRBAC(t *testing.T) {
	placement := access.Placement{
		Control: access.NamespaceScope{"breakglass-control": {}},
		Target:  access.NamespaceScope{productionNamespace: {}, "staging": {}},
	}
	options := cacheOptions(placement)

	control := []string{"breakglass-control"}
	if got := sortedNamespaces(options.DefaultNamespaces); !slices.Equal(got, control) {
		t.Fatalf("DefaultNamespaces = %v, want %v", got, control)
	}
	want := map[string][]string{
		"*v1alpha1.AccessProfile":      control,
		"*v1alpha1.BreakGlassRequest":  control,
		"*v1alpha1.BreakGlassApproval": control,
		"*v1alpha1.BreakGlassSession":  control,
		"*v1.RoleBinding":              {productionNamespace, "staging"},
	}
	assertByObjectNamespaces(t, options, want)
}

func TestCacheOptionsKeepsUnrestrictedTargetsWithExplicitControl(t *testing.T) {
	placement := access.Placement{Control: access.NamespaceScope{"breakglass-control": {}}}
	options := cacheOptions(placement)

	control := []string{"breakglass-control"}
	assertByObjectNamespaces(t, options, map[string][]string{
		"*v1alpha1.AccessProfile":      control,
		"*v1alpha1.BreakGlassRequest":  control,
		"*v1alpha1.BreakGlassApproval": control,
		"*v1alpha1.BreakGlassSession":  control,
		"*v1.RoleBinding":              {cache.AllNamespaces},
	})
}

func TestCacheOptionsDevelopmentDefaultCachesAllNamespaces(t *testing.T) {
	options := cacheOptions(access.Placement{})
	if options.DefaultNamespaces != nil || options.ByObject != nil {
		t.Fatalf("cacheOptions(empty) = %#v, want all-namespaces default", options)
	}
}

func assertByObjectNamespaces(t *testing.T, options cache.Options, want map[string][]string) {
	t.Helper()
	if len(options.ByObject) != len(want) {
		t.Fatalf("ByObject has %d entries, want %d", len(options.ByObject), len(want))
	}
	for object, byObject := range options.ByObject {
		name := fmt.Sprintf("%T", object)
		wantNamespaces, ok := want[name]
		if !ok {
			t.Fatalf("ByObject has unexpected type %s", name)
		}
		if got := sortedNamespaces(byObject.Namespaces); !slices.Equal(got, wantNamespaces) {
			t.Fatalf("ByObject[%s] namespaces = %v, want %v", name, got, wantNamespaces)
		}
	}
}

func sortedNamespaces(configs map[string]cache.Config) []string {
	return slices.Sorted(maps.Keys(configs))
}
