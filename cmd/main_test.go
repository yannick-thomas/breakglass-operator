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
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/cache"

	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
)

const productionNamespace = "production"

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
