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
	"strings"
	"testing"
)

const productionNamespace = "production"

func TestParseAllowedTargetNamespaces(t *testing.T) {
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
		{name: "rejects empty item", value: "production,,staging", wantErr: "empty namespace"},
		{name: "rejects invalid namespace", value: "Production", wantErr: "invalid namespace"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseAllowedTargetNamespaces(test.value)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("parseAllowedTargetNamespaces(%q) error = %v, want substring %q", test.value, err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAllowedTargetNamespaces(%q) error = %v", test.value, err)
			}
			if len(got) != len(test.want) {
				t.Fatalf("parseAllowedTargetNamespaces(%q) = %#v, want %#v", test.value, got, test.want)
			}
			for namespace := range test.want {
				if _, ok := got[namespace]; !ok {
					t.Fatalf("parseAllowedTargetNamespaces(%q) = %#v, missing %q", test.value, got, namespace)
				}
			}
		})
	}
}
