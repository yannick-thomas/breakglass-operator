package main

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestNamespaceObservationMustBeNarrow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		field  string
		values []string
		want   bool
	}{
		{"exact", "verbs", []string{"get"}, true},
		{"no name constraint", "resourceNames", nil, false},
		{"different name", "resourceNames", []string{"other"}, false},
		{"list", "verbs", []string{"get", "list"}, false},
		{"writes", "verbs", []string{"get", "delete"}, false},
		{"all verbs", "verbs", []string{"*"}, false},
		{"all resources", "resources", []string{"*"}, false},
		{"all groups", "apiGroups", []string{"*"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := map[string]any{
				"apiGroups": []any{""}, "resources": []any{"namespaces"},
				"resourceNames": []any{"production"}, "verbs": []any{"get"},
			}
			if err := unstructured.SetNestedStringSlice(rule, tc.values, tc.field); err != nil {
				t.Fatal(err)
			}
			role := unstructured.Unstructured{Object: map[string]any{"rules": []any{rule}}}
			if got := roleHasExactNamespaceObservation(role); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
