// Copyright 2026.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import "testing"

func drainCheck(profile string) map[string]any {
	selector := map[string]any{"matchLabels": map[string]any{controlNamespaceLabel: "true"}}
	if profile == namespacedProfile {
		selector = map[string]any{"matchExpressions": []any{map[string]any{
			"key": "kubernetes.io/metadata.name", "operator": "In", "values": []any{controlNamespace},
		}}}
	}
	return map[string]any{
		"name": controlNamespaceWebhook, "failurePolicy": "Fail", "sideEffects": "None", "timeoutSeconds": int64(5),
		"namespaceSelector": selector,
		"rules": []any{map[string]any{
			"apiGroups": []any{""}, "apiVersions": []any{"v1"}, "operations": []any{"DELETE"},
			"resources": []any{"namespaces"}, "scope": "Cluster",
		}},
	}
}

func TestDrainCheckMustMatchOnlyControlNamespaceDeletion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile string
		mutate  func(map[string]any)
		wantErr bool
	}{
		{name: "default label", profile: defaultProfile, mutate: func(map[string]any) {}},
		{name: "namespaced names", profile: namespacedProfile, mutate: func(map[string]any) {}},
		{name: "label in namespaced profile", profile: namespacedProfile, mutate: func(w map[string]any) {
			w["namespaceSelector"] = drainCheck(defaultProfile)["namespaceSelector"]
		}, wantErr: true},
		{name: "no selector", profile: defaultProfile, wantErr: true,
			mutate: func(w map[string]any) { delete(w, "namespaceSelector") }},
		{name: "extra name", profile: namespacedProfile, mutate: func(w map[string]any) {
			expressions := w["namespaceSelector"].(map[string]any)["matchExpressions"].([]any)
			expressions[0].(map[string]any)["values"] = []any{controlNamespace, "production"}
		}, wantErr: true},
		{name: "ignore failures", profile: defaultProfile, wantErr: true,
			mutate: func(w map[string]any) { w["failurePolicy"] = "Ignore" }},
		{name: "also updates", profile: defaultProfile, mutate: func(w map[string]any) {
			w["rules"].([]any)[0].(map[string]any)["operations"] = []any{"DELETE", "UPDATE"}
		}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			webhook := drainCheck(tc.profile)
			tc.mutate(webhook)
			if err := verifyDrainCheck(webhook, tc.profile); (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
