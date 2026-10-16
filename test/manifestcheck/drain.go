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

import (
	"fmt"
	"reflect"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	validatingWebhookKind          = "ValidatingWebhookConfiguration"
	validatingWebhookConfiguration = "breakglass-operator-validating-webhook-configuration"
	controlNamespaceWebhook        = "vcontrolnamespace-v1.kb.io"
	controlNamespaceLabel          = "access.breakglass.io/control-namespace"
)

// verifyWebhookSelectors keeps admission of access objects unconditional and
// scopes the fail-closed control-namespace drain check (ADR-004) to control
// namespaces. Profiles with explicit control namespaces must select exactly
// those names; the all-namespaces profiles select the opt-in label.
func verifyWebhookSelectors(objects []unstructured.Unstructured, profile string) error {
	drainChecks := 0
	for _, kind := range []string{"MutatingWebhookConfiguration", validatingWebhookKind} {
		for _, configuration := range objects {
			if configuration.GetKind() != kind {
				continue
			}
			webhooks, _, _ := unstructured.NestedSlice(configuration.Object, "webhooks")
			for _, item := range webhooks {
				webhook, ok := item.(map[string]any)
				if !ok {
					return fmt.Errorf("%s contains a malformed webhook", kind)
				}
				if _, exists := webhook["objectSelector"]; exists {
					return fmt.Errorf("%s webhook %v must not use an objectSelector", kind, webhook["name"])
				}
				if webhook["name"] != controlNamespaceWebhook {
					if _, exists := webhook["namespaceSelector"]; exists {
						return fmt.Errorf("%s webhook %v must not use a namespaceSelector", kind, webhook["name"])
					}
					continue
				}
				if kind != validatingWebhookKind || configuration.GetName() != validatingWebhookConfiguration {
					return fmt.Errorf("control-namespace drain check must be a validating webhook")
				}
				if err := verifyDrainCheck(webhook, profile); err != nil {
					return err
				}
				drainChecks++
			}
		}
	}
	if drainChecks != 1 {
		return fmt.Errorf("exactly one control-namespace drain check is required, found %d", drainChecks)
	}
	return nil
}

func verifyDrainCheck(webhook map[string]any, profile string) error {
	wantRules := []any{map[string]any{
		"apiGroups": []any{""}, "apiVersions": []any{"v1"}, "operations": []any{"DELETE"},
		"resources": []any{namespaceRule}, "scope": "Cluster",
	}}
	if !reflect.DeepEqual(webhook["rules"], wantRules) {
		return fmt.Errorf("control-namespace drain check must match only Namespace DELETE with scope Cluster")
	}
	if webhook["failurePolicy"] != "Fail" || webhook["sideEffects"] != "None" ||
		!hasIntValue(webhook["timeoutSeconds"], 5) {
		return fmt.Errorf("control-namespace drain check must fail closed with a 5s timeout")
	}
	wantSelector := map[string]any{"matchLabels": map[string]any{controlNamespaceLabel: "true"}}
	if profile == namespacedProfile {
		wantSelector = map[string]any{"matchExpressions": []any{map[string]any{
			"key": "kubernetes.io/metadata.name", "operator": "In", "values": []any{controlNamespace},
		}}}
	}
	if !reflect.DeepEqual(webhook["namespaceSelector"], wantSelector) {
		return fmt.Errorf("control-namespace drain check must select exactly the control namespaces for profile %q", profile)
	}
	return nil
}
