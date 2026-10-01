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

// manifestcheck verifies security invariants in rendered installation manifests.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

const (
	defaultProfile    = "default"
	productionProfile = "production"
	namespacedProfile = "production-namespaced"

	managerName      = "breakglass-operator-controller-manager"
	managerNamespace = "breakglass-operator-system"
	managerRoleName  = "breakglass-operator-manager-role"
	roleBindingRule  = "rolebindings"
)

func main() {
	profile := flag.String("profile", "", "rendered manifest profile to verify")
	flag.Parse()
	if err := validateProfile(*profile, os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, "manifest verification failed:", err)
		os.Exit(1)
	}
}

func validateProfile(profile string, input io.Reader) error {
	if profile != defaultProfile && profile != productionProfile && profile != namespacedProfile {
		return fmt.Errorf("unsupported profile %q", profile)
	}

	objects, err := decodeObjects(input)
	if err != nil {
		return err
	}
	if err := verifyWebhookSecurity(objects); err != nil {
		return err
	}
	if err := verifyRequiredCRDs(objects); err != nil {
		return err
	}
	if err := verifyManagerPodSecurity(objects); err != nil {
		return err
	}
	if profile == defaultProfile {
		return nil
	}
	if err := verifyProductionAvailability(objects); err != nil {
		return err
	}
	if profile == namespacedProfile {
		return verifyNamespacedRBACBoundary(objects)
	}
	return nil
}

func verifyRequiredCRDs(objects []unstructured.Unstructured) error {
	for _, name := range []string{
		"accessprofiles.access.breakglass.io",
		"breakglassrequests.access.breakglass.io",
		"breakglassapprovals.access.breakglass.io",
		"breakglasssessions.access.breakglass.io",
	} {
		if _, err := requiredObject(objects, "CustomResourceDefinition", name); err != nil {
			return fmt.Errorf("required BreakGlass CRD missing: %w", err)
		}
	}
	return nil
}

func decodeObjects(input io.Reader) ([]unstructured.Unstructured, error) {
	decoder := utilyaml.NewYAMLOrJSONDecoder(input, 4096)
	var objects []unstructured.Unstructured
	for {
		var raw map[string]any
		err := decoder.Decode(&raw)
		if errors.Is(err, io.EOF) {
			return objects, nil
		}
		if err != nil {
			return nil, fmt.Errorf("decode manifest: %w", err)
		}
		if len(raw) != 0 {
			objects = append(objects, unstructured.Unstructured{Object: raw})
		}
	}
}

func verifyWebhookSecurity(objects []unstructured.Unstructured) error {
	service, err := requiredObjectInNamespace(objects, "Service", "breakglass-operator-webhook-service", managerNamespace)
	if err != nil {
		return err
	}
	certificate, err := requiredObjectInNamespace(
		objects, "Certificate", "breakglass-operator-serving-cert", managerNamespace,
	)
	if err != nil {
		return err
	}
	wantCAReference := certificate.GetNamespace() + "/" + certificate.GetName()
	for _, configuration := range []struct {
		kind string
		name string
	}{
		{kind: "MutatingWebhookConfiguration", name: "breakglass-operator-mutating-webhook-configuration"},
		{kind: "ValidatingWebhookConfiguration", name: "breakglass-operator-validating-webhook-configuration"},
	} {
		webhook, err := requiredObject(objects, configuration.kind, configuration.name)
		if err != nil {
			return err
		}
		annotations := webhook.GetAnnotations()
		if annotations["cert-manager.io/inject-ca-from"] != wantCAReference {
			return fmt.Errorf("%s must request cert-manager CA injection", configuration.kind)
		}
		webhooks, found, err := unstructured.NestedSlice(webhook.Object, "webhooks")
		if err != nil || !found || len(webhooks) == 0 {
			return fmt.Errorf("%s must contain webhooks", configuration.kind)
		}
		for _, item := range webhooks {
			webhookSpec, ok := item.(map[string]any)
			if !ok || webhookSpec["failurePolicy"] != "Fail" {
				return fmt.Errorf("every %s webhook must use failurePolicy: Fail", configuration.kind)
			}
			if webhookSpec["sideEffects"] != "None" {
				return fmt.Errorf("every %s webhook must declare sideEffects: None", configuration.kind)
			}
			serviceName, _, _ := unstructured.NestedString(webhookSpec, "clientConfig", "service", "name")
			serviceNamespace, _, _ := unstructured.NestedString(webhookSpec, "clientConfig", "service", "namespace")
			if serviceName != service.GetName() || serviceNamespace != service.GetNamespace() {
				return fmt.Errorf("every %s webhook must target the rendered webhook Service", configuration.kind)
			}
		}
	}
	return nil
}

func verifyManagerPodSecurity(objects []unstructured.Unstructured) error {
	manager, err := requiredObject(objects, "Deployment", managerName)
	if err != nil {
		return err
	}
	runAsNonRoot, _, _ := unstructured.NestedBool(
		manager.Object, "spec", "template", "spec", "securityContext", "runAsNonRoot",
	)
	seccompType, _, _ := unstructured.NestedString(
		manager.Object, "spec", "template", "spec", "securityContext", "seccompProfile", "type",
	)
	if !runAsNonRoot || seccompType != "RuntimeDefault" {
		return fmt.Errorf("manager pod must use runAsNonRoot and RuntimeDefault seccomp")
	}
	container, found := namedContainer(manager, "manager")
	if !found {
		return fmt.Errorf("manager Deployment must contain a manager container")
	}
	readOnlyRootFilesystem, _, _ := unstructured.NestedBool(container, "securityContext", "readOnlyRootFilesystem")
	allowPrivilegeEscalation, _, _ := unstructured.NestedBool(container, "securityContext", "allowPrivilegeEscalation")
	dropCapabilities, _, _ := unstructured.NestedStringSlice(container, "securityContext", "capabilities", "drop")
	if !readOnlyRootFilesystem || allowPrivilegeEscalation || !containsString(dropCapabilities, "ALL") {
		return fmt.Errorf("manager container must be restricted and drop all capabilities")
	}
	return nil
}

func verifyProductionAvailability(objects []unstructured.Unstructured) error {
	manager, err := requiredObject(objects, "Deployment", managerName)
	if err != nil {
		return err
	}
	replicas, found, err := unstructured.NestedFieldNoCopy(manager.Object, "spec", "replicas")
	if err != nil || !found || !hasIntValue(replicas, 2) {
		return fmt.Errorf("manager Deployment must have exactly two replicas")
	}
	constraints, found, err := unstructured.NestedSlice(
		manager.Object, "spec", "template", "spec", "topologySpreadConstraints",
	)
	if err != nil || !found || !hasHostnameSpreadConstraint(constraints) {
		return fmt.Errorf("manager Deployment must spread replicas across hostnames with DoNotSchedule")
	}

	pdb, err := requiredObject(objects, "PodDisruptionBudget", managerName)
	if err != nil {
		return err
	}
	minAvailable, found, err := unstructured.NestedFieldNoCopy(pdb.Object, "spec", "minAvailable")
	if err != nil || !found || !hasIntValue(minAvailable, 1) {
		return fmt.Errorf("manager PodDisruptionBudget must set minAvailable: 1")
	}
	return nil
}

func hasHostnameSpreadConstraint(constraints []any) bool {
	for _, item := range constraints {
		constraint, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if constraint["topologyKey"] == "kubernetes.io/hostname" &&
			constraint["whenUnsatisfiable"] == "DoNotSchedule" &&
			hasIntValue(constraint["maxSkew"], 1) {
			return true
		}
	}
	return false
}

func hasIntValue(value any, expected int64) bool {
	switch number := value.(type) {
	case int:
		return int64(number) == expected
	case int64:
		return number == expected
	case float64:
		return number == float64(expected)
	default:
		return false
	}
}

func verifyNamespacedRBACBoundary(objects []unstructured.Unstructured) error {
	managerRole, err := requiredObject(objects, "ClusterRole", managerRoleName)
	if err != nil {
		return err
	}
	if roleHasResource(managerRole, roleBindingRule) {
		return fmt.Errorf("manager ClusterRole must not grant cluster-wide RoleBinding access")
	}
	if !roleHasNamedClusterRoleBind(managerRole) {
		return fmt.Errorf("manager ClusterRole must retain the scoped curated-role bind permission")
	}

	role, err := requiredObjectInNamespace(objects, "Role", "breakglass-operator-manager-rolebindings", "production")
	if err != nil {
		return err
	}
	if !roleHasExactRoleBindingVerbs(role) {
		return fmt.Errorf("production Role must grant only the required RoleBinding verbs")
	}
	if err := verifyManagerRoleBinding(objects); err != nil {
		return err
	}

	manager, err := requiredObject(objects, "Deployment", managerName)
	if err != nil {
		return err
	}
	container, found := namedContainer(manager, "manager")
	if !found {
		return fmt.Errorf("manager Deployment must contain a manager container")
	}
	if allowedTargetNamespaceArguments(container) == 1 {
		return nil
	}
	return fmt.Errorf("manager Deployment must restrict allowed target namespaces to production")
}

func namedContainer(deployment unstructured.Unstructured, name string) (map[string]any, bool) {
	containers, found, err := unstructured.NestedSlice(deployment.Object, "spec", "template", "spec", "containers")
	if err != nil || !found {
		return nil, false
	}
	for _, item := range containers {
		container, ok := item.(map[string]any)
		if ok && container["name"] == name {
			return container, true
		}
	}
	return nil, false
}

func allowedTargetNamespaceArguments(container map[string]any) int {
	args := stringValues(container["args"])
	count := 0
	for _, arg := range args {
		if arg == "--allowed-target-namespaces=production" {
			count++
		}
		isAllowedTargetNamespaceArgument := len(arg) >= len("--allowed-target-namespaces=") &&
			arg[:len("--allowed-target-namespaces=")] == "--allowed-target-namespaces="
		if isAllowedTargetNamespaceArgument && arg != "--allowed-target-namespaces=production" {
			return 0
		}
	}
	return count
}

func verifyManagerRoleBinding(objects []unstructured.Unstructured) error {
	binding, err := requiredObjectInNamespace(
		objects, "RoleBinding", "breakglass-operator-manager-rolebindings", "production",
	)
	if err != nil {
		return err
	}
	roleRefName, _, _ := unstructured.NestedString(binding.Object, "roleRef", "name")
	roleRefKind, _, _ := unstructured.NestedString(binding.Object, "roleRef", "kind")
	if roleRefKind != "Role" || roleRefName != "breakglass-operator-manager-rolebindings" {
		return fmt.Errorf("production manager RoleBinding must reference its local Role")
	}
	subjects, found, err := unstructured.NestedSlice(binding.Object, "subjects")
	if err != nil || !found || len(subjects) != 1 {
		return fmt.Errorf("production manager RoleBinding must have exactly one ServiceAccount subject")
	}
	subject, ok := subjects[0].(map[string]any)
	if !ok || subject["kind"] != "ServiceAccount" ||
		subject["name"] != managerName || subject["namespace"] != managerNamespace {
		return fmt.Errorf("production manager RoleBinding must bind the manager ServiceAccount")
	}
	return nil
}

func roleHasResource(role unstructured.Unstructured, resource string) bool {
	rules, _, _ := unstructured.NestedSlice(role.Object, "rules")
	for _, item := range rules {
		rule, ok := item.(map[string]any)
		if ok && (containsString(rule["resources"], resource) || containsString(rule["resources"], "*")) {
			return true
		}
	}
	return false
}

func roleHasNamedClusterRoleBind(role unstructured.Unstructured) bool {
	rules, _, _ := unstructured.NestedSlice(role.Object, "rules")
	for _, item := range rules {
		rule, ok := item.(map[string]any)
		if ok && containsString(rule["resources"], "clusterroles") &&
			containsString(rule["verbs"], "bind") && len(stringValues(rule["resourceNames"])) > 0 {
			return true
		}
	}
	return false
}

func roleHasExactRoleBindingVerbs(role unstructured.Unstructured) bool {
	for _, item := range nestedRules(role) {
		if containsString(item["resources"], roleBindingRule) {
			return sameStrings(stringValues(item["verbs"]), []string{"create", "delete", "get", "list", "update", "watch"})
		}
	}
	return false
}

func nestedRules(role unstructured.Unstructured) []map[string]any {
	rules, _, _ := unstructured.NestedSlice(role.Object, "rules")
	result := make([]map[string]any, 0, len(rules))
	for _, item := range rules {
		if rule, ok := item.(map[string]any); ok {
			result = append(result, rule)
		}
	}
	return result
}

func containsString(value any, expected string) bool {
	return slices.Contains(stringValues(value), expected)
}

func stringValues(value any) []string {
	if strings, ok := value.([]string); ok {
		return strings
	}
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func sameStrings(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	seen := make(map[string]bool, len(actual))
	for _, value := range actual {
		seen[value] = true
	}
	for _, value := range expected {
		if !seen[value] {
			return false
		}
	}
	return true
}

func requiredObject(objects []unstructured.Unstructured, kind, name string) (unstructured.Unstructured, error) {
	for _, object := range objects {
		if object.GetKind() == kind && object.GetName() == name {
			return object, nil
		}
	}
	return unstructured.Unstructured{}, fmt.Errorf("required %s %q is missing", kind, name)
}

func requiredObjectInNamespace(
	objects []unstructured.Unstructured,
	kind, name, namespace string,
) (unstructured.Unstructured, error) {
	object, err := requiredObject(objects, kind, name)
	if err != nil {
		return unstructured.Unstructured{}, err
	}
	if object.GetNamespace() != namespace {
		return unstructured.Unstructured{}, fmt.Errorf("%s %q must be in namespace %q", kind, name, namespace)
	}
	return object, nil
}
