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

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	expiryGuardName           = "breakglass-operator-expiry-guard"
	expiryGuardRoleName       = "breakglass-operator-expiry-guard-role"
	expiryGuardNamespacedRole = "breakglass-operator-expiry-guard-rolebindings"
	expiryGuardSessionsRole   = "breakglass-operator-expiry-guard-sessions"
	expiryGuardNamespacesRole = "breakglass-operator-expiry-guard-namespaces"

	verbGet    = "get"
	verbList   = "list"
	verbDelete = "delete"
)

// verifyExpiryGuard checks that the independent expiry guard (SR-06) is
// installed with its own identity, restricted pod security, and nothing but
// read access to sessions, get/list/delete on RoleBindings, and get on
// Namespaces. Listing finds bindings whose session no longer exists; the
// Namespace get, through a ClusterRole that outlives the namespaces, confirms
// that a deleted namespace is absent (ADR-004).
func verifyExpiryGuard(objects []unstructured.Unstructured, namespaced bool) error {
	cronJob, err := requiredObjectInNamespace(objects, "CronJob", expiryGuardName, managerNamespace)
	if err != nil {
		return err
	}
	if policy, _, _ := unstructured.NestedString(cronJob.Object, "spec", "concurrencyPolicy"); policy != "Forbid" {
		return fmt.Errorf("expiry guard CronJob must forbid concurrent runs")
	}
	podSpec, _, _ := unstructured.NestedMap(cronJob.Object, "spec", "jobTemplate", "spec", "template", "spec")
	if podSpec["serviceAccountName"] != expiryGuardName {
		return fmt.Errorf("expiry guard must run with its own ServiceAccount, not the manager's")
	}
	if err := verifyRestrictedPod(podSpec, "expiry-guard"); err != nil {
		return fmt.Errorf("expiry guard: %w", err)
	}

	if err := verifyExpiryGuardNamespaces(objects, namespaced); err != nil {
		return err
	}

	sessionReads := guardRule{"access.breakglass.io", "breakglasssessions", []string{verbGet, verbList}}
	bindingWrites := guardRule{"rbac.authorization.k8s.io", roleBindingRule, []string{verbGet, verbList, verbDelete}}
	clusterRole, clusterRoleErr := requiredObject(objects, "ClusterRole", expiryGuardRoleName)
	if !namespaced {
		if clusterRoleErr != nil {
			return clusterRoleErr
		}
		if !rulesAreExactly(clusterRole, []guardRule{sessionReads, bindingWrites}) {
			return fmt.Errorf("expiry guard ClusterRole must grant only session reads and RoleBinding get/list/delete")
		}
		return nil
	}
	// A namespaced installation reads sessions either cluster-wide (Kustomize)
	// or only in the control namespace (Helm), never both and never more.
	if clusterRoleErr == nil {
		if !rulesAreExactly(clusterRole, []guardRule{sessionReads}) {
			return fmt.Errorf("expiry guard ClusterRole must grant only session reads")
		}
	} else {
		sessions, err := requiredObjectInNamespace(objects, "Role", expiryGuardSessionsRole, controlNamespace)
		if err != nil {
			return err
		}
		if !rulesAreExactly(sessions, []guardRule{sessionReads}) {
			return fmt.Errorf("control-namespace expiry guard Role must grant only session reads")
		}
	}

	role, err := requiredObjectInNamespace(objects, "Role", expiryGuardNamespacedRole, "production")
	if err != nil {
		return err
	}
	if !rulesAreExactly(role, []guardRule{bindingWrites}) {
		return fmt.Errorf("production expiry guard Role must grant only RoleBinding get/list/delete")
	}
	containers, _, _ := unstructured.NestedSlice(podSpec, "containers")
	if len(containers) != 1 {
		return fmt.Errorf("expiry guard must have exactly one container")
	}
	container, _ := containers[0].(map[string]any)
	if allowedTargetNamespaceArguments(container) != 1 {
		return fmt.Errorf("expiry guard must restrict allowed target namespaces to production")
	}
	if controlNamespaceArguments(container) != 1 {
		return fmt.Errorf("expiry guard must restrict control namespaces to %s", controlNamespace)
	}
	return nil
}

type guardRule struct {
	group    string
	resource string
	verbs    []string
}

func rulesAreExactly(role unstructured.Unstructured, want []guardRule) bool {
	rules := nestedRules(role)
	if len(rules) != len(want) {
		return false
	}
	for i, rule := range rules {
		if !sameStrings(stringValues(rule["apiGroups"]), []string{want[i].group}) ||
			!sameStrings(stringValues(rule["resources"]), []string{want[i].resource}) ||
			!sameStrings(stringValues(rule["verbs"]), want[i].verbs) ||
			len(stringValues(rule["resourceNames"])) > 0 {
			return false
		}
	}
	return true
}

func verifyRestrictedPod(podSpec map[string]any, containerName string) error {
	runAsNonRoot, _, _ := unstructured.NestedBool(podSpec, "securityContext", "runAsNonRoot")
	seccompType, _, _ := unstructured.NestedString(podSpec, "securityContext", "seccompProfile", "type")
	if !runAsNonRoot || seccompType != "RuntimeDefault" {
		return fmt.Errorf("pod must use runAsNonRoot and RuntimeDefault seccomp")
	}
	containers, _, _ := unstructured.NestedSlice(podSpec, "containers")
	for _, item := range containers {
		container, ok := item.(map[string]any)
		if !ok || container["name"] != containerName {
			continue
		}
		readOnlyRootFilesystem, _, _ := unstructured.NestedBool(container, "securityContext", "readOnlyRootFilesystem")
		allowPrivilegeEscalation, _, _ := unstructured.NestedBool(container, "securityContext", "allowPrivilegeEscalation")
		dropCapabilities, _, _ := unstructured.NestedStringSlice(container, "securityContext", "capabilities", "drop")
		if !readOnlyRootFilesystem || allowPrivilegeEscalation || !containsString(dropCapabilities, "ALL") {
			return fmt.Errorf("container %q must be restricted and drop all capabilities", containerName)
		}
		return nil
	}
	return fmt.Errorf("container %q is missing", containerName)
}

// verifyExpiryGuardNamespaces requires the guard's Namespace get: cluster-wide
// in the all-namespaces profiles, and exactly the target and control
// namespaces in the namespaced profile.
func verifyExpiryGuardNamespaces(objects []unstructured.Unstructured, namespaced bool) error {
	role, err := requiredObject(objects, "ClusterRole", expiryGuardNamespacesRole)
	if err != nil {
		return err
	}
	if namespaced {
		if len(nestedRules(role)) != 1 || !roleHasExactNamespaceObservation(role) {
			return fmt.Errorf("expiry guard may get only the production and %s namespaces", controlNamespace)
		}
	} else if !rulesAreExactly(role, []guardRule{{"", namespaceRule, []string{verbGet}}}) {
		return fmt.Errorf("expiry guard namespace ClusterRole must grant only get on namespaces")
	}
	binding, err := requiredObject(objects, "ClusterRoleBinding", expiryGuardNamespacesRole)
	if err != nil {
		return err
	}
	roleRefKind, _, _ := unstructured.NestedString(binding.Object, "roleRef", "kind")
	roleRefName, _, _ := unstructured.NestedString(binding.Object, "roleRef", "name")
	if roleRefKind != "ClusterRole" || roleRefName != expiryGuardNamespacesRole {
		return fmt.Errorf("expiry guard namespace ClusterRoleBinding must reference its ClusterRole")
	}
	subjects, _, _ := unstructured.NestedSlice(binding.Object, "subjects")
	if len(subjects) != 1 {
		return fmt.Errorf("expiry guard namespace ClusterRoleBinding must have exactly one subject")
	}
	subject, ok := subjects[0].(map[string]any)
	if !ok || subject["kind"] != "ServiceAccount" || subject["name"] != expiryGuardName ||
		subject["namespace"] != managerNamespace {
		return fmt.Errorf("expiry guard namespace ClusterRoleBinding must bind the expiry guard ServiceAccount")
	}
	return nil
}
