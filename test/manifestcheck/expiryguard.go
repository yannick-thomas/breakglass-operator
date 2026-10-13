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

	verbGet    = "get"
	verbDelete = "delete"
)

// verifyExpiryGuard checks that the independent expiry guard (SR-06) is
// installed with its own identity, restricted pod security, and nothing but
// read access to sessions plus get/delete on RoleBindings.
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

	clusterRole, err := requiredObject(objects, "ClusterRole", expiryGuardRoleName)
	if err != nil {
		return err
	}
	want := []guardRule{{"access.breakglass.io", "breakglasssessions", []string{verbGet, "list"}}}
	if !namespaced {
		want = append(want, guardRule{"rbac.authorization.k8s.io", roleBindingRule, []string{verbGet, verbDelete}})
	}
	if !rulesAreExactly(clusterRole, want) {
		return fmt.Errorf("expiry guard ClusterRole must grant only session reads and RoleBinding get/delete")
	}
	if !namespaced {
		return nil
	}

	role, err := requiredObjectInNamespace(objects, "Role", expiryGuardNamespacedRole, "production")
	if err != nil {
		return err
	}
	if !rulesAreExactly(role, []guardRule{{"rbac.authorization.k8s.io", roleBindingRule, []string{verbGet, verbDelete}}}) {
		return fmt.Errorf("production expiry guard Role must grant only RoleBinding get/delete")
	}
	containers, _, _ := unstructured.NestedSlice(podSpec, "containers")
	if len(containers) != 1 {
		return fmt.Errorf("expiry guard must have exactly one container")
	}
	container, _ := containers[0].(map[string]any)
	if allowedTargetNamespaceArguments(container) != 1 {
		return fmt.Errorf("expiry guard must restrict allowed target namespaces to production")
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
