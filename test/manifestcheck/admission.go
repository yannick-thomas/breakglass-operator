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
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	admissionName           = "breakglass-operator-admission"
	admissionContainer      = "admission"
	admissionComponent      = "admission"
	admissionMetricsService = "breakglass-operator-admission-metrics-service"
	webhookServiceName      = "breakglass-operator-webhook-service"
	servingCertificateName  = "breakglass-operator-serving-cert"
	webhookPort             = 9443
	metricsPort             = 8443

	allowedTargetFlag   = "--allowed-target-namespaces="
	controlFlag         = "--control-namespaces="
	requestIdentityFlag = "--request-controller-username="

	accessGroup = "access.breakglass.io"
)

// accessKinds are the four namespaced access kinds admission reads.
var accessKinds = []string{"accessprofiles", "breakglassapprovals", "breakglassrequests", "breakglasssessions"}

// verifyAdmission checks the separate admission workload of ADR-005: its own
// identity and restricted pod, sole ownership of the webhook endpoint and
// serving certificate, least-privilege RBAC, identical placement flags to the
// manager, and the manager identity as the trusted request controller.
func verifyAdmission(objects []unstructured.Unstructured, profile string) error {
	admission, err := requiredObjectInNamespace(objects, "Deployment", admissionName, managerNamespace)
	if err != nil {
		return err
	}
	manager, err := requiredObjectInNamespace(objects, "Deployment", managerName, managerNamespace)
	if err != nil {
		return err
	}
	if err := verifyAdmissionPod(admission); err != nil {
		return err
	}
	admissionC, _ := namedContainer(admission, admissionContainer)
	managerC, found := namedContainer(manager, "manager")
	if !found {
		return fmt.Errorf("manager Deployment must contain a manager container")
	}
	secretName, err := servingCertificateSecret(objects)
	if err != nil {
		return err
	}
	if err := verifyAdmissionServesWebhooks(admission, admissionC, secretName); err != nil {
		return err
	}
	if err := verifyManagerServesNoWebhook(manager, managerC, secretName); err != nil {
		return err
	}
	if err := verifyWebhookServiceTargetsAdmission(objects, admission, manager); err != nil {
		return err
	}
	if err := verifyAdmissionMetrics(objects, admission, admissionC); err != nil {
		return err
	}
	if err := verifySamePlacement(admissionC, managerC); err != nil {
		return err
	}
	if err := verifyRequestControllerIdentity(manager, admissionC, managerC); err != nil {
		return err
	}
	if err := verifyAdmissionRBAC(objects, admission, profile == namespacedProfile); err != nil {
		return err
	}
	if profile != defaultProfile {
		return verifyAvailability(objects, admission, admissionName, "admission")
	}
	return nil
}

func verifyAdmissionPod(admission unstructured.Unstructured) error {
	labels := podLabels(admission)
	if labels["app.kubernetes.io/component"] != admissionComponent {
		return fmt.Errorf("admission pods must be labelled app.kubernetes.io/component=%s", admissionComponent)
	}
	podSpec, _, _ := unstructured.NestedMap(admission.Object, "spec", "template", "spec")
	serviceAccount, _ := podSpec["serviceAccountName"].(string)
	if serviceAccount != admissionName {
		return fmt.Errorf("admission must run with its own ServiceAccount %s, not %q", admissionName, serviceAccount)
	}
	if err := verifyRestrictedPod(podSpec, admissionContainer); err != nil {
		return fmt.Errorf("admission: %w", err)
	}
	container, _ := namedContainer(admission, admissionContainer)
	if !slices.Equal(stringValues(container["command"]), []string{"/admission"}) {
		return fmt.Errorf("admission container must run /admission")
	}
	if slices.Contains(stringValues(container["args"]), "--leader-elect") {
		return fmt.Errorf("admission must not use leader election")
	}
	return nil
}

func servingCertificateSecret(objects []unstructured.Unstructured) (string, error) {
	certificate, err := requiredObjectInNamespace(objects, "Certificate", servingCertificateName, managerNamespace)
	if err != nil {
		return "", err
	}
	secretName, _, _ := unstructured.NestedString(certificate.Object, "spec", "secretName")
	if secretName == "" {
		return "", fmt.Errorf("serving Certificate must name its Secret")
	}
	return secretName, nil
}

func verifyAdmissionServesWebhooks(admission unstructured.Unstructured, container map[string]any, secret string) error {
	if !hasContainerPort(container, webhookPort) || !hasArg(container, fmt.Sprintf("--webhook-port=%d", webhookPort)) {
		return fmt.Errorf("admission must serve webhooks on port %d", webhookPort)
	}
	if !mountsSecret(admission, container, secret) || !hasArgPrefix(container, "--webhook-cert-path=") {
		return fmt.Errorf("admission must mount the serving certificate Secret %q", secret)
	}
	return nil
}

func verifyManagerServesNoWebhook(manager unstructured.Unstructured, container map[string]any, secret string) error {
	if hasContainerPort(container, webhookPort) || hasArgPrefix(container, "--webhook-") {
		return fmt.Errorf("manager must not expose a webhook port or webhook flags")
	}
	if mountsSecret(manager, container, secret) || volumeUsesSecret(manager, secret) {
		return fmt.Errorf("manager must not mount the webhook serving certificate")
	}
	return nil
}

func verifyWebhookServiceTargetsAdmission(
	objects []unstructured.Unstructured, admission, manager unstructured.Unstructured,
) error {
	service, err := requiredObjectInNamespace(objects, "Service", webhookServiceName, managerNamespace)
	if err != nil {
		return err
	}
	selector, _, _ := unstructured.NestedStringMap(service.Object, "spec", "selector")
	if len(selector) == 0 || !selects(selector, podLabels(admission)) {
		return fmt.Errorf("webhook Service must select the admission pods")
	}
	if selects(selector, podLabels(manager)) {
		return fmt.Errorf("webhook Service must not select the manager pods")
	}
	ports, _, _ := unstructured.NestedSlice(service.Object, "spec", "ports")
	for _, item := range ports {
		port, _ := item.(map[string]any)
		if hasIntValue(port["targetPort"], webhookPort) || port["targetPort"] == "webhook-server" {
			return nil
		}
	}
	return fmt.Errorf("webhook Service must forward to admission port %d", webhookPort)
}

func verifyAdmissionMetrics(
	objects []unstructured.Unstructured, admission unstructured.Unstructured, container map[string]any,
) error {
	if !hasArg(container, fmt.Sprintf("--metrics-bind-address=:%d", metricsPort)) ||
		hasArg(container, "--metrics-secure=false") {
		return fmt.Errorf("admission must serve authenticated HTTPS metrics on :%d", metricsPort)
	}
	service, err := requiredObjectInNamespace(objects, "Service", admissionMetricsService, managerNamespace)
	if err != nil {
		return err
	}
	selector, _, _ := unstructured.NestedStringMap(service.Object, "spec", "selector")
	if len(selector) == 0 || !selects(selector, podLabels(admission)) {
		return fmt.Errorf("admission metrics Service must select the admission pods")
	}
	return nil
}

// verifySamePlacement requires identical placement flags on both Deployments:
// a difference would let admission accept objects the manager never
// reconciles, or the reverse.
func verifySamePlacement(admission, manager map[string]any) error {
	for _, prefix := range []string{allowedTargetFlag, controlFlag} {
		if !slices.Equal(argsWithPrefix(admission, prefix), argsWithPrefix(manager, prefix)) {
			return fmt.Errorf("admission and manager must use identical %s flags", strings.TrimSuffix(prefix, "="))
		}
	}
	return nil
}

// verifyRequestControllerIdentity requires that admission trusts exactly the
// manager's ServiceAccount for request-sourced sessions, and that the manager
// stamps the same identity.
func verifyRequestControllerIdentity(manager unstructured.Unstructured, admission, managerC map[string]any) error {
	serviceAccount, _, _ := unstructured.NestedString(manager.Object, "spec", "template", "spec", "serviceAccountName")
	want := []string{requestIdentityFlag + "system:serviceaccount:" + managerNamespace + ":" + serviceAccount}
	if !slices.Equal(argsWithPrefix(admission, requestIdentityFlag), want) {
		return fmt.Errorf("admission must trust exactly the manager ServiceAccount: %s", want[0])
	}
	if !slices.Equal(argsWithPrefix(managerC, requestIdentityFlag), want) {
		return fmt.Errorf("manager must use its own ServiceAccount as request controller username")
	}
	return nil
}

// admissionRule is one permission admission may hold.
type admissionRule struct {
	group     string
	resources []string
	verbs     []string
}

// admissionAllowed lists every rule admission may hold. Anything else, such
// as bind, escalate, RoleBinding or session writes, or status writes, fails.
var admissionAllowed = []admissionRule{
	{"authorization.k8s.io", []string{"subjectaccessreviews"}, []string{verbCreate}},
	{"authentication.k8s.io", []string{"tokenreviews"}, []string{verbCreate}},
	{"", []string{namespaceRule}, []string{verbGet}},
	{accessGroup, accessKinds, []string{verbGet, verbList}},
}

// grantedRule is a rule bound to the admission ServiceAccount, with the
// namespace of its binding ("" for a ClusterRoleBinding).
type grantedRule struct {
	namespace string
	rule      map[string]any
}

func verifyAdmissionRBAC(
	objects []unstructured.Unstructured, admission unstructured.Unstructured, namespaced bool,
) error {
	serviceAccount, _, _ := unstructured.NestedString(admission.Object, "spec", "template", "spec", "serviceAccountName")
	if _, err := requiredObjectInNamespace(objects, serviceAccountKind, serviceAccount, managerNamespace); err != nil {
		return err
	}
	granted, err := rulesBoundTo(objects, serviceAccount)
	if err != nil {
		return err
	}
	for _, item := range granted {
		if !ruleAllowedForAdmission(item.rule) {
			return fmt.Errorf("admission RBAC grants a forbidden rule %v", item.rule)
		}
	}
	if !anyRule(granted, func(g grantedRule) bool {
		return g.namespace == "" && containsString(g.rule["resources"], "subjectaccessreviews")
	}) {
		return fmt.Errorf("admission must be able to create SubjectAccessReviews")
	}

	namespaceGets := filterRules(granted, func(g grantedRule) bool {
		return containsString(g.rule["resources"], namespaceRule)
	})
	accessReads := filterRules(granted, func(g grantedRule) bool {
		return containsString(g.rule["apiGroups"], accessGroup)
	})
	if !namespaced {
		if !anyRule(namespaceGets, func(g grantedRule) bool { return g.namespace == "" }) ||
			!anyRule(accessReads, func(g grantedRule) bool { return g.namespace == "" && coversAccessKinds(g.rule) }) {
			return fmt.Errorf("admission must get namespaces and get/list the access kinds")
		}
		return nil
	}
	if len(namespaceGets) != 1 || namespaceGets[0].namespace != "" ||
		!sameStrings(stringValues(namespaceGets[0].rule["resourceNames"]), []string{targetNamespace, controlNamespace}) {
		return fmt.Errorf("admission may get only the production and %s namespaces", controlNamespace)
	}
	if len(accessReads) == 0 {
		return fmt.Errorf("admission must get/list the access kinds in %s", controlNamespace)
	}
	for _, read := range accessReads {
		if read.namespace != controlNamespace || !coversAccessKinds(read.rule) {
			return fmt.Errorf("admission may read the access kinds only in %s", controlNamespace)
		}
	}
	return nil
}

func ruleAllowedForAdmission(rule map[string]any) bool {
	groups := stringValues(rule["apiGroups"])
	resources := stringValues(rule["resources"])
	verbs := stringValues(rule["verbs"])
	if len(groups) != 1 || len(resources) == 0 || len(verbs) == 0 || len(stringValues(rule["nonResourceURLs"])) > 0 {
		return false
	}
	for _, allowed := range admissionAllowed {
		if groups[0] != allowed.group {
			continue
		}
		if subset(resources, allowed.resources) && subset(verbs, allowed.verbs) {
			return true
		}
	}
	return false
}

func coversAccessKinds(rule map[string]any) bool {
	return subset(accessKinds, stringValues(rule["resources"])) &&
		subset([]string{verbGet, verbList}, stringValues(rule["verbs"])) &&
		len(stringValues(rule["resourceNames"])) == 0
}

// rulesBoundTo resolves every ClusterRoleBinding and RoleBinding whose
// subjects include the ServiceAccount and returns the referenced rules.
func rulesBoundTo(objects []unstructured.Unstructured, serviceAccount string) ([]grantedRule, error) {
	var granted []grantedRule
	for _, binding := range objects {
		if binding.GetKind() != "ClusterRoleBinding" && binding.GetKind() != "RoleBinding" {
			continue
		}
		if !bindsServiceAccount(binding, serviceAccount) {
			continue
		}
		roleKind, _, _ := unstructured.NestedString(binding.Object, "roleRef", "kind")
		roleName, _, _ := unstructured.NestedString(binding.Object, "roleRef", "name")
		role, err := requiredObject(objects, roleKind, roleName)
		if err != nil {
			return nil, fmt.Errorf("%s %q binds %s to a missing role: %w",
				binding.GetKind(), binding.GetName(), serviceAccount, err)
		}
		if roleKind == "Role" && role.GetNamespace() != binding.GetNamespace() {
			return nil, fmt.Errorf("RoleBinding %q references a Role in another namespace", binding.GetName())
		}
		namespace := ""
		if binding.GetKind() == "RoleBinding" {
			namespace = binding.GetNamespace()
		}
		for _, rule := range nestedRules(role) {
			granted = append(granted, grantedRule{namespace: namespace, rule: rule})
		}
	}
	return granted, nil
}

func bindsServiceAccount(binding unstructured.Unstructured, serviceAccount string) bool {
	subjects, _, _ := unstructured.NestedSlice(binding.Object, "subjects")
	for _, item := range subjects {
		subject, ok := item.(map[string]any)
		if ok && subject["kind"] == serviceAccountKind && subject["name"] == serviceAccount &&
			subject["namespace"] == managerNamespace {
			return true
		}
	}
	return false
}

// verifyAvailability requires two replicas spread across hostnames and a
// PodDisruptionBudget with minAvailable 1 that selects the Deployment's pods.
func verifyAvailability(
	objects []unstructured.Unstructured, deployment unstructured.Unstructured, pdbName, component string,
) error {
	replicas, found, err := unstructured.NestedFieldNoCopy(deployment.Object, "spec", "replicas")
	if err != nil || !found || !hasIntValue(replicas, 2) {
		return fmt.Errorf("%s Deployment must have exactly two replicas", component)
	}
	constraints, found, err := unstructured.NestedSlice(
		deployment.Object, "spec", "template", "spec", "topologySpreadConstraints",
	)
	if err != nil || !found || !hasHostnameSpreadConstraint(constraints) {
		return fmt.Errorf("%s Deployment must spread replicas across hostnames with DoNotSchedule", component)
	}
	pdb, err := requiredObjectInNamespace(objects, "PodDisruptionBudget", pdbName, managerNamespace)
	if err != nil {
		return err
	}
	minAvailable, found, err := unstructured.NestedFieldNoCopy(pdb.Object, "spec", "minAvailable")
	if err != nil || !found || !hasIntValue(minAvailable, 1) {
		return fmt.Errorf("%s PodDisruptionBudget must set minAvailable: 1", component)
	}
	selector, _, _ := unstructured.NestedStringMap(pdb.Object, "spec", "selector", "matchLabels")
	if len(selector) == 0 || !selects(selector, podLabels(deployment)) {
		return fmt.Errorf("%s PodDisruptionBudget must select the %s pods", component, component)
	}
	return nil
}

func podLabels(deployment unstructured.Unstructured) map[string]string {
	labels, _, _ := unstructured.NestedStringMap(deployment.Object, "spec", "template", "metadata", "labels")
	return labels
}

func selects(selector, labels map[string]string) bool {
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func hasContainerPort(container map[string]any, port int64) bool {
	ports, _ := container["ports"].([]any)
	for _, item := range ports {
		if entry, ok := item.(map[string]any); ok && hasIntValue(entry["containerPort"], port) {
			return true
		}
	}
	return false
}

func hasArg(container map[string]any, arg string) bool {
	return slices.Contains(stringValues(container["args"]), arg)
}

func hasArgPrefix(container map[string]any, prefix string) bool {
	return len(argsWithPrefix(container, prefix)) > 0
}

func argsWithPrefix(container map[string]any, prefix string) []string {
	var result []string
	for _, arg := range stringValues(container["args"]) {
		if strings.HasPrefix(arg, prefix) {
			result = append(result, arg)
		}
	}
	slices.Sort(result)
	return result
}

// mountsSecret reports whether the container mounts a volume backed by the
// Secret.
func mountsSecret(deployment unstructured.Unstructured, container map[string]any, secret string) bool {
	volumes := secretVolumes(deployment)
	mounts, _ := container["volumeMounts"].([]any)
	for _, item := range mounts {
		mount, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := mount["name"].(string)
		if volumes[name] == secret {
			return true
		}
	}
	return false
}

func volumeUsesSecret(deployment unstructured.Unstructured, secret string) bool {
	for _, name := range secretVolumes(deployment) {
		if name == secret {
			return true
		}
	}
	return false
}

func secretVolumes(deployment unstructured.Unstructured) map[string]string {
	volumes, _, _ := unstructured.NestedSlice(deployment.Object, "spec", "template", "spec", "volumes")
	result := map[string]string{}
	for _, item := range volumes {
		volume, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := volume["name"].(string)
		secretName, _, _ := unstructured.NestedString(volume, "secret", "secretName")
		result[name] = secretName
	}
	return result
}

func subset(values, allowed []string) bool {
	for _, value := range values {
		if !slices.Contains(allowed, value) {
			return false
		}
	}
	return true
}

func anyRule(rules []grantedRule, match func(grantedRule) bool) bool {
	return slices.ContainsFunc(rules, match)
}

func filterRules(rules []grantedRule, match func(grantedRule) bool) []grantedRule {
	var result []grantedRule
	for _, rule := range rules {
		if match(rule) {
			result = append(result, rule)
		}
	}
	return result
}
