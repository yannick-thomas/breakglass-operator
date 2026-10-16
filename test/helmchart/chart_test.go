// Package helmchart exercises the installer's security boundary through Helm.
package helmchart

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

const chartPath = "charts/breakglass-operator"

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func helmCommand(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	helm := os.Getenv("HELM")
	if helm == "" {
		var err error
		helm, err = exec.LookPath("helm")
		if err != nil {
			t.Skip("Helm is required; run make verify-helm")
		}
	}
	cmd := exec.Command(helm, args...)
	cmd.Dir = repoRoot(t)
	return cmd.CombinedOutput()
}

func render(t *testing.T, release, namespace string, extra ...string) []unstructured.Unstructured {
	t.Helper()
	args := []string{"template", release, chartPath, "--namespace", namespace,
		"--include-crds", "--set", "image.tag=test"}
	output, err := helmCommand(t, append(args, extra...)...)
	if err != nil {
		t.Fatalf("Helm rendering failed: %v\n%s", err, output)
	}
	return decode(t, output)
}

func decode(t *testing.T, data []byte) []unstructured.Unstructured {
	t.Helper()
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var objects []unstructured.Unstructured
	for {
		var raw map[string]any
		err := decoder.Decode(&raw)
		if errors.Is(err, io.EOF) {
			return objects
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > 0 {
			objects = append(objects, unstructured.Unstructured{Object: raw})
		}
	}
}

func object(t *testing.T, objects []unstructured.Unstructured, kind, name, namespace string) map[string]any {
	t.Helper()
	for _, item := range objects {
		if item.GetKind() == kind && item.GetName() == name && item.GetNamespace() == namespace {
			return item.Object
		}
	}
	t.Fatalf("missing %s %s/%s", kind, namespace, name)
	return nil
}

func field(t *testing.T, item map[string]any, path ...string) any {
	t.Helper()
	value, found, err := unstructured.NestedFieldNoCopy(item, path...)
	if err != nil || !found {
		t.Fatalf("missing/invalid %v: %v", path, err)
	}
	return value
}

func TestCRDsStayInSync(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRoot(t), "config/crd/bases/*.yaml"))
	if err != nil || len(files) != 4 {
		t.Fatalf("expected four canonical CRDs: %v", err)
	}
	for _, source := range files {
		want, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(repoRoot(t), chartPath, "crds", filepath.Base(source)))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s differs from canonical CRD; run make helm-sync-crds", filepath.Base(source))
		}
	}
}

func TestRenderedSecurityBoundary(t *testing.T) {
	defaultControl := []string{"breakglass-access"}
	for _, tc := range []struct {
		name, release, namespace        string
		targets, controls, roles, flags []string
	}{
		{"default", "breakglass-operator", "breakglass-operator-system",
			[]string{"production"}, defaultControl, []string{"breakglass-pod-observer"}, nil},
		{"all-options", "emergency", "platform-access",
			[]string{"payments", "inventory"}, []string{"payments-access", "inventory-access"},
			[]string{"breakglass-logs-v1", "breakglass-restart-v1"},
			[]string{"-f", chartPath + "/ci/all-options.yaml"}},
		{"single-node", "dev", "access-system",
			[]string{"production"}, defaultControl, []string{"breakglass-pod-observer"},
			[]string{"-f", chartPath + "/ci/single-node.yaml"}},
		{"local-example", "local", "access-system",
			[]string{"production"}, defaultControl, []string{"breakglass-pod-observer"},
			[]string{"-f", chartPath + "/examples/values-local.yaml"}},
		{"production-example", "prod", "access-system",
			[]string{"production"}, defaultControl, []string{"breakglass-pod-observer"},
			[]string{"-f", chartPath + "/examples/values-production.yaml", "--set", "webui.image.tag=test"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objects := render(t, tc.release, tc.namespace, tc.flags...)
			verifyRoleBoundary(t, objects, tc.release, tc.namespace, tc.targets, tc.controls, tc.roles)
			verifyControlBoundary(t, objects, tc.release, tc.namespace, tc.controls)
			verifyGuardNamespaceObservation(t, objects, tc.release, tc.namespace,
				observedNamespaces(tc.targets, tc.controls))
			verifyAdmission(t, objects, tc.release, tc.namespace, tc.controls)
			verifyAdmissionTopology(t, objects, tc.release, tc.namespace)
			verifyAdmissionRBAC(t, objects, tc.release, tc.namespace, tc.targets, tc.controls)
			verifySourceParity(t, objects, tc.release, tc.controls, tc.targets, tc.roles)
			manager := object(t, objects, "Deployment", tc.release+"-controller-manager", tc.namespace)
			managerPod := field(t, manager, "spec", "template", "spec").(map[string]any)
			verifyPod(t, managerPod, tc.release+"-controller-manager", tc.targets, tc.controls)
			container := field(t, managerPod, "containers").([]any)[0].(map[string]any)
			args, _, _ := unstructured.NestedStringSlice(container, "args")
			if !slices.Contains(args, controllerIdentityArg(tc.release, tc.namespace)) {
				t.Fatal("request controller identity does not match rendered ServiceAccount")
			}
			admission := object(t, objects, "Deployment", tc.release+"-admission", tc.namespace)
			admissionPod := field(t, admission, "spec", "template", "spec").(map[string]any)
			verifyPod(t, admissionPod, tc.release+"-admission", tc.targets, tc.controls)
			guard := object(t, objects, "CronJob", tc.release+"-expiry-guard", tc.namespace)
			guardPod := field(t, guard, "spec", "jobTemplate", "spec", "template", "spec").(map[string]any)
			verifyPod(t, guardPod, tc.release+"-expiry-guard", tc.targets, tc.controls)
			if field(t, guard, "spec", "concurrencyPolicy") != "Forbid" {
				t.Fatal("expiry guard must not overlap")
			}
			if tc.name == "all-options" {
				verifyOptionalClients(t, objects, tc.release, tc.namespace)
			}
		})
	}
}

// observedNamespaces is the ordered, duplicate-free set of namespaces that
// admission and the guard may get: the targets and the control namespaces
// (approval deletion during namespace deletion).
func observedNamespaces(targets, controls []string) []string {
	var names []string
	for _, name := range append(slices.Clone(targets), controls...) {
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names
}

func verifyRoleBoundary(
	t *testing.T, objects []unstructured.Unstructured, release, namespace string, targets, controls, roles []string,
) {
	t.Helper()
	for _, item := range objects {
		switch item.GetKind() {
		case "Namespace", "AccessProfile", "BreakGlassSession", "BreakGlassRequest", "BreakGlassApproval":
			t.Fatalf("chart must not install policy or incident resources: %s", item.GetKind())
		case "ClusterRole":
			rules := field(t, item.Object, "rules").([]any)
			for _, raw := range rules {
				rule := raw.(map[string]any)
				resources, _, _ := unstructured.NestedStringSlice(rule, "resources")
				verbs, _, _ := unstructured.NestedStringSlice(rule, "verbs")
				groups, _, _ := unstructured.NestedStringSlice(rule, "apiGroups")
				for _, values := range [][]string{resources, verbs, groups} {
					if slices.Contains(values, "*") {
						t.Fatal("wildcard ClusterRole permission")
					}
				}
				if slices.Contains(resources, "rolebindings") || slices.Contains(resources, "clusterrolebindings") ||
					slices.Contains(verbs, "escalate") || slices.Contains(verbs, "impersonate") {
					t.Fatalf("global RBAC grant in %s", item.GetName())
				}
				if slices.Contains(resources, "clusterroles") {
					names, _, _ := unstructured.NestedStringSlice(rule, "resourceNames")
					if !reflect.DeepEqual(names, roles) || !sameSet(verbs, []string{"get", "bind"}) {
						t.Fatal("curated-role read/bind must be restricted to the explicit role names")
					}
				}
				if slices.Contains(resources, "namespaces") {
					names, _, _ := unstructured.NestedStringSlice(rule, "resourceNames")
					// The manager confirms only target namespace absence; admission
					// and the guard also observe the control namespaces (ADR-005).
					want := observedNamespaces(targets, controls)
					if item.GetName() == release+"-manager-role" {
						want = targets
					}
					if !reflect.DeepEqual(names, want) || !reflect.DeepEqual(verbs, []string{"get"}) {
						t.Fatalf("namespace observation in %s must match the explicit namespace sets", item.GetName())
					}
				}
			}
		case "Role":
			if strings.HasSuffix(item.GetName(), "-rolebindings") && !slices.Contains(targets, item.GetNamespace()) {
				t.Fatal("RoleBinding permissions outside configured namespaces")
			}
		}
	}
	for _, target := range targets {
		for _, component := range []struct {
			name  string
			verbs []string
		}{
			{"manager", []string{"create", "delete", "get", "list", "update", "watch"}},
			{"expiry-guard", []string{"get", "list", "delete"}},
		} {
			name := release + "-" + component.name + "-rolebindings"
			role := object(t, objects, "Role", name, target)
			rules := field(t, role, "rules").([]any)
			if len(rules) != 1 {
				t.Fatal("namespace role has unexpected permissions")
			}
			rule := rules[0].(map[string]any)
			verbs, _, _ := unstructured.NestedStringSlice(rule, "verbs")
			resources, _, _ := unstructured.NestedStringSlice(rule, "resources")
			if !sameSet(verbs, component.verbs) || !reflect.DeepEqual(resources, []string{"rolebindings"}) {
				t.Fatal("namespace role exceeds required RoleBinding permissions")
			}
			binding := object(t, objects, "RoleBinding", name, target)
			subjects := field(t, binding, "subjects").([]any)
			sa := release + "-expiry-guard"
			if component.name == "manager" {
				sa = release + "-controller-manager"
			}
			want := map[string]any{"kind": "ServiceAccount", "name": sa, "namespace": namespace}
			if len(subjects) != 1 || !reflect.DeepEqual(subjects[0], want) {
				t.Fatal("namespace permissions bound to wrong identity")
			}
		}
	}
}

// verifyControlBoundary checks that the manager and the expiry guard reach
// access objects only through Roles in the control namespaces (ADR-004).
func verifyControlBoundary(
	t *testing.T, objects []unstructured.Unstructured, release, namespace string, controls []string,
) {
	t.Helper()
	for _, name := range []string{
		release + "-manager-role", release + "-admission-role", release + "-expiry-guard-role",
		release + "-expiry-guard-namespaces",
	} {
		for _, item := range objects {
			if item.GetKind() != "ClusterRole" || item.GetName() != name {
				continue
			}
			for _, raw := range field(t, item.Object, "rules").([]any) {
				groups, _, _ := unstructured.NestedStringSlice(raw.(map[string]any), "apiGroups")
				if slices.Contains(groups, "access.breakglass.io") {
					t.Fatalf("%s grants access objects cluster-wide", name)
				}
			}
		}
	}
	for _, item := range objects {
		if item.GetKind() == "Role" && (strings.HasSuffix(item.GetName(), "-manager-access") ||
			strings.HasSuffix(item.GetName(), "-admission-access") ||
			strings.HasSuffix(item.GetName(), "-expiry-guard-sessions")) && !slices.Contains(controls, item.GetNamespace()) {
			t.Fatal("access object permissions outside configured control namespaces")
		}
	}
	for _, control := range controls {
		guard := object(t, objects, "Role", release+"-expiry-guard-sessions", control)
		rules := field(t, guard, "rules").([]any)
		verbs, _, _ := unstructured.NestedStringSlice(rules[0].(map[string]any), "verbs")
		resources, _, _ := unstructured.NestedStringSlice(rules[0].(map[string]any), "resources")
		if len(rules) != 1 || !sameSet(verbs, []string{"get", "list"}) ||
			!reflect.DeepEqual(resources, []string{"breakglasssessions"}) {
			t.Fatal("expiry guard may only read sessions in a control namespace")
		}
		for _, component := range []struct{ role, sa string }{
			{release + "-manager-access", release + "-controller-manager"},
			{release + "-admission-access", release + "-admission"},
			{release + "-expiry-guard-sessions", release + "-expiry-guard"},
		} {
			object(t, objects, "Role", component.role, control)
			binding := object(t, objects, "RoleBinding", component.role, control)
			subjects := field(t, binding, "subjects").([]any)
			want := map[string]any{"kind": "ServiceAccount", "name": component.sa, "namespace": namespace}
			if len(subjects) != 1 || !reflect.DeepEqual(subjects[0], want) {
				t.Fatal("control namespace permissions bound to wrong identity")
			}
		}
	}
}

// verifyGuardNamespaceObservation requires the expiry guard's Namespace get
// to name exactly the target and control namespaces, through a ClusterRole
// that outlives them.
func verifyGuardNamespaceObservation(
	t *testing.T, objects []unstructured.Unstructured, release, namespace string, observed []string,
) {
	t.Helper()
	name := release + "-expiry-guard-namespaces"
	role := object(t, objects, "ClusterRole", name, "")
	want := []any{map[string]any{
		"apiGroups": []any{""}, "resources": []any{"namespaces"},
		"resourceNames": stringItems(observed), "verbs": []any{"get"},
	}}
	if !reflect.DeepEqual(field(t, role, "rules"), want) {
		t.Fatalf("expiry guard may get only its target and control namespaces, got %v", field(t, role, "rules"))
	}
	binding := object(t, objects, "ClusterRoleBinding", name, "")
	subjects := field(t, binding, "subjects").([]any)
	subject := map[string]any{"kind": "ServiceAccount", "name": release + "-expiry-guard", "namespace": namespace}
	if len(subjects) != 1 || !reflect.DeepEqual(subjects[0], subject) ||
		field(t, binding, "roleRef", "kind") != "ClusterRole" || field(t, binding, "roleRef", "name") != name {
		t.Fatal("expiry guard namespace get is bound to the wrong identity or role")
	}
}

// controlNamespaceWebhook is the drain check for control namespaces (ADR-004).
const controlNamespaceWebhook = "vcontrolnamespace-v1.kb.io"

func verifyAdmission(t *testing.T, objects []unstructured.Unstructured, release, namespace string, controls []string) {
	t.Helper()
	for _, mode := range []struct {
		kind, suffix  string
		drainWebhooks int
	}{
		{"MutatingWebhookConfiguration", "mutating", 0}, {"ValidatingWebhookConfiguration", "validating", 1},
	} {
		config := object(t, objects, mode.kind, release+"-"+mode.suffix+"-webhook-configuration", "")
		annotations, _, _ := unstructured.NestedStringMap(config, "metadata", "annotations")
		if annotations["cert-manager.io/inject-ca-from"] != namespace+"/"+release+"-serving-cert" {
			t.Fatal("webhook CA injection must reference the rendered certificate")
		}
		webhooks := field(t, config, "webhooks").([]any)
		accessWebhooks, drainWebhooks := 0, 0
		for _, raw := range webhooks {
			webhook := raw.(map[string]any)
			if webhook["failurePolicy"] != "Fail" || webhook["sideEffects"] != "None" ||
				webhook["timeoutSeconds"] != float64(5) {
				t.Fatal("webhooks must fail closed with a bounded timeout")
			}
			service := field(t, webhook, "clientConfig", "service").(map[string]any)
			if service["name"] != release+"-webhook-service" || service["namespace"] != namespace {
				t.Fatal("webhook points at the wrong Service")
			}
			if _, exists := webhook["objectSelector"]; exists {
				t.Fatal("object selector may bypass admission")
			}
			if webhook["name"] == controlNamespaceWebhook {
				drainWebhooks++
				verifyControlNamespaceWebhook(t, webhook, controls)
				continue
			}
			accessWebhooks++
			if _, exists := webhook["namespaceSelector"]; exists {
				t.Fatal("namespace selector may bypass admission")
			}
			for _, rule := range field(t, webhook, "rules").([]any) {
				if rule.(map[string]any)["scope"] != "Namespaced" {
					t.Fatal("admission must match the namespaced access objects")
				}
			}
		}
		if accessWebhooks != 3 {
			t.Fatal("all three admission resources must be protected")
		}
		if drainWebhooks != mode.drainWebhooks {
			t.Fatal("exactly one validating drain check must guard control-namespace deletion")
		}
	}
}

// verifyControlNamespaceWebhook requires the drain check to match only the
// deletion of exactly the control namespaces. It fails closed, so a wider
// selector would make unrelated namespace deletions depend on the manager.
func verifyControlNamespaceWebhook(t *testing.T, webhook map[string]any, controls []string) {
	t.Helper()
	rules := field(t, webhook, "rules").([]any)
	want := []any{map[string]any{
		"apiGroups": []any{""}, "apiVersions": []any{"v1"}, "operations": []any{"DELETE"},
		"resources": []any{"namespaces"}, "scope": "Cluster",
	}}
	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("drain check must match only Namespace DELETE, got %v", rules)
	}
	wantSelector := map[string]any{"matchExpressions": []any{map[string]any{
		"key": "kubernetes.io/metadata.name", "operator": "In", "values": stringItems(controls),
	}}}
	if !reflect.DeepEqual(webhook["namespaceSelector"], wantSelector) {
		t.Fatalf("drain check must select exactly the control namespaces, got %v", webhook["namespaceSelector"])
	}
	if field(t, webhook, "clientConfig", "service", "path") != "/validate-core-v1-namespace" {
		t.Fatal("drain check points at the wrong handler")
	}
}

func verifyPod(t *testing.T, pod map[string]any, serviceAccount string, targets, controls []string) {
	t.Helper()
	if pod["serviceAccountName"] != serviceAccount {
		t.Fatal("pod uses the wrong ServiceAccount")
	}
	if field(t, pod, "securityContext", "runAsNonRoot") != true ||
		field(t, pod, "securityContext", "seccompProfile", "type") != "RuntimeDefault" {
		t.Fatal("pod security must remain restricted")
	}
	containers := field(t, pod, "containers").([]any)
	if len(containers) != 1 {
		t.Fatal("unexpected sidecar at the security boundary")
	}
	container := containers[0].(map[string]any)
	if field(t, container, "securityContext", "readOnlyRootFilesystem") != true ||
		field(t, container, "securityContext", "allowPrivilegeEscalation") != false {
		t.Fatal("container security weakened")
	}
	drop, _, _ := unstructured.NestedStringSlice(container, "securityContext", "capabilities", "drop")
	if !reflect.DeepEqual(drop, []string{"ALL"}) {
		t.Fatal("container must drop all capabilities")
	}
	args, _, _ := unstructured.NestedStringSlice(container, "args")
	if !slices.Contains(args, "--allowed-target-namespaces="+strings.Join(targets, ",")) ||
		!slices.Contains(args, "--control-namespaces="+strings.Join(controls, ",")) {
		t.Fatal("pod namespace scope disagrees with its RBAC")
	}
}

func verifyOptionalClients(t *testing.T, objects []unstructured.Unstructured, release, namespace string) {
	t.Helper()
	reader := object(t, objects, "ClusterRole", release+"-webui-reader", "")
	rules := field(t, reader, "rules").([]any)
	if len(rules) != 1 {
		t.Fatal("WebUI must have only one read-only rule")
	}
	verbs, _, _ := unstructured.NestedStringSlice(rules[0].(map[string]any), "verbs")
	if !sameSet(verbs, []string{"get", "list"}) {
		t.Fatal("WebUI may not write or impersonate")
	}
	monitor := object(t, objects, "ServiceMonitor", release+"-metrics", namespace)
	endpoints := field(t, monitor, "spec", "endpoints").([]any)
	tls := field(t, endpoints[0].(map[string]any), "tlsConfig").(map[string]any)
	if tls["insecureSkipVerify"] != false || field(t, tls, "ca", "secret", "name") != "platform-metrics-ca" {
		t.Fatal("monitor must verify its explicitly configured CA")
	}
	object(t, objects, "PrometheusRule", release+"-alerts", namespace)
	ingress := object(t, objects, "Ingress", release+"-webui", namespace)
	if len(field(t, ingress, "spec", "tls").([]any)) != 1 {
		t.Fatal("WebUI ingress must use TLS")
	}
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// Keep the two installers on the same controller/admission API contract. The
// chart deliberately replaces global RBAC reads/CRUD with explicit names.
func verifySourceParity(
	t *testing.T, objects []unstructured.Unstructured, release string, controls, targets, roles []string,
) {
	t.Helper()
	read := func(path string) []unstructured.Unstructured {
		data, err := os.ReadFile(filepath.Join(repoRoot(t), path))
		if err != nil {
			t.Fatal(err)
		}
		return decode(t, data)
	}
	sourceRole := read("config/rbac/role.yaml")[0]
	var expectedRules, expectedControlRules []any
	for _, raw := range field(t, sourceRole.Object, "rules").([]any) {
		rule := raw.(map[string]any)
		resources, _, _ := unstructured.NestedStringSlice(rule, "resources")
		names, _, _ := unstructured.NestedStringSlice(rule, "resourceNames")
		groups, _, _ := unstructured.NestedStringSlice(rule, "apiGroups")
		// The chart narrows these generated cluster-wide rules to explicit names.
		if slices.Equal(resources, []string{"rolebindings"}) ||
			(slices.Equal(resources, []string{"namespaces"}) && len(names) == 0) ||
			(slices.Equal(resources, []string{"clusterroles"}) && len(names) == 0) {
			continue
		}
		// Access objects and their events live in the control namespaces.
		if slices.Equal(groups, []string{"access.breakglass.io"}) || slices.Equal(resources, []string{"events"}) {
			expectedControlRules = append(expectedControlRules, rule)
			continue
		}
		if slices.Equal(resources, []string{"clusterroles"}) {
			rule["resourceNames"] = stringItems(roles)
		}
		expectedRules = append(expectedRules, rule)
	}
	expectedRules = append(expectedRules, map[string]any{
		"apiGroups": []any{""}, "resources": []any{"namespaces"},
		"resourceNames": stringItems(targets), "verbs": []any{"get"},
	})
	managerRole := object(t, objects, "ClusterRole", release+"-manager-role", "")
	if !reflect.DeepEqual(field(t, managerRole, "rules"), expectedRules) {
		t.Fatal("manager RBAC has drifted from the generated controller contract")
	}
	for _, control := range controls {
		access := object(t, objects, "Role", release+"-manager-access", control)
		if !reflect.DeepEqual(field(t, access, "rules"), expectedControlRules) {
			t.Fatal("manager control-namespace RBAC has drifted from the generated controller contract")
		}
	}
	verifyAdmissionSourceParity(t, objects, release, controls, targets)
	for _, source := range read("config/webhook/manifests.yaml") {
		rendered := object(t, objects, source.GetKind(), release+"-"+source.GetName(), "")
		expected := field(t, source.Object, "webhooks").([]any)
		actual := field(t, rendered, "webhooks").([]any)
		if len(actual) != len(expected) {
			t.Fatal("webhook count differs from canonical admission configuration")
		}
		for i, raw := range expected {
			sourceWebhook := raw.(map[string]any)
			chartWebhook := actual[i].(map[string]any)
			rules := field(t, sourceWebhook, "rules").([]any)
			// Access objects are namespaced; Namespace objects are cluster-scoped.
			for _, rule := range rules {
				rule := rule.(map[string]any)
				rule["scope"] = "Namespaced"
				resources, _, _ := unstructured.NestedStringSlice(rule, "resources")
				if slices.Equal(resources, []string{"namespaces"}) {
					rule["scope"] = "Cluster"
				}
			}
			if !reflect.DeepEqual(field(t, chartWebhook, "rules"), rules) ||
				field(t, sourceWebhook, "clientConfig", "service", "path") !=
					field(t, chartWebhook, "clientConfig", "service", "path") {
				t.Fatal("webhook resources, operations or handler path differ from canonical admission")
			}
		}
	}
}

func stringItems(values []string) []any {
	items := make([]any, len(values))
	for i, value := range values {
		items[i] = value
	}
	return items
}

func TestUnsafeValuesAreRejected(t *testing.T) {
	for _, override := range []string{
		"allowedTargetNamespaces=[]", "allowedTargetNamespaces={*}",
		"allowedTargetNamespaces={production,production}", "curatedClusterRoles=[]",
		"curatedClusterRoles={*}", "webhooks.enabled=false", "extraArgs={--metrics-secure=false}",
		"expiryGuard.enabled=false", "replicaCount=0", "replicaCount=1",
		"metrics.serviceMonitor.enabled=true", "webui.enabled=true",
		"image.digest=sha256:bad", "image.tag=latest@sha256:bad",
		"certManager.issuerRef.name=missing-kind", "availability.podDisruptionBudget.minAvailable=2",
	} {
		t.Run(override, func(t *testing.T) {
			args := []string{"template", "test", chartPath, "--set", "image.tag=test", "--set", override}
			if output, err := helmCommand(t, args...); err == nil {
				t.Fatalf("unsafe/incomplete values were accepted: %s\n%s", override, output)
			}
		})
	}
	if output, err := helmCommand(t, "template", "test", chartPath); err == nil {
		t.Fatalf("missing image accepted: %s", output)
	}
}

func TestReleasePackagePinsBothImages(t *testing.T) {
	helm := os.Getenv("HELM")
	if helm == "" {
		var err error
		helm, err = exec.LookPath("helm")
		if err != nil {
			t.Skip("Helm is required; run make verify-helm")
		}
	}
	destination := t.TempDir()
	managerImage := "registry.example.com/operator@sha256:" + strings.Repeat("a", 64)
	webuiImage := "registry.example.com/webui@sha256:" + strings.Repeat("b", 64)
	revision := strings.Repeat("c", 40)
	cmd := exec.Command("python3", "hack/package-helm.py", "--helm", helm,
		"--image", managerImage, "--webui-image", webuiImage, "--source-revision", revision,
		"--version", "0.1.0", "--app-version", "test", "--destination", destination)
	cmd.Dir = repoRoot(t)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("packaging failed: %v\n%s", err, output)
	}
	output, err := helmCommand(t, "template", "release", filepath.Join(destination, "breakglass-operator-0.1.0.tgz"),
		"--namespace", "release-system", "-f", chartPath+"/examples/values-production.yaml")
	if err != nil {
		t.Fatalf("packaged chart cannot enable WebUI without overriding images: %v\n%s", err, output)
	}
	objects := decode(t, output)
	for _, component := range []struct{ suffix, image string }{
		{"controller-manager", managerImage}, {"admission", managerImage}, {"webui", webuiImage},
	} {
		deployment := object(t, objects, "Deployment", "release-"+component.suffix, "release-system")
		containers := field(t, deployment, "spec", "template", "spec", "containers").([]any)
		if field(t, containers[0].(map[string]any), "image") != component.image {
			t.Fatal("packaged chart does not run the exact reviewed image digest")
		}
	}
	metadata, err := os.ReadFile(filepath.Join(destination, "release.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		SourceRevision string            `json:"sourceRevision"`
		Images         map[string]string `json:"images"`
	}
	if err := json.Unmarshal(metadata, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SourceRevision != revision || manifest.Images["operator"] != managerImage ||
		manifest.Images["webui"] != webuiImage {
		t.Fatal("release metadata disagrees with packaged image defaults")
	}
}

func TestReleaseRequiresSuccessfulCIForExactRevision(t *testing.T) {
	revision := strings.Repeat("a", 40)
	for _, tc := range []struct {
		name, sha, event, status, conclusion string
		allowed                              bool
	}{
		{"passed", revision, "push", "completed", "success", true},
		{"manual", revision, "workflow_dispatch", "completed", "success", true},
		{"failed", revision, "push", "completed", "failure", false},
		{"running", revision, "push", "in_progress", "", false},
		{"different-source", strings.Repeat("b", 40), "push", "completed", "success", false},
		{"pr-only", revision, "pull_request", "completed", "success", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{"workflow_runs": []map[string]string{{
				"head_sha": tc.sha, "head_branch": "main", "event": tc.event,
				"status": tc.status, "conclusion": tc.conclusion,
			}}}
			data, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("python3", "hack/require-release-ci.py", revision)
			cmd.Dir = repoRoot(t)
			cmd.Stdin = bytes.NewReader(data)
			output, err := cmd.CombinedOutput()
			if (err == nil) != tc.allowed {
				t.Fatalf("unexpected release authorization: %v\n%s", err, output)
			}
		})
	}
}

// admissionSourcePath is the ClusterRole controller-gen derives from the
// webhook RBAC markers (ADR-005); it is also the Kustomize admission role.
const admissionSourcePath = "config/rbac/admission_role.yaml"

// verifyAdmissionSourceParity requires the chart's admission rights to equal
// those the webhook markers declare, with namespace reads narrowed to explicit
// names and access-object reads moved into the control namespaces.
func verifyAdmissionSourceParity(
	t *testing.T, objects []unstructured.Unstructured, release string, controls, targets []string,
) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), admissionSourcePath))
	if err != nil {
		t.Fatal(err)
	}
	sources := decode(t, data)
	if len(sources) != 1 || sources[0].GetKind() != "ClusterRole" {
		t.Fatalf("%s must hold exactly one ClusterRole", admissionSourcePath)
	}
	sourceRules := field(t, sources[0].Object, "rules").([]any)
	expectedRules := make([]any, 0, len(sourceRules))
	expectedControlRules := make([]any, 0, len(sourceRules))
	for _, raw := range sourceRules {
		rule := raw.(map[string]any)
		groups, _, _ := unstructured.NestedStringSlice(rule, "apiGroups")
		resources, _, _ := unstructured.NestedStringSlice(rule, "resources")
		switch {
		case slices.Equal(groups, []string{"access.breakglass.io"}):
			expectedControlRules = append(expectedControlRules, rule)
			continue
		case slices.Equal(resources, []string{"namespaces"}):
			rule["resourceNames"] = stringItems(observedNamespaces(targets, controls))
		}
		expectedRules = append(expectedRules, rule)
	}
	admissionRole := object(t, objects, "ClusterRole", release+"-admission-role", "")
	if !sameRules(t, field(t, admissionRole, "rules").([]any), expectedRules) {
		t.Fatal("admission RBAC has drifted from the generated webhook contract")
	}
	for _, control := range controls {
		access := object(t, objects, "Role", release+"-admission-access", control)
		if !sameRules(t, field(t, access, "rules").([]any), expectedControlRules) {
			t.Fatal("admission control-namespace RBAC has drifted from the generated webhook contract")
		}
	}
}

// sameRules compares two rule lists regardless of their order.
func sameRules(t *testing.T, a, b []any) bool {
	t.Helper()
	encode := func(rules []any) []string {
		encoded := make([]string, len(rules))
		for i, rule := range rules {
			data, err := json.Marshal(rule)
			if err != nil {
				t.Fatal(err)
			}
			encoded[i] = string(data)
		}
		slices.Sort(encoded)
		return encoded
	}
	return slices.Equal(encode(a), encode(b))
}

func controllerIdentityArg(release, namespace string) string {
	return "--request-controller-username=system:serviceaccount:" + namespace + ":" + release + "-controller-manager"
}

// placementArgPrefixes name the arguments the manager and admission must
// share: the namespace scope and the trusted controller identity (ADR-005).
var placementArgPrefixes = []string{
	"--allowed-target-namespaces=", "--control-namespaces=", "--request-controller-username=",
}

func placementArgs(args []string) []string {
	var placement []string
	for _, arg := range args {
		for _, prefix := range placementArgPrefixes {
			if strings.HasPrefix(arg, prefix) {
				placement = append(placement, arg)
			}
		}
	}
	return placement
}

func soleContainer(t *testing.T, deployment map[string]any) map[string]any {
	t.Helper()
	containers := field(t, deployment, "spec", "template", "spec", "containers").([]any)
	if len(containers) != 1 {
		t.Fatal("unexpected sidecar at the security boundary")
	}
	return containers[0].(map[string]any)
}

func hasArgPrefix(args []string, prefix string) bool {
	return slices.ContainsFunc(args, func(arg string) bool { return strings.HasPrefix(arg, prefix) })
}

// verifyAdmissionTopology checks the separate admission Deployment (ADR-005):
// only admission serves webhooks and mounts the serving certificate, and both
// Deployments run the same image, scope, availability and trust anchor.
func verifyAdmissionTopology(t *testing.T, objects []unstructured.Unstructured, release, namespace string) {
	t.Helper()
	object(t, objects, "ServiceAccount", release+"-admission", namespace)
	manager := object(t, objects, "Deployment", release+"-controller-manager", namespace)
	admission := object(t, objects, "Deployment", release+"-admission", namespace)
	managerContainer, admissionContainer := soleContainer(t, manager), soleContainer(t, admission)
	managerArgs, _, _ := unstructured.NestedStringSlice(managerContainer, "args")
	admissionArgs, _, _ := unstructured.NestedStringSlice(admissionContainer, "args")

	if !reflect.DeepEqual(field(t, managerContainer, "command"), []any{"/manager"}) ||
		!reflect.DeepEqual(field(t, admissionContainer, "command"), []any{"/admission"}) {
		t.Fatal("manager and admission must run their own binaries")
	}
	if managerContainer["image"] != admissionContainer["image"] {
		t.Fatal("manager and admission must run the same operator image")
	}
	if len(placementArgs(managerArgs)) != len(placementArgPrefixes) ||
		!reflect.DeepEqual(placementArgs(managerArgs), placementArgs(admissionArgs)) {
		t.Fatal("manager and admission placement arguments differ")
	}
	if !slices.Contains(admissionArgs, controllerIdentityArg(release, namespace)) {
		t.Fatal("admission must trust exactly the manager's ServiceAccount for request-sourced sessions")
	}
	if hasArgPrefix(admissionArgs, "--leader-elect") || !slices.Contains(managerArgs, "--leader-elect") {
		t.Fatal("only the manager uses leader election")
	}
	if !slices.Contains(admissionArgs, "--metrics-secure=true") {
		t.Fatal("admission metrics must be served securely")
	}
	if field(t, manager, "spec", "replicas") != field(t, admission, "spec", "replicas") {
		t.Fatal("admission must run as many replicas as the manager")
	}
	verifyWebhookServing(t, objects, release, namespace, manager, admission)
	verifyAdmissionAvailability(t, objects, release, namespace, manager, admission)
}

// verifyWebhookServing requires that only admission serves webhooks, holds the
// serving certificate and backs the webhook and admission metrics Services.
func verifyWebhookServing(
	t *testing.T, objects []unstructured.Unstructured, release, namespace string, manager, admission map[string]any,
) {
	t.Helper()
	managerContainer, admissionContainer := soleContainer(t, manager), soleContainer(t, admission)
	managerArgs, _, _ := unstructured.NestedStringSlice(managerContainer, "args")
	admissionArgs, _, _ := unstructured.NestedStringSlice(admissionContainer, "args")
	if hasArgPrefix(managerArgs, "--webhook-") {
		t.Fatal("manager must not serve webhooks")
	}
	if !slices.Contains(admissionArgs, "--webhook-port=9443") ||
		!slices.Contains(admissionArgs, "--webhook-cert-path=/tmp/k8s-webhook-server/serving-certs") {
		t.Fatal("admission must serve webhooks with the mounted serving certificate")
	}
	webhookSecret := release + "-webhook-server-cert"
	for _, component := range []struct {
		deployment, container map[string]any
		serves                bool
	}{{manager, managerContainer, false}, {admission, admissionContainer, true}} {
		ports, _, _ := unstructured.NestedSlice(component.container, "ports")
		servesPort := slices.ContainsFunc(ports, func(raw any) bool {
			port := raw.(map[string]any)
			return port["name"] == "webhook-server" || port["containerPort"] == float64(9443)
		})
		volumes, _, _ := unstructured.NestedSlice(component.deployment, "spec", "template", "spec", "volumes")
		mountsCert := slices.ContainsFunc(volumes, func(raw any) bool {
			name, _, _ := unstructured.NestedString(raw.(map[string]any), "secret", "secretName")
			return name == webhookSecret
		})
		if servesPort != component.serves || mountsCert != component.serves {
			t.Fatal("only admission may expose the webhook port and mount the serving certificate")
		}
	}

	// The webhook Service selects the admission pods and never the manager.
	admissionLabels, _, _ := unstructured.NestedStringMap(admission, "spec", "template", "metadata", "labels")
	managerLabels, _, _ := unstructured.NestedStringMap(manager, "spec", "template", "metadata", "labels")
	if admissionLabels["app.kubernetes.io/component"] != "admission" {
		t.Fatal("admission pods must carry the admission component label")
	}
	selectorMatches := func(selector, labels map[string]string) bool {
		for key, value := range selector {
			if labels[key] != value {
				return false
			}
		}
		return len(selector) > 0
	}
	service := object(t, objects, "Service", release+"-webhook-service", namespace)
	selector, _, _ := unstructured.NestedStringMap(service, "spec", "selector")
	if !selectorMatches(selector, admissionLabels) || selectorMatches(selector, managerLabels) {
		t.Fatal("webhook Service must select only the admission pods")
	}
	deploymentSelector, _, _ := unstructured.NestedStringMap(admission, "spec", "selector", "matchLabels")
	if !reflect.DeepEqual(deploymentSelector, selector) || selectorMatches(deploymentSelector, managerLabels) {
		t.Fatal("admission Deployment selector must not overlap the manager pods")
	}
	metrics := object(t, objects, "Service", release+"-admission-metrics-service", namespace)
	metricsSelector, _, _ := unstructured.NestedStringMap(metrics, "spec", "selector")
	if !reflect.DeepEqual(metricsSelector, selector) {
		t.Fatal("admission metrics Service must select the admission pods")
	}
}

// verifyAdmissionAvailability requires admission to follow the manager's
// host spreading and PodDisruptionBudget policy, each for its own pods.
func verifyAdmissionAvailability(
	t *testing.T, objects []unstructured.Unstructured, release, namespace string, manager, admission map[string]any,
) {
	t.Helper()
	deploymentSelector, _, _ := unstructured.NestedStringMap(admission, "spec", "selector", "matchLabels")
	spread := func(deployment map[string]any) ([]any, bool) {
		constraints, found, _ := unstructured.NestedSlice(deployment, "spec", "template", "spec", "topologySpreadConstraints")
		return constraints, found
	}
	managerSpread, managerSpreads := spread(manager)
	admissionSpread, admissionSpreads := spread(admission)
	if managerSpreads != admissionSpreads || len(managerSpread) != len(admissionSpread) {
		t.Fatal("admission host spreading must follow the manager")
	}
	if admissionSpreads {
		spreadSelector, _, _ := unstructured.NestedStringMap(
			admissionSpread[0].(map[string]any), "labelSelector", "matchLabels")
		if !reflect.DeepEqual(spreadSelector, deploymentSelector) {
			t.Fatal("admission spreading must select the admission pods")
		}
	}
	var managerPDB, admissionPDB map[string]any
	for _, item := range objects {
		if item.GetKind() == "PodDisruptionBudget" && item.GetNamespace() == namespace {
			switch item.GetName() {
			case release + "-controller-manager":
				managerPDB = item.Object
			case release + "-admission":
				admissionPDB = item.Object
			}
		}
	}
	if (managerPDB == nil) != (admissionPDB == nil) {
		t.Fatal("admission must have a PodDisruptionBudget exactly when the manager has one")
	}
	if admissionPDB != nil {
		pdbSelector, _, _ := unstructured.NestedStringMap(admissionPDB, "spec", "selector", "matchLabels")
		if !reflect.DeepEqual(pdbSelector, deploymentSelector) ||
			field(t, admissionPDB, "spec", "minAvailable") != field(t, managerPDB, "spec", "minAvailable") {
			t.Fatal("admission PodDisruptionBudget must protect the admission pods like the manager's")
		}
	}
}

// verifyAdmissionRBAC bounds admission to reading (ADR-005): it may ask
// authorization questions, get the target and control namespaces by name and
// read the access kinds in the control namespaces. It must never grant,
// extend or repair access.
func verifyAdmissionRBAC(
	t *testing.T, objects []unstructured.Unstructured, release, namespace string, targets, controls []string,
) {
	t.Helper()
	subject := map[string]any{"kind": "ServiceAccount", "name": release + "-admission", "namespace": namespace}
	allowed := map[string]bool{
		"ClusterRole/" + release + "-admission-role":    true,
		"ClusterRole/" + release + "-metrics-auth-role": true,
		"Role/" + release + "-admission-access":         true,
	}
	for _, item := range objects {
		if item.GetKind() != "ClusterRoleBinding" && item.GetKind() != "RoleBinding" {
			continue
		}
		subjects, _, _ := unstructured.NestedSlice(item.Object, "subjects")
		if !slices.ContainsFunc(subjects, func(raw any) bool { return reflect.DeepEqual(raw, subject) }) {
			continue
		}
		ref := field(t, item.Object, "roleRef", "kind").(string) + "/" + field(t, item.Object, "roleRef", "name").(string)
		if !allowed[ref] {
			t.Fatalf("admission is bound to unexpected %s through %s", ref, item.GetName())
		}
		if ref == "Role/"+release+"-admission-access" && !slices.Contains(controls, item.GetNamespace()) {
			t.Fatal("admission reads access objects outside the control namespaces")
		}
	}

	want := []any{
		map[string]any{
			"apiGroups": []any{"authorization.k8s.io"}, "resources": []any{"subjectaccessreviews"},
			"verbs": []any{"create"},
		},
		map[string]any{
			"apiGroups": []any{""}, "resources": []any{"namespaces"},
			"resourceNames": stringItems(observedNamespaces(targets, controls)), "verbs": []any{"get"},
		},
	}
	role := object(t, objects, "ClusterRole", release+"-admission-role", "")
	if rules := field(t, role, "rules"); !reflect.DeepEqual(rules, want) {
		t.Fatalf("admission ClusterRole exceeds its read-only contract: %v", rules)
	}
	binding := object(t, objects, "ClusterRoleBinding", release+"-admission-rolebinding", "")
	if field(t, binding, "roleRef", "name") != release+"-admission-role" ||
		!reflect.DeepEqual(field(t, binding, "subjects"), []any{subject}) {
		t.Fatal("admission ClusterRole is bound to the wrong identity")
	}
	wantAccess := []any{map[string]any{
		"apiGroups": []any{"access.breakglass.io"},
		"resources": []any{"accessprofiles", "breakglassapprovals", "breakglassrequests", "breakglasssessions"},
		"verbs":     []any{"get", "list"},
	}}
	for _, control := range controls {
		access := object(t, objects, "Role", release+"-admission-access", control)
		if !reflect.DeepEqual(field(t, access, "rules"), wantAccess) {
			t.Fatalf("admission may only get and list access objects in %s", control)
		}
		binding := object(t, objects, "RoleBinding", release+"-admission-access", control)
		if !reflect.DeepEqual(field(t, binding, "subjects"), []any{subject}) {
			t.Fatal("admission access Role is bound to the wrong identity")
		}
	}

	// The manager no longer answers admission questions (ADR-005).
	for _, raw := range field(t, object(t, objects, "ClusterRole", release+"-manager-role", ""), "rules").([]any) {
		resources, _, _ := unstructured.NestedStringSlice(raw.(map[string]any), "resources")
		if slices.Contains(resources, "subjectaccessreviews") {
			t.Fatal("manager must not keep the webhooks' SubjectAccessReview right")
		}
	}
}
