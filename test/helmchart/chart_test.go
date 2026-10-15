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
			verifyRoleBoundary(t, objects, tc.release, tc.namespace, tc.targets, tc.roles)
			verifyControlBoundary(t, objects, tc.release, tc.namespace, tc.controls)
			verifyAdmission(t, objects, tc.release, tc.namespace)
			verifySourceParity(t, objects, tc.release, tc.controls, tc.targets, tc.roles)
			manager := object(t, objects, "Deployment", tc.release+"-controller-manager", tc.namespace)
			managerPod := field(t, manager, "spec", "template", "spec").(map[string]any)
			verifyPod(t, managerPod, tc.release+"-controller-manager", tc.targets, tc.controls)
			container := field(t, managerPod, "containers").([]any)[0].(map[string]any)
			args, _, _ := unstructured.NestedStringSlice(container, "args")
			identity := "--request-controller-username=system:serviceaccount:" +
				tc.namespace + ":" + tc.release + "-controller-manager"
			if !slices.Contains(args, identity) {
				t.Fatal("admission controller identity does not match rendered ServiceAccount")
			}
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

func verifyRoleBoundary(
	t *testing.T, objects []unstructured.Unstructured, release, namespace string, targets, roles []string,
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
					if !reflect.DeepEqual(names, targets) || !reflect.DeepEqual(verbs, []string{"get"}) {
						t.Fatal("namespace observation must match the explicit target set")
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
	for _, name := range []string{release + "-manager-role", release + "-expiry-guard-role"} {
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

func verifyAdmission(t *testing.T, objects []unstructured.Unstructured, release, namespace string) {
	t.Helper()
	for _, mode := range []struct{ kind, suffix string }{
		{"MutatingWebhookConfiguration", "mutating"}, {"ValidatingWebhookConfiguration", "validating"},
	} {
		config := object(t, objects, mode.kind, release+"-"+mode.suffix+"-webhook-configuration", "")
		annotations, _, _ := unstructured.NestedStringMap(config, "metadata", "annotations")
		if annotations["cert-manager.io/inject-ca-from"] != namespace+"/"+release+"-serving-cert" {
			t.Fatal("webhook CA injection must reference the rendered certificate")
		}
		webhooks := field(t, config, "webhooks").([]any)
		if len(webhooks) != 3 {
			t.Fatal("all three admission resources must be protected")
		}
		for _, raw := range webhooks {
			webhook := raw.(map[string]any)
			if webhook["failurePolicy"] != "Fail" || webhook["sideEffects"] != "None" ||
				webhook["timeoutSeconds"] != float64(5) {
				t.Fatal("webhooks must fail closed with a bounded timeout")
			}
			if _, exists := webhook["namespaceSelector"]; exists {
				t.Fatal("namespace selector may bypass admission")
			}
			if _, exists := webhook["objectSelector"]; exists {
				t.Fatal("object selector may bypass admission")
			}
			for _, rule := range field(t, webhook, "rules").([]any) {
				if rule.(map[string]any)["scope"] != "Namespaced" {
					t.Fatal("admission must match the namespaced access objects")
				}
			}
			service := field(t, webhook, "clientConfig", "service").(map[string]any)
			if service["name"] != release+"-webhook-service" || service["namespace"] != namespace {
				t.Fatal("webhook points at the wrong Service")
			}
		}
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
		if slices.Equal(resources, []string{"rolebindings"}) ||
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
			for _, rule := range rules {
				rule.(map[string]any)["scope"] = "Namespaced"
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
		{"controller-manager", managerImage}, {"webui", webuiImage},
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
