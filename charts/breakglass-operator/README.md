# BreakGlass Operator Helm chart

This chart installs the existing Kubernetes grant path with namespace-restricted
RBAC, fail-closed TLS admission, a separate expiry guard, and two manager replicas
by default. It does not install cert-manager, application namespaces, curated
roles, AccessProfiles, or requester/approver group bindings. Manage policy in a
separate GitOps application and sync it only after admission is ready.

The initial CI qualification uses Helm **4.3.0**. Kubernetes compatibility remains
subject to [the repository's qualification process](../../docs/compatibility.md);
the chart does not introduce a new supported Kubernetes version range.

## Installation

Install cert-manager first and create the approved application namespaces. Use a
unique release name of at most 28 characters; names are derived from the release
name and namespace, including the controller identity admission trusts. Install
exactly one operator instance per cluster: the CRDs and reconciliation domain are
cluster-scoped. Do not install Helm beside an existing Kustomize installation or
use `--take-ownership` as an unreviewed migration.

Source installs deliberately require an image from successful gated CI or a
release. The chart never silently defaults to `latest` or claims that an image
exists for an unreleased version.

```yaml
# deployment-values.yaml
image:
  repository: ghcr.io/yannick-thomas/breakglass-operator
  digest: sha256:<digest-from-a-successful-gated-build>
allowedTargetNamespaces:
  - production
  - payments
curatedClusterRoles:
  - breakglass-pod-observer
  - breakglass-payments-diagnostics-v1
```

```bash
kubectl get crd certificates.cert-manager.io issuers.cert-manager.io
kubectl get namespace production payments
helm upgrade --install breakglass-operator ./charts/breakglass-operator \
  --namespace breakglass-operator-system --create-namespace \
  --values deployment-values.yaml --wait --timeout 5m
```

After a versioned release containing this chart has been published, its `.tgz`
is also available as a GitHub Release asset and at
`oci://ghcr.io/yannick-thomas/charts/breakglass-operator`. Release packages default
to the **same image digest** as that release's installer YAMLs:

```bash
helm upgrade --install breakglass-operator \
  oci://ghcr.io/yannick-thomas/charts/breakglass-operator \
  --version <released-chart-version> \
  --namespace breakglass-operator-system --create-namespace \
  --values deployment-values.yaml --wait --timeout 5m
```

The first GHCR chart/image packages may need to be made readable by the target
environment. Chart publication is a release-workflow action, not an installation
side effect. CI builds also attach digest-pinned development chart packages to the
installer artifact; they do not publish unversioned charts to the OCI registry.

Before granting `create`, `use`, or `approve`, verify two ready managers, ready
serving certificates, and non-empty webhook CA bundles. Then create the reviewed
profiles/roles and run a harmless, attributed request through expiry. The default
curated role name is an RBAC allowlist entry, not an installed role or access grant.

## Configuration and fixed boundaries

| Value | Purpose |
| --- | --- |
| `image.repository`, `image.digest` | Immutable operator image; also used by the guard. An explicit `image.tag` is permitted for reviewed development installs; digest and tag are mutually exclusive. |
| `allowedTargetNamespaces` | Non-empty, unique namespace names. The same set controls manager/guard arguments, namespaced Roles/RoleBindings, and named Namespace observation. |
| `curatedClusterRoles` | Non-empty, unique names; the manager receives `get` and `bind` only on these roles. |
| `replicaCount`, `availability.*` | Defaults: two replicas, hostname spreading, PDB with one available replica. |
| `resources`, `nodeSelector`, `tolerations`, `priorityClassName` | Manager/guard scheduling and resource settings. |
| `certManager.issuerRef` | Optional existing `Issuer` or `ClusterIssuer`; otherwise create the local self-signed Issuer used by the Kustomize deployment. |
| `expiryGuard.*` | Sweep schedule, grace, timeout and resources. The guard cannot be disabled through values. |
| `metrics.serviceMonitor.*` | Optional monitor; an explicit CA Secret is required and TLS verification remains enabled. |
| `metrics.prometheusRule.*` | Optional lifecycle, integrity, cleanup and guard alerts. |
| `webui.*` | Optional OIDC client, read-only facade, separate image and HTTPS ingress. Disabled by default. |

There is no `extraArgs`, arbitrary RBAC rule, webhook-disable, failure-policy, or
security-context override. Values schema rejects unknown keys, empty scope,
wildcards, invalid images, and incomplete optional integrations. Templates also
refuse empty/wildcard scope even if someone skips schema validation. Pod security,
leader election, webhook paths/operations, CA injection and attributed controller
identity are part of the installation contract.

For single-node development, explicitly set `replicaCount: 1`,
`availability.spreadAcrossHosts: false`, and
`availability.podDisruptionBudget.enabled: false`. This changes availability only;
admission and namespaced RBAC remain enforced. Never remove a namespace or curated
role from an upgrade while an active grant depends on it: revoke/drain those grants
and prove cleanup before removing the controller's ability to clean them up.

### Metrics

Install the Prometheus Operator CRDs before enabling monitoring. Set monitor/rule
labels to match your Prometheus selectors. `caSecretName` is a Secret in the
**release namespace** that contains the reviewed serving CA; for the default
self-signed metrics certificate it can be `<release>-metrics-server-cert`.
For an external issuer, supply the trust bundle required by that issuer.

Bind the chart's **unbound** `<release>-metrics-reader` ClusterRole to the actual
Prometheus ServiceAccount separately. The monitor uses that scraper's bearer
token; no broad metrics-reader binding is created by this chart. The scraper must
also be permitted to resolve the CA Secret. The guard alerts require
kube-state-metrics; select the release's namespace/Service when composing dashboards
or alert routing in a shared Prometheus deployment.

NetworkPolicies are deliberately cluster-specific GitOps resources. Review ingress
from API servers, kubelet probes, ingress controllers and scrapers, and egress to
the API server, DNS and OIDC provider. This chart does not claim to know those
addresses or install a generic permissive network policy.

### Optional WebUI

Enable `webui.enabled` only with an explicit WebUI image, an HTTPS `publicURL`,
OIDC issuer and client ID. The Kubernetes API server must trust that issuer and
client audience and map the token to the intended Kubernetes username/groups.
Writes use the human's token; the UI ServiceAccount receives only CRD `get/list`.
Review the [WebUI trust boundary](../../docs/WEBUI.md) before exposing it.

If the provider requires a client secret, reference an existing Secret using
`webui.oidc.existingSecret` and `clientSecretKey`. The chart never embeds OIDC secrets
in values. If `webui.ingress.enabled` is set, `host` must match `publicURL` and a TLS
Secret is required. If ingress is disabled, supply a separately reviewed HTTPS
gateway. Enforce HTTPS redirects at that gateway; a TLS block alone does not
configure every ingress controller's redirect policy.

The UI uses one replica and `Recreate` because sessions live in memory. Upgrades
may require users to log in again; UI removal does not revoke existing grants.

## CRDs, upgrades and removal

The four files in `crds/` are byte-identical copies of `config/crd/bases/`.
Run `make helm-sync-crds` after generating CRD changes. CI checks synchronization.
Helm installs missing CRDs from this directory, but does **not** upgrade or delete
them. Do not move CRDs into ordinary templates or uninstall them to force an update.

For each upgrade:

1. Record the old chart, values, image digest, CRDs, webhook state and active grants.
2. Review the API change and its migration procedure. Apply the new release's CRDs
   explicitly, using its checkout (`kubectl apply -f charts/breakglass-operator/crds/`)
   or extracted chart package. Do not blindly replace an incompatible live schema.
3. Drain any grants affected by a removed namespace, curated role or incompatible
   API change before changing RBAC. Keep cert-manager and admission running.
4. Upgrade the pinned chart/image; verify certificates, webhook CA injection, an
   attributed test request and confirmed cleanup.

Helm upgrade E2E qualifies a rollout **within this chart version** that retains the
exact active RoleBinding UID. It is not a cross-version API/rollback guarantee.
Never roll back to the removed free-form access API.

Before `helm uninstall`, remove requester/approver permissions, resolve outstanding
requests, and revoke/drain every session while manager and guard are still alive.
For every `status.bindingRef`, verify that the recorded **namespace/name/UID** no
longer represents a live grant. An ambiguous/replaced binding is a security
investigation, not permission to run a broad label delete. Preserve audit evidence.

Only then uninstall the release. Helm leaves CRDs and their historical resources
in place; it removes manager, guard, webhooks, certificates and chart-owned RBAC.
Uninstall is **not** a revocation mechanism and there is no hook claiming otherwise.
Do not delete the CRDs until retention, finalizers and cleanup have been reviewed.

## Development and verification

```bash
make verify-helm
make test-e2e-helm             # dedicated Kind cluster with two workers
make package-helm IMG=<repository>@sha256:<digest> CHART_VERSION=0.1.0
```

`verify-helm` runs strict lint, the **same production-namespaced manifest checks**
used by Kustomize, multi-namespace/custom-release contract tests, invalid-value
tests, webhook/RBAC source parity and CRD synchronization. The Helm Kind job runs
the production failure/lifecycle suite, including an active-grant Helm upgrade.
Release publication waits for those gates and uses the already gated image.
