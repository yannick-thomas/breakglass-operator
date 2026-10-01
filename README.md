# BreakGlass Operator

The BreakGlass Operator provides Kubernetes-native, **namespaced**,
time-bound emergency access. It is intended for the narrow but common gap
between permanent production access and an incident where an on-call engineer
needs a small, auditable permission set for a short time.

`v1alpha1` supports two explicit, conservative delivery modes:

```text
AccessProfile (admin-owned, fixed role + namespace + maximum duration)
        │
        ├─ SelfService: requester has RBAC verb use
        │       │
        │       ▼
        │   BreakGlassSession (profile + duration + reason)
        │
        └─ ApprovalRequired: requester use → request → independent approve
                                                │
                                                ▼
                                     controller-sourced BreakGlassSession
                                                │
                                                ▼
one UID-tracked RoleBinding in the profile's fixed namespace
        │
        └─ revoked, expired, or suspended on integrity failure
```

There is no free-form role, target namespace, or grantee in a self-service
request. A `ClusterRole` is bound through a namespaced `RoleBinding`; this
does **not** make the grant cluster-wide.

## What is protected

* **Controlled delegation:** `AccessProfile` fixes the curated `ClusterRole`,
  target namespace, and maximum duration. Its policy fields are immutable.
  The controller reports a `Ready` condition before an incident, including
  invalid durations, missing curated roles, and namespaces outside the
  manager's configured scope.
* **Real requester identity:** the mutating webhook overwrites `spec.subject`
  and snapshots the profile UID from Kubernetes' authenticated admission
  request. Human self-service is the only supported subject model for now.
* **Profile-specific authorization:** the validating webhook performs a
  `SubjectAccessReview` for the custom verb `use` on exactly the named
  `AccessProfile`.
* **Independent approval where required:** `deliveryMode: ApprovalRequired`
  denies direct sessions. A requester creates immutable intent, a different
  human with the named `approve` verb records one append-only decision, and
  only the configured controller identity may create the resulting session.
  Request, approval, session, profile and binding are linked by server-issued
  UIDs; the active session rechecks that chain and suspends on source drift.
* **Fail-closed lifecycle:** the standard Kustomize deployment installs TLS
  webhooks with `failurePolicy: Fail` and a five-second timeout. A missing,
  replaced, or modified binding suspends the session; it is never silently
  recreated.
* **UID-safe cleanup:** the controller persists the server-issued RoleBinding
  UID and uses it as a deletion precondition. A replacement object with the
  same name is never adopted or deleted.
* **Curated-role integrity:** activation snapshots the referenced ClusterRole's
  UID and canonical rules hash. A missing, replaced, or rule-drifted role
  suspends the active session and removes only its UID-tracked RoleBinding.
* **Least-privilege sample:** `breakglass-pod-observer` permits only pod,
  event, and pod-log observation. It intentionally excludes secrets, exec,
  attach, port-forward, writes, and workload edits.

Kubernetes Events and status conditions are operational signals. Durable
forensics belong in Kubernetes audit logs and a restricted SIEM/audit sink;
Prometheus is not an audit database. See [the security design](docs/security-design.md)
and [operational metrics](docs/observability.md). The reviewed production
release gates and the longer-term product direction are documented in the
[security review](docs/security-review.md) and [product vision](docs/product-vision.md).

## Prerequisites and deployment

The default deployment includes the admission webhooks and cert-manager
resources. Install cert-manager in the cluster first, then deploy the operator:

```bash
make deploy IMG=<your-registry>/breakglass-operator:<tag>
```

For a multi-node production cluster, use the production availability overlay
instead. It retains the same secure default and adds two controller replicas,
leader election, hostname spreading, and a PodDisruptionBudget:

```bash
kubectl apply -k config/overlays/production
```

See [production operations](docs/production-operations.md) for readiness,
upgrade, recovery, and metrics-boundary checks. The overlay intentionally
requires two schedulable nodes; use a separately reviewed development overlay
for a single-node environment.

For a high-assurance installation with profiles that target only known
namespaces, start from the single-namespace
[namespaced production overlay](config/overlays/production-namespaced). It
removes the manager's global RoleBinding CRUD and aligns its cache, admission,
controller policy, and namespaced RBAC to the approved namespace set.

Do not expose `BreakGlassSession` self-service access through a CRD-only or
`make run` installation: the admission configuration is part of the security
boundary. The manager always registers its webhooks; the default Kustomize
configuration mounts a cert-manager-issued serving certificate and injects its
CA into both webhook configurations.

The generated manager role has `bind` only for the sample curated role
`breakglass-pod-observer`. When introducing another profile role, extend the
deployment RBAC deliberately with that exact role name before deploying it.
Do not replace this with unrestricted `bind`.

### Downloadable installer bundles

Every successful gated CI run on `main` publishes a GitHub Actions artifact named
`breakglass-operator-install-<commit>`. It contains the fully rendered,
single-file installers `install.yaml`, `install-production.yaml`, and
`install-production-namespaced.yaml`. Their manager image is pinned by digest,
so the reviewed manifest and the executed image cannot drift apart. The image
bundle supports both `linux/amd64` and `linux/arm64` clusters.

Download the artifact from the **CI** workflow, select the one
profile that matches your cluster, and apply it directly. For example:

```bash
# cert-manager must already be installed and ready.
# The namespaced profile deliberately expects this approved target namespace.
kubectl create namespace production --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f install-production-namespaced.yaml
```

For a versioned production release, download the same digest-pinned YAML files
and `SHA256SUMS` from the matching GitHub Release. Before applying the
namespaced installer, run `make preflight-production-namespaced`; it verifies
cert-manager and the deliberately pre-existing `production` namespace without
changing the cluster.

The first GitHub Container Registry package may need to be made readable by
the target cluster (or public for unauthenticated pulls) in its package
settings. Do not apply more than one installer profile to the same cluster.
The bundle intentionally does not install cert-manager or create an
application namespace: both are cluster-level decisions that should remain
under platform-team control.

The installer intentionally does **not** include generic Kubebuilder
`Admin`/`Editor`/`Viewer` roles for either CRD. Define platform-admin and
requester permissions explicitly; a broad profile-editor role could otherwise
delete and recreate a profile name with a different policy.

### Upgrade from the original free-form API

This `v1alpha1` revision is intentionally incompatible with the original
free-form `roleRef`/`targetNamespace` session shape. It does not infer a new
profile for an old active grant. Before upgrading a live cluster:

1. Inventory active sessions and let them expire or revoke them explicitly.
2. Back up the existing custom resources and record the installed controller
   image/configuration.
3. Install the CRDs, cert-manager resources, webhook service, and webhook
   configurations together; verify the webhooks are ready before granting
   anyone `create` on `breakglasssessions`.
4. Apply curated roles, profiles, and profile-scoped `use` RBAC, then run a
   harmless namespaced request as a rollout check.

Treat rollback as a tested operational procedure: do not restore a controller
that accepts free-form sessions while its CRD or authorization boundaries have
already been changed.

## Minimal profile and request

An administrator first creates a curated role and an immutable profile:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: breakglass-pod-observer
rules:
  - apiGroups: [""]
    resources: ["pods", "events"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]
---
apiVersion: access.breakglass.io/v1alpha1
kind: AccessProfile
metadata:
  name: production-pod-observer
spec:
  roleRef:
    kind: ClusterRole
    name: breakglass-pod-observer
  targetNamespace: production
  maxDuration: 30m
  deliveryMode: SelfService
```

Give an on-call group normal `create` access to `breakglasssessions` and only
the selected profile's custom `use` permission. `resourceNames` is the key
restriction:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: breakglass-production-observer-requester
rules:
  - apiGroups: ["access.breakglass.io"]
    resources: ["breakglasssessions"]
    verbs: ["create", "get", "list", "watch", "patch"]
  - apiGroups: ["access.breakglass.io"]
    resources: ["accessprofiles"]
    resourceNames: ["production-pod-observer"]
    verbs: ["use"]
```

`patch` is intentionally limited to early self-revocation: admission permits
only the immutable request fields plus the one-way `spec.revoked: true`
transition, and it rejects an attempt to change another requester's session.
The repository also supplies an unbound, profile-specific requester role and
a separate audit-reader role in `config/samples/`; bind them to distinct
on-call and audit groups through your GitOps policy.

The requester submits only intent; do not provide `subject` or
`accessProfileUID` because the mutating webhook owns both fields:

```yaml
apiVersion: access.breakglass.io/v1alpha1
kind: BreakGlassSession
metadata:
  generateName: incident-db-
spec:
  accessProfile: production-pod-observer
  duration: 20m
  reason: "INC-1092: investigate database connection exhaustion"
```

Inspect the lifecycle:

```bash
kubectl get accessprofiles
kubectl describe accessprofile production-pod-observer
kubectl get bgs
kubectl describe bgs <session-name>
kubectl get rolebinding -n production -l access.breakglass.io/session=<session-name>
```

An `AccessProfile` must report `Ready=True` before it can be relied on during
an incident. `Ready=False` explains the platform configuration problem; fix it
by creating the referenced curated role, choosing a positive `maxDuration`, or
including the profile's namespace in the manager's
`--allowed-target-namespaces` configuration. `Ready` is a deployment preflight,
not an authorization grant: requesters still need the profile-specific `use`
permission described above.

For early revocation, set the one-way field below. All access request fields
remain immutable.

```bash
kubectl patch bgs <session-name> --type=merge -p '{"spec":{"revoked":true}}'
```

## Approval-required workflow

Use an approval-required profile for higher-risk production access. The
repository supplies a least-privilege sample profile plus distinct requester
and approver roles in `config/samples/`. Bind those roles to different groups
through GitOps; neither role receives RoleBinding, `bind`, or controller
credentials.

```yaml
apiVersion: access.breakglass.io/v1alpha1
kind: BreakGlassRequest
metadata:
  name: incident-db-approval
spec:
  accessProfile: production-pod-observer-approval
  duration: 20m
  reason: "INC-1092: investigate database connection exhaustion"
---
apiVersion: access.breakglass.io/v1alpha1
kind: BreakGlassApproval
metadata:
  # The webhook replaces this with the one deterministic slot for the request.
  generateName: incident-db-approval-
spec:
  requestRef:
    name: incident-db-approval
  decision: Approved
  comment: "Incident commander approval"
```

The requester supplies neither `requester`, `accessProfileUID` nor
`requestTTL`; the approver supplies neither request UID nor `approver`. The
webhooks derive those values from the authenticated Kubernetes identity and
server state. Do not grant requesters broad `list` or `watch` access to the
cluster-scoped request resource: it can reveal other incidents. See the
[request workflow design](docs/breakglass-request-design.md) and
[ADR-001](docs/adr-001-single-grant-path.md) for the full trust boundary.

## Development and verification

```bash
make generate manifests
make build
go test ./...                 # Requires local envtest processes/ports
```

Focused unit tests cover requester attribution, profile authorization,
UID-safe cleanup, drift suspension, TTL scheduling, and metric privacy. Some
sandboxed environments prohibit envtest from opening loopback listeners; the
CI/Kind pipeline should run the full webhook and lifecycle suite.

The operator does not yet claim a Kubernetes version range. Required Kind/E2E
runs capture the evidence needed to qualify one exact, digest-pinned tuple;
see [Compatibility qualification](docs/compatibility.md).

## Current scope and next gates

This is intentionally not a generic PAM replacement. It is most useful as a
small, Kubernetes-native production-access primitive beside existing OIDC,
RBAC, GitOps, audit, and incident systems.

Before a broad rollout of approval-required profiles, prioritize the
production install gate, curated-role integrity (a role name alone does not
freeze its rules), alert/runbook/audit integration, and realistic Kind/E2E
tests for every request-to-session recovery point. CLI, ChatOps and a future
optional WebUI must remain clients of this single server-verified path; they
must not create a second approval or RBAC grant model. The ranked rationale is
maintained in [ROADMAP.md](ROADMAP.md).
