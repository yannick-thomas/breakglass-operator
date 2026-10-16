# ADR-005: Run admission separately from the grant controller

**Status:** Accepted, implemented
**Scope:** The manager Deployment, the admission webhooks, their RBAC,
certificates, Helm and Kustomize installations, and the E2E suites.

## Context

One `manager` Deployment ran the reconcilers and every admission webhook.
Two problems follow:

- **The network-facing component holds the strongest identity.** The webhook
  server accepts calls from the API server. It ran under the ServiceAccount
  that may `bind` the curated ClusterRoles and create and delete RoleBindings
  in every target namespace. A flaw in the admission path would therefore be
  a flaw in the one identity that can grant access.
- **Admission availability follows the controller lifecycle.** A controller
  rollout, crash or memory pressure also removes webhook endpoints. Since
  admission fails closed, a controller restart blocks every new request and
  session, and the control-namespace drain check (ADR-004) blocks namespace
  deletion. The production E2E suite already shows webhook timeouts right
  after a rolling manager restart.

## Decision

1. **Two Deployments from one image.** The image gains a third binary,
   `/admission` (`cmd/admission`), beside `/manager` and `/expiry-guard`.
   `release.json` and the chart keep pinning one operator image digest.
2. **`admission` serves every webhook.** It registers the session, request,
   approval and control-namespace webhooks with the same placement flags as
   the manager (`--allowed-target-namespaces`, `--control-namespaces`) and
   `--request-ttl`. It runs no reconciler, needs no leader election, and runs
   at least two replicas with a PodDisruptionBudget and host spreading, like
   the manager.
3. **`manager` serves no webhook.** It keeps the reconcilers, leader
   election, metrics and the session state collector. It loses the webhook
   server, port and serving certificate.
4. **Separate least-privilege identities.**
   - `admission`: create `subjectaccessreviews`; get and list the four access
     kinds in the control namespaces; get namespaces by name (control and
     target). No `bind`, no `escalate`, no RoleBinding or Session writes, no
     status writes.
   - `manager`: unchanged except that rules only the webhooks needed are
     removed.
5. **The controller identity stays the trust anchor for sourced sessions.**
   Admission accepts a request-sourced session only from the manager's
   ServiceAccount username (`--request-controller-username`), exactly as
   before. The value now names a different ServiceAccount than the one
   admission runs as.
6. **Names.**

   | Object | Kustomize (default prefix) | Helm |
   | --- | --- | --- |
   | Deployment, ServiceAccount | `breakglass-operator-admission` | `<release>-admission` |
   | Pod label | `app.kubernetes.io/component: admission` | same |
   | Webhook Service | `breakglass-operator-webhook-service`, selecting the admission pods | `<release>-webhook-service`, same |
   | Serving certificate | unchanged name, mounted into admission only | same |

   Keeping the Service and certificate names keeps the webhook
   configurations, CA injection and existing checks stable.

## Consequences

- A compromised or buggy admission pod can read access objects and ask the
  API server authorization questions. It cannot grant, extend or repair
  access.
- Admission can be rolled, scaled and restarted without touching the
  controller, and the reverse. Each keeps its own PodDisruptionBudget.
- A manager outage no longer blocks requests, approvals or the drain check;
  only provisioning and cleanup wait. An admission outage still fails closed.
  The E2E outage scenarios scale the admission Deployment.
- A terminating admission pod reports not ready but keeps answering for
  `--shutdown-delay` (default 15s, below the 30s termination grace period).
  Endpoint removal and node proxy updates lag behind pod termination; a
  webhook that stopped at once would make the API server call a dead address
  until its 5s timeout, and admission fails closed. The Helm E2E upgrade, which
  rolls the admission pods, showed exactly this.
- One more Deployment, ServiceAccount and set of RBAC objects to operate.
  Both Deployments must run the same image and the same placement flags;
  the chart and the overlays render both from one value set, and the
  manifest checks fail if they differ.
- Upgrading from a single-Deployment installation is a reinstall within the
  same unreleased `v1alpha1` line (ADR-004); no migration path is provided.

## Alternatives considered

- **Keep one Deployment, split only RBAC per container.** Kubernetes
  authorizes the Pod's ServiceAccount, not the container; both containers
  would still share one identity.
- **A `--mode` flag on `/manager`.** Equivalent at runtime, but a separate
  binary keeps admission free of controller wiring and makes the
  architecture test able to forbid reconciler imports in `cmd/admission`.
