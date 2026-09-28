# Security review

**Review date:** 2026-09-28

**Reviewed revision:** `8aa3ee3`
**Method:** manual static review of API types, admission, reconciliation, RBAC,
rendered Kustomize configuration, container/CI configuration, and focused unit
tests. This is not a penetration test, a Kubernetes cluster assessment, or a
substitute for an independent release review.

## Executive summary

The current API is a meaningful improvement over a free-form break-glass CR:
the requester cannot choose the grantee, role, or target namespace; admission
uses Kubernetes-authenticated identity and named-profile `use` authorization;
and bindings are cleaned up only when their server-issued UID still matches.

It is **not yet ready for an unrestricted production rollout**. The remaining
risks are concentrated at the installation and policy-authoring boundary, not
in the ordinary self-service request shape. In particular, a generic manager
installation can create RoleBindings in every namespace, and a profile freezes
a ClusterRole *name* but not the role's rules. Both must be addressed before
using high-impact profiles.

## Scope and trust boundaries

| Asset | Required protection | Current boundary |
| --- | --- | --- |
| Emergency Kubernetes permissions | Only approved user, role, namespace, and TTL may receive them | `AccessProfile`, admission, controller snapshot, RoleBinding UID |
| Requester identity | Must come from Kubernetes authentication, never from YAML | Mutating and validating admission webhook |
| Profile delegation | Requesters may use only explicitly named profiles | `SubjectAccessReview` with custom `use` verb |
| Binding cleanup | Must not delete a replacement or unrelated binding | Recorded binding UID plus delete precondition |
| Incident reason and identity | Must not leak through broad observability access | RBAC for CR reads; metrics use bounded non-identifying labels |
| Manager identity | Must not become a general RBAC escalation proxy | `bind` is named-role restricted; namespace scope is still broad |

### Assumptions that must hold in every installation

* Kubernetes API authentication is trustworthy and requesters cannot bypass the
  configured admission webhooks.
* Only a tightly controlled platform/security group can create or replace
  `AccessProfile` objects, curated roles, manager RBAC, or webhook resources.
* Requesters receive `create` and named-profile `use` rights only; they do not
  receive broad update, delete, list, or profile-authoring rights by default.
* Kubernetes audit logs are retained outside the cluster with access controls
  appropriate for incident identities and reasons.

## Confirmed controls

* The request CR does not offer a free `roleRef`, target namespace, or subject.
* The mutating webhook overwrites the grantee with
  `AdmissionRequest.userInfo.username`; the validator checks it again.
* `SubjectAccessReview` authorizes `use` on the specific `AccessProfile` name.
* `AccessProfile` policy fields are immutable; profile UID is snapshotted to
  detect delete/recreate under the same name.
* Current grants are strictly namespaced `RoleBinding` objects, not
  `ClusterRoleBinding` objects.
* Binding owner reference, labels, role, subject, namespace, name, and UID are
  all verified. Drift suspends access instead of repairing/regranting it.
* Cleanup uses a Kubernetes UID precondition. A replacement with the same name
  is deliberately left untouched.
* Webhooks are configured fail-closed with TLS/CA injection. Metrics are HTTPS
  with authentication/authorization and avoid high-cardinality identity labels.

## Findings and release gates

| ID | Priority | Finding | Required disposition |
| --- | --- | --- |
| SR-01 | P0 | The generic manager ClusterRole can create/delete/read RoleBindings cluster-wide. | The `production-namespaced` overlay removes that rule and binds it only in an explicit namespace; use it (or an equivalent multi-namespace GitOps composition) for high-assurance profiles. Do not treat the generic default as a high-assurance production policy. |
| SR-02 | P0 | A profile snapshots a curated `ClusterRole` name but not its rule set. Editing that ClusterRole can widen an already active session immediately. | Complete [issue #4](https://github.com/yannick-thomas/breakglass-operator/issues/4): immutable/versioned roles plus rule hash/UID snapshot, role watch, and suspend-on-drift. |
| SR-03 | P0 | Fail-closed admission is configured but not yet proven under webhook outage, controller restart, certificate rotation, and binding replacement in a real cluster. | Complete [issue #3](https://github.com/yannick-thomas/breakglass-operator/issues/3) with Kind/E2E and upgrade/rollback test gates before granting production requester rights. |
| SR-04 | P1 | “Human-only” rejects standard ServiceAccount usernames, but does not assert an OIDC issuer, verified human claim, or approved identity group. A non-standard workload identity with RBAC could appear as a user. | Define the supported identity provider and an allowlisted requester group/claim at the platform boundary. Add a policy extension only when it can be enforced and tested without duplicating IdP logic. |
| SR-05 | P1 | `BreakGlassSession` contains requester identity and incident reason. Any principal with broad `get/list/watch` rights can read sensitive operational context. | Ship least-privilege requester/viewer RBAC examples, separate an audit-reader role, and restrict CR reads. Keep reasons and identities out of Prometheus labels. |
| SR-06 | P1 | TTL cleanup is controller-driven. During a total controller outage an expired RoleBinding can remain effective until recovery or the audited emergency procedure runs. | Meet the HA/PDB gate, alert on past-expiry sessions, test recovery, and document an offline process that checks binding UID before action. Longer term, pair JIT RBAC with short-lived human credentials. |
| SR-07 | P1 | The optional generated ServiceMonitor is not production-safe until it validates the metrics serving CA; the correct NetworkPolicy also depends on real API-server, probe, and scraper topology. | Keep both optional by default. Add a reviewed cluster-specific metrics overlay and prove it in that environment. |
| SR-08 | P2 | Release provenance is incomplete: image digest/signature, SBOM, dependency vulnerability scans, and a supported Kubernetes-version matrix are not release gates yet. | Add signed, digest-pinned releases, SBOM/scan attestations, and CI checks before a supported `v1` promise. |

## Decisions from this review

1. Do not add cluster-wide grants to `v1alpha1`.
2. Do not add automatic binding repair; a detected integrity failure remains a
   suspension and investigation event.
3. Do not create an in-etcd audit-event CRD. Kubernetes audit plus a restricted
   external sink is the forensic source of truth.
4. The next workflow CRD remains `BreakGlassRequest`, but only after SR-01 to
   SR-03 are closed. Approval cannot compensate for an overly broad manager.

## Minimum production release checklist

* [ ] The manager's RoleBinding privileges match only approved target namespaces.
* [ ] Each curated role is immutable/versioned and role drift suspends active grants.
* [ ] Webhook, controller restart, certificate rotation, TTL, replacement, and
  rollback tests pass on a disposable Kubernetes cluster.
* [ ] `create`, `use`, profile authoring, revocation, audit reading, and
  controller administration are granted to distinct least-privilege groups.
* [ ] Kubernetes audit events are exported to a durable, restricted sink.
* [ ] Alerts cover webhook failure, sessions past expiry, cleanup errors, and
  binding/profile drift.
* [ ] The deployed controller image is digest-pinned, signed, scanned, and has
  an SBOM available to operators.
