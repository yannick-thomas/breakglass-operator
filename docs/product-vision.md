# Product vision

## The product in one sentence

BreakGlass Operator is the Kubernetes-native control plane for granting the
*smallest useful production permission* to the *right authenticated person*
for the *shortest defensible time*—with evidence that the permission went away.

It is not a replacement for identity providers, SIEMs, or a general PAM suite.
It makes those systems useful at the Kubernetes RBAC boundary, where incident
response otherwise often falls back to permanent administrator access.

## Who it serves

| Persona | Outcome |
| --- | --- |
| On-call engineer | Receives a narrowly defined, time-limited permission without waiting for a broad admin role. |
| Platform owner | Publishes a small, versioned catalogue of allowed emergency actions and owns the deployment boundary. |
| Security/incident commander | Can require approval, monitor exceptions, revoke access, and investigate a complete Kubernetes audit trail. |
| Auditor | Can show that emergency access was authorized, bounded, expired/revoked, and correlated with an incident. |

## Product loop

```text
Curated access profile
        → request with reason and bounded duration
        → policy/approval decision
        → one namespaced JIT grant
        → observe, revoke, and expire
        → correlate durable audit evidence
```

The current operator implements the deliberately conservative grant step: an
admin-owned profile produces one UID-tracked namespaced RoleBinding. Every
future convenience feature must preserve that invariant rather than become a
second access-control path.

## Where it creates real value

* **Production debugging without standing privilege:** e.g. read pods, events,
  logs, rollout status, or a narrowly scoped custom resource in one namespace.
* **Incident response with a usable safety rail:** responders get access in
  minutes, while the platform retains an explicit policy boundary and expiry.
* **Least-privilege migration:** teams can replace “all developers are admin
  just in case” with a small profile catalogue and measurable usage evidence.
* **Audit-ready exception handling:** identity, policy, lifecycle, and binding
  integrity can be correlated in the Kubernetes audit/SIEM pipeline without
  leaking them into Prometheus labels.

## Product principles

1. **Profiles, not arbitrary RBAC.** Requesters choose an approved capability,
   never a role, namespace, or grantee.
2. **Fail closed, then make failure operable.** An unavailable webhook blocks a
   new request; HA, runbooks, alerts, and an audited offline procedure make
   that safe in real incidents.
3. **Namespaced before cluster-wide.** A ClusterRole bound by a RoleBinding is
   reusable policy, not cluster-wide access. A different high-assurance design
   is required before cluster-level grants are considered.
4. **Evidence over opaque automation.** Status, events, audit logs, and
   bounded metrics explain what happened; the operator never silently repairs
   suspicious RBAC state.
5. **Integrate rather than reimplement.** Kubernetes authentication, RBAC,
   cert-manager, audit, GitOps, OIDC, and incident tooling stay authoritative.
6. **No security theatre.** A ticket format, approval button, or dashboard is
   valuable only if its authorization, outage behaviour, and audit trail are
   independently verifiable.

## Capability horizon

| Horizon | Product capability | API direction |
| --- | --- | --- |
| Now | Profile-gated, namespaced JIT RoleBinding with UID-safe cleanup and bounded telemetry | `AccessProfile` + `BreakGlassSession` |
| Trustworthy operation | Namespace-scoped manager RBAC, curated-role integrity, E2E failure tests, release provenance, audit/runbooks | No new CRD |
| Governed access | Request/approval separation, expiry before approval, no self-approval, policy preview | `BreakGlassRequest`; optional append-only approval type only if native approval is needed |
| Human workflow | `kubectl breakglass`, ChatOps adapters, incident/ticket verification, on-call routing | Clients consume the request workflow; no second grant API |
| Identity convergence | Short-lived OIDC/cloud credentials, verified risk signals, cloud-IAM correlation | Separate identity integrations; do not overload a RoleBinding CRD |

## The next CRD—only when the foundation is proven

`BreakGlassRequest` is the next justified domain object. It separates an
untrusted request from an active grant and records immutable requester,
profile UID, requested duration, reason, and decision lifecycle:

```text
Pending → Approved → SessionCreated → Expired
       ↘ Denied
```

The controller—not an approver or ChatOps callback—creates the resulting
session. An approval decision must be idempotent, non-self-approved, time
bounded, and auditable. A separate `ApprovalPolicy` is premature until teams
demonstrably share approval/quorum semantics; configuration CRDs should follow
real policy reuse, not anticipated complexity.

## Non-goals that keep the product useful

* A generic replacement for Kubernetes RBAC or enterprise PAM.
* A path to `cluster-admin` through a friendly CRD.
* Storing sensitive forensic records redundantly in etcd.
* Long-lived ServiceAccount tokens presented as a human break-glass session.
* A dashboard that hides whether access actually expired.

## Outcomes to measure

Operational metrics stay privacy-safe and bounded. Per-person, incident, role,
or namespace analytics belong in the protected audit/SIEM system.

* Percentage of production responders without standing privileged RBAC.
* Time from approved request to a narrow active grant.
* Percentage of sessions cleaned up within the expiry SLO.
* Count and time-to-triage of binding/profile integrity suspensions.
* Percentage of emergency sessions with an auditable incident correlation.
* Number of profile uses by risk class, only if the class is a small,
  administrator-managed vocabulary.

The north-star outcome is not “more break-glass sessions.” It is fewer
permanent production privileges while responders remain effective under stress.
