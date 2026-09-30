# BreakGlassRequest design

The normative architectural decision for this workflow is
[ADR-001: One profile-bound path to a temporary RBAC grant](adr-001-single-grant-path.md).

`BreakGlassRequest` is the approval-workflow API. It is deliberately not an
alternative way to create a `RoleBinding`: it is an untrusted request that
can become an immutable, reviewed `BreakGlassSession` only after approval.

## Boundary

```text
human requester -> BreakGlassRequest (Pending)
human approver  -> BreakGlassApproval (Approved | Denied)
controller      -> BreakGlassSession (Active) -> namespaced RoleBinding
```

The only component allowed to create the final session is the controller. The
requester, approver, CLI, ChatOps adapter, and future WebUI must never receive
RoleBinding permissions or the manager ServiceAccount token.

## API shape

`BreakGlassRequest.spec` contains only `accessProfile`, `duration`, `reason`,
and a short request TTL. A mutating webhook snapshots the authenticated human
requester, `AccessProfile` UID, and the manager-configured request TTL. The
fields are immutable after creation.

`BreakGlassApproval` references the request by **name and UID**, declares
`Approved` or `Denied`, and is append-only. Its webhook snapshots the human
approver. It rejects self-approval and stale or expired requests. An approval
policy is intentionally absent: profile-scoped RBAC decides who may approve
until real policy reuse proves that a policy CRD is needed.

The request status is controller-owned:

```text
Pending -> Approved -> Provisioning -> SessionCreated
       \-> Denied | Expired | Failed
```

The resulting session stores the source request UID in its immutable spec. An
approved request is consumed exactly once: before creating a session, the
controller persists a deterministic session-name reservation; after creation,
it persists the server-assigned session UID. Retries and controller restarts
therefore cannot create a second grant.

## Implemented workflow boundary

`v1alpha1` implements the complete first approval workflow, with one explicit
delivery mode per immutable `AccessProfile`:

* `SelfService` permits only a direct, authenticated `BreakGlassSession`.
  Omitted delivery modes from older profiles resolve compatibly to
  `SelfService`.
* `ApprovalRequired` permits only `BreakGlassRequest`; the session webhook
  rejects a direct session for that profile.
* A request and approval webhook overwrite requester/approver identity from
  Kubernetes admission identity, reject ServiceAccounts and self-approval,
  use profile-specific `use` and `approve` authorizations, and fail closed on
  stale profile/request data or an expired immutable request deadline.
* Each request UID has exactly one deterministic, append-only approval slot.
  Simultaneous approve/deny attempts become a Kubernetes create conflict,
  rather than an ambiguous controller choice.
* Only the exact configured request-controller ServiceAccount can create the
  resulting session. Admission verifies the request UID, approval UID,
  profile mode, copied request fields, deadline, and reserved session name.
* The session controller rechecks the same request/approval UID chain before
  activation and during active integrity checks. A missing, recreated, or
  invalid source suspends access and removes only the controller's recorded
  RoleBinding UID.

The controller never creates a `RoleBinding` from a request or approval. It
creates a validated session; the session controller remains the only component
that turns it into a namespaced RBAC grant.

## Admission and RBAC

* Requesters receive `create` on requests and custom `use` on named
  `ApprovalRequired` profiles. They do **not** need `list` or `watch` on the
  cluster-scoped request resource.
* Approvers receive `create` only on approvals and custom `approve` on named
  profiles. They do **not** receive session or RoleBinding permissions.
* The controller receives the sole permission to create a session sourced
  from an approved request. The session webhook must accept that exact
  controller identity only for the request-controller path; it must continue
  to reject workload ServiceAccounts and client-supplied subjects.
* Profile authors, requesters, approvers, auditors, and controller operators
  remain separate groups.

## WebUI boundary

The WebUI is optional and disabled by default. It is a client of the Request
API, authenticated through the platform's existing OIDC/Kubernetes identity.
It may create requests, show the caller's requests, and submit approvals only
through its caller-bound API flow. It must not hold cluster-admin credentials,
bind roles, impersonate humans, or implement a parallel approval datastore.

## Release gates

1. Production Kind/E2E is green for certificate reissue, total outage, TTL
   recovery, role drift, and webhook recovery.
2. Request/approval webhooks have explicit fail-closed tests for self-approval,
   stale UID, unauthorized profile, duplicate decision, request expiry, and
   direct-session bypass attempts.
3. E2E proves controller restart between every persistence step cannot create
   duplicate sessions; deleting/recreating a request or approval suspends an
   active session and removes only its own binding.
4. Audit events and metrics stay privacy-safe; IDs and identities remain out
   of Prometheus labels. A production SIEM/audit-sink correlation contract is
   documented before broad use of `ApprovalRequired` profiles.
