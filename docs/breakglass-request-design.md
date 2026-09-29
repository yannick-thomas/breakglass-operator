# BreakGlassRequest design

`BreakGlassRequest` is the next workflow API. It is deliberately not an
alternative way to create a `RoleBinding`: it is an untrusted request that
must become an immutable, reviewed `BreakGlassSession` only after approval.

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
requester and `AccessProfile` UID. The fields are immutable after creation.

`BreakGlassApproval` references the request by **name and UID**, declares
`Approved` or `Denied`, and is append-only. Its webhook snapshots the human
approver. It rejects self-approval and stale or expired requests. An approval
policy is intentionally absent: profile-scoped RBAC decides who may approve
until real policy reuse proves that a policy CRD is needed.

The request status is controller-owned:

```text
Pending -> Approved -> SessionCreated
       \-> Denied
       \-> Expired
```

The resulting session stores the source request UID in its status/audit
reference. An approved request is consumed exactly once; retries remain
idempotent and cannot create a second grant.

## Admission and RBAC

* Requesters receive `create`, read-only access to their requests, and custom
  `use` on named AccessProfiles.
* Approvers receive `create` only on approvals for named profiles (plus the
  minimum request read access required to make a decision).
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

## Acceptance gates before implementation

1. Production Kind/E2E is green for certificate reissue, total outage, TTL
   recovery, role drift, and webhook recovery.
2. Request/approval webhooks have explicit fail-closed tests for self-approval,
   stale UID, unauthorized profile, replay, and request expiry.
3. A controller restart cannot create duplicate sessions for one approved
   request.
4. Audit events and metrics stay privacy-safe; IDs and identities remain out
   of Prometheus labels.
