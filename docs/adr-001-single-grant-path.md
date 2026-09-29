# ADR-001: One profile-bound path to a temporary RBAC grant

**Status:** Accepted architecture; implementation in progress  
**Scope:** `v1alpha1`, namespaced Kubernetes RBAC grants

## Decision

A temporary `RoleBinding` may be created or UID-safely deleted only by the
session controller. A person, CLI, ChatOps adapter, or future WebUI can create
intent or a decision, but can never create a binding, receive `bind`, or hold
the manager credential.

This is more precise than “only the operator creates sessions”: a human may
continue to create a compatible self-service session for an explicitly
self-service profile. They never create the RBAC grant itself.

## Domains and trust boundaries

| Domain | Owns | Must not do |
| --- | --- | --- |
| `AccessProfile` | Immutable platform policy: curated role, target namespace, maximum duration, grant mode | Store incident-specific decisions |
| `BreakGlassRequest` | Immutable, authenticated access intent | Create a grant |
| `BreakGlassApproval` | Immutable, authenticated decision by another authorized person | Change policy or RBAC |
| `BreakGlassSession` | Controller-created, concrete, temporary grant | Accept free role, namespace, or subject choices |
| Audit, events, metrics | Evidence and operations | Become a second decision or grant channel |

Profiles are cluster-scoped platform policy. Every current `v1alpha1` grant
remains a namespaced `RoleBinding`; `ClusterRoleBinding` is outside this API.

## Required grant modes

`AccessProfile` must express one immutable delivery mode before the approval
workflow is enabled:

```text
SelfService       → human creates a direct BreakGlassSession
ApprovalRequired  → human creates only a BreakGlassRequest
```

Existing profiles retain `SelfService` for compatibility. The session webhook
must reject direct sessions for `ApprovalRequired`; the request webhook must
accept only `ApprovalRequired`. Thus a profile has exactly one human entry
path and approval can never be bypassed by a direct session.

## Target data flow

```text
GitOps admin → AccessProfile (policy, role, namespace, TTL, grant mode)
                         │
             Kubernetes identity + named use/approve authorization
                         │
     ┌── SelfService ────┴──────────────┐
     │                                   │
BreakGlassSession              BreakGlassRequest (intent, profile UID, deadline)
     │                                   │
     │                         BreakGlassApproval (one independent decision)
     │                                   │
     └────────── Session admission: exact controller identity,
                  request/approval/profile UID and deadline revalidation
                                         │
                               Session controller
                                         │
                      namespaced RoleBinding → expiry / revoke / cleanup
```

For security decisions, admission webhooks and the grant controller read the
API server directly. The controller cache is only a scheduling mechanism.

## Security invariants

1. Only the session controller can create/delete managed RoleBindings and has
   `bind` on explicitly curated roles.
2. `AdmissionRequest.userInfo` is the sole source of requester and approver
   identity; supplied YAML values are overwritten and revalidated.
3. Profile, request, approval, session, and binding relationships use both
   name and UID. A delete/recreate with the same name is never a successor.
4. A request yields at most one session. The controller persists a
   deterministic `SessionRef` before the create side effect; retries reuse it.
5. A request has one irreversible decision slot, named deterministically from
   its UID. A concurrent second decision receives a Kubernetes conflict rather
   than entering a nondeterministic “first list result wins” race.
6. Missing deadline/status, stale references, profile recreation, role drift,
   unknown manager identity, or incomplete provisioning block new grants.
7. Managed bindings are never adopted or silently repaired. Integrity drift
   suspends the session and cleanup uses the recorded binding UID.
8. Prometheus labels use only fixed vocabularies. Identity, reason, ticket,
   profile, role, namespace, and object IDs remain in restricted audit/SIEM
   channels.

## Lifecycle and failures

The request controller persists a crash-safe state machine:

```text
Pending → Approved → Provisioning → SessionCreated
   ├──→ Denied
   ├──→ Expired
   └──→ Failed
```

`SessionCreated` means that a session CR with the recorded server UID exists;
it does not claim that the RoleBinding is already active. A future UI must use
the session's actual lifecycle for an “access active” indication.

| Failure | Required behavior |
| --- | --- |
| Webhook unavailable | New requests, approvals, and sessions fail closed; active grants retain their existing TTL behavior. |
| Controller restart | Reconcile from persisted references; no duplicate session or unbound binding. |
| Manager outage | No new grants; recovery and the documented offline procedure handle cleanup risk. |
| Profile/role drift | Pending requests are not grantable; active sessions suspend rather than regrant. |
| Request recreate/delete | UID mismatch rejects all old references; source integrity must suspend/revoke a sourced session. |
| Simultaneous approvals | One deterministic approval slot permits one decision only. |

## RBAC and privacy boundary

| Actor | Minimum authority |
| --- | --- |
| Requester | Create request, named `use` on allowed profile; no bindings or approvals |
| Approver | Create deterministic approval, named `approve` on allowed profile; no sessions or bindings |
| Grant controller | Read request/approval, write request status, create sourced sessions, manage bindings only in allowed namespaces |
| UI | No manager credential, no `bind`, no RoleBinding/Session writes; user-bound request/approval calls only |

Cluster-scoped requests cannot be filtered by `spec.requester` using native
Kubernetes RBAC. Therefore requesters must not receive broad `list`/`watch`
access. “My requests” requires a separately reviewed, OIDC-bound read facade
or a redesigned visibility API; it is not a simple UI feature.

## Deliberate non-goals

The operator does not implement an OIDC provider, user/group lifecycle,
ticketing, on-call routing, SIEM retention/search, UI session management,
parallel approval datastore, generic PAM, Cloud IAM, or an RBAC editor.
Those systems may integrate as clients of the verified workflow but never
receive a direct grant path.

## Prioritized implementation roadmap

1. Add and enforce `SelfService` versus `ApprovalRequired` on profiles.
2. Implement the complete request → deterministic approval → reserved session
   state machine with exact UID and controller-identity admission checks.
3. Deliver RBAC, installers, E2E, and failure tests as one security gate:
   self-approval, stale/recreated objects, concurrent decisions, restart,
   webhook outage, drift, and expiry.
4. Decide request visibility, retention, and the platform OIDC identity
   contract before implementing a UI.
5. Add CLI/ChatOps only as clients of this workflow; add the optional UI last.

## Open decisions

* Is one independent decision sufficient for the first release, or is there a
  demonstrated need for a quorum policy? Do not add `ApprovalPolicy` without
  real reuse.
* Is one manager ServiceAccount acceptable initially, or should admission,
  request, and session controllers be split into separate deployments?
* Which reviewed visibility mechanism can expose a requester's own history
  without leaking other incident reasons or identities?
