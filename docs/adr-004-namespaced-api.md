# ADR-004: Namespaced access objects in dedicated control namespaces

**Status:** Accepted; implementation in progress
**Scope:** All four `access.breakglass.io/v1alpha1` kinds, the manager, the
expiry guard, the WebUI, Helm and Kustomize. Phase 1 of the multi-tenancy
concept; it must land before the M5 pilot.

## Context

`AccessProfile`, `BreakGlassRequest`, `BreakGlassApproval` and
`BreakGlassSession` were cluster-scoped. That has three consequences that
block any later separation between teams (tenants):

- **Visibility cannot be separated by RBAC.** Anyone with `list` on
  `breakglassrequests` sees every requester and every incident reason. Only
  the WebUI filtered results, which is a code boundary, not an authorization
  boundary (SR-05).
- **Administration cannot be delegated.** Creating a profile requires
  cluster-wide `create` on `accessprofiles`, so a team that manages its own
  profiles could manage everyone's.
- **Audit and quota have no natural key.** Kubernetes audit events, events and
  `ResourceQuota` are organized by namespace.

A CRD's scope is immutable. Changing it later means deleting the CRD and every
object of it, which becomes a migration with data once real teams use the
operator. No version has been released yet (M1 is not accepted), so the change
is cheapest now.

## Decision

1. **All four kinds are namespaced.** They live in a *control namespace*.
   Every reference between them (`accessProfile`, `requestRef`,
   `approvalRef`, `sessionRef`) is a name in the same namespace. A request or
   session can never reference a profile in another namespace.
2. **Profiles still grant in exactly one target namespace.**
   `spec.targetNamespace` is unchanged. The grant is still one namespaced
   `RoleBinding` of a curated `ClusterRole`, created only by the session
   controller (ADR-001).
3. **Control and target namespaces are disjoint.** The manager flag
   `--control-namespaces` lists the namespaces in which access objects are
   accepted. When both it and `--allowed-target-namespaces` are explicit, the
   manager refuses to start if they overlap, and the profile webhook rejects a
   profile whose target is a control namespace. An empty list keeps the
   all-namespaces development default.
4. **Authorization is namespaced.** The SubjectAccessReviews for `use`,
   `approve` and `revoke` carry the profile's namespace. A `Role` in a
   control namespace is therefore enough to authorize people for that
   namespace's profiles.
5. **Bindings are tied to their session by labels, not owner references.**
   Kubernetes forbids owner references across namespaces; the garbage
   collector would delete such a binding at once. The binding carries
   `access.breakglass.io/session-namespace` in addition to the existing
   managed-by, session and session-UID labels. The session status still
   records the binding's UID, which stays the authority for deletion.
6. **Orphaned bindings are swept.** Without garbage collection, a binding
   whose session disappeared without its finalizer running would keep its
   access. The expiry guard therefore also deletes managed bindings whose
   session (namespace, name and UID) no longer exists, with UID and version
   preconditions. No grace period applies: the guard lists bindings before
   sessions, and a session always exists before its binding, so a binding of
   a live session is never mistaken for an orphan. A binding labelled for a
   session outside the guard's control namespaces is reported, never deleted,
   because that signals drift between guard and manager flags. A binding with
   the managed-by label but no complete session identity claims no session;
   it is listed as ignored and does not fail the run.
7. **No migration from the cluster-scoped API.** The version stays
   `v1alpha1`. Existing installations delete the CRDs (and with them every
   access object) and reinstall. No release with the cluster-scoped API was
   published.

## Consequences

- RBAC in a control namespace decides who sees reasons and identities. Helm
  renders the operator's and the expiry guard's rights on access objects per
  control namespace (`controlNamespaces`); the Kustomize production overlay
  passes `--control-namespaces=breakglass-access`.
- Admission webhook rules match `scope: Namespaced`. A `Cluster` scope would
  silently exempt every access object from admission; the chart test fails on
  it.
- Validating and mutating webhooks reject an access object outside the
  control namespaces before any other check.
- Approvals are append-only evidence of a human decision. Deleting the
  request does not release its approval; otherwise a requester could delete
  the request and then erase the decision. An approval may be deleted only
  while its namespace is being deleted (deletionTimestamp set or phase
  `Terminating`), so a control namespace can still be deleted while the
  operator runs. The webhook reads the Namespace directly from the API server
  and denies the deletion on any read error. The manager therefore needs
  `get` on its control namespaces as well as its target namespaces; the
  namespace-restricted Kustomize overlay and the Helm chart name both sets.
- **A control namespace must be drained before it is deleted.** In a
  namespace-restricted installation (Helm, the namespaced Kustomize overlay)
  the manager's rights on access objects are Roles in that control namespace.
  If the namespace were deleted while sessions remain, namespace cleanup could
  remove those Roles first; the sessions' finalizers would then hold the
  namespace forever, because the manager could no longer read or update them.
  A validating webhook on Namespace `DELETE` therefore denies deleting a
  control namespace that still holds any BreakGlassSession, including one that
  is already being deleted (its finalizer still needs the manager). The
  sessions are listed from the API server, not a cache, and any read error
  denies. The webhook uses `failurePolicy: Fail`: while no admission pod is
  available (ADR-005), the deletion is denied rather than risked; while only
  the manager is down, sessions still block it. Its
  `namespaceSelector` keeps that outage behaviour away from every other
  namespace: Helm and the namespaced overlay select exactly the control
  namespaces by `kubernetes.io/metadata.name`; the all-namespaces Kustomize
  profiles (default, production), which have no fixed list, select only
  namespaces labelled `access.breakglass.io/control-namespace=true`. That
  label is opt-in, so an unlabelled namespace with access objects is not
  protected in those profiles. A namespace that is already terminating is not
  blocked again. One race remains: a session created after the webhook's list
  but before the namespace becomes `Terminating` is not seen. Kubernetes
  rejects creation in a terminating namespace, so the window is a single
  admission round-trip; a session created in it is stranded in the same way
  and needs manual recovery (restore the manager's Role in the namespace).
- The expiry guard lists sessions per control namespace and bindings per
  target namespace. Its namespaced Roles disappear with their namespace, so a
  deleted namespace makes listing Forbidden. The guard therefore also has
  `get` on exactly its target and control Namespaces through a ClusterRole
  that outlives them. It treats a namespace as empty only when that read
  returns NotFound. Forbidden, any other error, or a terminating namespace is
  reported as unreadable, the run exits 2, and the other namespaces are still
  swept. A binding claiming a session in an unreadable control namespace is
  refused, never deleted as an orphan. Without explicit namespaces the guard
  lists cluster-wide, and a failed list ends the run (exit 1).
- A binding event whose labels were removed still reaches its session through
  an index on the binding location recorded in the session status, so drift
  is detected at once rather than at the next periodic check.
- The WebUI addresses objects by namespace and name. It keeps its read-only
  ServiceAccount; restricting that ServiceAccount to registered control
  namespaces follows in phase 3 of the multi-tenancy concept.
- Owner references no longer corroborate a binding. Labels can be forged by
  anyone who may write RoleBindings in the target namespace, exactly as owner
  references could. The recorded UID, the expected location, the role
  reference and the single subject are still verified on every check.
- Tenants (a control namespace mapped to its target namespaces and roles) are
  not part of this decision. They follow in phase 2 and only add rules on top
  of this layout.

## Alternatives considered

- **Keep cluster-scoped kinds and add a tenant label.** Rejected: visibility
  would still depend on WebUI filtering, and delegated profile management
  would still need cluster-wide rights.
- **Access objects in the target namespace.** Rejected: incident reasons and
  identities would be readable by whoever administers the workload
  namespace, and profile administration would mix with workload
  administration.
- **One operator release per team.** Rejected: CRDs and webhooks are
  cluster-wide, so releases would validate and block each other, and it
  multiplies operations.
