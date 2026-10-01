# Production JIT access design

## Decision implemented in `v1alpha1`

The original learning API accepted `roleRef`, `targetNamespace`, and
`subject` directly in a `BreakGlassSession`. That shape is not safe for
self-service: the privileged controller, rather than the requester, creates
the RBAC binding and could become an unintended escalation proxy.

The current `v1alpha1` API intentionally breaks that model. A session request
contains only:

```yaml
spec:
  accessProfile: production-pod-observer
  duration: 20m
  reason: "INC-1092: investigate database connection exhaustion"
```

The administrator-owned `AccessProfile` fixes the only role, namespace, and
duration ceiling the request may use:

```yaml
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

Profiles are cluster-scoped because they are platform policy, but every
`v1alpha1` grant is a **namespaced RoleBinding**. A referenced `ClusterRole`
provides reusable rules; it does not create a ClusterRoleBinding.

## Trust and authorization flow

1. Kubernetes authenticates the API caller.
2. `deliveryMode: SelfService` lets the session webhook overwrite
   `spec.subject` with `AdmissionRequest.userInfo.username`, snapshot the
   profile UID, and authorize named `use` on the profile.
3. `deliveryMode: ApprovalRequired` denies direct sessions. The request and
   approval webhooks instead authenticate requester and approver, require
   distinct named `use`/`approve` authorization, and record one immutable,
   UID-bound decision before the controller can reserve a session.
4. The session webhook accepts that controller-sourced session only from the
   configured manager identity after rechecking request UID, approval UID,
   profile mode, deadline, reservation, and copied intent fields.
5. The session controller resolves the profile, verifies its UID and maximum
   duration, snapshots role/scope into status, and creates the one
   RoleBinding. It continues to verify the request/approval source, profile,
   role, binding and expiry after activation.
6. A later profile deletion, name reuse, policy mismatch, request/approval
   source loss, binding replacement, binding-content drift, or missing expiry
   suspends the session instead of recreating access.

The requester needs normal `create` on `breakglasssessions` **and** an RBAC
rule such as:

```yaml
apiGroups: ["access.breakglass.io"]
resources: ["accessprofiles"]
resourceNames: ["production-pod-observer"]
verbs: ["use"]
```

This design handles effective Kubernetes impersonation correctly: the API
server passes the impersonated identity in `userInfo`, and Kubernetes audit
logs record the corresponding impersonation chain. The operator never trusts a
requester-supplied username.

## Deployment boundary

The admission webhooks are a mandatory production control, not optional
polish. The default Kustomize deployment enables cert-manager-issued serving
certificates, CA injection, `failurePolicy: Fail`, and a short timeout. Do not
grant self-service session creation in a cluster where those configurations
are absent or unhealthy.

The controller needs `create/delete/get/list/update/watch` on RoleBindings and
`bind` on the curated ClusterRoles it may reference. `update` is used only for
the one-way, UID-verified subject promotion after the reservation checkpoint.
The checked-in manager
RBAC grants `bind` only on `breakglass-pod-observer`, the sample profile role.
Extending the profile catalogue requires an explicit deployment RBAC change
with exact `resourceNames`; unrestricted `bind` is not an acceptable shortcut.

For a high-assurance installation, bind the manager's RoleBinding privileges
only in the namespaces that host profiles, using a deployment overlay. The
generic controller role is intentionally a starting manifest, not authority to
make arbitrary profiles work everywhere.

## Binding integrity and expiry

At activation the controller records `status.bindingRef` with kind, namespace,
name, and the RoleBinding UID assigned by Kubernetes. That UID is authoritative
for cleanup. The controller additionally verifies its controller owner
reference, labels, role reference, and subject on every binding watch and at a
bounded periodic interval.

Activation has a deliberate reservation checkpoint: the controller first
creates an owner-bound RoleBinding with the approved role but **no subjects**.
It persists the binding UID, grant snapshot, and expiry before making the
one-way subject update that grants access. A status-write failure in this
window can therefore leave at most a non-authorizing reservation; it cannot
leave an untracked user grant. Once the UID is recorded, every later update or
delete is tied to that exact server-issued object identity.

If a binding is missing, replaced, or modified, the session becomes
`Suspended`; it is not self-healed. Cleanup uses a UID precondition, so a new
object reusing the same name remains untouched. The sole pre-UID exception is
terminal cleanup of a zero-subject reservation after a failed status write: it
requires the deterministic name, exact controller owner reference, and
high-entropy Session UID labels, and is searched only in configured target
namespaces. It cannot revoke or grant access because the reservation has no
subjects. Expiry and manual revocation remove the exact tracked object when it
still exists.

This means a security response should alert on `Suspended` and inspect the
associated audit logs rather than assuming a destroyed binding will reappear.

## Deliberate limits and next hardening

* Self-service human identities only. Group, ServiceAccount, delegated-grantee,
  token, and workload access are separate designs with different forensic and
  revocation properties.
* The resolved grant snapshots the curated ClusterRole's UID and a canonical
  hash of its policy rules. Every active integrity check reads that named role
  directly from the API server; a missing/recreated role or changed rules
  suspends the session and removes only its UID-tracked binding. The manager
  intentionally needs `get`/`bind` only on explicitly enumerated role names,
  rather than broad ClusterRole list/watch. Because the check shares the
  one-minute active integrity interval, role changes are not instantaneous;
  versioned, immutable curated roles remain the preferred operating model.
  Sessions created before the snapshot fields existed suspend fail-closed at
  their next active check and should be inventoried before upgrade.
* Approval-required profiles use exactly one independent, append-only
  `BreakGlassApproval` per request UID. Quorum, escalation, ticket policy and
  an `ApprovalPolicy` CRD remain deliberately out of scope until real shared
  policy reuse justifies their additional invariants.
* Events and Prometheus metrics are operational data. Kubernetes audit logs
  and a durable restricted sink remain the source of forensic truth.

See [ROADMAP.md](../ROADMAP.md) for the rollout sequence and
[operational metrics](observability.md) for alerting guidance.
