# Production JIT access design

## Decision

Replace free-form `roleRef`, `targetNamespace`, and requester-supplied
`subject` with an administrator-controlled `AccessProfile` and an admission
webhook before treating this operator as a production PAM control.

The current `v1alpha1` API is retained temporarily as a controller-learning
slice and is hardened against accidental misuse. It must not be exposed as a
self-service privilege-escalation API.

## Why a free role reference is unsafe

Kubernetes prevents a user from creating a role binding for permissions they do
not already have unless they also have the `bind` permission on the referenced
role. The controller, rather than the session requester, creates the binding.
Giving the controller broad binding permission and accepting arbitrary fields
therefore moves that escalation check behind the controller and can bypass its
intent.

The same applies to `subject`: a controller cannot reliably discover the
authenticated author of a custom resource from the stored object. A caller who
can create a session must not be able to nominate another user or a powerful
service account as the recipient.

## Proposed v1 API

`AccessProfile` is cluster-scoped and writable only by the platform-security
administrators. Each profile has one fixed RBAC target and one fixed scope:

```yaml
apiVersion: access.breakglass.io/v1
kind: AccessProfile
metadata:
  name: prod-namespace-debug
spec:
  roleRef:
    kind: ClusterRole
    name: production-debug
  targetNamespace: production
  maxDuration: 60m
```

The request becomes deliberately small:

```yaml
apiVersion: access.breakglass.io/v1
kind: BreakGlassSession
metadata:
  generateName: incident-
spec:
  accessProfile: prod-namespace-debug
  duration: 30m
  reason: INC-1092: investigate database connection exhaustion
```

The controller resolves the profile server-side. A request cannot select a
different role or turn a namespaced grant into a `ClusterRoleBinding`. Keep
cluster-scoped profiles exceptional and separate from namespaced profiles.

## Admission and authorization flow

1. A mutating admission webhook records the authenticated requester's
   `AdmissionRequest.userInfo` as the immutable recipient identity. It
   overwrites, rather than trusts, any client-supplied identity field.
2. A validating webhook runs after mutation, checks that the final recipient
   matches the requester, and rejects changes to the request fields.
3. The validating webhook performs a `SubjectAccessReview` for a custom `use`
   verb on the named `AccessProfile`. Platform RBAC can then grant, for example,
   `use` on `accessprofiles/prod-namespace-debug` to an on-call group without
   granting use of other profiles.
4. Both webhook configurations use `failurePolicy: Fail`, are served over TLS,
   and cover `CREATE` and relevant `UPDATE` operations. The controller must not
   be installed as a privileged production component without this policy.

Approvals (ticket state, two-person approval, risk signals) belong between steps
3 and 4, either in the webhook or in a separate approval object. They should
never be inferred from a free-form reason string.

## RBAC deployment boundary

The manager needs permission to create the RBAC binding and, in ordinary
Kubernetes RBAC, `bind` on the referenced role. Do not solve that by giving the
manager unrestricted `bind` while allowing free-form role names.

For namespaced profiles, run the manager with `RoleBinding` write permission in
only the approved namespaces and `bind` limited with `resourceNames` to the
roles used by those profiles. A separate, tightly controlled installation should
handle the rare cluster-scoped profiles. This separates the blast radius of a
namespaced debug grant from cluster administration.

## Lifecycle and audit requirements

The controller establishes the expiry once and never extends it. It uses
`RequeueAfter` as the normal timer, watches its own binding to repair deletion,
and uses a finalizer for deletion cleanup. Binding ownership is recorded with
both the session name and UID; this prevents a matching name from being adopted
or deleted accidentally.

Kubernetes Events are useful operational signals, but they are short-lived and
should not carry the full incident reason. Send Kubernetes API audit logs,
operator logs, and lifecycle status changes to the durable SIEM/audit store.
Capture the requester, profile, approved duration, immutable reason, binding
name, activation time, expiry, revocation actor, and outcome there.
