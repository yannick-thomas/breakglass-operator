# Namespaced production overlay

This is the high-assurance production example for the one target namespace
`production`. It inherits the HA/webhook configuration from `../production`,
then removes global RoleBinding CRUD from the manager's ClusterRole and grants
that capability only through a namespaced `Role` and `RoleBinding`.

It also passes `--allowed-target-namespaces=production` and
`--control-namespaces=breakglass-access` to both the manager and the admission
Deployment; the manifest check fails if their flags differ. Access objects (profiles, requests,
approvals, sessions) are accepted only in `breakglass-access`, and both
admission and reconciliation reject an `AccessProfile` whose target namespace
is outside the allowed set or is a control namespace (ADR-004). The manager
caches only these two namespaces. This prevents a profile author from turning
the generic controller identity into a binding proxy for another namespace.
Create `breakglass-access` before applying profiles.

Render it with:

```bash
kubectl kustomize config/overlays/production-namespaced
```

For each additional target namespace, copy the Role and RoleBinding pair,
change its `metadata.namespace`, and add the namespace to the comma-separated
argument (patched into both Deployments) and to the `resourceNames` of the
manager's and admission's Namespace `get` rules. Keep the argument and every RBAC resource in one reviewed
GitOps change. Do not merely add the argument: without the corresponding Role
and RoleBinding, the controller correctly fails closed on binding creation.

The overlay still grants the manager cluster-wide read/watch access to the
access objects, plus named-role `bind`; its cache and admission limit it to the
control namespace. Restricting those rights to the control namespace follows
with per-tenant RBAC. It does not enable cluster-wide RBAC grants. The manager
gets only the `production` Namespace.

The admission server (ADR-005) runs as `breakglass-operator-admission` with
its own ServiceAccount. Its ClusterRole keeps only SubjectAccessReview
`create` and `get` on the `production` and `breakglass-access` Namespaces;
it reads the four access kinds only through the Role
`breakglass-operator-admission-access` in `breakglass-access`. It has no
`bind`, `escalate`, RoleBinding, session or status writes. Add a matching Role
and RoleBinding for each additional control namespace.

The control-namespace drain check (ADR-004) selects exactly `breakglass-access`
by `kubernetes.io/metadata.name`. When adding or renaming a control namespace,
change `--control-namespaces`, admission's and the guard's Namespace
`resourceNames`, admission's access Role, and this webhook selector in the
same change.
