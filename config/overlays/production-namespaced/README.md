# Namespaced production overlay

This is the high-assurance production example for the one target namespace
`production`. It inherits the HA/webhook configuration from `../production`,
then removes global RoleBinding CRUD from the manager's ClusterRole and grants
that capability only through a namespaced `Role` and `RoleBinding`.

It also passes `--allowed-target-namespaces=production`. The manager caches
RoleBindings only there, and both admission and reconciliation reject an
`AccessProfile` whose target namespace is outside that set. This prevents a
profile author from turning the generic controller identity into a binding
proxy for another namespace.

Render it with:

```bash
kubectl kustomize config/overlays/production-namespaced
```

For each additional target namespace, copy the Role and RoleBinding pair,
change its `metadata.namespace`, and add the namespace to the comma-separated
manager argument. Keep the argument and every RBAC resource in one reviewed
GitOps change. Do not merely add the argument: without the corresponding Role
and RoleBinding, the controller correctly fails closed on binding creation.

The overlay still needs cluster-scoped read/watch access to `AccessProfile` and
`BreakGlassSession`, plus named-role `bind`, because those are cluster-scoped
policy and request objects. It does not enable cluster-wide RBAC grants.
