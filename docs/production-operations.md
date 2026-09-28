# Production operations

The production deployment is an availability overlay over the same secure
installation used by the default package. It does not create a less restricted
mode of the operator.

## Install and verify

Install cert-manager first, publish an immutable/signed controller image, then
apply the complete production package in one release operation:

```bash
kubectl apply -k config/overlays/production
```

In GitOps, compose the overlay with an image digest rather than editing the
generated manager manifest in place:

```yaml
# kustomization.yaml in the environment repository
resources:
  - ../../breakglass-operator/config/overlays/production
images:
  - name: controller
    newName: registry.example.com/platform/breakglass-operator
    digest: sha256:<verified-image-digest>
```

Before assigning any requester the `create` or profile-specific `use` rights,
verify all of the following:

```bash
kubectl rollout status deployment/breakglass-operator-controller-manager \
  -n breakglass-operator-system --timeout=5m
kubectl get certificate/breakglass-operator-serving-cert -n breakglass-operator-system
kubectl get mutatingwebhookconfiguration breakglass-operator-mutating-webhook-configuration
kubectl get validatingwebhookconfiguration breakglass-operator-validating-webhook-configuration
kubectl get poddisruptionbudget/breakglass-operator-controller-manager \
  -n breakglass-operator-system
```

Both webhook configurations must have a non-empty `clientConfig.caBundle`, the
certificate must be `Ready`, and two manager Pods must be ready. The
production overlay requires two schedulable hosts so that an involuntary loss
of one host does not take down the controller and admission server together.

Run a harmless end-to-end request using a dedicated test user and a read-only
profile. Verify requester attribution, a positive `use` authorization,
creation of exactly one RoleBinding in the profile namespace, and expiry
cleanup. Repeat the request after deleting one manager Pod. A failed admission
webhook must reject a new request rather than admitting a client-controlled
subject or role.

## Upgrade and rollback

1. Record the image digest, rendered manifest, current CRDs, active sessions,
   and the state of the webhook configurations.
2. Run the release's Kind/E2E suite against a disposable cluster, including
   webhook CA readiness, denied `use`, TTL/restart, binding replacement, and
   cleanup behaviour.
3. Apply the release, wait for both manager Pods and the serving certificate to
   become ready, then perform the harmless request check above.
4. Keep the former controller image and manifest available, but never roll
   back to an image or manifest that accepts the removed free-form session API.
   First revoke or allow expiry of grants incompatible with the target version.

The API server deliberately fails new requests closed when the webhook is
unavailable. Treat a webhook failure as an access-control incident, not as a
reason to remove the webhook configuration or set `failurePolicy: Ignore`.

## Controller outage, expiry, and emergency recovery

With two replicas and leader election, one manager Pod may disappear without
stopping admission or reconciliation. Restore the deployment before taking
manual RBAC action:

```bash
kubectl get pods -n breakglass-operator-system -l control-plane=controller-manager
kubectl rollout status deployment/breakglass-operator-controller-manager \
  -n breakglass-operator-system --timeout=5m
```

During a total controller outage, an expired binding can survive longer than
its intended TTL. This is a documented best-effort cleanup SLO, not a safe
extension of access. Escalate through the platform emergency procedure. That
procedure must independently match the session's persisted
`status.bindingRef` **name, namespace, and UID** against the live RoleBinding,
record the action in the Kubernetes audit stream, and refuse to delete a
replacement object with the same name. Do not use broad label deletes or
delete bindings based on name alone.

If the binding is missing, replaced, or altered, the controller suspends the
session and does not recreate it. Investigate the audit log and restore access
only through a new, authorized BreakGlassSession after the incident is
understood.

## Metrics and alerts

Use the alert recommendations in [observability.md](observability.md). At a
minimum, page on sessions past expiry, cleanup errors, admission errors, and
binding drift. Send Kubernetes audit logs and lifecycle Events to a durable,
restricted sink; Prometheus labels intentionally do not identify people,
profiles, namespaces, or incident tickets.

Before enabling a `ServiceMonitor`, configure CA validation for the metrics
certificate and restrict scraper reachability with a NetworkPolicy that is
tested against the actual API-server, kubelet-probe, and monitoring topology.
