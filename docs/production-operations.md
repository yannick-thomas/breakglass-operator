# Production operations

The production deployment is an availability overlay over the same secure
installation used by the default package. It does not create a less restricted
mode of the operator.

## Components and identities

The operator runs two Deployments from one image (ADR-005):

| Component | Deployment / ServiceAccount | Does | May |
| --- | --- | --- | --- |
| Manager | `breakglass-operator-controller-manager` (`/manager`) | Reconciles profiles, requests and sessions; creates and deletes the grant RoleBindings; exports lifecycle metrics. Leader election, no webhook port. | `bind` the curated ClusterRoles by name; RoleBinding CRUD in the target namespaces; read/watch the access objects; write session, request and profile status and session finalizers; create sessions from approved requests; Events; `get` on the target Namespaces. |
| Admission | `breakglass-operator-admission` (`/admission`) | Serves every mutating and validating webhook behind `breakglass-operator-webhook-service` (port 9443) and mounts the serving certificate; exports `breakglass_admission_requests_total`. No reconciler, no leader election. | Create SubjectAccessReviews; `get`/`list` the four access kinds in the control namespaces; `get` on the target and control Namespaces. No `bind`, no `escalate`, no RoleBinding, session or status writes. |
| Expiry guard | `breakglass-operator-expiry-guard` CronJob (`/expiry-guard`) | Deletes expired and orphaned grant bindings independently of the manager. | Read sessions; `get`/`list`/`delete` RoleBindings in target namespaces; `get` on the target and control Namespaces. |

The manager's ClusterRole is generated from the markers in
`internal/controller` (`config/rbac/role.yaml`), the admission ClusterRole
from those in `internal/webhook` (`config/rbac/admission_role.yaml`). Both
receive the metrics-auth role so their metrics endpoints authenticate
scrapers.

Admission accepts a session sourced from an approved request only from the
manager's identity: both Deployments carry
`--request-controller-username=system:serviceaccount:breakglass-operator-system:breakglass-operator-controller-manager`.
Both must also carry identical `--allowed-target-namespaces` and
`--control-namespaces` values; `test/manifestcheck` fails a rendered
installation where they differ.

### Outage behaviour

- **Admission unavailable:** every webhook fails closed. No request,
  approval, session or approval deletion is admitted, and deleting a selected
  control namespace is denied. Existing grants keep working and the manager
  keeps expiring and cleaning them up.
- **Manager unavailable:** admission keeps accepting and rejecting requests,
  approvals and sessions, and the drain check keeps working. Provisioning of
  new grants and cleanup at expiry wait until the manager is back; the expiry
  guard still removes expired bindings.

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
kubectl rollout status deployment/breakglass-operator-admission \
  -n breakglass-operator-system --timeout=5m
kubectl get certificate/breakglass-operator-serving-cert -n breakglass-operator-system
kubectl get mutatingwebhookconfiguration breakglass-operator-mutating-webhook-configuration
kubectl get validatingwebhookconfiguration breakglass-operator-validating-webhook-configuration
kubectl get poddisruptionbudget/breakglass-operator-controller-manager \
  poddisruptionbudget/breakglass-operator-admission -n breakglass-operator-system
kubectl get endpointslices -n breakglass-operator-system \
  -l kubernetes.io/service-name=breakglass-operator-webhook-service
```

Both webhook configurations must have a non-empty `clientConfig.caBundle`, the
certificate must be `Ready`, two manager Pods and two admission Pods must be
ready, and the webhook Service endpoints must name only admission Pods. The
production overlays require two schedulable hosts so that an involuntary loss
of one host takes down neither the controller nor admission.

Run a harmless end-to-end request using a dedicated test user and a read-only
profile. Verify requester attribution, a positive `use` authorization,
creation of exactly one RoleBinding in the profile namespace, and expiry
cleanup. Repeat the request after deleting one manager Pod and one admission
Pod. A failed admission
webhook must reject a new request rather than admitting a client-controlled
subject or role.

The repository executes this boundary in CI with a disposable Kind cluster
that has two schedulable worker nodes:

```bash
make test-e2e-production
```

It renders the `production-namespaced` overlay, verifies two manager and two
admission Pods, certificate and PDB readiness, deletes one Pod before a real
attributed request, then scales the admission Deployment down to prove
admission fails closed before restoring it and successfully issuing a fresh
request. It reissues the serving
certificate and verifies that an active session keeps the exact recorded
RoleBinding UID through a rolling manager restart. It does not remove or weaken
the webhook configuration to simulate an outage. Its final lifecycle check
first removes the manager's namespaced RoleBinding permissions, then deletes
the target namespace and active session concurrently. This covers the
`Forbidden` cleanup race hidden by cluster-wide RoleBinding permissions.

The namespaced overlay retains only `get` on the explicitly named target
Namespace in its manager ClusterRole. If namespaced RBAC disappears, cleanup
waits until a direct API read returns Namespace `NotFound`. A terminating,
recreated, or unreadable namespace is not proof of cleanup; the finalizer
remains for retry or investigation. Custom namespace overlays must update
this `resourceNames` list along with their RoleBinding scope and
`--allowed-target-namespaces`; no namespace writes or cluster-wide binding
permissions are required.

The namespaced overlay also requires the control namespace
`breakglass-access`, which it does not create. Create it before applying
access profiles: profiles, requests, approvals, and sessions live only there
(ADR-004). Bind requester and approver roles in `breakglass-access` with
RoleBindings, not ClusterRoleBindings. Both the manager and the expiry guard
receive `--control-namespaces=breakglass-access` next to
`--allowed-target-namespaces=production`. Control namespaces must not
overlap target namespaces, and they are required whenever target namespaces
are explicit: the manager and admission refuse to start with explicit target
namespaces but no control namespaces. The namespaced overlay patches both
flags into every Deployment; custom overlays must change both flags on the
manager, admission and the expiry guard together.

In the namespaced overlay admission reads access objects only through the Role
`breakglass-operator-admission-access` in `breakglass-access` and gets only
the `production` and `breakglass-access` Namespaces; its ClusterRole keeps
only SubjectAccessReview create and those named Namespaces. The manager gets
only the `production` Namespace. When adding a target or control namespace,
update these `resourceNames` and Roles in the same change. Never manually force namespace finalization while
relying on normal namespace garbage-collection guarantees.

The expiry guard has its own Namespace `get`: the
`<release>-expiry-guard-namespaces` ClusterRole (Kustomize:
`breakglass-operator-expiry-guard-namespaces`) grants `get` on the target and
control namespaces by name. Because it outlives those namespaces, the guard can
confirm that a deleted namespace is gone (NotFound) and keep sweeping the
others. In the namespaced Kustomize overlay the names are set in
`expiry-guard-namespaces-production.yaml`, which must stay in sync with the
guard's `--allowed-target-namespaces` and `--control-namespaces`.

### Retiring a control namespace

A control namespace can be deleted only after it holds no BreakGlassSession
(ADR-004). The validating webhook `vcontrolnamespace-v1.kb.io` denies the
deletion otherwise, naming the remaining sessions. Retire a control namespace
while the manager runs:

1. Remove requester permissions in the namespace so no new session is created.
2. Revoke or delete every session in it and wait until they are gone; each
   finalizer is removed only after the manager deleted the session's
   RoleBinding:

   ```bash
   kubectl -n breakglass-access delete breakglasssessions --all --wait=false
   kubectl -n breakglass-access get breakglasssessions   # repeat until empty
   ```

3. Verify that every recorded `status.bindingRef` is gone from its target
   namespace, then delete the namespace.
4. Remove it from `controlNamespaces` (Helm) or `--control-namespaces` and the
   webhook selector (Kustomize) only afterwards. Removing it first drops the
   manager's Roles there and the drain check, recreating the stranded-session
   risk.

The webhook fails closed. While no admission Pod is available, every deletion
of a selected control namespace is denied (`failed calling webhook
"vcontrolnamespace-v1.kb.io"`); restore the admission Deployment and retry. Other namespaces
are unaffected: Helm and the namespaced overlay select only the control
namespaces by name. The default and production Kustomize profiles accept access
objects in every namespace and therefore guard only namespaces labelled
`access.breakglass.io/control-namespace=true`; label every namespace that holds
access objects there. Never bypass the check by deleting the webhook
configuration: a namespace deleted with live sessions loses the manager's Roles
and stays `Terminating` until the Roles are restored by hand.

## Upgrade and rollback

1. Record the image digest, rendered manifest, current CRDs, active sessions,
   and the state of the webhook configurations.
2. Run the release's Kind/E2E suite against a disposable cluster, including
   webhook CA readiness, denied `use`, a rolling manager restart that preserves
   the active binding UID, TTL/recovery, binding replacement, and cleanup
   behaviour.
3. Apply the release, wait for both manager Pods, both admission Pods and the
   serving certificate to become ready, then perform the harmless request
   check above. Upgrading from a single-Deployment installation (manager
   serving the webhooks) is a reinstall (ADR-005). Upgrading from
   cluster-scoped CRDs is destructive; see the procedure below.
4. Keep the former controller image and manifest available, but never roll
   back to an image or manifest that accepts the removed free-form session API.
   First revoke or allow expiry of grants incompatible with the target version.

### Upgrading from cluster-scoped access objects (ADR-004): destructive

Installations created before ADR-004 have cluster-scoped `AccessProfile`,
`BreakGlassRequest`, `BreakGlassApproval` and `BreakGlassSession` CRDs.
Kubernetes treats a CRD's `spec.scope` as immutable: applying the new CRDs
over them fails (`spec.scope: Invalid value: "Namespaced": field is
immutable`), even when no session is active. Neither `kubectl apply` nor
`helm upgrade` can perform this upgrade, and Helm never replaces existing
CRDs. The only path is to delete the four CRDs, which deletes **every** access
object, and install the new release from scratch. There is no conversion:
old objects are not valid under the new schema and are not restored.

1. **Stop new access.** Remove `use`, `approve` and session/request `create`
   permissions from requesters and approvers.
2. **End every grant while the old manager still runs.** Revoke or let expire
   every session, then confirm:
   ```bash
   kubectl get breakglasssessions -o custom-columns=NAME:.metadata.name,PHASE:.status.phase,BINDING:.status.bindingRef.namespace/.status.bindingRef.name
   kubectl get rolebindings -A -l app.kubernetes.io/managed-by=breakglass-operator
   ```
   Every session must be terminal and no managed RoleBinding may remain. The
   old manager must still be running: deleting a session runs its finalizer,
   which removes the session's RoleBinding.
3. **Delete the sessions** (`kubectl delete breakglasssessions --all`) and
   wait until they are gone, again while the old manager runs.
4. **Preserve evidence.** Export all access objects for the audit record:
   ```bash
   kubectl get accessprofiles,breakglassrequests,breakglassapprovals -o yaml > breakglass-pre-adr-004.yaml
   ```
   This export is evidence, not a backup to restore: the objects have no
   namespace and cannot be applied to the new CRDs.
5. **Remove the old operator**, including its webhook configurations (Helm:
   `helm uninstall`; Kustomize: `make undeploy`). The old approval webhook
   denies every approval delete and would otherwise block step 6.
6. **Delete the CRDs** (`kubectl delete crd accessprofiles.access.breakglass.io
   breakglassrequests.access.breakglass.io breakglassapprovals.access.breakglass.io
   breakglasssessions.access.breakglass.io`, or `make uninstall`) and wait until
   `kubectl get crd | grep access.breakglass.io` prints nothing. If a CRD stays
   in `InstanceDeletionInProgress`, a session still holds its finalizer: verify
   from the export of step 2 that its recorded RoleBinding namespace, name and
   UID no longer exist, and only then remove the finalizer by hand. A
   remaining binding is a security investigation, not a cleanup chore.
7. **Install the new release**: create the control namespaces (label them
   `access.breakglass.io/control-namespace=true` for the default and production
   Kustomize profiles), then install with Helm or Kustomize, which creates the
   namespaced CRDs.
8. **Recreate the policy**: write each profile again with
   `metadata.namespace` set to a control namespace, bind requester, approver,
   revoker and auditor roles with RoleBindings in that namespace, and run the
   harmless request check above.

The Kind suite proves rollout continuity for a single rendered version. It is
not a cross-version compatibility or downgrade guarantee. Add a pinned
previous-version fixture and an explicit API-compatibility contract before
claiming version-to-version upgrade or rollback support.

The current Kubernetes compatibility qualification process is documented in
[Compatibility qualification](compatibility.md). It deliberately publishes no
support range until a successful required E2E run has produced and locked the
exact Kind node image and API-server evidence.

The API server deliberately fails new requests closed when the admission
Deployment is unavailable. Treat a webhook failure as an access-control incident, not as a
reason to remove the webhook configuration or set `failurePolicy: Ignore`.

## Controller outage, expiry, and emergency recovery

With two replicas and leader election, one manager Pod may disappear without
stopping reconciliation. Admission runs separately and is not affected by a
manager outage at all; only provisioning and cleanup wait. Restore the
deployment before taking manual RBAC action:

```bash
kubectl get pods -n breakglass-operator-system -l control-plane=controller-manager
kubectl rollout status deployment/breakglass-operator-controller-manager \
  -n breakglass-operator-system --timeout=5m
```

If admission is down, new requests, approvals and sessions are rejected until
it is back:

```bash
kubectl get pods -n breakglass-operator-system -l app.kubernetes.io/component=admission
kubectl logs -n breakglass-operator-system -l app.kubernetes.io/component=admission --tail=50
kubectl rollout status deployment/breakglass-operator-admission \
  -n breakglass-operator-system --timeout=5m
```

During a total controller outage, the independent `expiry-guard` CronJob still
removes expired bindings, normally within `--grace` (two minutes) plus one
schedule interval after `status.expiresAt`. It relies only on the API server and
the Kubernetes CronJob controller, not on the manager. Check that it runs:

```bash
kubectl get cronjob,jobs -n breakglass-operator-system -l app.kubernetes.io/component=expiry-guard
kubectl logs -n breakglass-operator-system -l app.kubernetes.io/component=expiry-guard --tail=50
```

Guard exit codes:

- `0`: the run completed in every namespace.
- `1`: the run could not complete at all (flags, client, cluster-wide list,
  unexpected API error, timeout).
- `2`: the run completed but needs a human: a binding was refused, or a
  configured namespace could not be read. Check the `unreadableNamespaces`
  count in the log; typical causes are a missing guard Role or RoleBinding, or
  a namespace stuck in `Terminating`.

A failed guard Job means an expired binding could not be proven to be the
recorded one (for example a replacement with another UID). The guard leaves it
untouched; investigate it like binding drift. If the guard itself cannot run
(API server degraded, CronJob controller unavailable, quota), an expired binding
can survive longer than its intended TTL. This is a documented best-effort
cleanup SLO, not a safe extension of access. Escalate through the platform
emergency procedure. That procedure must independently match the session's persisted
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
binding drift. Lifecycle metrics come from the manager
(`breakglass-operator-controller-manager-metrics-service`), admission
decisions (`breakglass_admission_requests_total`) from the admission Pods
(`breakglass-operator-admission-metrics-service`); scrape both on HTTPS port
8443. Send Kubernetes audit logs and lifecycle Events to a durable,
restricted sink; Prometheus labels intentionally do not identify people,
profiles, namespaces, or incident tickets.

Before enabling a `ServiceMonitor`, configure CA validation for the metrics
certificate and restrict scraper reachability with a NetworkPolicy that is
tested against the actual API-server, kubelet-probe, and monitoring topology.

The optional [observability pack](../config/observability) supplies a small
PrometheusRule set and Grafana dashboard ConfigMap. It is deliberately not
part of the default installation because monitoring operators, dashboard
sidecars, namespaces, CA trust, and alert-routing policy are cluster-specific.

## Binding or profile integrity drift

Treat a drift alert as a security event. Inspect the affected session and its
Kubernetes audit records; do not edit the generated RoleBinding to "repair"
it. The controller suspends the grant and removes the binding. Restore access
only with a new session after the profile and curated role have been reviewed.
