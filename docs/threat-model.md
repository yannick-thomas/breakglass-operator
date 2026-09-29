# Threat model

## Security objective

Grant a verified human only a pre-approved, namespaced Kubernetes permission
for a bounded incident window. A requester must not choose the grantee, role,
namespace, or lifetime beyond the administrator-owned profile limit.

## Assets and trust boundaries

| Asset | Trust boundary | Security property |
| --- | --- | --- |
| Human identity | Kubernetes API authentication and audit chain | YAML never supplies the subject. |
| Permission policy | GitOps-controlled AccessProfile and curated ClusterRole | Role, target namespace, and maximum TTL are fixed. |
| Active grant | Controller-owned RoleBinding with recorded UID | Replacement or drift suspends; it is never adopted. |
| Admission boundary | TLS webhook with `failurePolicy: Fail` | A non-running webhook rejects new sessions. |
| Audit context | Kubernetes audit pipeline and restricted readers | Reasons and identities do not enter Prometheus labels. |

## Threats and dispositions

| Threat | Control | Residual risk / operator action |
| --- | --- | --- |
| Requester submits `cluster-admin`, another user, or another namespace | Request has only named profile; mutating/validating webhooks own subject and profile UID | Treat webhook unavailability as an access-control incident. |
| Requester uses a profile not granted to them | `SubjectAccessReview` checks named custom `use` verb | Bind profile-specific requester roles, not a wildcard profile role. |
| Profile or role is replaced under the same name | UID snapshot; active role rules hash; periodic direct role read | Curated roles remain versioned/immutable; investigate suspended sessions. |
| Managed RoleBinding is edited, deleted, or replaced | Owner, labels, subject, role, namespace, expiry, and UID integrity checks | Controller intentionally does not repair or delete a replacement. |
| Controller outage leaves an expired binding | HA/PDB, past-expiry alert, recovery test, UID-safe manual runbook | TTL is a cleanup SLO, not cryptographic credential expiry. |
| Webhook outage allows an unvalidated request | `failurePolicy: Fail`, multi-replica deployment, outage E2E | Availability loss blocks requests; never change policy to `Ignore`. |
| Broad readers discover incident reasons or identities | Separate requester/auditor RBAC; no identifying metric labels | Export Kubernetes audit logs to a restricted durable sink. |
| Workload impersonates a human requester | Standard ServiceAccount names are rejected | Supported OIDC issuer/group policy is a platform prerequisite, not yet enforced by this API. |

## Non-goals and exclusions

The operator is not an IdP, ticketing system, SIEM, generic PAM replacement,
or cloud-IAM broker. Cluster-wide grants, service-account self-service,
automatic binding repair, and a fail-open emergency path are excluded from
`v1alpha1`.

## Release requirements

A supported production release needs a reviewed target Kubernetes-version
matrix, a tested cert-manager integration, digest-pinned and signed image,
SBOM/vulnerability evidence, and a successful production Kind/E2E gate. Until
then the implementation is an evaluated production-access primitive, not a
blanket compatibility promise.
