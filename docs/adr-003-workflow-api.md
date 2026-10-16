# ADR-003: Workflow API — incident reference, approver routing, four-eyes approval, and reviews

**Status:** Proposed
**Scope:** Additive `v1alpha1` changes to `AccessProfile`, `BreakGlassRequest`, `BreakGlassSession`, and `BreakGlassApproval`, plus one new append-only kind, `BreakGlassReview`. To be settled before the API is promoted to `v1beta1`.

## Context

The grant path is sound (ADR-001), and the rules have a single home
(ADR-002). What is missing are the workflow facts that auditors and incident
responders ask for:

- **Which incident?** A free-text `reason` is not a verifiable link to an
  incident or ticket.
- **Who should decide?** Approval authority is the RBAC verb `approve` on a
  profile. Nothing tells the system whom to ask, so requests wait unnoticed.
- **Is one approver enough?** High-risk profiles need two independent people.
  Today exactly one approval slot exists per request.
- **What happened afterwards?** There is no structured record of what the
  person did, or of whether someone reviewed it.
- **What does a profile mean?** A profile has no human-readable description,
  risk level, owner, or runbook. Its spec is fully immutable, so adding text
  later would force a new profile.

## Principles

These follow from the product vision and ADR-001/002 and constrain every
option below:

1. **Kubernetes RBAC remains the only authorization source.** Profiles may
   narrow, never widen, who may act. Routing information decides whom to
   notify; it never authorizes anyone.
2. **Policy that affects a decision is snapshotted at admission**, like
   `requestTTL` today, so a profile change never alters a running request or
   session.
3. **Everything is additive, and defaults keep today's behavior.** Existing
   profiles, requests, and sessions remain valid without migration.
4. **Every new rule is a domain rule** in `internal/domain/access` with a
   plain unit test; webhooks and use cases only apply it.
5. **Evidence over automation.** Records are append-only objects; no
   controller-owned audit CRD replaces the Kubernetes audit log (security
   review decision 3). The new review records add human statements the audit
   log cannot contain; they do not mirror it.

## Decision overview

```yaml
apiVersion: access.breakglass.io/v1alpha1
kind: AccessProfile
metadata:
  name: production-db-admin
spec:
  # existing, immutable policy
  roleRef: {kind: ClusterRole, name: breakglass-db-admin}
  targetNamespace: production
  maxDuration: 30m
  deliveryMode: ApprovalRequired

  # new, immutable policy (all optional; omitted = today's behavior)
  incident:
    required: true
    pattern: '^(INC|PD)-[0-9]+$'
  approval:
    requiredApprovals: 2
    route:
      groups: ["oncall-db", "platform-leads"]
  review:
    summaryRequired: true
    summaryWithin: 24h

  # new, mutable catalog information (never part of a decision)
  catalog:
    description: "Read/write access to the production database namespace"
    risk: High
    owner: team-database
    runbookURL: https://runbooks.example.com/db/breakglass
```

| # | Feature | API change | Increment |
| --- | --- | --- | --- |
| 1 | Profile catalog | `AccessProfile.spec.catalog`; immutability rule narrowed to the policy fields | 1 |
| 2 | Incident reference | `spec.incident` on the profile; `spec.incidentRef` on request and session | 1 |
| 3 | Approver routing | `spec.approval.route` on the profile (notification only) | 1 |
| 4 | Four-eyes approval | `spec.approval.requiredApprovals`; per-approver approval slots | 2 |
| 5 | Post-session summary | `spec.review`; new kind `BreakGlassReview` | 2 |
| 6 | Emergency access with retrospective review | New delivery mode | Separate decision (see below) |

## 1. Profile catalog

```go
// AccessProfileCatalog is descriptive and never part of an authorization decision.
type AccessProfileCatalog struct {
    // +kubebuilder:validation:MaxLength=512
    Description string `json:"description,omitempty"`
    // +kubebuilder:validation:Enum=Low;Medium;High
    Risk string `json:"risk,omitempty"`
    // +kubebuilder:validation:MaxLength=63
    Owner string `json:"owner,omitempty"`
    // +kubebuilder:validation:Pattern=`^https://`
    RunbookURL string `json:"runbookURL,omitempty"`
}
```

- **Immutability:** The rule `self == oldSelf` on the whole spec is replaced by
  per-field rules on `roleRef`, `targetNamespace`, `maxDuration`,
  `deliveryMode`, `incident`, `approval`, and `review`. `catalog` stays
  mutable. The CRD validation test must prove that every policy field remains
  immutable.
- **Usage:** The WebUI and the CLI show the catalog. `risk` is display only; it
  implies nothing. A high-risk profile must say so through
  `approval.requiredApprovals`.
- **Rejected alternative:** Annotations. They cannot be validated by the
  schema and are easy to misspell.

## 2. Incident reference

```go
// AccessProfileIncidentPolicy decides whether an incident reference is required.
type AccessProfileIncidentPolicy struct {
    Required bool `json:"required,omitempty"`
    // Pattern is an RE2 expression a reference must match.
    // +kubebuilder:validation:MaxLength=256
    Pattern string `json:"pattern,omitempty"`
}

// IncidentReference ties access to an incident or ticket.
type IncidentReference struct {
    // +kubebuilder:validation:Pattern=`^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,127}$`
    ID string `json:"id"`
    // +kubebuilder:validation:Pattern=`^https://`
    URL string `json:"url,omitempty"`
}
```

- **Fields:** `BreakGlassRequest.spec.incidentRef` and
  `BreakGlassSession.spec.incidentRef` are optional and immutable. The request
  controller copies the request's reference into the session it provisions,
  and session source verification includes it in "session matches request".
- **Domain rule:**
  `access.CheckIncidentReference(policy, ref) error`. A missing reference when
  one is required, or a reference that does not match the pattern, is denied
  at admission. The pattern is compiled when the profile is validated: an
  invalid pattern makes the profile `Ready=False` (`InvalidIncidentPattern`)
  and denies every request for it.
- **Snapshot:** The session's resolved grant records the policy that applied
  (`status.grant.incidentRequired`), so later profile drift is detectable like
  other policy drift.
- **Privacy:** Like `reason`, the reference is operational context. It never
  appears in metric labels.
- **Not in this increment:** Verifying the reference against PagerDuty or
  Jira. External verification would put a third-party API in the critical path
  of an emergency. It belongs in an optional, separately failing integration
  that sets an advisory `IncidentVerified` condition. It must never be a
  precondition for access unless a later decision makes it one deliberately.

## 3. Approver routing

```go
type AccessProfileApprovalPolicy struct {
    // +kubebuilder:validation:Minimum=1
    // +kubebuilder:validation:Maximum=3
    // +kubebuilder:default=1
    RequiredApprovals int32 `json:"requiredApprovals,omitempty"`
    Route ApprovalRoute `json:"route,omitempty"`
}

// ApprovalRoute names who should be asked. It grants no authority.
type ApprovalRoute struct {
    // +kubebuilder:validation:MaxItems=10
    Groups []string `json:"groups,omitempty"`
    // +kubebuilder:validation:MaxItems=10
    Users []string `json:"users,omitempty"`
}
```

- **Purpose:** The route is consumed by notifications and by clients. The
  WebUI shows "awaiting approval from oncall-db". A notifier pages these
  people. Authorization is still exactly the RBAC verb `approve` on the
  profile.
- **Why not authorization:** Making route membership a second authorization
  check would create two places to grant approval rights, and a typo in a
  group name would silently lock out approvers. If a platform wants approval
  limited to on-call, it binds `approve` to the on-call group. That is one
  place, and it is auditable with `kubectl auth can-i`.
- **Not in this increment:** Dynamic on-call schedules, such as resolving
  "whoever is on call in PagerDuty now". They belong to the notification
  integration, not to the API.

## 4. Four-eyes approval

- **Snapshot:** `requiredApprovals` is copied into
  `BreakGlassRequest.spec.requiredApprovals` at admission, as `requestTTL` is
  today. The request controller and session verification use only the
  snapshot.
- **Approval slots:**
  - Today there is one slot per request:
    `breakglass-approval-<sha256(requestUID)[:8]>`.
  - Under this proposal there is one slot per request and approver:
    `breakglass-approval-<sha256(requestUID)[:8]>-<sha256(approverUsername)[:8]>`.
  - The approval webhook stamps the name, as it does today. A second decision
    by the same person collides on create, so one person can never count twice.
- **Status:** `BreakGlassRequest.status.approvalRefs` (a list) replaces the
  single `approvalRef`. The old field is still written for
  `requiredApprovals == 1`, so existing clients keep working.
- **Domain rules:**
  - `access.Decide(request, approvals) Outcome`. Any valid `Denied` decision
    denies the request. The request is `Approved` once the number of distinct,
    independent approvers who approved reaches `requiredApprovals`. Every
    approval must already satisfy `Approval.DecidesFor`: it cites exactly this
    request, the approver is a named user, and the approver is not the
    requester.
  - Session source verification re-reads every recorded approval by name and
    UID and applies the same rule.
- **Compatibility:**
  - Requests admitted before the upgrade carry no `requiredApprovals`; they are
    treated as 1, and their legacy single slot remains valid.
  - New requests use per-approver slots only. Approval-workflow requests live
    at most `requestTTL` (15 minutes by default), so no long-lived mixed state
    exists.
  - The upgrade test (SR-03) must cover a request that is pending across the
    upgrade.
- **Limit:** At most 3 approvals. Beyond that, a pre-approved standing role is
  the honest answer, not a longer approval chain.

## 5. Post-session summary: `BreakGlassReview`

A new append-only kind in the session's control namespace (ADR-004). It records human statements about a
finished session.

```go
type BreakGlassReviewSpec struct {
    // SessionRef is stamped from the session by admission (name and UID).
    SessionRef BreakGlassRequestReference `json:"sessionRef"`
    // +kubebuilder:validation:Enum=Summary
    Type string `json:"type"`
    // Author is stamped from the authenticated admission user.
    Author SubjectReference `json:"author"`
    // +kubebuilder:validation:MinLength=10
    // +kubebuilder:validation:MaxLength=4096
    Text string `json:"text"`
}
```

- **Profile policy:** `spec.review.summaryRequired` and `summaryWithin` are
  snapshotted into the session's grant at activation.
- **Who may write:** Only the session's subject may write the `Summary`, and
  only after the session has ended (Expired or Revoked).
- **Deterministic name:** `breakglass-review-<sha256(sessionUID)[:8]>-summary`,
  so there is exactly one summary per session. The spec is immutable and
  deletion is denied, as for approvals.
- **Status:** The session lifecycle sets an advisory condition `ReviewComplete`
  with reason `Pending`, `Completed`, or `Overdue` (after `summaryWithin`).
  This never changes access.
- **Telemetry:** A gauge `breakglass_sessions_review_overdue` feeds an alert.
- **Extensibility:** `Type` is an enum so that the emergency mode (below) can
  add `Endorsement` and `Objection` without a new kind.
- **Rejected alternative:** Writing the summary into the session. Its spec is
  intentionally immutable, and its status belongs to the controller. A
  separate append-only object keeps authorship and time attributable.

## 6. Emergency access with retrospective review (separate decision)

The genuine break-glass case: at night, with no approver reachable. Sketch:

- **Delivery mode:** `EmergencyWithReview`. The requester creates a session
  directly, but only with a shorter `emergency.maxDuration`, a required
  incident reference, and an immediate high-priority notification.
- **Review:** Within `emergency.reviewWithin`, an independent person with
  `approve` on the profile records an `Endorsement` or an `Objection`
  (`BreakGlassReview` types above).
- **Outcome:** An objection revokes the session immediately if it is still
  active, and marks it for an incident review. A missing review becomes
  `Overdue` and pages.

This weakens the four-eyes guarantee in exchange for availability. It
therefore needs its own ADR, an explicit per-profile opt-in, separate RBAC
(the verb `emergency` instead of `use`), and a threat-model update before it
is implemented. It is listed here only so that the `BreakGlassReview` type set
and the incident reference are designed to support it.

## Domain placement

All new rules go into `internal/domain/access`, next to the existing ones:

| Rule | Function |
| --- | --- |
| Incident reference required or matching | `CheckIncidentReference` |
| Profile defects for new fields | `ProfileIncidentPatternInvalid`, `ProfileApprovalCountInvalid` |
| Approval quorum | `Decide(request, approvals)` |
| Approval slot name | `ApprovalName(requestUID, approver)` |
| Summary authorship and timing | `CheckSummary(session, review, now)` |
| Review state | `ReviewState(session, reviews, now)` |

The request lifecycle and the session lifecycle use these rules through their
existing ports. Each needs one new read: the request lifecycle lists approvals
for a request, and the session lifecycle reads the review.

## Increments

1. **Catalog, incident reference, approver routing.** All three are additive
   and need no new kind. The WebUI and the planned `kubectl breakglass` show
   catalog, route, and incident. The notification integration can use the
   route.
2. **Four-eyes approval and `BreakGlassReview` with `Summary`.** Requires the
   upgrade test from SR-03 before release.
3. **Emergency access.** Only after its own ADR and threat-model update.

## Open questions

1. Should the incident ID pattern have a cluster-wide default (a manager flag)
   in addition to the per-profile pattern? Proposal: no. Each profile is
   explicit and reviewable on its own.
2. Should a denial require a non-empty `comment`? Proposal: yes, as a domain
   rule in the approval webhook (`Denied` requires 10–1024 characters). It is
   small, has no API change, and helps requesters understand the outcome.
3. Should the summary be visible to everyone who can read sessions? It carries
   the same sensitivity as `reason` (SR-05). Proposal: restrict reads of
   `breakglassreviews` like sessions, and solve the visibility question
   together with SR-05.
