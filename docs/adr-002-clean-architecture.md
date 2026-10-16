# ADR-002: Clean architecture inside the Kubebuilder layout

**Status:** Accepted, implemented
**Scope:** The manager (reconcilers), the admission binary (webhooks, ADR-005) and the expiry guard. The WebUI keeps its own layering (`internal/webui`).

## Context

The operator's value is a small set of security rules. Each rule must hold no
matter which entry point a person uses:

- who may receive which profile;
- for how long;
- when an approval is independent;
- when a granted binding can no longer be trusted.

Before this decision those rules lived inside Kubernetes adapters:

- **Profile validation** was written four times: in the session controller,
  the profile controller, the session webhook, and its reuse by the request and
  approval webhooks.
- **Namespace scope** was also written four times.
- **The independent-approval check** was written three times, in slightly
  different variants.
- **The decision deadline** was written four times.
- **The session controller** had grown to about 1,950 lines that mixed policy,
  the state machine, API calls, metrics, and events.

Testing a rule meant faking an API server.

## Decision

Source code dependencies point inward only. The Kubebuilder layout stays where
the CLI expects it: `cmd/`, `api/`, `internal/controller`, and
`internal/webhook` become thin adapters around an inner core.

```text
            ┌──────────────────────────────────────────────────────┐
 adapters   │ internal/controller   internal/webhook   cmd/…       │
            │ internal/expiryguard  internal/adapter/apiconv       │
            │   └ controller-runtime, client-go, API types         │
            │ ┌──────────────────────────────────────────────────┐ │
 use cases  │ │ internal/usecase/sessionlifecycle                │ │
            │ │ internal/usecase/requestlifecycle                │ │
            │ │ internal/usecase/profilereadiness                │ │
            │ │ internal/usecase/expirysweep    + port (errors)  │ │
            │ │ ┌──────────────────────────────────────────────┐ │ │
 domain     │ │ │ internal/domain/access   (standard library)  │ │ │
            │ │ └──────────────────────────────────────────────┘ │ │
            │ └──────────────────────────────────────────────────┘ │
            └──────────────────────────────────────────────────────┘
```

| Layer | Package | Contains | May depend on |
| --- | --- | --- | --- |
| Domain | `internal/domain/access` | The rules. Value types for profile, session, request, approval, binding, condition, and issue. Profile validation, delivery-mode channels, namespace scope, human-requester check, independent approval, decision deadline, binding identity and integrity checks, re-verification against live policy, deterministic names. | Go standard library only |
| Use cases | `internal/usecase/…` | Stateful workflows that apply the rules through ports. Ports are small interfaces for policy reads, binding writes, persistence, events, and telemetry. `port` defines the error kinds (not found, already exists, conflict, forbidden) that use cases distinguish. | Domain, other use-case packages, `logr` |
| Adapters | `internal/controller`, `internal/webhook`, `internal/expiryguard`, `internal/adapter/apiconv`, `cmd/…` | Translation between API types and the domain (`apiconv`). Port implementations with controller-runtime clients. Watches, indexes, RBAC and webhook markers, metrics mapping, flag parsing. | Everything inward |

Admission webhooks are stateless policy decisions. They call domain rules
directly and keep their exact user-facing messages; a use-case layer would add
nothing there. Reconcilers are stateful workflows, so they delegate to use
cases.

`api/v1alpha1` exposes the deterministic approval and session names, which are
part of the object-naming contract. It delegates their derivation to the
domain, so there is one implementation.

## Rules for contributors

1. **New or changed security rule:** put it in `internal/domain/access` with a
   plain unit test, then call it from every adapter that needs it. Never
   restate a rule in an adapter.
2. **New workflow step that needs I/O:** add it to the use case and extend a
   port if necessary. Keep API types, `client.Client`, and `apierrors` out of
   use cases. Adapters classify errors with `apiconv.Classify`.
3. **New watch, index, marker, metric, or flag:** it belongs in the adapter.
   RBAC and webhook markers stay in `internal/controller` and
   `internal/webhook`, so `make manifests` keeps generating the same
   manifests.
4. **Tests:**
   - Domain rules: table-driven tests without fakes.
   - Use cases: in-memory port fakes; see
     `internal/usecase/sessionlifecycle/lifecycle_test.go`.
   - Adapters: the existing fake-client and envtest suites.
   - `internal/controller/export_test.go` keeps the established controller
     tests written against API types by translating to the production use
     case and domain functions.

## Enforcement

- `test/architecture` runs with `make test`. It fails if any package under
  `internal/domain` or `internal/usecase` transitively depends on anything
  outside its allowed set.
- The depguard rules `domain-is-pure` and `usecases-depend-inward` in
  `.golangci.yml` report direct violations in `make lint` and the editor.

## Consequences

- **The refactoring preserves behavior.** It is covered by the unchanged
  controller and webhook tests and by identical generated CRDs, RBAC, and
  webhook manifests. Status conditions, reasons, messages, events, metric
  labels, and admission messages are unchanged.
- **Three checks were unified on the strictest existing variant.** Through
  admission none of these differences was reachable, because the approval
  webhook already stamps a non-empty approver into the deterministic slot.
  - Session admission for a request-sourced session now also requires the
    approval in the deterministic slot and a non-empty approver name. The
    session lifecycle already required both.
  - The request lifecycle treats an approval with an empty approver name as
    invalid.
- **One extra cached read when promoting a reservation.** The binding gateway
  re-reads the reservation from the cache and refuses the update if its UID or
  resource version changed. Before, the update relied on the resource version
  alone; the outcome is the same.
- **The session controller shrank from about 1,950 lines** to a ~270-line
  reconciler plus gateway and telemetry adapters. The lifecycle logic now
  lives in four files with distinct responsibilities: dispatch, verification,
  bindings, and termination.
- **The expiry guard shares the domain's binding identity rules.** Its
  Kubernetes adapter is about 80 lines.
