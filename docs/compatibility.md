# Compatibility qualification

The operator does not currently publish a Kubernetes support range. Before a
version is called supported, the exact tuple must be observed in a successful
required E2E run and committed as a digest-pinned compatibility lock.

Every required Kind suite emits a short `*-kind-compatibility-evidence-*`
artifact containing:

* the Kind CLI version;
* `kubectl version -o yaml` from the actual test API server;
* the selected Kind node and its Docker image metadata; and
* the exact cert-manager fixture version.

The standard suite qualifies admission, certificates, lifecycle, and approval
behavior. The production suite qualifies the HA overlay, manager/webhook
outage, certificate reissue, restart continuity, and TTL recovery. A valid
support tuple requires both suites to pass for the same revision.

## Creating the first lock

1. Run the required E2E gates on `main` or dispatch them for the candidate
   revision.
2. Inspect both evidence artifacts. Record the server `gitVersion` and the
   node image's immutable repository digest rather than a mutable tag.
3. Verify the checksum of the cert-manager release manifest and pin the
   auxiliary metrics-test image by digest.
4. Commit one lock entry, make `Makefile` pass its node image explicitly, and
   make CI source the lock for both suites.
5. Only then document that exact tuple as supported. A second row requires an
   independent successful qualification; upstream compatibility claims alone
   are insufficient.

This process does not certify managed Kubernetes distributions, external
issuers or CA policies, OIDC identity providers, arm64 runtime behavior, or
operator upgrade/rollback. Those are separate contracts with their own tests.
