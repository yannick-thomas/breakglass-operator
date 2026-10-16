# Production overlay

This overlay consumes `config/default` and adds availability to both
Deployments (ADR-005):

* two manager replicas with leader election, and two admission replicas
  (admission needs no leader election; every replica serves);
* one `PodDisruptionBudget` per Deployment
  (`breakglass-operator-controller-manager`, `breakglass-operator-admission`)
  that keeps one replica available during voluntary disruptions; and
* hostname spreading plus preferred pod anti-affinity, per Deployment.

The manager runs the reconcilers and serves no webhook. The admission
Deployment serves every webhook behind `breakglass-operator-webhook-service`
and alone mounts the serving certificate. Rolling one never removes the
other: a manager rollout no longer blocks requests, and an admission rollout
keeps one replica serving.

Render it with:

```bash
kubectl kustomize config/overlays/production
```

The strict hostname spread constraint intentionally requires at least two
schedulable nodes. A single-node cluster must use `config/default` or maintain
a separately reviewed non-HA overlay; silently weakening this production
configuration would make the availability claim misleading.

This overlay inherits the default's cert-manager-issued webhook certificate,
CA injection, fail-closed webhooks, and authenticated HTTPS metrics endpoints
(`breakglass-operator-controller-manager-metrics-service` and
`breakglass-operator-admission-metrics-service`).
It does not enable the generated Prometheus `ServiceMonitor`: that scaffold
uses `insecureSkipVerify` until a cluster-specific, CA-validating scraper
configuration is supplied. It also does not add a network policy because the
allowed Prometheus and API-server source topology must be verified for each
cluster, including probe traffic.

Like the default, this overlay accepts access objects in every namespace, so
the fail-closed control-namespace drain check (ADR-004) guards only namespaces
labelled `access.breakglass.io/control-namespace=true`. Label each namespace
that holds access objects; see "Retiring a control namespace" in
`docs/production-operations.md`.
