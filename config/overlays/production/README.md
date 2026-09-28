# Production overlay

This overlay consumes `config/default` and adds controller availability:

* two manager replicas with leader election;
* a `PodDisruptionBudget` that keeps one replica available during voluntary
  disruptions; and
* hostname spreading plus preferred pod anti-affinity.

Render it with:

```bash
kubectl kustomize config/overlays/production
```

The strict hostname spread constraint intentionally requires at least two
schedulable nodes. A single-node cluster must use `config/default` or maintain
a separately reviewed non-HA overlay; silently weakening this production
configuration would make the availability claim misleading.

This overlay inherits the default's cert-manager-issued webhook certificate,
CA injection, fail-closed webhooks, and authenticated HTTPS metrics endpoint.
It does not enable the generated Prometheus `ServiceMonitor`: that scaffold
uses `insecureSkipVerify` until a cluster-specific, CA-validating scraper
configuration is supplied. It also does not add a network policy because the
allowed Prometheus and API-server source topology must be verified for each
cluster, including probe traffic.
