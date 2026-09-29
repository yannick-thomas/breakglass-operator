# Optional observability pack

This pack is intentionally separate from the secure default installer. It
requires a Prometheus Operator `PrometheusRule` CRD and a Grafana dashboard
sidecar that recognizes `grafana_dashboard: "1"` ConfigMaps. Adapt the
namespace, labels, and alert routing to the monitoring platform, then apply:

```bash
kubectl apply -k config/observability
```

The rules contain only bounded, privacy-safe metrics. Use Kubernetes audit-log
export to correlate a person, incident reason, profile, and namespace.
