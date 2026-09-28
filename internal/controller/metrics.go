package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// ActiveSessionsGauge tracks the number of currently active BreakGlass sessions.
	ActiveSessionsGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "breakglass_active_sessions",
			Help: "Current number of active BreakGlass emergency sessions",
		},
	)

	// SessionsTotal tracks the total count of session state transitions.
	SessionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "breakglass_sessions_total",
			Help: "Total count of BreakGlass sessions transitioned by phase, role, and target namespace",
		},
		[]string{"phase", "role", "target_namespace"},
	)

	// DriftCorrectionsTotal counts how often an RBAC binding had to be recreated/healed.
	DriftCorrectionsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "breakglass_drift_corrections_total",
			Help: "Total count of RBAC bindings automatically restored due to drift detection",
		},
	)
)

func init() {
	// Register custom metrics with the global controller-runtime metrics registry
	crmetrics.Registry.MustRegister(
		ActiveSessionsGauge,
		SessionsTotal,
		DriftCorrectionsTotal,
	)
}
