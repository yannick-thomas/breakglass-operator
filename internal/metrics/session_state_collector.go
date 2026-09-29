/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerruntimemetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
)

// ScopeResolver maps a session to one of the bounded scope labels. It is kept
// outside the collector so a profile-based API can derive scope from a
// controller-persisted binding reference without exposing profile names or
// namespaces as labels.
type ScopeResolver func(*accessv1alpha1.BreakGlassSession) Scope

// SessionStateCollector derives current security state from the manager cache
// at scrape time. This avoids incorrect increment/decrement accounting after
// manager restarts, reconcile retries, or finalizer races.
type SessionStateCollector struct {
	reader         client.Reader
	resolveScope   ScopeResolver
	now            func() time.Time
	active         *prometheus.Desc
	pastExpiry     *prometheus.Desc
	collectSuccess *prometheus.Desc
}

var _ prometheus.Collector = (*SessionStateCollector)(nil)

// NewSessionStateCollector returns a cache-backed collector. A nil resolver
// safely emits scope="unknown" rather than deriving a label from request data.
func NewSessionStateCollector(reader client.Reader, resolveScope ScopeResolver) *SessionStateCollector {
	return NewSessionStateCollectorWithClock(reader, resolveScope, time.Now)
}

// NewSessionStateCollectorWithClock is intended for deterministic unit tests.
func NewSessionStateCollectorWithClock(reader client.Reader, resolveScope ScopeResolver, now func() time.Time) *SessionStateCollector {
	if now == nil {
		now = time.Now
	}
	return &SessionStateCollector{
		reader:       reader,
		resolveScope: resolveScope,
		now:          now,
		active: prometheus.NewDesc(
			prometheus.BuildFQName(metricNamespace, "", "active_sessions"),
			"Number of BreakGlassSessions whose persisted phase is Active.",
			[]string{metricLabelScope},
			nil,
		),
		pastExpiry: prometheus.NewDesc(
			prometheus.BuildFQName(metricNamespace, "", "sessions_past_expiry"),
			"Number of active BreakGlassSessions with missing or elapsed expiry.",
			[]string{metricLabelScope},
			nil,
		),
		collectSuccess: prometheus.NewDesc(
			prometheus.BuildFQName(metricNamespace, "", "session_state_collection_success"),
			"Whether the current BreakGlassSession state could be listed from the controller cache.",
			nil,
			nil,
		),
	}
}

// RegisterSessionStateCollector registers the cache-backed state collector in
// controller-runtime's registry. Call it once after constructing the manager.
func RegisterSessionStateCollector(reader client.Reader, resolveScope ScopeResolver) (*SessionStateCollector, error) {
	collector := NewSessionStateCollector(reader, resolveScope)
	if err := controllerruntimemetrics.Registry.Register(collector); err != nil {
		return nil, fmt.Errorf("register BreakGlass session state collector: %w", err)
	}
	return collector, nil
}

// Describe implements prometheus.Collector.
func (c *SessionStateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.active
	ch <- c.pastExpiry
	ch <- c.collectSuccess
}

// Collect implements prometheus.Collector. A cache List is local to the
// controller manager and does not create one Kubernetes API request per
// Prometheus scrape.
func (c *SessionStateCollector) Collect(ch chan<- prometheus.Metric) {
	if c.reader == nil {
		ch <- prometheus.MustNewConstMetric(c.collectSuccess, prometheus.GaugeValue, 0)
		return
	}

	sessions := &accessv1alpha1.BreakGlassSessionList{}
	if err := c.reader.List(context.Background(), sessions); err != nil {
		ch <- prometheus.MustNewConstMetric(c.collectSuccess, prometheus.GaugeValue, 0)
		return
	}

	activeByScope := map[Scope]float64{}
	pastExpiryByScope := map[Scope]float64{}
	now := c.now()
	for i := range sessions.Items {
		session := &sessions.Items[i]
		if session.Status.Phase != accessv1alpha1.PhaseActive {
			continue
		}

		scope := c.scopeFor(session)
		activeByScope[scope]++
		if isPastExpiry(session.Status.ExpiresAt, now) {
			pastExpiryByScope[scope]++
		}
	}

	for _, scope := range []Scope{ScopeNamespaced, ScopeCluster, ScopeUnknown} {
		// Emit zero-valued series too. This makes a security alert distinguish
		// a healthy zero from an absent metric series.
		ch <- prometheus.MustNewConstMetric(c.active, prometheus.GaugeValue, activeByScope[scope], string(scope))
		ch <- prometheus.MustNewConstMetric(c.pastExpiry, prometheus.GaugeValue, pastExpiryByScope[scope], string(scope))
	}
	ch <- prometheus.MustNewConstMetric(c.collectSuccess, prometheus.GaugeValue, 1)
}

func (c *SessionStateCollector) scopeFor(session *accessv1alpha1.BreakGlassSession) Scope {
	if c.resolveScope == nil {
		return ScopeUnknown
	}
	return normalizeScope(c.resolveScope(session))
}

func isPastExpiry(expiresAt *metav1.Time, now time.Time) bool {
	return expiresAt == nil || !now.Before(expiresAt.Time)
}
