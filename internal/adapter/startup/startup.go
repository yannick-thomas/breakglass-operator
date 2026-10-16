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

// Package startup holds the flag parsing and server options that the manager
// (cmd/main.go) and the admission server (cmd/admission) share. Both binaries
// must interpret the placement flags identically (ADR-005), so the parsing
// lives here once.
package startup

import (
	"crypto/tls"
	"flag"
	"fmt"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
)

// Flag names shared by both binaries.
const (
	AllowedTargetNamespacesFlag = "allowed-target-namespaces"
	ControlNamespacesFlag       = "control-namespaces"
)

// PlacementFlags holds the raw values of the namespace placement flags.
type PlacementFlags struct {
	AllowedTargetNamespaces string
	ControlNamespaces       string
}

// Bind registers the placement flags on fs.
func (f *PlacementFlags) Bind(fs *flag.FlagSet) {
	fs.StringVar(&f.AllowedTargetNamespaces, AllowedTargetNamespacesFlag, "",
		"Comma-separated namespaces in which access may be granted. "+
			"Empty permits all namespaces and is for development only.")
	fs.StringVar(&f.ControlNamespaces, ControlNamespacesFlag, "",
		"Comma-separated namespaces in which AccessProfiles, requests, approvals, and sessions may live. "+
			"Must not overlap allowed-target-namespaces and is required when that is set. "+
			"Empty permits all namespaces and is for development only.")
}

// Placement parses and validates the flag values.
func (f PlacementFlags) Placement() (access.Placement, error) {
	target, err := ParseNamespaceFlag(AllowedTargetNamespacesFlag, f.AllowedTargetNamespaces)
	if err != nil {
		return access.Placement{}, err
	}
	control, err := ParseNamespaceFlag(ControlNamespacesFlag, f.ControlNamespaces)
	if err != nil {
		return access.Placement{}, err
	}
	placement := access.Placement{Control: control, Target: target}
	if err := placement.Validate(); err != nil {
		return access.Placement{}, err
	}
	return placement, nil
}

// ParseNamespaceFlag parses a comma-separated namespace scope and names the
// flag in any error.
func ParseNamespaceFlag(flagName, value string) (access.NamespaceScope, error) {
	scope, err := access.ParseNamespaceScope(value)
	if err != nil {
		return nil, fmt.Errorf("%s %w", flagName, err)
	}
	return scope, nil
}

// ServingFlags configures the HTTPS metrics endpoint and HTTP/2.
type ServingFlags struct {
	MetricsAddr     string
	SecureMetrics   bool
	MetricsCertPath string
	MetricsCertName string
	MetricsCertKey  string
	EnableHTTP2     bool
}

// Bind registers the metrics and HTTP/2 flags on fs.
func (f *ServingFlags) Bind(fs *flag.FlagSet) {
	fs.StringVar(&f.MetricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	fs.BoolVar(&f.SecureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	fs.StringVar(&f.MetricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	fs.StringVar(&f.MetricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	fs.StringVar(&f.MetricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	fs.BoolVar(&f.EnableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
}

// TLSOptions disables HTTP/2 unless it was enabled explicitly. HTTP/2 is off
// by default because of the HTTP/2 Stream Cancellation and Rapid Reset CVEs:
// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
// - https://github.com/advisories/GHSA-4374-p667-p6c8
func (f ServingFlags) TLSOptions(log logr.Logger) []func(*tls.Config) {
	if f.EnableHTTP2 {
		return nil
	}
	return []func(*tls.Config){func(c *tls.Config) {
		log.Info("Disabling HTTP/2")
		c.NextProtos = []string{"http/1.1"}
	}}
}

// MetricsOptions returns the metrics server options. Secure serving protects
// the endpoint with authentication and authorization (TokenReview and
// SubjectAccessReview, granted by the metrics-auth role). Without a
// certificate path controller-runtime generates a self-signed certificate,
// which is meant for development only.
func (f ServingFlags) MetricsOptions(log logr.Logger, tlsOpts []func(*tls.Config)) metricsserver.Options {
	options := metricsserver.Options{
		BindAddress:   f.MetricsAddr,
		SecureServing: f.SecureMetrics,
		TLSOpts:       tlsOpts,
	}
	if f.SecureMetrics {
		options.FilterProvider = filters.WithAuthenticationAndAuthorization
	}
	if len(f.MetricsCertPath) > 0 {
		log.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", f.MetricsCertPath, "metrics-cert-name", f.MetricsCertName,
			"metrics-cert-key", f.MetricsCertKey)
		options.CertDir = f.MetricsCertPath
		options.CertName = f.MetricsCertName
		options.KeyName = f.MetricsCertKey
	}
	return options
}
