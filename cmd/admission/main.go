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

// Command admission serves the BreakGlass admission webhooks (ADR-005). It
// runs no reconciler and no leader election. Every read goes directly to the
// API server; the only write is creating SubjectAccessReviews.
package main

import (
	"errors"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/adapter/startup"
	webhookv1alpha1 "github.com/yannick-thomas/breakglass-operator/internal/webhook/v1alpha1"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(accessv1alpha1.AddToScheme(scheme))
}

func main() {
	var serving startup.ServingFlags
	var placementFlags startup.PlacementFlags
	var webhookCertPath, webhookCertName, webhookCertKey string
	var webhookPort int
	var requestTTL time.Duration
	var requestControllerUsername string
	var probeAddr string
	var shutdownDelay time.Duration
	serving.Bind(flag.CommandLine)
	placementFlags.Bind(flag.CommandLine)
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.DurationVar(&requestTTL, "request-ttl", 15*time.Minute,
		"Maximum time a BreakGlassRequest may await a decision. Must be greater than zero.")
	flag.StringVar(&requestControllerUsername, "request-controller-username", "",
		"Exact Kubernetes username (the manager's ServiceAccount) permitted to create a session sourced "+
			"from an approved BreakGlassRequest. Empty rejects every request-sourced session.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.IntVar(&webhookPort, "webhook-port", 9443, "Port the webhook server listens on.")
	flag.DurationVar(&shutdownDelay, "shutdown-delay", startup.DefaultShutdownDelay,
		"How long a terminating pod keeps answering admission calls while it reports not ready, so the "+
			"Service endpoints and node proxies stop routing to it first. Keep it below the termination grace period.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	placement, err := placementFlags.Placement()
	if err != nil {
		setupLog.Error(err, "Invalid namespace placement")
		os.Exit(1)
	}
	if requestTTL <= 0 {
		setupLog.Error(errors.New("request-ttl must be greater than zero"), "Invalid request TTL")
		os.Exit(1)
	}

	tlsOpts := serving.TLSOptions(setupLog)
	webhookServerOptions := webhook.Options{
		TLSOpts: tlsOpts,
		Port:    webhookPort,
	}
	if len(webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)
		webhookServerOptions.CertDir = webhookCertPath
		webhookServerOptions.CertName = webhookCertName
		webhookServerOptions.KeyName = webhookCertKey
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                serving.MetricsOptions(setupLog, tlsOpts),
		WebhookServer:          webhook.NewServer(webhookServerOptions),
		HealthProbeBindAddress: probeAddr,
		// Admission is stateless: every replica serves, none leads.
		LeaderElection: false,
		NewClient:      uncachedClient,
	})
	if err != nil {
		setupLog.Error(err, "Failed to create admission manager")
		os.Exit(1)
	}

	if err := webhookv1alpha1.SetupAccessProfileWebhookWithManager(mgr, placement); err != nil {
		setupLog.Error(err, "Failed to create webhook", "webhook", "AccessProfile")
		os.Exit(1)
	}
	if err := webhookv1alpha1.SetupBreakGlassSessionWebhookWithManager(
		mgr, placement, requestControllerUsername,
	); err != nil {
		setupLog.Error(err, "Failed to create webhook", "webhook", "BreakGlassSession")
		os.Exit(1)
	}
	if err := webhookv1alpha1.SetupBreakGlassRequestWebhookWithManager(mgr, placement, requestTTL); err != nil {
		setupLog.Error(err, "Failed to create webhook", "webhook", "BreakGlassRequest")
		os.Exit(1)
	}
	if err := webhookv1alpha1.SetupBreakGlassApprovalWebhookWithManager(mgr, placement); err != nil {
		setupLog.Error(err, "Failed to create webhook", "webhook", "BreakGlassApproval")
		os.Exit(1)
	}
	if err := webhookv1alpha1.SetupControlNamespaceWebhookWithManager(mgr, placement); err != nil {
		setupLog.Error(err, "Failed to create webhook", "webhook", "ControlNamespace")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	// Ready only once the webhook server listens, so the Service never
	// routes admission calls to a replica that cannot answer them.
	if err := mgr.AddReadyzCheck("webhook", mgr.GetWebhookServer().StartedChecker()); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}
	// A terminating replica reports not ready but keeps answering for
	// shutdownDelay: admission fails closed, so a call routed to an address
	// that stopped at once would be denied during every rollout.
	var drain startup.Drain
	if err := mgr.AddReadyzCheck("draining", drain.ReadyCheck); err != nil {
		setupLog.Error(err, "Failed to set up drain check")
		os.Exit(1)
	}
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)

	setupLog.Info("Starting admission server")
	if err := mgr.Start(drain.Context(signals, shutdownDelay, func() { os.Exit(1) })); err != nil {
		setupLog.Error(err, "Failed to run admission server")
		os.Exit(1)
	}
}

// uncachedClient builds the manager client without a cache reader. Admission
// reads through the manager's APIReader and only creates
// SubjectAccessReviews through this client; dropping the cache guarantees
// that no read ever starts an informer the admission identity has no list or
// watch permission for.
func uncachedClient(config *rest.Config, options client.Options) (client.Client, error) {
	options.Cache = nil
	return client.New(config, options)
}
