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

package main

import (
	"flag"
	"os"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/adapter/startup"
	"github.com/yannick-thomas/breakglass-operator/internal/controller"
	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	breakglassmetrics "github.com/yannick-thomas/breakglass-operator/internal/metrics"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(accessv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var serving startup.ServingFlags
	var placementFlags startup.PlacementFlags
	var enableLeaderElection bool
	var maxSessionDuration time.Duration
	var requestControllerUsername string
	var probeAddr string
	serving.Bind(flag.CommandLine)
	placementFlags.Bind(flag.CommandLine)
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.DurationVar(&maxSessionDuration, "max-session-duration", 4*time.Hour,
		"Maximum lifetime allowed for a BreakGlassSession. Set to 0 to disable the controller-side limit.")
	flag.StringVar(&requestControllerUsername, "request-controller-username", "",
		"Exact Kubernetes username of this manager's ServiceAccount. Empty disables request provisioning. "+
			"The admission server must trust the same username.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// The manager serves no admission webhook (ADR-005); cmd/admission does.
	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'.
	metricsServerOptions := serving.MetricsOptions(setupLog, serving.TLSOptions(setupLog))

	placement, err := placementFlags.Placement()
	if err != nil {
		setupLog.Error(err, "Invalid namespace placement")
		os.Exit(1)
	}

	managerOptions := ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "d0d95bf7.breakglass.io",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
		Cache: cacheOptions(placement),
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), managerOptions)
	if err != nil {
		setupLog.Error(err, "Failed to start manager")
		os.Exit(1)
	}

	if err := (&controller.BreakGlassSessionReconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Scheme:    mgr.GetScheme(),
		// The reconciler still accepts client-go's legacy EventRecorder interface.
		// nolint:staticcheck // Migrate the reconciler interface before switching to manager.GetEventRecorder.
		Recorder:                mgr.GetEventRecorderFor("breakglass-controller"),
		MaxSessionDuration:      maxSessionDuration,
		Metrics:                 breakglassmetrics.DefaultRecorder,
		AllowedTargetNamespaces: placement.Target,
		ControlNamespaces:       placement.Control,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "breakglasssession")
		os.Exit(1)
	}
	if err := (&controller.AccessProfileReconciler{
		Client:                  mgr.GetClient(),
		APIReader:               mgr.GetAPIReader(),
		Scheme:                  mgr.GetScheme(),
		AllowedTargetNamespaces: placement.Target,
		ControlNamespaces:       placement.Control,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "accessprofile")
		os.Exit(1)
	}
	if err := (&controller.BreakGlassRequestReconciler{
		Client:                    mgr.GetClient(),
		Metrics:                   breakglassmetrics.DefaultRecorder,
		RequestControllerUsername: requestControllerUsername,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "breakglassrequest")
		os.Exit(1)
	}
	if _, err := breakglassmetrics.RegisterSessionStateCollector(mgr.GetClient(), controller.SessionScope); err != nil {
		setupLog.Error(err, "Failed to register BreakGlass session metrics")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "Failed to run manager")
		os.Exit(1)
	}
}

// cacheOptions scopes each informer to the namespaces its RBAC covers.
// Access objects live only in control namespaces and RoleBindings only in
// target namespaces, so a shared namespace set would watch objects the
// manager has no permission to list and the cache would never sync. Any
// other namespaced type defaults to the control namespaces. An empty scope
// keeps the all-namespaces development default for its kinds; Validate
// guarantees that explicit target namespaces come with explicit control
// namespaces.
func cacheOptions(placement access.Placement) cache.Options {
	if !placement.Target.Explicit() && !placement.Control.Explicit() {
		return cache.Options{}
	}
	control := namespaceConfigs(placement.Control)
	byObject := map[client.Object]cache.ByObject{
		&accessv1alpha1.AccessProfile{}:      {Namespaces: control},
		&accessv1alpha1.BreakGlassRequest{}:  {Namespaces: control},
		&accessv1alpha1.BreakGlassApproval{}: {Namespaces: control},
		&accessv1alpha1.BreakGlassSession{}:  {Namespaces: control},
	}
	bindings := map[string]cache.Config{cache.AllNamespaces: {}}
	if placement.Target.Explicit() {
		bindings = namespaceConfigs(placement.Target)
	}
	byObject[&rbacv1.RoleBinding{}] = cache.ByObject{Namespaces: bindings}
	return cache.Options{DefaultNamespaces: control, ByObject: byObject}
}

func namespaceConfigs(namespaces map[string]struct{}) map[string]cache.Config {
	configs := make(map[string]cache.Config, len(namespaces))
	for namespace := range namespaces {
		configs[namespace] = cache.Config{}
	}
	return configs
}
