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

// Command expiry-guard performs one independent expiry sweep and exits. It is
// meant to run as a CronJob with its own ServiceAccount, so expired access is
// removed even while the controller manager is unavailable.
//
// Exit codes: 0 sweep completed, 1 sweep could not complete, 2 sweep completed
// but at least one expired binding needs a human (see the logs).
package main

import (
	"context"
	"flag"
	"os"
	"time"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/expiryguard"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/expirysweep"
)

const (
	exitError    = 1
	exitRefusals = 2
)

func main() {
	var grace, timeout time.Duration
	var allowedNamespaces, controlNamespaces string
	var dryRun bool
	flag.DurationVar(&grace, "grace", expirysweep.DefaultGrace,
		"Time after a session's expiry before the guard removes its binding. Leaves the controller time to clean up first.")
	flag.DurationVar(&timeout, "timeout", time.Minute, "Maximum duration of one sweep.")
	flag.StringVar(&allowedNamespaces, "allowed-target-namespaces", "",
		"Comma-separated namespaces the guard may act in. Keep in sync with the manager. Empty permits all namespaces.")
	flag.StringVar(&controlNamespaces, "control-namespaces", "",
		"Comma-separated namespaces in which sessions live. Keep in sync with the manager. Empty reads all namespaces.")
	flag.BoolVar(&dryRun, "dry-run", false, "Report what would be removed without deleting anything.")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("expiry-guard")

	if grace < 0 || timeout <= 0 {
		log.Info("Invalid flags: grace must not be negative and timeout must be positive")
		os.Exit(exitError)
	}
	scope, err := access.ParseNamespaceScope(allowedNamespaces)
	if err != nil {
		log.Error(err, "Invalid allowed-target-namespaces")
		os.Exit(exitError)
	}
	control, err := access.ParseNamespaceScope(controlNamespaces)
	if err != nil {
		log.Error(err, "Invalid control-namespaces")
		os.Exit(exitError)
	}
	if err := (access.Placement{Control: control, Target: scope}).Validate(); err != nil {
		log.Error(err, "Invalid namespace placement")
		os.Exit(exitError)
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(accessv1alpha1.AddToScheme(scheme))

	cfg, err := ctrl.GetConfig()
	if err != nil {
		log.Error(err, "Could not load Kubernetes client configuration")
		os.Exit(exitError)
	}
	// A direct, uncached client: the guard must see the API server's state,
	// not a possibly stale informer cache.
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		log.Error(err, "Could not create Kubernetes client")
		os.Exit(exitError)
	}

	ctx, cancel := context.WithTimeout(ctrl.SetupSignalHandler(), timeout)
	defer cancel()

	guard := expiryguard.New(c, control)
	guard.Grace, guard.Scope, guard.DryRun, guard.Log = grace, scope, dryRun, log
	report, err := guard.Sweep(ctx)
	log.Info("Finished expiry sweep", "removed", len(report.Removed), "refused", len(report.Refused), "dryRun", dryRun)
	if err != nil {
		log.Error(err, "Could not complete expiry sweep")
		os.Exit(exitError)
	}
	if report.Failed() {
		os.Exit(exitRefusals)
	}
}
