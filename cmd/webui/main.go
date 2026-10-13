package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"

	"github.com/yannick-thomas/breakglass-operator/internal/webui/auth"
	"github.com/yannick-thomas/breakglass-operator/internal/webui/config"
	"github.com/yannick-thomas/breakglass-operator/internal/webui/facade"
	"github.com/yannick-thomas/breakglass-operator/internal/webui/frontend"
	"github.com/yannick-thomas/breakglass-operator/internal/webui/handler"
)

func main() {
	zapLog, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	log := zapr.NewLogger(zapLog)

	cfg := config.LoadFromEnv()
	if err := cfg.Validate(); err != nil {
		log.Error(err, "Invalid WebUI configuration")
		os.Exit(1)
	}
	log.Info("Starting BreakGlass WebUI service",
		"listenAddr", cfg.ListenAddr,
		"port", cfg.Port,
		"oidcEnabled", cfg.OIDCEnabled,
		"devMode", cfg.DevMode,
	)
	if cfg.DevMode {
		log.Info("Dev mode signs in with the current kubeconfig identity; never use it for shared or in-cluster deployments")
	}

	// 1. OIDC Client (absent in dev mode, where kubeconfig is the credential)
	var oidcClient *auth.OIDCClient
	if cfg.OIDCEnabled {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		oidcClient, err = auth.NewOIDCClient(ctx, cfg)
		cancel()
		if err != nil {
			log.Error(err, "Failed to initialize OIDC client")
			os.Exit(1)
		}
	}

	// 2. K8s Facade
	k8sFacade, err := facade.NewK8sFacade(cfg)
	if err != nil {
		log.Error(err, "Failed to initialize Kubernetes facade")
		os.Exit(1)
	}

	// 3. Frontend Assets
	staticFS, err := frontend.GetFS()
	if err != nil {
		log.Error(err, "Failed to load embedded frontend assets")
		os.Exit(1)
	}

	// 4. HTTP Handler
	h := handler.NewHandler(cfg, auth.NewStore(), oidcClient, k8sFacade, staticFS, log)

	serverAddr := fmt.Sprintf("%s:%d", cfg.ListenAddr, cfg.Port)
	srv := &http.Server{
		Addr:         serverAddr,
		Handler:      h,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	// Start server in background
	go func() {
		log.Info("WebUI listening", "address", serverAddr)
		var srvErr error
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			srvErr = srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			srvErr = srv.ListenAndServe()
		}
		if srvErr != nil && !errors.Is(srvErr, http.ErrServerClosed) {
			log.Error(srvErr, "HTTP server failed")
			os.Exit(1)
		}
	}()

	// Graceful shutdown handling
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)
	sig := <-stopChan
	log.Info("Shutdown signal received", "signal", sig.String())

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error(err, "Failed to gracefully shutdown server")
	} else {
		log.Info("WebUI server stopped cleanly")
	}
}
