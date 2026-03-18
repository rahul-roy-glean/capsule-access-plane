package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/rahul-roy-glean/capsule-access-plane/identity"
	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
	"github.com/rahul-roy-glean/capsule-access-plane/policy"
	"github.com/rahul-roy-glean/capsule-access-plane/server"
)

func main() {
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	// Read attestation secret (required)
	attestationSecret := os.Getenv("ATTESTATION_SECRET")
	if attestationSecret == "" {
		slog.Error("ATTESTATION_SECRET environment variable is required")
		os.Exit(1)
	}

	// Create identity verifier
	verifier, err := identity.NewHMACVerifier([]byte(attestationSecret))
	if err != nil {
		slog.Error("failed to create HMAC verifier", "err", err)
		os.Exit(1)
	}

	// Load manifests from embedded filesystem
	registry := manifest.NewInMemoryRegistry()
	loader := &manifest.YAMLLoader{}
	if err := manifest.LoadAllFamilies(loader, registry); err != nil {
		slog.Error("failed to load manifest families", "err", err)
		os.Exit(1)
	}
	slog.Info("loaded manifest families", "count", len(registry.List()))

	// Create policy engine
	engine := policy.NewManifestBasedEngine(registry)

	// Phase 1: all lanes are deferred
	implAvailability := map[accessplane.Lane]accessplane.ImplementationState{
		accessplane.LaneDirectHTTP:      accessplane.StateImplementationDeferred,
		accessplane.LaneHelperSession:   accessplane.StateImplementationDeferred,
		accessplane.LaneRemoteExecution: accessplane.StateImplementationDeferred,
	}

	// Create resolve handler
	logger := slog.Default()
	resolveHandler := server.NewResolveHandler(verifier, engine, implAvailability, logger)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Wire real resolve endpoint
	mux.Handle("POST /v1/resolve", resolveHandler)

	// Remaining endpoints are still stubs
	stubEndpoints := []struct {
		pattern string
		method  string
	}{
		{"POST /v1/grants/project", "ProjectGrant"},
		{"POST /v1/grants/exchange", "ExchangeCapability"},
		{"POST /v1/grants/refresh", "RefreshGrant"},
		{"POST /v1/grants/revoke", "RevokeGrant"},
		{"POST /v1/events/runner", "PublishRunnerEvent"},
	}

	for _, ep := range stubEndpoints {
		method := ep.method
		mux.HandleFunc(ep.pattern, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusNotImplemented, map[string]string{
				"error":   "not_implemented",
				"phase":   "phase1",
				"message": method + " not implemented in Phase 1",
			})
		})
	}

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("starting access plane", "addr", listenAddr, "phase", "phase1")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "err", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
