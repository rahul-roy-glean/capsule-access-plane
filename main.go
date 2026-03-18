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
	"github.com/rahul-roy-glean/capsule-access-plane/grants"
	"github.com/rahul-roy-glean/capsule-access-plane/identity"
	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
	"github.com/rahul-roy-glean/capsule-access-plane/policy"
	"github.com/rahul-roy-glean/capsule-access-plane/runtime"
	"github.com/rahul-roy-glean/capsule-access-plane/server"
	"github.com/rahul-roy-glean/capsule-access-plane/store"
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

	// Database URL (default: capsule-access.db)
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "capsule-access.db"
	}

	// Credential reference (default: env:GITHUB_TOKEN)
	credentialRef := os.Getenv("CREDENTIAL_REF")
	if credentialRef == "" {
		credentialRef = "env:GITHUB_TOKEN"
	}

	// Create identity verifier
	verifier, err := identity.NewHMACVerifier([]byte(attestationSecret))
	if err != nil {
		slog.Error("failed to create HMAC verifier", "err", err)
		os.Exit(1)
	}

	// Open SQLite store and run migrations
	ctx := context.Background()
	dataStore, err := store.Open(ctx, databaseURL)
	if err != nil {
		slog.Error("failed to open store", "err", err)
		os.Exit(1)
	}
	defer func() { _ = dataStore.Close() }()
	slog.Info("opened SQLite store", "database", databaseURL)

	// Load manifests from embedded filesystem
	registry := manifest.NewInMemoryRegistry()
	loader := &manifest.YAMLLoader{}
	if err := manifest.LoadAllFamilies(loader, registry); err != nil {
		slog.Error("failed to load manifest families", "err", err)
		os.Exit(1) //nolint:gocritic // exitAfterDefer: acceptable in main()
	}
	slog.Info("loaded manifest families", "count", len(registry.List()))

	// Create policy engine
	engine := policy.NewManifestBasedEngine(registry)

	// Phase 2: direct_http is now implemented; remote_execution is now implemented
	implAvailability := map[accessplane.Lane]accessplane.ImplementationState{
		accessplane.LaneDirectHTTP:      accessplane.StateImplemented,
		accessplane.LaneHelperSession:   accessplane.StateImplementationDeferred,
		accessplane.LaneRemoteExecution: accessplane.StateImplemented,
	}

	// Create credential resolver
	credResolver := grants.NewCredentialResolver(dataStore.DB())

	// Create grant store and service
	grantStore := grants.NewSQLStore(dataStore.DB())
	grantService := grants.NewService(grantStore, credResolver, 15*time.Minute)

	// Create direct HTTP proxy adapter
	adapter := runtime.NewDirectHTTPAdapter(registry)

	// Create handlers
	logger := slog.Default()
	resolveHandler := server.NewResolveHandler(verifier, engine, implAvailability, logger)
	grantHandlers := server.NewGrantHandlers(verifier, grantService, adapter, credentialRef, logger)
	executeHandler := server.NewExecuteHandler(verifier, registry, engine, credResolver, credentialRef, logger)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Wire real resolve endpoint
	mux.Handle("POST /v1/resolve", resolveHandler)

	// Wire grant lifecycle endpoints
	mux.HandleFunc("POST /v1/grants/project", grantHandlers.ProjectGrant)
	mux.HandleFunc("POST /v1/grants/exchange", grantHandlers.ExchangeCapability)
	mux.HandleFunc("POST /v1/grants/refresh", grantHandlers.RefreshGrant)
	mux.HandleFunc("POST /v1/grants/revoke", grantHandlers.RevokeGrant)

	// Wire remote broker execution endpoint
	mux.Handle("POST /v1/execute/http", executeHandler)

	// Remaining endpoints are still stubs
	mux.HandleFunc("POST /v1/events/runner", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotImplemented, map[string]string{
			"error":   "not_implemented",
			"phase":   "phase2",
			"message": "PublishRunnerEvent not implemented in Phase 2",
		})
	})

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	shutdownCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("starting access plane", "addr", listenAddr, "phase", "phase2")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	<-shutdownCtx.Done()
	slog.Info("shutting down")

	gracefulCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(gracefulCtx); err != nil {
		slog.Error("shutdown error", "err", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
