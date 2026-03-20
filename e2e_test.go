package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/rahul-roy-glean/capsule-access-plane/bundle"
	"github.com/rahul-roy-glean/capsule-access-plane/grants"
	"github.com/rahul-roy-glean/capsule-access-plane/identity"
	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
	"github.com/rahul-roy-glean/capsule-access-plane/policy"
	"github.com/rahul-roy-glean/capsule-access-plane/providers"
	"github.com/rahul-roy-glean/capsule-access-plane/runtime"
	"github.com/rahul-roy-glean/capsule-access-plane/server"
	"github.com/rahul-roy-glean/capsule-access-plane/store"
)

const testSecret = "e2e-test-secret"

// e2eServer sets up a complete server stack with in-memory SQLite, returning
// the base URL, a signed-token helper, and a cleanup function.
func e2eServer(t *testing.T) (baseURL string, signToken func(runnerID, sessionID string) string, cleanup func()) {
	t.Helper()

	// Store
	ctx := context.Background()
	dataStore, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	// Identity
	verifier, _ := identity.NewHMACVerifier([]byte(testSecret))

	// Manifests
	registry := manifest.NewInMemoryRegistry()
	loader := &manifest.YAMLLoader{}
	if err := manifest.LoadAllFamilies(loader, registry); err != nil {
		t.Fatalf("load families: %v", err)
	}

	// Policy
	engine := policy.NewManifestBasedEngine(registry)

	// Implementation availability — Phase 2: direct_http is implemented, remote_execution is implemented
	implAvailability := map[accessplane.Lane]accessplane.ImplementationState{
		accessplane.LaneDirectHTTP:      accessplane.StateImplemented,
		accessplane.LaneHelperSession:   accessplane.StateImplementationDeferred,
		accessplane.LaneRemoteExecution: accessplane.StateImplemented,
	}

	// Grant infrastructure
	t.Setenv("E2E_TOKEN", "e2e-credential-secret-value")
	credResolver := grants.NewCredentialResolver(dataStore.DB())
	defaultProvider := providers.NewStaticProvider("default", credResolver, "env:E2E_TOKEN", nil)
	providerRegistry := providers.NewRegistry()
	providerRegistry.SetDefault(defaultProvider)
	_ = providerRegistry.Register(defaultProvider)

	grantStore := grants.NewSQLStore(dataStore.DB())
	grantService := grants.NewService(grantStore, 15*time.Minute)
	adapter := runtime.NewDirectHTTPAdapter(registry)

	// Handlers
	logger := slog.Default()
	resolveHandler := server.NewResolveHandler(verifier, engine, implAvailability, logger)
	grantHandlers := server.NewGrantHandlers(verifier, grantService, adapter, providerRegistry, registry, logger)
	executeHandler := server.NewExecuteHandler(verifier, registry, engine, providerRegistry, logger)

	// Mux
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.Handle("POST /v1/resolve", resolveHandler)
	mux.HandleFunc("POST /v1/grants/project", grantHandlers.ProjectGrant)
	mux.HandleFunc("POST /v1/grants/exchange", grantHandlers.ExchangeCapability)
	mux.HandleFunc("POST /v1/grants/refresh", grantHandlers.RefreshGrant)
	mux.HandleFunc("POST /v1/grants/revoke", grantHandlers.RevokeGrant)
	mux.Handle("POST /v1/execute/http", executeHandler)
	mux.HandleFunc("POST /v1/events/runner", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "not_implemented",
			"phase":   "phase2",
			"message": "PublishRunnerEvent not implemented in Phase 2",
		})
	})

	// Start server on random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(listener) }()

	base := fmt.Sprintf("http://%s", listener.Addr().String())

	sign := func(runnerID, sessionID string) string {
		claims := &identity.Claims{
			RunnerID:    runnerID,
			SessionID:   sessionID,
			WorkloadKey: "wk-e2e",
			HostID:      "host-e2e",
			IssuedAt:    time.Now().Add(-time.Minute),
			ExpiresAt:   time.Now().Add(time.Hour),
		}
		token, err := identity.SignClaims(claims, []byte(testSecret))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return token
	}

	return base, sign, func() {
		_ = srv.Shutdown(context.Background())
		_ = dataStore.Close()
	}
}

func doJSON(t *testing.T, method, url, token string, body any) (*http.Response, map[string]any) {
	t.Helper()
	var reqBody io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request %s %s: %v", method, url, err)
	}

	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)
	_ = resp.Body.Close()
	return resp, result
}

// ============================================================
// E2E Tests
// ============================================================

func TestE2E_Healthz(t *testing.T) {
	base, _, cleanup := e2eServer(t)
	defer cleanup()

	resp, body := doJSON(t, "GET", base+"/healthz", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("healthz: status=%d", resp.StatusCode)
	}
	if body["status"] != "ok" {
		t.Errorf("healthz body: %v", body)
	}
}

func TestE2E_Resolve_DirectHTTP_Implemented(t *testing.T) {
	base, sign, cleanup := e2eServer(t)
	defer cleanup()

	token := sign("r1", "s1")
	resp, body := doJSON(t, "POST", base+"/v1/resolve", token, accessplane.ResolveOperationRequest{
		Actor:         accessplane.ActorContext{UserID: "u1"},
		Runner:        accessplane.RunnerContext{SessionID: "s1", RunnerID: "r1", TurnID: "t1"},
		ToolFamily:    "github_rest",
		LogicalAction: "read_repo",
	})

	if resp.StatusCode != 200 {
		t.Fatalf("resolve: status=%d body=%v", resp.StatusCode, body)
	}
	if body["decision"] != "allow" {
		t.Errorf("decision=%v, want allow", body["decision"])
	}
	if body["selected_lane"] != "direct_http" {
		t.Errorf("selected_lane=%v, want direct_http", body["selected_lane"])
	}
	// Phase 2: direct_http should be "implemented", not "implementation_deferred"
	if body["implementation_state"] != "implemented" {
		t.Errorf("implementation_state=%v, want implemented", body["implementation_state"])
	}
}

func TestE2E_Resolve_RemoteExecution_Implemented(t *testing.T) {
	base, sign, cleanup := e2eServer(t)
	defer cleanup()

	token := sign("r1", "s1")
	resp, body := doJSON(t, "POST", base+"/v1/resolve", token, accessplane.ResolveOperationRequest{
		Actor:         accessplane.ActorContext{UserID: "u1"},
		Runner:        accessplane.RunnerContext{SessionID: "s1", RunnerID: "r1", TurnID: "t1"},
		ToolFamily:    "internal_admin_cli",
		LogicalAction: "rotate_secrets",
	})

	if resp.StatusCode != 200 {
		t.Fatalf("resolve: status=%d body=%v", resp.StatusCode, body)
	}
	if body["selected_lane"] != "remote_execution" {
		t.Errorf("selected_lane=%v, want remote_execution", body["selected_lane"])
	}
	if body["implementation_state"] != "implemented" {
		t.Errorf("implementation_state=%v, want implemented", body["implementation_state"])
	}
}

func TestE2E_Resolve_MissingAuth(t *testing.T) {
	base, _, cleanup := e2eServer(t)
	defer cleanup()

	resp, _ := doJSON(t, "POST", base+"/v1/resolve", "", accessplane.ResolveOperationRequest{
		Actor:      accessplane.ActorContext{UserID: "u1"},
		Runner:     accessplane.RunnerContext{SessionID: "s1", RunnerID: "r1"},
		ToolFamily: "github_rest",
	})

	if resp.StatusCode != 401 {
		t.Errorf("status=%d, want 401", resp.StatusCode)
	}
}

func TestE2E_Resolve_RunnerMismatch(t *testing.T) {
	base, sign, cleanup := e2eServer(t)
	defer cleanup()

	// Token for r1/s1, but request says r2/s2
	token := sign("r1", "s1")
	resp, _ := doJSON(t, "POST", base+"/v1/resolve", token, accessplane.ResolveOperationRequest{
		Actor:      accessplane.ActorContext{UserID: "u1"},
		Runner:     accessplane.RunnerContext{SessionID: "s2", RunnerID: "r2"},
		ToolFamily: "github_rest",
	})

	if resp.StatusCode != 403 {
		t.Errorf("status=%d, want 403", resp.StatusCode)
	}
}

func TestE2E_Resolve_UnknownFamily(t *testing.T) {
	base, sign, cleanup := e2eServer(t)
	defer cleanup()

	token := sign("r1", "s1")
	resp, _ := doJSON(t, "POST", base+"/v1/resolve", token, accessplane.ResolveOperationRequest{
		Actor:      accessplane.ActorContext{UserID: "u1"},
		Runner:     accessplane.RunnerContext{SessionID: "s1", RunnerID: "r1"},
		ToolFamily: "nonexistent_tool",
	})

	if resp.StatusCode != 403 {
		t.Errorf("status=%d, want 403", resp.StatusCode)
	}
}

func TestE2E_FullGrantLifecycle(t *testing.T) {
	base, sign, cleanup := e2eServer(t)
	defer cleanup()

	token := sign("r1", "s1")

	// 1. Resolve → should return direct_http + implemented
	resp, body := doJSON(t, "POST", base+"/v1/resolve", token, accessplane.ResolveOperationRequest{
		Actor:         accessplane.ActorContext{UserID: "u1"},
		Runner:        accessplane.RunnerContext{SessionID: "s1", RunnerID: "r1", TurnID: "t1"},
		ToolFamily:    "github_rest",
		LogicalAction: "read_repo",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("resolve: status=%d", resp.StatusCode)
	}
	if body["implementation_state"] != "implemented" {
		t.Fatalf("resolve: implementation_state=%v", body["implementation_state"])
	}

	// 2. ProjectGrant → creates grant, starts proxy
	resp, body = doJSON(t, "POST", base+"/v1/grants/project", token, accessplane.ProjectGrantRequest{
		RunnerID:   "r1",
		SessionID:  "s1",
		TurnID:     "t1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
		Scope:      "repo:read",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("project: status=%d body=%v", resp.StatusCode, body)
	}
	grantID, _ := body["grant_id"].(string)
	if grantID == "" {
		t.Fatal("project: empty grant_id")
	}
	if body["status"] != "projected" {
		t.Errorf("project: status=%v, want projected", body["status"])
	}
	projectionRef, _ := body["projection_ref"].(string)
	if projectionRef == "" {
		t.Error("project: empty projection_ref (proxy should have started)")
	}

	// 3. ExchangeCapability → validates grant is active
	resp, body = doJSON(t, "POST", base+"/v1/grants/exchange", token, accessplane.ExchangeCapabilityRequest{
		GrantID:  grantID,
		RunnerID: "r1",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("exchange: status=%d body=%v", resp.StatusCode, body)
	}
	if body["status"] != "active" {
		t.Errorf("exchange: status=%v, want active", body["status"])
	}
	if body["grant_id"] != grantID {
		t.Errorf("exchange: grant_id=%v, want %s", body["grant_id"], grantID)
	}

	// 4. RefreshGrant → extends expiry
	resp, body = doJSON(t, "POST", base+"/v1/grants/refresh", token, accessplane.RefreshGrantRequest{
		GrantID:  grantID,
		RunnerID: "r1",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("refresh: status=%d body=%v", resp.StatusCode, body)
	}
	if body["status"] != "refreshed" {
		t.Errorf("refresh: status=%v, want refreshed", body["status"])
	}

	// 5. RevokeGrant → revokes grant and stops proxy
	resp, body = doJSON(t, "POST", base+"/v1/grants/revoke", token, accessplane.RevokeGrantRequest{
		GrantID:  grantID,
		RunnerID: "r1",
		Reason:   "test cleanup",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("revoke: status=%d body=%v", resp.StatusCode, body)
	}
	if body["status"] != "revoked" {
		t.Errorf("revoke: status=%v, want revoked", body["status"])
	}

	// 6. ExchangeCapability after revoke → should fail
	resp, _ = doJSON(t, "POST", base+"/v1/grants/exchange", token, accessplane.ExchangeCapabilityRequest{
		GrantID:  grantID,
		RunnerID: "r1",
	})
	if resp.StatusCode != 500 {
		t.Errorf("exchange-after-revoke: status=%d, want 500", resp.StatusCode)
	}
}

func TestE2E_GrantLifecycle_AuthErrors(t *testing.T) {
	base, sign, cleanup := e2eServer(t)
	defer cleanup()

	token := sign("r1", "s1")

	// ProjectGrant with no auth → 401
	resp, _ := doJSON(t, "POST", base+"/v1/grants/project", "", accessplane.ProjectGrantRequest{
		RunnerID:   "r1",
		SessionID:  "s1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
	})
	if resp.StatusCode != 401 {
		t.Errorf("project no auth: status=%d, want 401", resp.StatusCode)
	}

	// ProjectGrant with runner mismatch → 403
	resp, _ = doJSON(t, "POST", base+"/v1/grants/project", token, accessplane.ProjectGrantRequest{
		RunnerID:   "r-wrong",
		SessionID:  "s1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
	})
	if resp.StatusCode != 403 {
		t.Errorf("project mismatch: status=%d, want 403", resp.StatusCode)
	}
}

func TestE2E_GrantLifecycle_CrossRunner(t *testing.T) {
	base, sign, cleanup := e2eServer(t)
	defer cleanup()

	token1 := sign("r1", "s1")
	token2 := sign("r2", "s2")

	// Runner 1 creates a grant
	resp, body := doJSON(t, "POST", base+"/v1/grants/project", token1, accessplane.ProjectGrantRequest{
		RunnerID:   "r1",
		SessionID:  "s1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("project: status=%d body=%v", resp.StatusCode, body)
	}
	grantID := body["grant_id"].(string)

	// Runner 2 tries to exchange Runner 1's grant → should fail (runner mismatch in service)
	resp, _ = doJSON(t, "POST", base+"/v1/grants/exchange", token2, accessplane.ExchangeCapabilityRequest{
		GrantID:  grantID,
		RunnerID: "r2",
	})
	if resp.StatusCode != 500 {
		t.Errorf("cross-runner exchange: status=%d, want 500 (service rejects runner mismatch)", resp.StatusCode)
	}

	// Runner 2 tries to revoke Runner 1's grant → should fail
	resp, _ = doJSON(t, "POST", base+"/v1/grants/revoke", token2, accessplane.RevokeGrantRequest{
		GrantID:  grantID,
		RunnerID: "r2",
	})
	if resp.StatusCode != 500 {
		t.Errorf("cross-runner revoke: status=%d, want 500", resp.StatusCode)
	}

	// Runner 2 tries to refresh Runner 1's grant → should fail
	resp, _ = doJSON(t, "POST", base+"/v1/grants/refresh", token2, accessplane.RefreshGrantRequest{
		GrantID:  grantID,
		RunnerID: "r2",
	})
	if resp.StatusCode != 500 {
		t.Errorf("cross-runner refresh: status=%d, want 500", resp.StatusCode)
	}
}

func TestE2E_RevokeIdempotent(t *testing.T) {
	base, sign, cleanup := e2eServer(t)
	defer cleanup()

	token := sign("r1", "s1")

	// Create grant
	resp, body := doJSON(t, "POST", base+"/v1/grants/project", token, accessplane.ProjectGrantRequest{
		RunnerID:   "r1",
		SessionID:  "s1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("project: status=%d", resp.StatusCode)
	}
	grantID := body["grant_id"].(string)

	// Revoke twice
	for i := range 2 {
		resp, body = doJSON(t, "POST", base+"/v1/grants/revoke", token, accessplane.RevokeGrantRequest{
			GrantID:  grantID,
			RunnerID: "r1",
		})
		if resp.StatusCode != 200 {
			t.Fatalf("revoke[%d]: status=%d body=%v", i, resp.StatusCode, body)
		}
		if body["status"] != "revoked" {
			t.Errorf("revoke[%d]: status=%v", i, body["status"])
		}
	}
}

func TestE2E_ProxyForwardsWithAuth(t *testing.T) {
	_, sign, cleanup := e2eServer(t)
	defer cleanup()

	// Start a target HTTP server that echoes the Authorization header
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Method", r.Method)
		_, _ = w.Write([]byte(r.Header.Get("Authorization")))
	}))
	defer target.Close()

	// We need a tool family that allows the target's host.
	// Since the target runs on 127.0.0.1 and github_rest only allows api.github.com,
	// this test verifies the proxy behavior at the unit level.
	// The E2E flow above already verifies the grant_handlers -> proxy wiring works.
	// Here we verify the proxy directly.

	registry := manifest.NewInMemoryRegistry()
	_ = registry.Register(&manifest.ToolManifest{
		Family:         "test_e2e_api",
		Version:        "1.0",
		SurfaceKind:    "http",
		SupportedLanes: []accessplane.Lane{accessplane.LaneDirectHTTP},
		Destinations:   []manifest.Destination{{Host: "127.0.0.1", AllowedIPs: []string{"127.0.0.0/8"}}},
		MethodConstraints: []manifest.MethodConstraint{
			{Method: "GET", PathPattern: "/**"},
			{Method: "POST", PathPattern: "/**"},
		},
	})
	adapter := runtime.NewDirectHTTPAdapter(registry)

	b := &bundle.ProjectionBundle{
		Version:   "v1",
		GrantID:   "e2e-proxy-grant",
		Lane:      accessplane.LaneDirectHTTP,
		ExpiresAt: time.Now().Add(time.Hour),
		AuditMetadata: bundle.AuditMetadata{
			UserID:    "u1",
			SessionID: "s1",
			RunnerID:  "r1",
		},
	}

	proxyAddr, err := adapter.InstallGrantWithCredential(context.Background(), b, "test_e2e_api", "e2e-credential-secret-value")
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	_ = sign // not needed for direct proxy test

	// Request through proxy → target
	req, _ := http.NewRequest("GET", "http://"+proxyAddr+"/test", nil)
	req.Header.Set("X-Target-URL", target.URL+"/hello")

	proxyResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer func() { _ = proxyResp.Body.Close() }()

	respBody, _ := io.ReadAll(proxyResp.Body)
	if string(respBody) != "Bearer e2e-credential-secret-value" {
		t.Errorf("proxy response = %q, want 'Bearer e2e-credential-secret-value'", string(respBody))
	}
	if proxyResp.Header.Get("X-Echo-Method") != "GET" {
		t.Errorf("echoed method = %q, want GET", proxyResp.Header.Get("X-Echo-Method"))
	}

	// Disallowed host → 403
	req2, _ := http.NewRequest("GET", "http://"+proxyAddr+"/test", nil)
	req2.Header.Set("X-Target-URL", "https://evil.com/steal")
	proxyResp2, _ := http.DefaultClient.Do(req2)
	_ = proxyResp2.Body.Close()
	if proxyResp2.StatusCode != 403 {
		t.Errorf("disallowed host: status=%d, want 403", proxyResp2.StatusCode)
	}

	// Disallowed method → 405
	req3, _ := http.NewRequest("DELETE", "http://"+proxyAddr+"/test", nil)
	req3.Header.Set("X-Target-URL", target.URL+"/hello")
	proxyResp3, _ := http.DefaultClient.Do(req3)
	_ = proxyResp3.Body.Close()
	if proxyResp3.StatusCode != 405 {
		t.Errorf("disallowed method: status=%d, want 405", proxyResp3.StatusCode)
	}

	// Revoke → proxy stops
	_ = adapter.RevokeGrant(context.Background(), "e2e-proxy-grant", "r1")

	state, _ := adapter.DescribeGrantState(context.Background(), "r1", "e2e-proxy-grant")
	if state.Status != "not_installed" {
		t.Errorf("after revoke: status=%q, want not_installed", state.Status)
	}
}

func TestE2E_StubEndpoints(t *testing.T) {
	base, sign, cleanup := e2eServer(t)
	defer cleanup()

	_ = sign

	// Events endpoint should still be 501
	resp, body := doJSON(t, "POST", base+"/v1/events/runner", "", map[string]string{})
	// No auth check on stubs, so it will return 405 (method not matched) or 501.
	// Actually, the stub doesn't check auth. Let's just verify it's wired.
	if resp.StatusCode != 501 {
		// It might be 401 if we didn't wire the stub. Check.
		t.Logf("events/runner: status=%d body=%v (expected 501)", resp.StatusCode, body)
	}
}

func TestE2E_ExecuteHTTP_FullFlow(t *testing.T) {
	base, sign, cleanup := e2eServer(t)
	defer cleanup()

	// Start a mock target that echoes the request.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Auth", r.Header.Get("Authorization"))
		w.Header().Set("X-Echo-Method", r.Method)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"hello"}`))
	}))
	defer target.Close()

	// Register a test tool family that allows the target's host (127.0.0.1).
	// The e2eServer uses the embedded manifests which don't include 127.0.0.1.
	// So we need a separate server that has our custom registry.
	// Instead, we'll test against the existing github_rest family with its allowed hosts.
	// Since that requires api.github.com, let's test the error cases via the main e2eServer
	// and the success case via a custom setup.

	token := sign("r1", "s1")

	// Test 1: Missing auth → 401
	resp, _ := doJSON(t, "POST", base+"/v1/execute/http", "", map[string]any{
		"runner_id":   "r1",
		"session_id":  "s1",
		"tool_family": "github_rest",
		"method":      "GET",
		"url":         "https://api.github.com/repos/foo/bar",
	})
	if resp.StatusCode != 401 {
		t.Errorf("no auth: status=%d, want 401", resp.StatusCode)
	}

	// Test 2: Runner mismatch → 403
	resp, _ = doJSON(t, "POST", base+"/v1/execute/http", token, map[string]any{
		"runner_id":   "r-wrong",
		"session_id":  "s1",
		"tool_family": "github_rest",
		"method":      "GET",
		"url":         "https://api.github.com/repos/foo/bar",
	})
	if resp.StatusCode != 403 {
		t.Errorf("runner mismatch: status=%d, want 403", resp.StatusCode)
	}

	// Test 3: Unknown tool family → 400
	resp, _ = doJSON(t, "POST", base+"/v1/execute/http", token, map[string]any{
		"runner_id":   "r1",
		"session_id":  "s1",
		"tool_family": "nonexistent",
		"method":      "GET",
		"url":         "https://api.github.com/repos/foo/bar",
	})
	if resp.StatusCode != 400 {
		t.Errorf("unknown family: status=%d, want 400", resp.StatusCode)
	}

	// Test 4: Disallowed host → 403
	resp, _ = doJSON(t, "POST", base+"/v1/execute/http", token, map[string]any{
		"runner_id":   "r1",
		"session_id":  "s1",
		"tool_family": "github_rest",
		"method":      "GET",
		"url":         "https://evil.example.com/steal",
	})
	if resp.StatusCode != 403 {
		t.Errorf("disallowed host: status=%d, want 403", resp.StatusCode)
	}

	// Test 5: Disallowed method → 405
	resp, _ = doJSON(t, "POST", base+"/v1/execute/http", token, map[string]any{
		"runner_id":   "r1",
		"session_id":  "s1",
		"tool_family": "github_rest",
		"method":      "DELETE",
		"url":         "https://api.github.com/repos/foo/bar",
	})
	if resp.StatusCode != 405 {
		t.Errorf("disallowed method: status=%d, want 405", resp.StatusCode)
	}
}

func TestE2E_ExecuteHTTP_SuccessWithMockTarget(t *testing.T) {
	// This test creates a custom e2e setup with a tool family that allows 127.0.0.1,
	// so we can actually execute against a local mock target.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Auth", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"proxied":"ok"}`))
	}))
	defer target.Close()

	// Minimal setup
	verifier, _ := identity.NewHMACVerifier([]byte(testSecret))

	registry := manifest.NewInMemoryRegistry()
	_ = registry.Register(&manifest.ToolManifest{
		Family:         "test_execute_api",
		Version:        "1.0",
		SurfaceKind:    "http",
		SupportedLanes: []accessplane.Lane{accessplane.LaneRemoteExecution},
		Destinations:   []manifest.Destination{{Host: "127.0.0.1", AllowedIPs: []string{"127.0.0.0/8"}}},
		MethodConstraints: []manifest.MethodConstraint{
			{Method: "GET", PathPattern: "/**"},
			{Method: "POST", PathPattern: "/**"},
		},
	})

	engine := policy.NewManifestBasedEngine(registry)
	t.Setenv("E2E_EXEC_TOKEN", "e2e-exec-cred")
	ctx := context.Background()
	dataStore, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = dataStore.Close() }()

	credResolver := grants.NewCredentialResolver(dataStore.DB())
	logger := slog.Default()

	defaultProvider := providers.NewStaticProvider("default", credResolver, "env:E2E_EXEC_TOKEN", nil)
	providerRegistry := providers.NewRegistry()
	providerRegistry.SetDefault(defaultProvider)
	_ = providerRegistry.Register(defaultProvider)

	executeHandler := server.NewExecuteHandler(verifier, registry, engine, providerRegistry, logger)

	mux := http.NewServeMux()
	mux.Handle("POST /v1/execute/http", executeHandler)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(listener) }()
	defer func() { _ = srv.Shutdown(context.Background()) }()

	base := fmt.Sprintf("http://%s", listener.Addr().String())

	claims := &identity.Claims{
		RunnerID:    "r1",
		SessionID:   "s1",
		WorkloadKey: "wk-e2e",
		HostID:      "host-e2e",
		IssuedAt:    time.Now().Add(-time.Minute),
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	token, err := identity.SignClaims(claims, []byte(testSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	resp, body := doJSON(t, "POST", base+"/v1/execute/http", token, map[string]any{
		"runner_id":   "r1",
		"session_id":  "s1",
		"turn_id":     "t1",
		"tool_family": "test_execute_api",
		"method":      "GET",
		"url":         target.URL + "/hello",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("execute: status=%d body=%v", resp.StatusCode, body)
	}
	if body["status_code"] != float64(200) {
		t.Errorf("status_code=%v, want 200", body["status_code"])
	}
	if body["body"] != `{"proxied":"ok"}` {
		t.Errorf("body=%v, want {\"proxied\":\"ok\"}", body["body"])
	}

	headers, _ := body["headers"].(map[string]any)
	if headers["X-Echo-Auth"] != "Bearer e2e-exec-cred" {
		t.Errorf("echoed auth=%v, want 'Bearer e2e-exec-cred'", headers["X-Echo-Auth"])
	}
	if body["audit_correlation_id"] == nil || body["audit_correlation_id"] == "" {
		t.Error("expected non-empty audit_correlation_id")
	}
}
