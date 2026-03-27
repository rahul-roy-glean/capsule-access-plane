package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/rahul-roy-glean/capsule-access-plane/grants"
	"github.com/rahul-roy-glean/capsule-access-plane/identity"
	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
	"github.com/rahul-roy-glean/capsule-access-plane/policy"
	"github.com/rahul-roy-glean/capsule-access-plane/providers"
	"github.com/rahul-roy-glean/capsule-access-plane/store"
)

func setupExecuteHandler(t *testing.T, reg manifest.Registry) (*ExecuteHandler, func()) {
	t.Helper()

	verifier, err := identity.NewHMACVerifier(handlerTestSecret)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	credResolver := grants.NewCredentialResolver(s.DB())
	engine := policy.NewManifestBasedEngine(reg)

	t.Setenv("TEST_EXEC_TOKEN", "test-exec-credential")

	defaultProvider := providers.NewStaticProvider("default", credResolver, "env:TEST_EXEC_TOKEN", nil)
	providerRegistry := providers.NewRegistry()
	providerRegistry.SetDefault(defaultProvider)
	_ = providerRegistry.Register(defaultProvider)

	handler := NewExecuteHandler(verifier, reg, engine, providerRegistry, slog.Default())
	return handler, func() { _ = s.Close() }
}

func execTestRegistry(t *testing.T) manifest.Registry {
	t.Helper()
	reg := manifest.NewInMemoryRegistry()
	_ = reg.Register(&manifest.ToolManifest{
		Family:         "test_exec_api",
		Version:        "1.0",
		SurfaceKind:    "http",
		SupportedLanes: []accessplane.Lane{accessplane.LaneRemoteExecution},
		Destinations:   []manifest.Destination{{Host: "127.0.0.1", AllowedIPs: []string{"127.0.0.0/8"}}},
		MethodConstraints: []manifest.MethodConstraint{
			{Method: "GET", PathPattern: "/**"},
			{Method: "POST", PathPattern: "/**"},
		},
	})
	return reg
}

func TestExecuteHTTP_ValidRequest(t *testing.T) {
	// Start a target server that echoes Authorization header and returns a body.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Auth", r.Header.Get("Authorization"))
		w.Header().Set("X-Echo-Method", r.Method)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer target.Close()

	reg := execTestRegistry(t)
	handler, cleanup := setupExecuteHandler(t, reg)
	defer cleanup()

	claims := testClaims()
	token := signTestToken(t, claims)

	reqBody := accessplane.ExecuteHTTPRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		TurnID:     "turn-1",
		ToolFamily: "test_exec_api",
		Method:     "GET",
		URL:        target.URL + "/test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/v1/execute/http", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body: %s", rr.Code, rr.Body.String())
	}

	var resp accessplane.ExecuteHTTPResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("response status_code = %d, want 200", resp.StatusCode)
	}
	if resp.Body != `{"result":"ok"}` {
		t.Errorf("response body = %q, want {\"result\":\"ok\"}", resp.Body)
	}
	if resp.Headers["X-Echo-Auth"] != "Bearer test-exec-credential" {
		t.Errorf("echoed auth = %q, want 'Bearer test-exec-credential'", resp.Headers["X-Echo-Auth"])
	}
	if resp.AuditCorrelationID == "" {
		t.Error("expected non-empty audit_correlation_id")
	}
}

func TestExecuteHTTP_MissingAuth(t *testing.T) {
	reg := execTestRegistry(t)
	handler, cleanup := setupExecuteHandler(t, reg)
	defer cleanup()

	req := httptest.NewRequest("POST", "/v1/execute/http", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestExecuteHTTP_RunnerMismatch(t *testing.T) {
	reg := execTestRegistry(t)
	handler, cleanup := setupExecuteHandler(t, reg)
	defer cleanup()

	claims := testClaims()
	token := signTestToken(t, claims)

	reqBody := accessplane.ExecuteHTTPRequest{
		RunnerID:   "wrong-runner",
		SessionID:  "session-1",
		TurnID:     "turn-1",
		ToolFamily: "test_exec_api",
		Method:     "GET",
		URL:        "https://127.0.0.1/test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/v1/execute/http", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

func TestExecuteHTTP_UnknownToolFamily(t *testing.T) {
	reg := execTestRegistry(t)
	handler, cleanup := setupExecuteHandler(t, reg)
	defer cleanup()

	claims := testClaims()
	token := signTestToken(t, claims)

	reqBody := accessplane.ExecuteHTTPRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		TurnID:     "turn-1",
		ToolFamily: "nonexistent",
		Method:     "GET",
		URL:        "https://127.0.0.1/test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/v1/execute/http", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400. body: %s", rr.Code, rr.Body.String())
	}
}

func TestExecuteHTTP_DisallowedHost(t *testing.T) {
	reg := execTestRegistry(t)
	handler, cleanup := setupExecuteHandler(t, reg)
	defer cleanup()

	claims := testClaims()
	token := signTestToken(t, claims)

	reqBody := accessplane.ExecuteHTTPRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		TurnID:     "turn-1",
		ToolFamily: "test_exec_api",
		Method:     "GET",
		URL:        "https://evil.example.com/steal",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/v1/execute/http", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

func TestExecuteHTTP_DisallowedMethod(t *testing.T) {
	reg := execTestRegistry(t)
	handler, cleanup := setupExecuteHandler(t, reg)
	defer cleanup()

	claims := testClaims()
	token := signTestToken(t, claims)

	reqBody := accessplane.ExecuteHTTPRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		TurnID:     "turn-1",
		ToolFamily: "test_exec_api",
		Method:     "DELETE",
		URL:        "https://127.0.0.1/test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/v1/execute/http", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

func TestExecuteHTTP_PolicyDenied(t *testing.T) {
	// A manifest with no supported lanes triggers policy deny.
	reg := manifest.NewInMemoryRegistry()
	_ = reg.Register(&manifest.ToolManifest{
		Family:         "test_no_lanes",
		Version:        "1.0",
		SurfaceKind:    "http",
		SupportedLanes: []accessplane.Lane{},
		Destinations:   []manifest.Destination{{Host: "127.0.0.1", AllowedIPs: []string{"127.0.0.0/8"}}},
	})

	handler, cleanup := setupExecuteHandler(t, reg)
	defer cleanup()

	claims := testClaims()
	token := signTestToken(t, claims)

	reqBody := accessplane.ExecuteHTTPRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		TurnID:     "turn-1",
		ToolFamily: "test_no_lanes",
		Method:     "GET",
		URL:        "https://127.0.0.1/test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/v1/execute/http", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403. body: %s", rr.Code, rr.Body.String())
	}
}

func TestExecuteHTTP_UsesRemoteAddrForDelegatedProvider(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Auth", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	verifier, err := identity.NewHMACVerifier(handlerTestSecret)
	if err != nil {
		t.Fatal(err)
	}

	reg := manifest.NewInMemoryRegistry()
	targetURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	targetPort, err := strconv.Atoi(targetURL.Port())
	if err != nil {
		t.Fatal(err)
	}
	_ = reg.Register(&manifest.ToolManifest{
		Family:         "delegated_exec",
		Version:        "1.0",
		SurfaceKind:    "http",
		SupportedLanes: []accessplane.Lane{accessplane.LaneRemoteExecution},
		Destinations:   []manifest.Destination{{Host: targetURL.Hostname(), Port: targetPort, Protocol: targetURL.Scheme, AllowedIPs: []string{"127.0.0.0/8"}}},
		MethodConstraints: []manifest.MethodConstraint{
			{Method: "GET", PathPattern: "/**"},
		},
		Provider: "delegated",
	})

	providerRegistry := providers.NewRegistry()
	dp := providers.NewDelegatedProvider("delegated", []string{"127.0.0.1"})
	dp.UpdateToken("", &providers.SessionToken{Token: "global-token", ExpiresAt: time.Now().Add(time.Hour)})
	dp.UpdateToken("10.0.0.8", &providers.SessionToken{Token: "session-token", ExpiresAt: time.Now().Add(time.Hour)})
	_ = providerRegistry.Register(dp)

	handler := NewExecuteHandler(verifier, reg, policy.NewManifestBasedEngine(reg), providerRegistry, slog.Default())

	token := signTestToken(t, testClaims())
	reqBody := accessplane.ExecuteHTTPRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		TurnID:     "turn-1",
		ToolFamily: "delegated_exec",
		Method:     "GET",
		URL:        target.URL + "/test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/v1/execute/http", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = "10.0.0.8:12345"

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body: %s", rr.Code, rr.Body.String())
	}

	var resp accessplane.ExecuteHTTPResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Headers["X-Echo-Auth"] != "Bearer session-token" {
		t.Errorf("echoed auth = %q, want session token", resp.Headers["X-Echo-Auth"])
	}
}
