package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/rahul-roy-glean/capsule-access-plane/grants"
	"github.com/rahul-roy-glean/capsule-access-plane/identity"
	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
	"github.com/rahul-roy-glean/capsule-access-plane/runtime"
	"github.com/rahul-roy-glean/capsule-access-plane/store"
)

func setupGrantHandlers(t *testing.T) (*GrantHandlers, *identity.HMACVerifier, func()) {
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

	sqlStore := grants.NewSQLStore(s.DB())
	creds := grants.NewCredentialResolver(s.DB())
	grantSvc := grants.NewService(sqlStore, creds, 15*time.Minute)

	reg := manifest.NewInMemoryRegistry()
	loader := &manifest.YAMLLoader{}
	if err := manifest.LoadAllFamilies(loader, reg); err != nil {
		t.Fatalf("failed to load families: %v", err)
	}
	adapter := runtime.NewDirectHTTPAdapter(reg)

	t.Setenv("TEST_GRANT_TOKEN", "test-credential-value")

	handlers := NewGrantHandlers(verifier, grantSvc, adapter, "env:TEST_GRANT_TOKEN", slog.Default())
	return handlers, verifier, func() { _ = s.Close() }
}

func TestProjectGrant_ValidRequest(t *testing.T) {
	handlers, _, cleanup := setupGrantHandlers(t)
	defer cleanup()

	claims := testClaims()
	token := signTestToken(t, claims)

	reqBody := accessplane.ProjectGrantRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		TurnID:     "turn-1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
		Scope:      "repo:read",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/v1/grants/project", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handlers.ProjectGrant(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body: %s", rr.Code, rr.Body.String())
	}

	var resp accessplane.ProjectGrantResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.GrantID == "" {
		t.Error("expected non-empty grant_id")
	}
	if resp.Status != "projected" {
		t.Errorf("status = %q, want projected", resp.Status)
	}
}

func TestProjectGrant_MissingAuth(t *testing.T) {
	handlers, _, cleanup := setupGrantHandlers(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/v1/grants/project", nil)
	rr := httptest.NewRecorder()
	handlers.ProjectGrant(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestProjectGrant_RunnerMismatch(t *testing.T) {
	handlers, _, cleanup := setupGrantHandlers(t)
	defer cleanup()

	claims := testClaims()
	token := signTestToken(t, claims)

	reqBody := accessplane.ProjectGrantRequest{
		RunnerID:   "wrong-runner",
		SessionID:  "session-1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/v1/grants/project", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	handlers.ProjectGrant(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403. body: %s", rr.Code, rr.Body.String())
	}
}

func TestExchangeCapability_ValidRequest(t *testing.T) {
	handlers, _, cleanup := setupGrantHandlers(t)
	defer cleanup()

	claims := testClaims()
	token := signTestToken(t, claims)

	// First project a grant.
	projBody, _ := json.Marshal(accessplane.ProjectGrantRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		TurnID:     "turn-1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
	})
	projReq := httptest.NewRequest("POST", "/v1/grants/project", bytes.NewReader(projBody))
	projReq.Header.Set("Authorization", "Bearer "+token)
	projRR := httptest.NewRecorder()
	handlers.ProjectGrant(projRR, projReq)

	var projResp accessplane.ProjectGrantResponse
	_ = json.NewDecoder(projRR.Body).Decode(&projResp)

	// Exchange the grant.
	exchBody, _ := json.Marshal(accessplane.ExchangeCapabilityRequest{
		GrantID:  projResp.GrantID,
		RunnerID: "runner-1",
	})
	exchReq := httptest.NewRequest("POST", "/v1/grants/exchange", bytes.NewReader(exchBody))
	exchReq.Header.Set("Authorization", "Bearer "+token)
	exchRR := httptest.NewRecorder()
	handlers.ExchangeCapability(exchRR, exchReq)

	if exchRR.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body: %s", exchRR.Code, exchRR.Body.String())
	}

	var exchResp accessplane.ExchangeCapabilityResponse
	_ = json.NewDecoder(exchRR.Body).Decode(&exchResp)
	if exchResp.Status != "active" {
		t.Errorf("status = %q, want active", exchResp.Status)
	}
}

func TestRefreshGrant_ValidRequest(t *testing.T) {
	handlers, _, cleanup := setupGrantHandlers(t)
	defer cleanup()

	claims := testClaims()
	token := signTestToken(t, claims)

	// Project a grant.
	projBody, _ := json.Marshal(accessplane.ProjectGrantRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
	})
	projReq := httptest.NewRequest("POST", "/v1/grants/project", bytes.NewReader(projBody))
	projReq.Header.Set("Authorization", "Bearer "+token)
	projRR := httptest.NewRecorder()
	handlers.ProjectGrant(projRR, projReq)

	var projResp accessplane.ProjectGrantResponse
	_ = json.NewDecoder(projRR.Body).Decode(&projResp)

	// Refresh.
	refreshBody, _ := json.Marshal(accessplane.RefreshGrantRequest{
		GrantID:  projResp.GrantID,
		RunnerID: "runner-1",
	})
	refreshReq := httptest.NewRequest("POST", "/v1/grants/refresh", bytes.NewReader(refreshBody))
	refreshReq.Header.Set("Authorization", "Bearer "+token)
	refreshRR := httptest.NewRecorder()
	handlers.RefreshGrant(refreshRR, refreshReq)

	if refreshRR.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body: %s", refreshRR.Code, refreshRR.Body.String())
	}

	var refreshResp accessplane.RefreshGrantResponse
	_ = json.NewDecoder(refreshRR.Body).Decode(&refreshResp)
	if refreshResp.Status != "refreshed" {
		t.Errorf("status = %q, want refreshed", refreshResp.Status)
	}
}

func TestRevokeGrant_ValidRequest(t *testing.T) {
	handlers, _, cleanup := setupGrantHandlers(t)
	defer cleanup()

	claims := testClaims()
	token := signTestToken(t, claims)

	// Project a grant.
	projBody, _ := json.Marshal(accessplane.ProjectGrantRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
	})
	projReq := httptest.NewRequest("POST", "/v1/grants/project", bytes.NewReader(projBody))
	projReq.Header.Set("Authorization", "Bearer "+token)
	projRR := httptest.NewRecorder()
	handlers.ProjectGrant(projRR, projReq)

	var projResp accessplane.ProjectGrantResponse
	_ = json.NewDecoder(projRR.Body).Decode(&projResp)

	// Revoke.
	revokeBody, _ := json.Marshal(accessplane.RevokeGrantRequest{
		GrantID:  projResp.GrantID,
		RunnerID: "runner-1",
	})
	revokeReq := httptest.NewRequest("POST", "/v1/grants/revoke", bytes.NewReader(revokeBody))
	revokeReq.Header.Set("Authorization", "Bearer "+token)
	revokeRR := httptest.NewRecorder()
	handlers.RevokeGrant(revokeRR, revokeReq)

	if revokeRR.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body: %s", revokeRR.Code, revokeRR.Body.String())
	}

	var revokeResp accessplane.RevokeGrantResponse
	_ = json.NewDecoder(revokeRR.Body).Decode(&revokeResp)
	if revokeResp.Status != "revoked" {
		t.Errorf("status = %q, want revoked", revokeResp.Status)
	}
}

func TestRevokeGrant_MissingAuth(t *testing.T) {
	handlers, _, cleanup := setupGrantHandlers(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/v1/grants/revoke", nil)
	rr := httptest.NewRecorder()
	handlers.RevokeGrant(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestRevokeGrant_RunnerMismatch(t *testing.T) {
	handlers, _, cleanup := setupGrantHandlers(t)
	defer cleanup()

	claims := testClaims()
	token := signTestToken(t, claims)

	// Project a grant.
	projBody, _ := json.Marshal(accessplane.ProjectGrantRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
	})
	projReq := httptest.NewRequest("POST", "/v1/grants/project", bytes.NewReader(projBody))
	projReq.Header.Set("Authorization", "Bearer "+token)
	projRR := httptest.NewRecorder()
	handlers.ProjectGrant(projRR, projReq)

	var projResp accessplane.ProjectGrantResponse
	_ = json.NewDecoder(projRR.Body).Decode(&projResp)

	// Revoke with different runner.
	diffClaims := &identity.Claims{
		RunnerID:    "runner-other",
		SessionID:   "session-other",
		WorkloadKey: "workload-1",
		HostID:      "host-1",
		IssuedAt:    time.Now().Add(-time.Minute),
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	diffToken := signTestToken(t, diffClaims)

	revokeBody, _ := json.Marshal(accessplane.RevokeGrantRequest{
		GrantID:  projResp.GrantID,
		RunnerID: "runner-other",
	})
	revokeReq := httptest.NewRequest("POST", "/v1/grants/revoke", bytes.NewReader(revokeBody))
	revokeReq.Header.Set("Authorization", "Bearer "+diffToken)
	revokeRR := httptest.NewRecorder()
	handlers.RevokeGrant(revokeRR, revokeReq)

	// Should get a 500 because the grant service validates runner_id mismatch.
	if revokeRR.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (runner mismatch in service). body: %s", revokeRR.Code, revokeRR.Body.String())
	}
}
