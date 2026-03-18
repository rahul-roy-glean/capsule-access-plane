package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/rahul-roy-glean/capsule-access-plane/identity"
	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
	"github.com/rahul-roy-glean/capsule-access-plane/policy"
)

var handlerTestSecret = []byte("handler-test-secret")

func setupHandler(t *testing.T) (*ResolveHandler, *identity.HMACVerifier) {
	t.Helper()

	verifier, err := identity.NewHMACVerifier(handlerTestSecret)
	if err != nil {
		t.Fatal(err)
	}

	reg := manifest.NewInMemoryRegistry()
	loader := &manifest.YAMLLoader{}
	if err := manifest.LoadAllFamilies(loader, reg); err != nil {
		t.Fatalf("failed to load families: %v", err)
	}

	engine := policy.NewManifestBasedEngine(reg)

	implAvailability := map[accessplane.Lane]accessplane.ImplementationState{
		accessplane.LaneDirectHTTP:      accessplane.StateImplementationDeferred,
		accessplane.LaneHelperSession:   accessplane.StateImplementationDeferred,
		accessplane.LaneRemoteExecution: accessplane.StateImplementationDeferred,
	}

	logger := slog.Default()
	handler := NewResolveHandler(verifier, engine, implAvailability, logger)
	return handler, verifier
}

func signTestToken(t *testing.T, claims *identity.Claims) string {
	t.Helper()
	token, err := identity.SignClaims(claims, handlerTestSecret)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func testClaims() *identity.Claims {
	return &identity.Claims{
		RunnerID:    "runner-1",
		SessionID:   "session-1",
		WorkloadKey: "workload-1",
		HostID:      "host-1",
		IssuedAt:    time.Now().Add(-time.Minute),
		ExpiresAt:   time.Now().Add(time.Hour),
	}
}

func TestResolveHandler_ValidRequest(t *testing.T) {
	handler, _ := setupHandler(t)

	claims := testClaims()
	token := signTestToken(t, claims)

	reqBody := accessplane.ResolveOperationRequest{
		Actor:         accessplane.ActorContext{UserID: "user-1"},
		Runner:        accessplane.RunnerContext{SessionID: "session-1", RunnerID: "runner-1", TurnID: "turn-1"},
		ToolFamily:    "github_rest",
		LogicalAction: "read_repo",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body: %s", rr.Code, rr.Body.String())
	}

	var resp accessplane.ResolveOperationResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Decision != accessplane.DecisionAllow {
		t.Errorf("decision = %q, want allow", resp.Decision)
	}
	if resp.SelectedLane != accessplane.LaneDirectHTTP {
		t.Errorf("lane = %q, want direct_http", resp.SelectedLane)
	}
	if resp.ImplementationState != accessplane.StateImplementationDeferred {
		t.Errorf("impl_state = %q, want implementation_deferred", resp.ImplementationState)
	}
}

func TestResolveHandler_MissingAuthHeader(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest("POST", "/v1/resolve", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestResolveHandler_InvalidToken(t *testing.T) {
	handler, _ := setupHandler(t)

	req := httptest.NewRequest("POST", "/v1/resolve", nil)
	req.Header.Set("Authorization", "Bearer invalid.token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestResolveHandler_UnknownToolFamily(t *testing.T) {
	handler, _ := setupHandler(t)

	claims := testClaims()
	token := signTestToken(t, claims)

	reqBody := accessplane.ResolveOperationRequest{
		Actor:      accessplane.ActorContext{UserID: "user-1"},
		Runner:     accessplane.RunnerContext{SessionID: "session-1", RunnerID: "runner-1", TurnID: "turn-1"},
		ToolFamily: "nonexistent",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403. body: %s", rr.Code, rr.Body.String())
	}
}

func TestResolveHandler_MissingActor(t *testing.T) {
	handler, _ := setupHandler(t)

	claims := testClaims()
	token := signTestToken(t, claims)

	reqBody := accessplane.ResolveOperationRequest{
		Actor:         accessplane.ActorContext{UserID: ""},
		Runner:        accessplane.RunnerContext{SessionID: "session-1", RunnerID: "runner-1", TurnID: "turn-1"},
		ToolFamily:    "github_rest",
		LogicalAction: "read_repo",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403. body: %s", rr.Code, rr.Body.String())
	}
}

func TestResolveHandler_DeferredLane(t *testing.T) {
	handler, _ := setupHandler(t)

	claims := testClaims()
	token := signTestToken(t, claims)

	reqBody := accessplane.ResolveOperationRequest{
		Actor:         accessplane.ActorContext{UserID: "user-1"},
		Runner:        accessplane.RunnerContext{SessionID: "session-1", RunnerID: "runner-1", TurnID: "turn-1"},
		ToolFamily:    "internal_admin_cli",
		LogicalAction: "rotate_secrets",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body: %s", rr.Code, rr.Body.String())
	}

	var resp accessplane.ResolveOperationResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Decision != accessplane.DecisionAllow {
		t.Errorf("decision = %q, want allow", resp.Decision)
	}
	if resp.SelectedLane != accessplane.LaneRemoteExecution {
		t.Errorf("lane = %q, want remote_execution", resp.SelectedLane)
	}
	if resp.ImplementationState != accessplane.StateImplementationDeferred {
		t.Errorf("impl_state = %q, want implementation_deferred", resp.ImplementationState)
	}
	if resp.ApprovalStatus != "approval_required" {
		t.Errorf("approval_status = %q, want approval_required", resp.ApprovalStatus)
	}
}

func TestResolveHandler_RunnerContextMismatch(t *testing.T) {
	handler, _ := setupHandler(t)

	claims := testClaims()
	token := signTestToken(t, claims)

	reqBody := accessplane.ResolveOperationRequest{
		Actor:         accessplane.ActorContext{UserID: "user-1"},
		Runner:        accessplane.RunnerContext{SessionID: "wrong-session", RunnerID: "wrong-runner", TurnID: "turn-1"},
		ToolFamily:    "github_rest",
		LogicalAction: "read_repo",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403. body: %s", rr.Code, rr.Body.String())
	}
}
