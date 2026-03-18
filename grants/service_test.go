package grants

import (
	"context"
	"testing"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/rahul-roy-glean/capsule-access-plane/store"
)

func setupTestService(t *testing.T) (*Service, func()) {
	t.Helper()

	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	sqlStore := NewSQLStore(s.DB())
	creds := NewCredentialResolver(s.DB())
	svc := NewService(sqlStore, creds, 15*time.Minute)

	return svc, func() { _ = s.Close() }
}

func TestProjectGrant_Success(t *testing.T) {
	svc, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()
	req := &accessplane.ProjectGrantRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		TurnID:     "turn-1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
		Scope:      "repo:read",
	}
	claims := RunnerClaims{RunnerID: "runner-1", SessionID: "session-1"}

	t.Setenv("TEST_TOKEN", "test-secret-value")
	resp, _, err := svc.ProjectGrant(ctx, req, claims, "env:TEST_TOKEN")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.GrantID == "" {
		t.Error("expected non-empty grant_id")
	}
	if resp.Status != "projected" {
		t.Errorf("status = %q, want projected", resp.Status)
	}
	if resp.ProjectionRef == "" {
		t.Error("expected non-empty projection_ref")
	}
}

func TestProjectGrant_RunnerMismatch(t *testing.T) {
	svc, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()
	req := &accessplane.ProjectGrantRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
	}
	claims := RunnerClaims{RunnerID: "runner-other", SessionID: "session-1"}

	t.Setenv("TEST_TOKEN", "test-secret-value")
	_, _, err := svc.ProjectGrant(ctx, req, claims, "env:TEST_TOKEN")
	if err == nil {
		t.Fatal("expected error for runner mismatch")
	}
}

func TestExchangeCapability_Success(t *testing.T) {
	svc, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()
	t.Setenv("TEST_TOKEN", "test-secret-value")

	projResp, _, err := svc.ProjectGrant(ctx, &accessplane.ProjectGrantRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
	}, RunnerClaims{RunnerID: "runner-1", SessionID: "session-1"}, "env:TEST_TOKEN")
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	resp, err := svc.ExchangeCapability(ctx, &accessplane.ExchangeCapabilityRequest{
		GrantID:  projResp.GrantID,
		RunnerID: "runner-1",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Status != "active" {
		t.Errorf("status = %q, want active", resp.Status)
	}
}

func TestExchangeCapability_ExpiredGrant(t *testing.T) {
	svc, cleanup := setupTestService(t)
	defer cleanup()

	// Use a service with very short TTL.
	sqlStore := svc.store
	creds := svc.credentials
	shortSvc := NewService(sqlStore, creds, 1*time.Millisecond)

	ctx := context.Background()
	t.Setenv("TEST_TOKEN", "test-secret-value")

	projResp, _, err := shortSvc.ProjectGrant(ctx, &accessplane.ProjectGrantRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
	}, RunnerClaims{RunnerID: "runner-1", SessionID: "session-1"}, "env:TEST_TOKEN")
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	// Wait for grant to expire.
	time.Sleep(5 * time.Millisecond)

	_, err = shortSvc.ExchangeCapability(ctx, &accessplane.ExchangeCapabilityRequest{
		GrantID:  projResp.GrantID,
		RunnerID: "runner-1",
	})
	if err == nil {
		t.Fatal("expected error for expired grant")
	}
}

func TestExchangeCapability_RevokedGrant(t *testing.T) {
	svc, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()
	t.Setenv("TEST_TOKEN", "test-secret-value")

	projResp, _, err := svc.ProjectGrant(ctx, &accessplane.ProjectGrantRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
	}, RunnerClaims{RunnerID: "runner-1", SessionID: "session-1"}, "env:TEST_TOKEN")
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	// Revoke it.
	_, err = svc.RevokeGrant(ctx, &accessplane.RevokeGrantRequest{
		GrantID:  projResp.GrantID,
		RunnerID: "runner-1",
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Exchange should fail.
	_, err = svc.ExchangeCapability(ctx, &accessplane.ExchangeCapabilityRequest{
		GrantID:  projResp.GrantID,
		RunnerID: "runner-1",
	})
	if err == nil {
		t.Fatal("expected error for revoked grant")
	}
}

func TestRefreshGrant_ExtendsExpiry(t *testing.T) {
	svc, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()
	t.Setenv("TEST_TOKEN", "test-secret-value")

	projResp, _, err := svc.ProjectGrant(ctx, &accessplane.ProjectGrantRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
	}, RunnerClaims{RunnerID: "runner-1", SessionID: "session-1"}, "env:TEST_TOKEN")
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	resp, err := svc.RefreshGrant(ctx, &accessplane.RefreshGrantRequest{
		GrantID:  projResp.GrantID,
		RunnerID: "runner-1",
	})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if resp.Status != "refreshed" {
		t.Errorf("status = %q, want refreshed", resp.Status)
	}
	if resp.ExpiresAt.Before(time.Now()) {
		t.Error("expected ExpiresAt to be in the future")
	}
}

func TestRevokeGrant_Success(t *testing.T) {
	svc, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()
	t.Setenv("TEST_TOKEN", "test-secret-value")

	projResp, _, err := svc.ProjectGrant(ctx, &accessplane.ProjectGrantRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
	}, RunnerClaims{RunnerID: "runner-1", SessionID: "session-1"}, "env:TEST_TOKEN")
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	resp, err := svc.RevokeGrant(ctx, &accessplane.RevokeGrantRequest{
		GrantID:  projResp.GrantID,
		RunnerID: "runner-1",
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if resp.Status != "revoked" {
		t.Errorf("status = %q, want revoked", resp.Status)
	}
}

func TestRevokeGrant_Idempotent(t *testing.T) {
	svc, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()
	t.Setenv("TEST_TOKEN", "test-secret-value")

	projResp, _, err := svc.ProjectGrant(ctx, &accessplane.ProjectGrantRequest{
		RunnerID:   "runner-1",
		SessionID:  "session-1",
		ToolFamily: "github_rest",
		Lane:       accessplane.LaneDirectHTTP,
	}, RunnerClaims{RunnerID: "runner-1", SessionID: "session-1"}, "env:TEST_TOKEN")
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	// Revoke twice.
	_, err = svc.RevokeGrant(ctx, &accessplane.RevokeGrantRequest{
		GrantID:  projResp.GrantID,
		RunnerID: "runner-1",
	})
	if err != nil {
		t.Fatalf("first revoke: %v", err)
	}

	resp, err := svc.RevokeGrant(ctx, &accessplane.RevokeGrantRequest{
		GrantID:  projResp.GrantID,
		RunnerID: "runner-1",
	})
	if err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if resp.Status != "revoked" {
		t.Errorf("status = %q, want revoked", resp.Status)
	}
}
