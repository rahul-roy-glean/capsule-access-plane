package grants

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
)

// Service implements the grant lifecycle: project, exchange, refresh, revoke.
type Service struct {
	store       GrantStore
	credentials *CredentialResolver
	defaultTTL  time.Duration
}

// NewService creates a grant service with the given store, credential resolver, and default TTL.
func NewService(store GrantStore, credentials *CredentialResolver, defaultTTL time.Duration) *Service {
	return &Service{
		store:       store,
		credentials: credentials,
		defaultTTL:  defaultTTL,
	}
}

// ProjectGrant creates a new grant for a tool operation.
// Returns the grant response and the resolved credential token (for adapter use).
func (s *Service) ProjectGrant(ctx context.Context, req *accessplane.ProjectGrantRequest, claims RunnerClaims, credentialRef string) (*accessplane.ProjectGrantResponse, string, error) {
	// Validate runner identity.
	if req.RunnerID != claims.RunnerID {
		return nil, "", fmt.Errorf("grants: runner_id mismatch: request=%s token=%s", req.RunnerID, claims.RunnerID)
	}

	// Resolve credential to verify it's available.
	resolvedToken, err := s.credentials.Resolve(ctx, credentialRef)
	if err != nil {
		return nil, "", fmt.Errorf("grants: credential unavailable: %w", err)
	}

	now := time.Now().UTC()
	grantID := uuid.New().String()

	g := &Grant{
		ID:                  grantID,
		Status:              GrantActive,
		Lane:                req.Lane,
		ToolFamily:          req.ToolFamily,
		Scope:               req.Scope,
		Target:              req.Target,
		SessionID:           req.SessionID,
		RunnerID:            req.RunnerID,
		TurnID:              req.TurnID,
		ImplementationState: accessplane.StateImplemented,
		CredentialRef:       credentialRef,
		ExpiresAt:           now.Add(s.defaultTTL),
		CreatedAt:           now,
		UpdatedAt:           now,
	}

	if err := s.store.InsertGrant(ctx, g); err != nil {
		return nil, "", fmt.Errorf("grants: insert: %w", err)
	}

	return &accessplane.ProjectGrantResponse{
		GrantID:       grantID,
		ProjectionRef: "proj-" + grantID,
		Status:        "projected",
	}, resolvedToken, nil
}

// ExchangeCapability validates that a grant is active and usable.
func (s *Service) ExchangeCapability(ctx context.Context, req *accessplane.ExchangeCapabilityRequest) (*accessplane.ExchangeCapabilityResponse, error) {
	g, err := s.store.GetGrant(ctx, req.GrantID)
	if err != nil {
		return nil, fmt.Errorf("grants: exchange: %w", err)
	}

	if g.RunnerID != req.RunnerID {
		return nil, fmt.Errorf("grants: exchange: runner_id mismatch")
	}

	if g.Status != GrantActive {
		return nil, fmt.Errorf("grants: exchange: grant is %s, not active", g.Status)
	}

	if time.Now().After(g.ExpiresAt) {
		return nil, fmt.Errorf("grants: exchange: grant has expired")
	}

	return &accessplane.ExchangeCapabilityResponse{
		GrantID:   g.ID,
		ExpiresAt: g.ExpiresAt,
		Status:    "active",
	}, nil
}

// RefreshGrant extends the lifetime of an active grant.
func (s *Service) RefreshGrant(ctx context.Context, req *accessplane.RefreshGrantRequest) (*accessplane.RefreshGrantResponse, error) {
	g, err := s.store.GetGrant(ctx, req.GrantID)
	if err != nil {
		return nil, fmt.Errorf("grants: refresh: %w", err)
	}

	if g.RunnerID != req.RunnerID {
		return nil, fmt.Errorf("grants: refresh: runner_id mismatch")
	}

	if g.Status != GrantActive {
		return nil, fmt.Errorf("grants: refresh: grant is %s, not active", g.Status)
	}

	newExpiry := time.Now().UTC().Add(s.defaultTTL)
	if err := s.store.UpdateGrantExpiry(ctx, g.ID, newExpiry); err != nil {
		return nil, fmt.Errorf("grants: refresh: %w", err)
	}

	return &accessplane.RefreshGrantResponse{
		GrantID:   g.ID,
		ExpiresAt: newExpiry,
		Status:    "refreshed",
	}, nil
}

// RevokeGrant revokes a grant.
func (s *Service) RevokeGrant(ctx context.Context, req *accessplane.RevokeGrantRequest) (*accessplane.RevokeGrantResponse, error) {
	g, err := s.store.GetGrant(ctx, req.GrantID)
	if err != nil {
		return nil, fmt.Errorf("grants: revoke: %w", err)
	}

	if g.RunnerID != req.RunnerID {
		return nil, fmt.Errorf("grants: revoke: runner_id mismatch")
	}

	// Idempotent: revoking an already-revoked grant is fine.
	if g.Status == GrantRevoked {
		return &accessplane.RevokeGrantResponse{
			GrantID: g.ID,
			Status:  "revoked",
		}, nil
	}

	now := time.Now().UTC()
	if err := s.store.UpdateGrantStatus(ctx, g.ID, GrantRevoked, &now); err != nil {
		return nil, fmt.Errorf("grants: revoke: %w", err)
	}

	return &accessplane.RevokeGrantResponse{
		GrantID: g.ID,
		Status:  "revoked",
	}, nil
}

// GetGrant retrieves a grant by ID (exposed for use by handlers/adapters).
func (s *Service) GetGrant(ctx context.Context, id string) (*Grant, error) {
	return s.store.GetGrant(ctx, id)
}

// RunnerClaims is the subset of identity claims needed by the grant service.
type RunnerClaims struct {
	RunnerID  string
	SessionID string
}
