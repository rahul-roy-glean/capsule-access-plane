package grants

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/rahul-roy-glean/capsule-access-plane/internal/capsule"
	"github.com/rahul-roy-glean/capsule-access-plane/internal/identity"
	"github.com/rahul-roy-glean/capsule-access-plane/internal/policy"
	"github.com/rahul-roy-glean/capsule-access-plane/internal/providers"
)

const (
	GrantTypeHTTP   = "http"
	GrantTypeHelper = "helper"
)

type Grant struct {
	ID            string              `json:"id"`
	Type          string              `json:"type"`
	Status        string              `json:"status"`
	SessionID     string              `json:"session_id"`
	RunnerID      string              `json:"runner_id"`
	WorkloadKey   string              `json:"workload_key"`
	TurnID        string              `json:"turn_id,omitempty"`
	Actor         policy.ActorContext `json:"actor"`
	Target        string              `json:"target"`
	Scope         string              `json:"scope"`
	CredentialRef string              `json:"credential_ref,omitempty"`
	Metadata      map[string]any      `json:"metadata,omitempty"`
	ExpiresAt     time.Time           `json:"expires_at"`
	CreatedAt     time.Time           `json:"created_at"`
	UpdatedAt     time.Time           `json:"updated_at"`
	RevokedAt     *time.Time          `json:"revoked_at,omitempty"`
}

type HelperSession struct {
	ID         string                    `json:"id"`
	GrantID    string                    `json:"grant_id"`
	ToolFamily string                    `json:"tool_family"`
	Format     string                    `json:"format"`
	Env        map[string]string         `json:"env"`
	Files      []providers.ProjectedFile `json:"files"`
}

type OpenHTTPGrantRequest struct {
	Claims        *identity.Claims
	Actor         policy.ActorContext
	TurnID        string
	Scope         string
	TTL           time.Duration
	Domains       []string
	CredentialRef string
	HeaderName    string
	HeaderPrefix  string
}

type OpenHelperSessionRequest struct {
	Claims            *identity.Claims
	Actor             policy.ActorContext
	TurnID            string
	Scope             string
	TTL               time.Duration
	ToolFamily        string
	CredentialRef     string
	RunnerAttestation string
	AccessPlaneURL    string
}

type Service struct {
	db          *sql.DB
	policy      *policy.Engine
	capsule     *capsule.Client
	credentials *providers.CredentialResolver
}

func NewService(db *sql.DB, engine *policy.Engine, capsuleClient *capsule.Client, credentialResolver *providers.CredentialResolver) *Service {
	return &Service{
		db:          db,
		policy:      engine,
		capsule:     capsuleClient,
		credentials: credentialResolver,
	}
}

func (s *Service) OpenHTTPGrant(ctx context.Context, req OpenHTTPGrantRequest) (*Grant, error) {
	if err := s.policy.AllowGrant(req.Domains, req.Scope, req.Actor); err != nil {
		return nil, err
	}
	if req.HeaderName == "" {
		req.HeaderName = "Authorization"
	}
	if req.HeaderPrefix == "" {
		req.HeaderPrefix = "Bearer "
	}
	if req.TTL <= 0 {
		req.TTL = 10 * time.Minute
	}

	token, err := s.credentials.Resolve(ctx, req.CredentialRef)
	if err != nil {
		return nil, err
	}

	grant := &Grant{
		ID:            uuid.NewString(),
		Type:          GrantTypeHTTP,
		Status:        "active",
		SessionID:     req.Claims.SessionID,
		RunnerID:      req.Claims.RunnerID,
		WorkloadKey:   req.Claims.WorkloadKey,
		TurnID:        req.TurnID,
		Actor:         req.Actor,
		Target:        joinTargets(req.Domains),
		Scope:         req.Scope,
		CredentialRef: req.CredentialRef,
		Metadata: map[string]any{
			"domains":       req.Domains,
			"header_name":   req.HeaderName,
			"header_prefix": req.HeaderPrefix,
		},
		ExpiresAt: time.Now().UTC().Add(req.TTL),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := s.insertGrant(ctx, grant); err != nil {
		return nil, err
	}

	if s.capsule != nil {
		headers := map[string]string{req.HeaderName: req.HeaderPrefix + token}
		if err := s.capsule.InstallGrant(ctx, capsule.InstallGrantRequest{
			GrantID:   grant.ID,
			GrantType: grant.Type,
			RunnerID:  grant.RunnerID,
			SessionID: grant.SessionID,
			TurnID:    grant.TurnID,
			Scope:     grant.Scope,
			Domains:   req.Domains,
			Headers:   headers,
			Token:     token,
			ExpiresAt: grant.ExpiresAt.Format(time.RFC3339),
		}); err != nil {
			return nil, fmt.Errorf("install HTTP grant in capsule: %w", err)
		}
	}

	return grant, nil
}

func (s *Service) OpenHelperSession(ctx context.Context, req OpenHelperSessionRequest) (*Grant, *HelperSession, error) {
	if err := s.policy.AllowGrant([]string{"helper-session"}, req.Scope, req.Actor); err != nil {
		return nil, nil, err
	}
	if req.TTL <= 0 {
		req.TTL = 10 * time.Minute
	}

	grant := &Grant{
		ID:            uuid.NewString(),
		Type:          GrantTypeHelper,
		Status:        "active",
		SessionID:     req.Claims.SessionID,
		RunnerID:      req.Claims.RunnerID,
		WorkloadKey:   req.Claims.WorkloadKey,
		TurnID:        req.TurnID,
		Actor:         req.Actor,
		Target:        req.ToolFamily,
		Scope:         req.Scope,
		CredentialRef: req.CredentialRef,
		Metadata: map[string]any{
			"tool_family": req.ToolFamily,
		},
		ExpiresAt: time.Now().UTC().Add(req.TTL),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := s.insertGrant(ctx, grant); err != nil {
		return nil, nil, err
	}

	bootstrap, err := providers.BuildHelperBootstrap(providers.HelperBootstrapRequest{
		AccessPlaneURL:    req.AccessPlaneURL,
		HelperSessionID:   grant.ID,
		RunnerAttestation: req.RunnerAttestation,
		ToolFamily:        req.ToolFamily,
		Scope:             req.Scope,
		TTL:               req.TTL,
	})
	if err != nil {
		return nil, nil, err
	}

	session := &HelperSession{
		ID:         uuid.NewString(),
		GrantID:    grant.ID,
		ToolFamily: req.ToolFamily,
		Format:     bootstrap.Format,
		Env:        bootstrap.Env,
		Files:      bootstrap.Files,
	}
	if err := s.insertHelperSession(ctx, session); err != nil {
		return nil, nil, err
	}

	if s.capsule != nil {
		var files []capsule.HelperFile
		for _, file := range bootstrap.Files {
			files = append(files, capsule.HelperFile{
				Path:    file.Path,
				Content: file.Content,
				Mode:    file.Mode,
			})
		}
		if err := s.capsule.InstallGrant(ctx, capsule.InstallGrantRequest{
			GrantID:     grant.ID,
			GrantType:   grant.Type,
			RunnerID:    grant.RunnerID,
			SessionID:   grant.SessionID,
			TurnID:      grant.TurnID,
			Scope:       grant.Scope,
			ToolFamily:  req.ToolFamily,
			HelperEnv:   session.Env,
			HelperFiles: files,
			ExpiresAt:   grant.ExpiresAt.Format(time.RFC3339),
		}); err != nil {
			return nil, nil, fmt.Errorf("install helper session in capsule: %w", err)
		}
	}

	return grant, session, nil
}

func (s *Service) RevokeGrant(ctx context.Context, grantID string) error {
	grant, err := s.GetGrant(ctx, grantID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `
		UPDATE grants
		SET status = 'revoked', revoked_at = ?, updated_at = ?
		WHERE id = ?
	`, now.Format(time.RFC3339), now.Format(time.RFC3339), grantID); err != nil {
		return fmt.Errorf("revoke grant: %w", err)
	}
	if s.capsule != nil {
		if err := s.capsule.RevokeGrant(ctx, capsule.RevokeGrantRequest{
			GrantID:   grant.ID,
			GrantType: grant.Type,
			RunnerID:  grant.RunnerID,
		}); err != nil {
			return fmt.Errorf("revoke grant in capsule: %w", err)
		}
	}
	return nil
}

func (s *Service) GetGrant(ctx context.Context, grantID string) (*Grant, error) {
	var metadataJSON string
	var revokedAt string
	var grant Grant
	err := s.db.QueryRowContext(ctx, `
		SELECT id, grant_type, status, session_id, runner_id, workload_key, turn_id,
		       actor_user, virtual_identity, agent_id, target, scope, credential_ref,
		       metadata_json, expires_at, created_at, updated_at, revoked_at
		FROM grants WHERE id = ?
	`, grantID).Scan(
		&grant.ID,
		&grant.Type,
		&grant.Status,
		&grant.SessionID,
		&grant.RunnerID,
		&grant.WorkloadKey,
		&grant.TurnID,
		&grant.Actor.UserID,
		&grant.Actor.VirtualIdentity,
		&grant.Actor.AgentID,
		&grant.Target,
		&grant.Scope,
		&grant.CredentialRef,
		&metadataJSON,
		&grant.ExpiresAt,
		&grant.CreatedAt,
		&grant.UpdatedAt,
		&revokedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("grant %q not found", grantID)
		}
		return nil, fmt.Errorf("query grant: %w", err)
	}
	if metadataJSON != "" {
		if err := json.Unmarshal([]byte(metadataJSON), &grant.Metadata); err != nil {
			return nil, fmt.Errorf("decode grant metadata: %w", err)
		}
	}
	if revokedAt != "" {
		parsed, err := time.Parse(time.RFC3339, revokedAt)
		if err == nil {
			grant.RevokedAt = &parsed
		}
	}
	return &grant, nil
}

func (s *Service) GetHelperSession(ctx context.Context, grantID string) (*HelperSession, error) {
	var envJSON string
	var filesJSON string
	var session HelperSession
	err := s.db.QueryRowContext(ctx, `
		SELECT id, grant_id, tool_family, format, env_json, files_json
		FROM helper_sessions WHERE grant_id = ?
	`, grantID).Scan(&session.ID, &session.GrantID, &session.ToolFamily, &session.Format, &envJSON, &filesJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("helper session for grant %q not found", grantID)
		}
		return nil, fmt.Errorf("query helper session: %w", err)
	}
	if err := json.Unmarshal([]byte(envJSON), &session.Env); err != nil {
		return nil, fmt.Errorf("decode helper env: %w", err)
	}
	if err := json.Unmarshal([]byte(filesJSON), &session.Files); err != nil {
		return nil, fmt.Errorf("decode helper files: %w", err)
	}
	return &session, nil
}

func (s *Service) ResolveGrantToken(ctx context.Context, grant *Grant) (string, error) {
	return s.credentials.Resolve(ctx, grant.CredentialRef)
}

func (s *Service) insertGrant(ctx context.Context, grant *Grant) error {
	metadataJSON, err := json.Marshal(grant.Metadata)
	if err != nil {
		return fmt.Errorf("encode grant metadata: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO grants (
			id, grant_type, status, session_id, runner_id, workload_key, turn_id,
			actor_user, virtual_identity, agent_id, target, scope, credential_ref,
			metadata_json, expires_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		grant.ID,
		grant.Type,
		grant.Status,
		grant.SessionID,
		grant.RunnerID,
		grant.WorkloadKey,
		grant.TurnID,
		grant.Actor.UserID,
		grant.Actor.VirtualIdentity,
		grant.Actor.AgentID,
		grant.Target,
		grant.Scope,
		grant.CredentialRef,
		string(metadataJSON),
		grant.ExpiresAt.Format(time.RFC3339),
		grant.CreatedAt.Format(time.RFC3339),
		grant.UpdatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("insert grant: %w", err)
	}
	return nil
}

func (s *Service) insertHelperSession(ctx context.Context, session *HelperSession) error {
	envJSON, err := json.Marshal(session.Env)
	if err != nil {
		return fmt.Errorf("encode helper env: %w", err)
	}
	filesJSON, err := json.Marshal(session.Files)
	if err != nil {
		return fmt.Errorf("encode helper files: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO helper_sessions (id, grant_id, tool_family, format, env_json, files_json)
		VALUES (?, ?, ?, ?, ?, ?)
	`, session.ID, session.GrantID, session.ToolFamily, session.Format, string(envJSON), string(filesJSON))
	if err != nil {
		return fmt.Errorf("insert helper session: %w", err)
	}
	return nil
}

func joinTargets(items []string) string {
	encoded, _ := json.Marshal(items)
	return string(encoded)
}
