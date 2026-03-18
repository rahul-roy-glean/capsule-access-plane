package grants

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// GrantStore defines the persistence interface for grants.
type GrantStore interface {
	InsertGrant(ctx context.Context, g *Grant) error
	GetGrant(ctx context.Context, id string) (*Grant, error)
	UpdateGrantStatus(ctx context.Context, id string, status GrantStatus, revokedAt *time.Time) error
	UpdateGrantExpiry(ctx context.Context, id string, expiresAt time.Time) error
}

// SQLStore implements GrantStore using a SQL database.
type SQLStore struct {
	db *sql.DB
}

// NewSQLStore creates a new SQLStore backed by the given database connection.
func NewSQLStore(db *sql.DB) *SQLStore {
	return &SQLStore{db: db}
}

// InsertGrant inserts a new grant record.
func (s *SQLStore) InsertGrant(ctx context.Context, g *Grant) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO grants (
			id, status, lane, tool_family, logical_action, target, scope,
			session_id, runner_id, turn_id, workload_key,
			actor_user, actor_virtual_identity, actor_agent_id,
			reason_code, implementation_state, credential_ref,
			expires_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		g.ID, g.Status, g.Lane, g.ToolFamily, g.LogicalAction, g.Target, g.Scope,
		g.SessionID, g.RunnerID, g.TurnID, g.WorkloadKey,
		g.Actor.UserID, g.Actor.VirtualIdentity, g.Actor.AgentID,
		g.ReasonCode, g.ImplementationState, g.CredentialRef,
		g.ExpiresAt.UTC().Format(time.RFC3339Nano),
		g.CreatedAt.UTC().Format(time.RFC3339Nano),
		g.UpdatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("grants: insert: %w", err)
	}
	return nil
}

// GetGrant retrieves a grant by ID.
func (s *SQLStore) GetGrant(ctx context.Context, id string) (*Grant, error) {
	var g Grant
	var expiresAt, createdAt, updatedAt string
	var revokedAt sql.NullString
	var credentialRef string

	err := s.db.QueryRowContext(ctx, `
		SELECT id, status, lane, tool_family, logical_action, target, scope,
			session_id, runner_id, turn_id, workload_key,
			actor_user, actor_virtual_identity, actor_agent_id,
			reason_code, implementation_state, credential_ref,
			expires_at, revoked_at, created_at, updated_at
		FROM grants WHERE id = ?`, id,
	).Scan(
		&g.ID, &g.Status, &g.Lane, &g.ToolFamily, &g.LogicalAction, &g.Target, &g.Scope,
		&g.SessionID, &g.RunnerID, &g.TurnID, &g.WorkloadKey,
		&g.Actor.UserID, &g.Actor.VirtualIdentity, &g.Actor.AgentID,
		&g.ReasonCode, &g.ImplementationState, &credentialRef,
		&expiresAt, &revokedAt, &createdAt, &updatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("grants: not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("grants: get: %w", err)
	}

	g.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expiresAt)
	g.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	g.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	g.CredentialRef = credentialRef
	if revokedAt.Valid {
		t, _ := time.Parse(time.RFC3339Nano, revokedAt.String)
		g.RevokedAt = &t
	}

	return &g, nil
}

// UpdateGrantStatus updates the status (and optionally revoked_at) of a grant.
func (s *SQLStore) UpdateGrantStatus(ctx context.Context, id string, status GrantStatus, revokedAt *time.Time) error {
	var err error
	if revokedAt != nil {
		_, err = s.db.ExecContext(ctx, `
			UPDATE grants SET status = ?, revoked_at = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
			WHERE id = ?`,
			status, revokedAt.UTC().Format(time.RFC3339Nano), id,
		)
	} else {
		_, err = s.db.ExecContext(ctx, `
			UPDATE grants SET status = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
			WHERE id = ?`,
			status, id,
		)
	}
	if err != nil {
		return fmt.Errorf("grants: update status: %w", err)
	}
	return nil
}

// UpdateGrantExpiry updates the expires_at timestamp of a grant.
func (s *SQLStore) UpdateGrantExpiry(ctx context.Context, id string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE grants SET expires_at = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
		WHERE id = ?`,
		expiresAt.UTC().Format(time.RFC3339Nano), id,
	)
	if err != nil {
		return fmt.Errorf("grants: update expiry: %w", err)
	}
	return nil
}

