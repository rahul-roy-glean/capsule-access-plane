package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type Event struct {
	EventType       string
	SessionID       string
	RunnerID        string
	TurnID          string
	ActorUser       string
	VirtualIdentity string
	AgentID         string
	Target          string
	Action          string
	Result          string
	PolicyDecision  string
	Duration        time.Duration
	Metadata        any
}

type Service struct {
	db *sql.DB
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

func (s *Service) Record(ctx context.Context, event Event) error {
	metadata := []byte("{}")
	if event.Metadata != nil {
		encoded, err := json.Marshal(event.Metadata)
		if err != nil {
			return fmt.Errorf("marshal audit metadata: %w", err)
		}
		metadata = encoded
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_events (
			event_type, session_id, runner_id, turn_id, actor_user, virtual_identity,
			agent_id, target, action, result, policy_decision, duration_ms, metadata_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		event.EventType,
		event.SessionID,
		event.RunnerID,
		event.TurnID,
		event.ActorUser,
		event.VirtualIdentity,
		event.AgentID,
		event.Target,
		event.Action,
		event.Result,
		event.PolicyDecision,
		event.Duration.Milliseconds(),
		string(metadata),
	)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}
