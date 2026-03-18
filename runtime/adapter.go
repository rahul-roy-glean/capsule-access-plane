package runtime

import (
	"context"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/rahul-roy-glean/capsule-access-plane/bundle"
)

// RuntimeAdapter is the contract that every runner-side implementation
// must satisfy in order to install, revoke, and inspect projected grants.
type RuntimeAdapter interface {
	// InstallGrant projects a bundle into the runner environment.
	InstallGrant(ctx context.Context, b *bundle.ProjectionBundle) error

	// RevokeGrant removes a previously installed grant.
	RevokeGrant(ctx context.Context, grantID string, runnerID string) error

	// DescribeGrantState returns the current state of an installed grant.
	DescribeGrantState(ctx context.Context, runnerID string, grantID string) (*GrantState, error)
}

// EventPublisher allows the runner to emit lifecycle events back to
// the control plane.
type EventPublisher interface {
	// PublishRunnerEvent sends a runner lifecycle event.
	PublishRunnerEvent(ctx context.Context, event RunnerEvent) error
}

// GrantState describes the current condition of an installed grant
// as observed by the runner.
type GrantState struct {
	RunnerID  string           `json:"runner_id"`
	GrantID   string           `json:"grant_id"`
	Status    string           `json:"status"`
	Lane      accessplane.Lane `json:"lane"`
	ExpiresAt time.Time        `json:"expires_at"`
}

// RunnerEvent is a lifecycle event emitted by the runner.
type RunnerEvent struct {
	Type      accessplane.RunnerEventType `json:"type"`
	RunnerID  string                      `json:"runner_id"`
	SessionID string                      `json:"session_id"`
	Timestamp time.Time                   `json:"timestamp"`
	Metadata  map[string]string           `json:"metadata,omitempty"`
}
