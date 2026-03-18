package accessplane

import "time"

// ProjectGrantRequest initiates a new grant for a tool operation.
type ProjectGrantRequest struct {
	GrantID    string `json:"grant_id"`
	RunnerID   string `json:"runner_id"`
	SessionID  string `json:"session_id"`
	TurnID     string `json:"turn_id"`
	ToolFamily string `json:"tool_family"`
	Lane       Lane   `json:"lane"`
	Scope      string `json:"scope"`
	Target     string `json:"target"`
}

// ProjectGrantResponse is the result of projecting a grant.
type ProjectGrantResponse struct {
	GrantID       string `json:"grant_id"`
	ProjectionRef string `json:"projection_ref"`
	Status        string `json:"status"`
}

// ExchangeCapabilityRequest exchanges a projected grant for an active capability.
type ExchangeCapabilityRequest struct {
	GrantID  string `json:"grant_id"`
	RunnerID string `json:"runner_id"`
}

// ExchangeCapabilityResponse is the result of exchanging a capability.
type ExchangeCapabilityResponse struct {
	GrantID   string    `json:"grant_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Status    string    `json:"status"`
}

// RefreshGrantRequest extends the lifetime of an active grant.
type RefreshGrantRequest struct {
	GrantID  string `json:"grant_id"`
	RunnerID string `json:"runner_id"`
}

// RefreshGrantResponse is the result of refreshing a grant.
type RefreshGrantResponse struct {
	GrantID   string    `json:"grant_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Status    string    `json:"status"`
}

// RevokeGrantRequest revokes an active grant.
type RevokeGrantRequest struct {
	GrantID  string `json:"grant_id"`
	RunnerID string `json:"runner_id"`
	Reason   string `json:"reason"`
}

// RevokeGrantResponse is the result of revoking a grant.
type RevokeGrantResponse struct {
	GrantID string `json:"grant_id"`
	Status  string `json:"status"`
}
