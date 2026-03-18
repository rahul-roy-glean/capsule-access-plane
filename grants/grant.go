package grants

import (
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
)

// GrantStatus tracks the lifecycle state of a grant.
type GrantStatus string

const (
	GrantActive        GrantStatus = "active"
	GrantRevoked       GrantStatus = "revoked"
	GrantExpired       GrantStatus = "expired"
	GrantFailedInstall GrantStatus = "failed_install"
	GrantInstallRemoved GrantStatus = "install_removed"
)

// Grant represents a granted capability for a tool operation.
type Grant struct {
	ID                  string                         `json:"id"`
	Status              GrantStatus                    `json:"status"`
	Lane                accessplane.Lane               `json:"lane"`
	ToolFamily          string                         `json:"tool_family"`
	LogicalAction       string                         `json:"logical_action"`
	Target              string                         `json:"target"`
	Scope               string                         `json:"scope"`
	SessionID           string                         `json:"session_id"`
	RunnerID            string                         `json:"runner_id"`
	TurnID              string                         `json:"turn_id"`
	WorkloadKey         string                         `json:"workload_key"`
	Actor               accessplane.ActorContext        `json:"actor"`
	ReasonCode          string                         `json:"reason_code"`
	ImplementationState accessplane.ImplementationState `json:"implementation_state"`
	CredentialRef       string                         `json:"credential_ref,omitempty"`
	ExpiresAt           time.Time                      `json:"expires_at"`
	RevokedAt           *time.Time                     `json:"revoked_at,omitempty"`
	CreatedAt           time.Time                      `json:"created_at"`
	UpdatedAt           time.Time                      `json:"updated_at"`
}

// ProjectedFile represents a file projected into the runner filesystem.
type ProjectedFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    int    `json:"mode"`
}

// ExchangeConstraints limits how a helper session credential can be used.
type ExchangeConstraints struct {
	MaxExchanges int           `json:"max_exchanges"`
	TTL          time.Duration `json:"ttl"`
}

// HelperSession represents an active credential helper session.
type HelperSession struct {
	ID                  string              `json:"id"`
	GrantID             string              `json:"grant_id"`
	ToolFamily          string              `json:"tool_family"`
	Format              string              `json:"format"`
	Files               []ProjectedFile     `json:"files"`
	Env                 map[string]string   `json:"env"`
	ExchangeConstraints *ExchangeConstraints `json:"exchange_constraints,omitempty"`
	CreatedAt           time.Time           `json:"created_at"`
}
