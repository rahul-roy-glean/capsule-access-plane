package audit

import (
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
)

// AuditEvent records a complete audit trail entry for a tool operation.
type AuditEvent struct {
	ActorUser          string               `json:"actor_user"`
	VirtualIdentity    string               `json:"virtual_identity,omitempty"`
	IdentityMode       string               `json:"identity_mode,omitempty"`
	AgentID            string               `json:"agent_id,omitempty"`
	SessionID          string               `json:"session_id"`
	RunnerID           string               `json:"runner_id"`
	TurnID             string               `json:"turn_id"`
	ToolFamily         string               `json:"tool_family"`
	LogicalAction      string               `json:"logical_action"`
	SelectedLane       accessplane.Lane     `json:"selected_lane"`
	Decision           accessplane.Decision `json:"decision"`
	Target             string               `json:"target"`
	Result             string               `json:"result"`
	Duration           time.Duration        `json:"duration"`
	ReasonCode         string               `json:"reason_code"`
	RuntimeCorrelation string               `json:"runtime_correlation,omitempty"`
}
