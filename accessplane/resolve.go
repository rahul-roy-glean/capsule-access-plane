package accessplane

// ActorContext identifies the human and agent involved in an operation.
type ActorContext struct {
	UserID          string `json:"user_id"`
	VirtualIdentity string `json:"virtual_identity,omitempty"`
	AgentID         string `json:"agent_id,omitempty"`
}

// ResolveOperationRequest is the input to the ResolveOperation contract.
type ResolveOperationRequest struct {
	Actor                 ActorContext     `json:"actor"`
	Runner                RunnerContext    `json:"runner"`
	ToolFamily            string           `json:"tool_family"`
	LogicalAction         string           `json:"logical_action"`
	Target                TargetDescriptor `json:"target"`
	RequestedScope        string           `json:"requested_scope"`
	LocalFidelityRequired bool             `json:"local_fidelity_required"`
	WriteIntent           bool             `json:"write_intent"`
	RiskHint              string           `json:"risk_hint,omitempty"`
}

// RunnerContext identifies the calling runner session.
type RunnerContext struct {
	SessionID string `json:"session_id"`
	RunnerID  string `json:"runner_id"`
	TurnID    string `json:"turn_id"`
}

// TargetDescriptor is a flexible target identification structure.
type TargetDescriptor struct {
	Resource  string            `json:"resource,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// Decision represents the allow/deny outcome of a policy evaluation.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

// ResolveOperationResponse is the output of the ResolveOperation contract.
type ResolveOperationResponse struct {
	Decision            Decision            `json:"decision"`
	SelectedLane        Lane                `json:"selected_lane"`
	DecisionReason      string              `json:"decision_reason"`
	GrantID             string              `json:"grant_id,omitempty"`
	ProjectionRef       string              `json:"projection_ref,omitempty"`
	ApprovalStatus      string              `json:"approval_status,omitempty"`
	ImplementationState ImplementationState `json:"implementation_state"`
}
