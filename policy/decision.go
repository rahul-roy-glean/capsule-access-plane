package policy

import "github.com/rahul-roy-glean/capsule-access-plane/accessplane"

// Decision is an alias for accessplane.Decision for convenience.
type Decision = accessplane.Decision

const (
	DecisionAllow = accessplane.DecisionAllow
	DecisionDeny  = accessplane.DecisionDeny
)

// PolicyDecision is the result of a policy engine evaluation.
type PolicyDecision struct {
	Decision            Decision                        `json:"decision"`
	SelectedLane        accessplane.Lane                `json:"selected_lane"`
	Reason              string                          `json:"reason"`
	ApprovalRequired    bool                            `json:"approval_required"`
	ImplementationState accessplane.ImplementationState `json:"implementation_state"`
}
