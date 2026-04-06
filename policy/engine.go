package policy

import "github.com/rahul-roy-glean/capsule-access-plane/accessplane"

// PolicyEngine evaluates policy for tool operations.
type PolicyEngine interface {
	Evaluate(input PolicyInput) (*PolicyDecision, error)
}

// PolicyInput contains all context needed for a policy decision.
type PolicyInput struct {
	Actor                      ActorContext                                         `json:"actor"`
	ToolFamily                 string                                               `json:"tool_family"`
	LogicalAction              string                                               `json:"logical_action"`
	RiskClass                  string                                               `json:"risk_class"`
	Target                     accessplane.TargetDescriptor                         `json:"target"`
	LocalFidelityRequired      bool                                                 `json:"local_fidelity_required"`
	Environment                string                                               `json:"environment"`
	ImplementationAvailability map[accessplane.Lane]accessplane.ImplementationState `json:"implementation_availability"`
}
