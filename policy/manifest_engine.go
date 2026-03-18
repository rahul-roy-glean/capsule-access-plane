package policy

import (
	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
)

// ManifestBasedEngine evaluates policy using the manifest registry.
type ManifestBasedEngine struct {
	registry manifest.Registry
}

// NewManifestBasedEngine creates a policy engine backed by the given manifest registry.
func NewManifestBasedEngine(registry manifest.Registry) *ManifestBasedEngine {
	return &ManifestBasedEngine{registry: registry}
}

// Evaluate applies policy rules to produce an allow/deny decision with lane selection.
func (e *ManifestBasedEngine) Evaluate(input PolicyInput) (*PolicyDecision, error) {
	// Rule 1: missing actor → deny
	if input.Actor.UserID == "" {
		return &PolicyDecision{
			Decision: DecisionDeny,
			Reason:   "missing actor: UserID is required",
		}, nil
	}

	// Rule 2: registry lookup
	m, err := e.registry.Get(input.ToolFamily)
	if err != nil {
		return &PolicyDecision{
			Decision: DecisionDeny,
			Reason:   "unknown tool family: " + input.ToolFamily,
		}, nil
	}

	// Rule 3: resolve risk class
	riskClass := input.RiskClass
	if riskClass == "" && input.LogicalAction != "" {
		for _, la := range m.LogicalActions {
			if la.Name == input.LogicalAction {
				riskClass = la.RiskClass
				break
			}
		}
	}

	// Rule 4: select lane
	var selectedLane accessplane.Lane

	if preferred, ok := m.PreferredLane[riskClass]; ok {
		selectedLane = preferred
	} else if preferred, ok := m.PreferredLane["default"]; ok {
		selectedLane = preferred
	} else if len(m.SupportedLanes) > 0 {
		selectedLane = m.SupportedLanes[0]
	} else {
		return &PolicyDecision{
			Decision: DecisionDeny,
			Reason:   "no supported lanes for family: " + input.ToolFamily,
		}, nil
	}

	// Rule 5: approval check
	approvalRequired := m.ExecutionHints != nil && m.ExecutionHints["require_approval"] == "true"

	// Rule 6: implementation availability — NEVER fall back to a different lane
	implState := accessplane.StateImplemented
	if input.ImplementationAvailability != nil {
		if state, exists := input.ImplementationAvailability[selectedLane]; exists {
			implState = state
		}
	}

	return &PolicyDecision{
		Decision:            DecisionAllow,
		SelectedLane:        selectedLane,
		Reason:              "policy allows operation",
		ApprovalRequired:    approvalRequired,
		ImplementationState: implState,
	}, nil
}
