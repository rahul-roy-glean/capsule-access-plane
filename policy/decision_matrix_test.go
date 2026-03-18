package policy

import (
	"strings"
	"testing"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
)

// stubFamilyConfig holds simplified manifest data for the stub engine.
type stubFamilyConfig struct {
	supportedLanes []accessplane.Lane
	preferredLane  map[string]accessplane.Lane // risk_class → lane
}

// stubPolicyEngine is a test-only PolicyEngine that uses hardcoded family
// configs to select lanes without needing the full manifest loader.
type stubPolicyEngine struct {
	families map[string]stubFamilyConfig
}

func (s *stubPolicyEngine) Evaluate(input PolicyInput) (*PolicyDecision, error) {
	// Rule 1: missing actor → deny
	if input.Actor.UserID == "" {
		return &PolicyDecision{
			Decision: DecisionDeny,
			Reason:   "missing actor: UserID is required",
		}, nil
	}

	// Rule 2: unknown family → deny
	fam, ok := s.families[input.ToolFamily]
	if !ok {
		return &PolicyDecision{
			Decision: DecisionDeny,
			Reason:   "unknown tool family: " + input.ToolFamily,
		}, nil
	}

	// Rule 3: select preferred lane for the risk class, falling back to first supported lane.
	var selectedLane accessplane.Lane
	if preferred, ok := fam.preferredLane[input.RiskClass]; ok {
		selectedLane = preferred
	} else if len(fam.supportedLanes) > 0 {
		selectedLane = fam.supportedLanes[0]
	} else {
		return &PolicyDecision{
			Decision: DecisionDeny,
			Reason:   "no supported lanes for family: " + input.ToolFamily,
		}, nil
	}

	// Rule 4: check implementation availability for the selected lane.
	// NEVER fall back to a different lane.
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
		ImplementationState: implState,
	}, nil
}

func TestDecisionMatrix(t *testing.T) {
	engine := &stubPolicyEngine{
		families: map[string]stubFamilyConfig{
			"http_api": {
				supportedLanes: []accessplane.Lane{accessplane.LaneDirectHTTP, accessplane.LaneRemoteExecution},
				preferredLane: map[string]accessplane.Lane{
					"low":    accessplane.LaneDirectHTTP,
					"medium": accessplane.LaneDirectHTTP,
					"high":   accessplane.LaneRemoteExecution,
				},
			},
			"cli_tool": {
				supportedLanes: []accessplane.Lane{accessplane.LaneRemoteExecution, accessplane.LaneHelperSession},
				preferredLane: map[string]accessplane.Lane{
					"low":    accessplane.LaneRemoteExecution,
					"medium": accessplane.LaneRemoteExecution,
					"high":   accessplane.LaneRemoteExecution,
				},
			},
		},
	}

	tests := []struct {
		name             string
		input            PolicyInput
		wantDecision     Decision
		wantLane         accessplane.Lane
		wantImplState    accessplane.ImplementationState
		wantDenyContains string
	}{
		{
			name: "read action on HTTP family selects direct_http",
			input: PolicyInput{
				Actor:         ActorContext{UserID: "user-1"},
				ToolFamily:    "http_api",
				LogicalAction: "read",
				RiskClass:     "low",
			},
			wantDecision:  DecisionAllow,
			wantLane:      accessplane.LaneDirectHTTP,
			wantImplState: accessplane.StateImplemented,
		},
		{
			name: "write action on CLI family selects remote_execution",
			input: PolicyInput{
				Actor:         ActorContext{UserID: "user-1"},
				ToolFamily:    "cli_tool",
				LogicalAction: "write",
				RiskClass:     "medium",
			},
			wantDecision:  DecisionAllow,
			wantLane:      accessplane.LaneRemoteExecution,
			wantImplState: accessplane.StateImplemented,
		},
		{
			name: "admin action on HTTP family selects remote_execution",
			input: PolicyInput{
				Actor:         ActorContext{UserID: "user-1"},
				ToolFamily:    "http_api",
				LogicalAction: "admin",
				RiskClass:     "high",
			},
			wantDecision:  DecisionAllow,
			wantLane:      accessplane.LaneRemoteExecution,
			wantImplState: accessplane.StateImplemented,
		},
		{
			name: "unknown family is denied",
			input: PolicyInput{
				Actor:         ActorContext{UserID: "user-1"},
				ToolFamily:    "unknown_tool",
				LogicalAction: "read",
				RiskClass:     "low",
			},
			wantDecision:     DecisionDeny,
			wantDenyContains: "unknown tool family",
		},
		{
			name: "missing actor is denied",
			input: PolicyInput{
				Actor:         ActorContext{UserID: ""},
				ToolFamily:    "http_api",
				LogicalAction: "read",
				RiskClass:     "low",
			},
			wantDecision:     DecisionDeny,
			wantDenyContains: "missing actor",
		},
		{
			name: "unknown risk class falls back to first supported lane",
			input: PolicyInput{
				Actor:         ActorContext{UserID: "user-1"},
				ToolFamily:    "cli_tool",
				LogicalAction: "custom",
				RiskClass:     "unknown_risk",
			},
			wantDecision:  DecisionAllow,
			wantLane:      accessplane.LaneRemoteExecution,
			wantImplState: accessplane.StateImplemented,
		},
		{
			name: "implementation availability is respected",
			input: PolicyInput{
				Actor:         ActorContext{UserID: "user-1"},
				ToolFamily:    "http_api",
				LogicalAction: "read",
				RiskClass:     "low",
				ImplementationAvailability: map[accessplane.Lane]accessplane.ImplementationState{
					accessplane.LaneDirectHTTP: accessplane.StateImplementationDeferred,
				},
			},
			wantDecision:  DecisionAllow,
			wantLane:      accessplane.LaneDirectHTTP,
			wantImplState: accessplane.StateImplementationDeferred,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.Evaluate(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if decision.Decision != tt.wantDecision {
				t.Errorf("decision = %q, want %q", decision.Decision, tt.wantDecision)
			}
			if tt.wantDecision == DecisionAllow {
				if decision.SelectedLane != tt.wantLane {
					t.Errorf("lane = %q, want %q", decision.SelectedLane, tt.wantLane)
				}
				if decision.ImplementationState != tt.wantImplState {
					t.Errorf("implementation_state = %q, want %q", decision.ImplementationState, tt.wantImplState)
				}
			}
			if tt.wantDenyContains != "" {
				if decision.Decision != DecisionDeny {
					t.Errorf("expected deny decision")
				}
				if !strings.Contains(decision.Reason, tt.wantDenyContains) {
					t.Errorf("reason %q does not contain %q", decision.Reason, tt.wantDenyContains)
				}
			}
		})
	}
}
