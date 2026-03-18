package policy

import (
	"testing"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
)

// TestDeferredLaneNeverDowngrades is a CRITICAL safety test.
// It verifies that when a family supports ONLY remote_execution and that lane
// is implementation_deferred, the engine returns remote_execution + deferred
// and NEVER falls back to helper_session or direct_http.
func TestDeferredLaneNeverDowngrades(t *testing.T) {
	engine := &stubPolicyEngine{
		families: map[string]stubFamilyConfig{
			"remote_only_tool": {
				supportedLanes: []accessplane.Lane{accessplane.LaneRemoteExecution},
				preferredLane: map[string]accessplane.Lane{
					"low":    accessplane.LaneRemoteExecution,
					"medium": accessplane.LaneRemoteExecution,
					"high":   accessplane.LaneRemoteExecution,
				},
			},
		},
	}

	input := PolicyInput{
		Actor:         ActorContext{UserID: "user-1"},
		ToolFamily:    "remote_only_tool",
		LogicalAction: "execute",
		RiskClass:     "medium",
		ImplementationAvailability: map[accessplane.Lane]accessplane.ImplementationState{
			accessplane.LaneRemoteExecution: accessplane.StateImplementationDeferred,
		},
	}

	decision, err := engine.Evaluate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Must be allowed (the policy permits the operation).
	if decision.Decision != DecisionAllow {
		t.Fatalf("decision = %q, want %q", decision.Decision, DecisionAllow)
	}

	// Must select remote_execution — the only supported lane.
	if decision.SelectedLane != accessplane.LaneRemoteExecution {
		t.Errorf("selected_lane = %q, want %q", decision.SelectedLane, accessplane.LaneRemoteExecution)
	}

	// Must report implementation_deferred, NOT implemented.
	if decision.ImplementationState != accessplane.StateImplementationDeferred {
		t.Errorf("implementation_state = %q, want %q", decision.ImplementationState, accessplane.StateImplementationDeferred)
	}

	// SAFETY: must NOT have fallen back to helper_session or direct_http.
	if decision.SelectedLane == accessplane.LaneHelperSession {
		t.Fatal("SAFETY VIOLATION: engine fell back to helper_session instead of keeping remote_execution")
	}
	if decision.SelectedLane == accessplane.LaneDirectHTTP {
		t.Fatal("SAFETY VIOLATION: engine fell back to direct_http instead of keeping remote_execution")
	}

	// Verify a DeferredError can be constructed from the decision fields.
	deferredErr := &accessplane.DeferredError{
		Lane:   decision.SelectedLane,
		Family: input.ToolFamily,
		Reason: "remote_execution not yet implemented",
	}
	if deferredErr.Lane != accessplane.LaneRemoteExecution {
		t.Errorf("DeferredError.Lane = %q, want %q", deferredErr.Lane, accessplane.LaneRemoteExecution)
	}
	if deferredErr.Family != "remote_only_tool" {
		t.Errorf("DeferredError.Family = %q, want %q", deferredErr.Family, "remote_only_tool")
	}
}

// TestDeferredLaneAcrossRiskClasses ensures the no-downgrade rule holds for
// every risk class, not just a single one.
func TestDeferredLaneAcrossRiskClasses(t *testing.T) {
	engine := &stubPolicyEngine{
		families: map[string]stubFamilyConfig{
			"remote_only_tool": {
				supportedLanes: []accessplane.Lane{accessplane.LaneRemoteExecution},
				preferredLane: map[string]accessplane.Lane{
					"low":    accessplane.LaneRemoteExecution,
					"medium": accessplane.LaneRemoteExecution,
					"high":   accessplane.LaneRemoteExecution,
				},
			},
		},
	}

	for _, riskClass := range []string{"low", "medium", "high"} {
		t.Run("risk_class_"+riskClass, func(t *testing.T) {
			input := PolicyInput{
				Actor:         ActorContext{UserID: "user-1"},
				ToolFamily:    "remote_only_tool",
				LogicalAction: "execute",
				RiskClass:     riskClass,
				ImplementationAvailability: map[accessplane.Lane]accessplane.ImplementationState{
					accessplane.LaneRemoteExecution: accessplane.StateImplementationDeferred,
				},
			}

			decision, err := engine.Evaluate(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if decision.SelectedLane != accessplane.LaneRemoteExecution {
				t.Errorf("risk_class=%s: selected_lane = %q, want %q",
					riskClass, decision.SelectedLane, accessplane.LaneRemoteExecution)
			}
			if decision.ImplementationState != accessplane.StateImplementationDeferred {
				t.Errorf("risk_class=%s: implementation_state = %q, want %q",
					riskClass, decision.ImplementationState, accessplane.StateImplementationDeferred)
			}
		})
	}
}
