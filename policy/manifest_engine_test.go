package policy

import (
	"strings"
	"testing"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
)

func testRegistry(t *testing.T) manifest.Registry {
	t.Helper()
	reg := manifest.NewInMemoryRegistry()
	loader := &manifest.YAMLLoader{}
	if err := manifest.LoadAllFamilies(loader, reg); err != nil {
		t.Fatalf("failed to load families: %v", err)
	}
	return reg
}

func TestManifestEngine_GithubRestRead(t *testing.T) {
	engine := NewManifestBasedEngine(testRegistry(t))

	decision, err := engine.Evaluate(PolicyInput{
		Actor:         ActorContext{UserID: "user-1"},
		ToolFamily:    "github_rest",
		LogicalAction: "read_repo",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != DecisionAllow {
		t.Errorf("decision = %q, want allow", decision.Decision)
	}
	if decision.SelectedLane != accessplane.LaneDirectHTTP {
		t.Errorf("lane = %q, want direct_http", decision.SelectedLane)
	}
}

func TestManifestEngine_InternalAdminCli(t *testing.T) {
	engine := NewManifestBasedEngine(testRegistry(t))

	decision, err := engine.Evaluate(PolicyInput{
		Actor:         ActorContext{UserID: "user-1"},
		ToolFamily:    "internal_admin_cli",
		LogicalAction: "rotate_secrets",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != DecisionAllow {
		t.Errorf("decision = %q, want allow", decision.Decision)
	}
	if decision.SelectedLane != accessplane.LaneRemoteExecution {
		t.Errorf("lane = %q, want remote_execution", decision.SelectedLane)
	}
	if !decision.ApprovalRequired {
		t.Error("expected approval_required = true")
	}
}

func TestManifestEngine_Kubectl(t *testing.T) {
	engine := NewManifestBasedEngine(testRegistry(t))

	decision, err := engine.Evaluate(PolicyInput{
		Actor:         ActorContext{UserID: "user-1"},
		ToolFamily:    "kubectl",
		LogicalAction: "get_pods",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != DecisionAllow {
		t.Errorf("decision = %q, want allow", decision.Decision)
	}
	if decision.SelectedLane != accessplane.LaneRemoteExecution {
		t.Errorf("lane = %q, want remote_execution", decision.SelectedLane)
	}
}

func TestManifestEngine_UnknownFamily(t *testing.T) {
	engine := NewManifestBasedEngine(testRegistry(t))

	decision, err := engine.Evaluate(PolicyInput{
		Actor:      ActorContext{UserID: "user-1"},
		ToolFamily: "nonexistent",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != DecisionDeny {
		t.Errorf("decision = %q, want deny", decision.Decision)
	}
	if !strings.Contains(decision.Reason, "unknown tool family") {
		t.Errorf("reason = %q, want 'unknown tool family'", decision.Reason)
	}
}

func TestManifestEngine_MissingActor(t *testing.T) {
	engine := NewManifestBasedEngine(testRegistry(t))

	decision, err := engine.Evaluate(PolicyInput{
		Actor:      ActorContext{UserID: ""},
		ToolFamily: "github_rest",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != DecisionDeny {
		t.Errorf("decision = %q, want deny", decision.Decision)
	}
	if !strings.Contains(decision.Reason, "missing actor") {
		t.Errorf("reason = %q, want 'missing actor'", decision.Reason)
	}
}

func TestManifestEngine_RiskClassFromLogicalAction(t *testing.T) {
	engine := NewManifestBasedEngine(testRegistry(t))

	decision, err := engine.Evaluate(PolicyInput{
		Actor:         ActorContext{UserID: "user-1"},
		ToolFamily:    "github_rest",
		LogicalAction: "read_repo",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != DecisionAllow {
		t.Errorf("decision = %q, want allow", decision.Decision)
	}
	if decision.SelectedLane != accessplane.LaneDirectHTTP {
		t.Errorf("lane = %q, want direct_http", decision.SelectedLane)
	}
}

func TestManifestEngine_DeferredLaneNeverDowngrades(t *testing.T) {
	engine := NewManifestBasedEngine(testRegistry(t))

	decision, err := engine.Evaluate(PolicyInput{
		Actor:         ActorContext{UserID: "user-1"},
		ToolFamily:    "internal_admin_cli",
		LogicalAction: "rotate_secrets",
		ImplementationAvailability: map[accessplane.Lane]accessplane.ImplementationState{
			accessplane.LaneRemoteExecution: accessplane.StateImplementationDeferred,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != DecisionAllow {
		t.Fatalf("decision = %q, want allow", decision.Decision)
	}
	if decision.SelectedLane != accessplane.LaneRemoteExecution {
		t.Fatalf("SAFETY: lane = %q, want remote_execution (no downgrade)", decision.SelectedLane)
	}
	if decision.ImplementationState != accessplane.StateImplementationDeferred {
		t.Errorf("impl_state = %q, want implementation_deferred", decision.ImplementationState)
	}
	if decision.SelectedLane == accessplane.LaneHelperSession {
		t.Fatal("SAFETY VIOLATION: fell back to helper_session")
	}
	if decision.SelectedLane == accessplane.LaneDirectHTTP {
		t.Fatal("SAFETY VIOLATION: fell back to direct_http")
	}
}

func TestManifestEngine_ImplementationAvailability(t *testing.T) {
	engine := NewManifestBasedEngine(testRegistry(t))

	decision, err := engine.Evaluate(PolicyInput{
		Actor:         ActorContext{UserID: "user-1"},
		ToolFamily:    "github_rest",
		LogicalAction: "read_repo",
		ImplementationAvailability: map[accessplane.Lane]accessplane.ImplementationState{
			accessplane.LaneDirectHTTP: accessplane.StateImplementationDeferred,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != DecisionAllow {
		t.Errorf("decision = %q, want allow", decision.Decision)
	}
	if decision.SelectedLane != accessplane.LaneDirectHTTP {
		t.Errorf("lane = %q, want direct_http", decision.SelectedLane)
	}
	if decision.ImplementationState != accessplane.StateImplementationDeferred {
		t.Errorf("impl_state = %q, want implementation_deferred", decision.ImplementationState)
	}
}
