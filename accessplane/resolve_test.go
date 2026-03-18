package accessplane

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestResolveOperationResponseJSONRoundTrip(t *testing.T) {
	orig := ResolveOperationResponse{
		Decision:            DecisionAllow,
		SelectedLane:        LaneDirectHTTP,
		DecisionReason:      "policy allows read on http_api",
		GrantID:             "grant-abc-123",
		ProjectionRef:       "proj-ref-456",
		ApprovalStatus:      "auto_approved",
		ImplementationState: StateImplemented,
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded ResolveOperationResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Decision != orig.Decision {
		t.Errorf("Decision = %q, want %q", decoded.Decision, orig.Decision)
	}
	if decoded.SelectedLane != orig.SelectedLane {
		t.Errorf("SelectedLane = %q, want %q", decoded.SelectedLane, orig.SelectedLane)
	}
	if decoded.DecisionReason != orig.DecisionReason {
		t.Errorf("DecisionReason = %q, want %q", decoded.DecisionReason, orig.DecisionReason)
	}
	if decoded.GrantID != orig.GrantID {
		t.Errorf("GrantID = %q, want %q", decoded.GrantID, orig.GrantID)
	}
	if decoded.ProjectionRef != orig.ProjectionRef {
		t.Errorf("ProjectionRef = %q, want %q", decoded.ProjectionRef, orig.ProjectionRef)
	}
	if decoded.ApprovalStatus != orig.ApprovalStatus {
		t.Errorf("ApprovalStatus = %q, want %q", decoded.ApprovalStatus, orig.ApprovalStatus)
	}
	if decoded.ImplementationState != orig.ImplementationState {
		t.Errorf("ImplementationState = %q, want %q", decoded.ImplementationState, orig.ImplementationState)
	}
}

func TestResolveOperationResponseOmitsEmptyOptionalFields(t *testing.T) {
	resp := ResolveOperationResponse{
		Decision:            DecisionDeny,
		SelectedLane:        "",
		DecisionReason:      "denied by policy",
		ImplementationState: "",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map error: %v", err)
	}

	// grant_id and projection_ref should be omitted when empty (omitempty tag).
	if _, exists := raw["grant_id"]; exists {
		t.Error("grant_id should be omitted when empty")
	}
	if _, exists := raw["projection_ref"]; exists {
		t.Error("projection_ref should be omitted when empty")
	}
}

func TestDeniedErrorJSONRoundTrip(t *testing.T) {
	orig := &DeniedError{
		Lane:   LaneRemoteExecution,
		Family: "cli_tool",
		Reason: "user not authorized for cli_tool operations",
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	// Verify the type discriminator is present.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map error: %v", err)
	}
	if raw["type"] != "denied" {
		t.Errorf("type = %q, want %q", raw["type"], "denied")
	}

	// Verify fields round-trip.
	if raw["family"] != "cli_tool" {
		t.Errorf("family = %v, want %q", raw["family"], "cli_tool")
	}
	if raw["reason"] != "user not authorized for cli_tool operations" {
		t.Errorf("reason = %v, want %q", raw["reason"], "user not authorized for cli_tool operations")
	}
	if raw["lane"] != string(LaneRemoteExecution) {
		t.Errorf("lane = %v, want %q", raw["lane"], LaneRemoteExecution)
	}

	// Verify Error() string is deterministic.
	errStr := orig.Error()
	if errStr != "denied: family=cli_tool reason=user not authorized for cli_tool operations" {
		t.Errorf("Error() = %q", errStr)
	}
}

func TestDeferredErrorJSONRoundTrip(t *testing.T) {
	orig := &DeferredError{
		Lane:   LaneRemoteExecution,
		Family: "remote_only_tool",
		Reason: "remote_execution not yet implemented",
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map error: %v", err)
	}
	if raw["type"] != "deferred" {
		t.Errorf("type = %q, want %q", raw["type"], "deferred")
	}
	if raw["lane"] != string(LaneRemoteExecution) {
		t.Errorf("lane = %v, want %q", raw["lane"], LaneRemoteExecution)
	}
	if raw["family"] != "remote_only_tool" {
		t.Errorf("family = %v, want %q", raw["family"], "remote_only_tool")
	}
	if raw["reason"] != "remote_execution not yet implemented" {
		t.Errorf("reason = %v, want %q", raw["reason"], "remote_execution not yet implemented")
	}

	errStr := orig.Error()
	if errStr != "deferred: family=remote_only_tool lane=remote_execution reason=remote_execution not yet implemented" {
		t.Errorf("Error() = %q", errStr)
	}
}

func TestUnsupportedErrorJSONRoundTrip(t *testing.T) {
	orig := &UnsupportedError{
		Lane:   LaneHelperSession,
		Family: "exotic_tool",
		Reason: "helper_session not available in phase 1",
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map error: %v", err)
	}
	if raw["type"] != "unsupported" {
		t.Errorf("type = %q, want %q", raw["type"], "unsupported")
	}
	if raw["lane"] != string(LaneHelperSession) {
		t.Errorf("lane = %v, want %q", raw["lane"], LaneHelperSession)
	}
	if raw["family"] != "exotic_tool" {
		t.Errorf("family = %v, want %q", raw["family"], "exotic_tool")
	}

	errStr := orig.Error()
	if errStr != "unsupported: family=exotic_tool reason=helper_session not available in phase 1" {
		t.Errorf("Error() = %q", errStr)
	}
}

func TestTypedErrorsCanBeDistinguished(t *testing.T) {
	errs := []error{
		&DeniedError{Family: "a", Reason: "denied"},
		&DeferredError{Lane: LaneRemoteExecution, Family: "b", Reason: "deferred"},
		&UnsupportedError{Family: "c", Reason: "unsupported"},
	}

	// Each error should match exactly one type via errors.As.
	for i, err := range errs {
		var denied *DeniedError
		var deferred *DeferredError
		var unsupported *UnsupportedError

		isDenied := errors.As(err, &denied)
		isDeferred := errors.As(err, &deferred)
		isUnsupported := errors.As(err, &unsupported)

		matchCount := 0
		if isDenied {
			matchCount++
		}
		if isDeferred {
			matchCount++
		}
		if isUnsupported {
			matchCount++
		}

		if matchCount != 1 {
			t.Errorf("error[%d] matched %d types, want exactly 1", i, matchCount)
		}

		switch i {
		case 0:
			if !isDenied {
				t.Errorf("error[0] should be DeniedError")
			}
		case 1:
			if !isDeferred {
				t.Errorf("error[1] should be DeferredError")
			}
		case 2:
			if !isUnsupported {
				t.Errorf("error[2] should be UnsupportedError")
			}
		}
	}
}
