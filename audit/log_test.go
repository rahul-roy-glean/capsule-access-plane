package audit

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
)

func TestLogResolveDecision(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	event := AuditEvent{
		ActorUser:       "alice",
		VirtualIdentity: "vi-1",
		AgentID:         "agent-42",
		SessionID:       "sess-1",
		RunnerID:        "runner-1",
		TurnID:          "turn-1",
		ToolFamily:      "github_rest",
		LogicalAction:   "read",
		SelectedLane:    accessplane.LaneDirectHTTP,
		Decision:        accessplane.DecisionAllow,
		Target:          "repos/foo/bar",
		Result:          "ok",
		ReasonCode:      "manifest_match",
	}

	LogResolveDecision(logger, event)

	out := buf.String()
	for _, want := range []string{
		"resolve_decision",
		"alice",
		"vi-1",
		"agent-42",
		"sess-1",
		"runner-1",
		"turn-1",
		"github_rest",
		"read",
		"repos/foo/bar",
		"manifest_match",
	} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("log output missing %q\ngot: %s", want, out)
		}
	}
}

func TestLogExecuteOperation(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	event := AuditEvent{
		SessionID:          "sess-3",
		RunnerID:           "runner-3",
		TurnID:             "turn-3",
		ToolFamily:         "github_rest",
		Target:             "https://api.github.com/repos/foo/bar",
		Result:             "status_200",
		RuntimeCorrelation: "exec-sess-3-turn-3-1234",
		Duration:           42000000, // 42ms
	}

	LogExecuteOperation(logger, event)

	out := buf.String()
	for _, want := range []string{
		"execute_operation",
		"sess-3",
		"runner-3",
		"turn-3",
		"github_rest",
		"api.github.com",
		"status_200",
		"exec-sess-3-turn-3-1234",
	} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("log output missing %q\ngot: %s", want, out)
		}
	}
}

func TestLogGrantOperation(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	event := AuditEvent{
		ActorUser:          "bob",
		SessionID:          "sess-2",
		RunnerID:           "runner-2",
		TurnID:             "turn-2",
		ToolFamily:         "github_rest",
		SelectedLane:       accessplane.LaneDirectHTTP,
		Target:             "repos/x/y",
		Result:             "granted",
		ReasonCode:         "policy_ok",
		RuntimeCorrelation: "corr-123",
	}

	LogGrantOperation(logger, "project_grant", event)

	out := buf.String()
	for _, want := range []string{
		"grant_operation",
		"project_grant",
		"bob",
		"sess-2",
		"runner-2",
		"corr-123",
	} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("log output missing %q\ngot: %s", want, out)
		}
	}
}
