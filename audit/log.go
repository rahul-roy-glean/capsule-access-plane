package audit

import "log/slog"

// LogResolveDecision emits a structured log record for a resolve decision.
func LogResolveDecision(logger *slog.Logger, event AuditEvent) {
	logger.Info("resolve_decision",
		"actor_user", event.ActorUser,
		"virtual_identity", event.VirtualIdentity,
		"agent_id", event.AgentID,
		"session_id", event.SessionID,
		"runner_id", event.RunnerID,
		"turn_id", event.TurnID,
		"tool_family", event.ToolFamily,
		"logical_action", event.LogicalAction,
		"selected_lane", event.SelectedLane,
		"decision", event.Decision,
		"target", event.Target,
		"result", event.Result,
		"reason_code", event.ReasonCode,
	)
}
