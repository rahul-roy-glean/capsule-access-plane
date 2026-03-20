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

// LogExecuteOperation emits a structured log record for a remote execution operation.
func LogExecuteOperation(logger *slog.Logger, event AuditEvent) {
	logger.Info("execute_operation",
		"actor_user", event.ActorUser,
		"session_id", event.SessionID,
		"runner_id", event.RunnerID,
		"turn_id", event.TurnID,
		"tool_family", event.ToolFamily,
		"target", event.Target,
		"result", event.Result,
		"reason_code", event.ReasonCode,
		"runtime_correlation", event.RuntimeCorrelation,
		"duration", event.Duration,
	)
}

// LogGrantOperation emits a structured log record for a grant lifecycle event.
func LogGrantOperation(logger *slog.Logger, operation string, event AuditEvent) {
	logger.Info("grant_operation",
		"operation", operation,
		"actor_user", event.ActorUser,
		"session_id", event.SessionID,
		"runner_id", event.RunnerID,
		"turn_id", event.TurnID,
		"tool_family", event.ToolFamily,
		"selected_lane", event.SelectedLane,
		"target", event.Target,
		"result", event.Result,
		"reason_code", event.ReasonCode,
		"runtime_correlation", event.RuntimeCorrelation,
	)
}

// LogProxyOperation emits a structured log record for a proxy (CONNECT/SSL bump) event.
func LogProxyOperation(logger *slog.Logger, event AuditEvent) {
	logger.Info("proxy_operation",
		"session_id", event.SessionID,
		"runner_id", event.RunnerID,
		"tool_family", event.ToolFamily,
		"target", event.Target,
		"result", event.Result,
		"reason_code", event.ReasonCode,
		"duration", event.Duration,
	)
}
