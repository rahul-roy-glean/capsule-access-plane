package accessplane

// RunnerEventType identifies the kind of runner lifecycle event.
type RunnerEventType string

const (
	EventRunnerAllocated        RunnerEventType = "runner_allocated"
	EventRunnerReleased         RunnerEventType = "runner_released"
	EventSessionPaused          RunnerEventType = "session_paused"
	EventSessionResumed         RunnerEventType = "session_resumed"
	EventSessionForked          RunnerEventType = "session_forked"
	EventHostDraining           RunnerEventType = "host_draining"
	EventGrantProjectionRemoved RunnerEventType = "grant_projection_removed"
)
