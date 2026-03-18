package accessplane

// ExecuteHTTPRequest is the input to the POST /v1/execute/http endpoint.
type ExecuteHTTPRequest struct {
	RunnerID   string            `json:"runner_id"`
	SessionID  string            `json:"session_id"`
	TurnID     string            `json:"turn_id"`
	ToolFamily string            `json:"tool_family"`
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
}

// ExecuteHTTPResponse is the output of the POST /v1/execute/http endpoint.
type ExecuteHTTPResponse struct {
	StatusCode         int               `json:"status_code"`
	Headers            map[string]string `json:"headers,omitempty"`
	Body               string            `json:"body"`
	AuditCorrelationID string            `json:"audit_correlation_id"`
}
