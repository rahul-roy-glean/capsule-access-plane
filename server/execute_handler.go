package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/rahul-roy-glean/capsule-access-plane/audit"
	"github.com/rahul-roy-glean/capsule-access-plane/grants"
	"github.com/rahul-roy-glean/capsule-access-plane/identity"
	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
	"github.com/rahul-roy-glean/capsule-access-plane/policy"
)

const maxResponseBody = 10 << 20 // 10 MB

// ExecuteHandler implements the POST /v1/execute/http endpoint.
type ExecuteHandler struct {
	verifier      identity.Verifier
	registry      manifest.Registry
	engine        policy.PolicyEngine
	credResolver  *grants.CredentialResolver
	credentialRef string
	logger        *slog.Logger
}

// NewExecuteHandler creates a handler for the remote broker execution endpoint.
func NewExecuteHandler(
	verifier identity.Verifier,
	registry manifest.Registry,
	engine policy.PolicyEngine,
	credResolver *grants.CredentialResolver,
	credentialRef string,
	logger *slog.Logger,
) *ExecuteHandler {
	return &ExecuteHandler{
		verifier:      verifier,
		registry:      registry,
		engine:        engine,
		credResolver:  credResolver,
		credentialRef: credentialRef,
		logger:        logger,
	}
}

// ServeHTTP handles the execute/http request.
func (h *ExecuteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Step 1: Authenticate
	claims, ok := h.authenticate(w, r)
	if !ok {
		return
	}

	// Step 2: Decode request body
	var req accessplane.ExecuteHTTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body: " + err.Error(),
		})
		return
	}

	// Step 3: Validate runner context matches token claims
	if req.RunnerID != claims.RunnerID || req.SessionID != claims.SessionID {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "runner context does not match attestation token",
		})
		return
	}

	// Step 4: Look up tool family manifest
	m, err := h.registry.Get(req.ToolFamily)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "unknown tool family: " + req.ToolFamily,
		})
		return
	}

	// Step 5: Validate destination host
	targetHost := manifest.ExtractHost(req.URL)
	if targetHost == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid target URL",
		})
		return
	}

	allowedHosts := manifest.BuildAllowedHosts(m.Destinations)
	if !allowedHosts[targetHost] {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": fmt.Sprintf("destination %s not allowed by manifest", targetHost),
		})
		return
	}

	// Step 6: Validate method constraints
	if len(m.MethodConstraints) > 0 {
		if !manifest.IsMethodAllowed(req.Method, m.MethodConstraints) {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
				"error": fmt.Sprintf("method %s not allowed by manifest", req.Method),
			})
			return
		}
	}

	// Step 7: Evaluate policy
	policyInput := policy.PolicyInput{
		Actor:      policy.ActorContext{UserID: claims.RunnerID},
		ToolFamily: req.ToolFamily,
	}
	decision, err := h.engine.Evaluate(policyInput)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "policy evaluation error: " + err.Error(),
		})
		return
	}
	if decision.Decision == accessplane.DecisionDeny {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "policy denied: " + decision.Reason,
		})
		return
	}

	// Step 8: Resolve credential
	credential, err := h.credResolver.Resolve(r.Context(), h.credentialRef)
	if err != nil {
		h.logger.Error("credential resolution failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "credential resolution failed",
		})
		return
	}

	// Step 9: Make outbound HTTP call
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	outReq, err := http.NewRequestWithContext(r.Context(), req.Method, req.URL, bodyReader)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "failed to create outbound request: " + err.Error(),
		})
		return
	}

	// Copy caller-specified headers.
	for k, v := range req.Headers {
		outReq.Header.Set(k, v)
	}

	// Inject credential.
	outReq.Header.Set("Authorization", "Bearer "+credential)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(outReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": "outbound request failed: " + err.Error(),
		})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Step 10: Read response body (capped at maxResponseBody)
	limitedBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": "failed to read response body: " + err.Error(),
		})
		return
	}

	// Build response headers map.
	respHeaders := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		respHeaders[k] = resp.Header.Get(k)
	}

	correlationID := fmt.Sprintf("exec-%s-%s-%d", req.SessionID, req.TurnID, start.UnixMilli())

	// Step 11: Audit log
	audit.LogExecuteOperation(h.logger, audit.AuditEvent{
		SessionID:          req.SessionID,
		RunnerID:           req.RunnerID,
		TurnID:             req.TurnID,
		ToolFamily:         req.ToolFamily,
		Target:             req.URL,
		Result:             fmt.Sprintf("status_%d", resp.StatusCode),
		RuntimeCorrelation: correlationID,
		Duration:           time.Since(start),
	})

	// Step 12: Return response
	writeJSON(w, http.StatusOK, accessplane.ExecuteHTTPResponse{
		StatusCode:         resp.StatusCode,
		Headers:            respHeaders,
		Body:               string(limitedBody),
		AuditCorrelationID: correlationID,
	})
}

// authenticate extracts and verifies the bearer token from the request.
func (h *ExecuteHandler) authenticate(w http.ResponseWriter, r *http.Request) (*identity.Claims, bool) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "missing or invalid Authorization header",
		})
		return nil, false
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	claims, err := h.verifier.Verify(token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "invalid attestation token: " + err.Error(),
		})
		return nil, false
	}

	return claims, true
}
