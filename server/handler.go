package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/rahul-roy-glean/capsule-access-plane/audit"
	"github.com/rahul-roy-glean/capsule-access-plane/identity"
	"github.com/rahul-roy-glean/capsule-access-plane/policy"
)

// ResolveHandler implements the POST /v1/resolve endpoint.
type ResolveHandler struct {
	verifier         identity.Verifier
	engine           policy.PolicyEngine
	implAvailability map[accessplane.Lane]accessplane.ImplementationState
	logger           *slog.Logger
}

// NewResolveHandler creates a handler wired to the given verifier, policy engine,
// and implementation availability map.
func NewResolveHandler(
	verifier identity.Verifier,
	engine policy.PolicyEngine,
	implAvailability map[accessplane.Lane]accessplane.ImplementationState,
	logger *slog.Logger,
) *ResolveHandler {
	return &ResolveHandler{
		verifier:         verifier,
		engine:           engine,
		implAvailability: implAvailability,
		logger:           logger,
	}
}

func (h *ResolveHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Step 1: Extract bearer token
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "missing or invalid Authorization header",
		})
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Step 2: Verify token
	claims, err := h.verifier.Verify(token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "invalid attestation token: " + err.Error(),
		})
		return
	}

	// Step 3: Decode request body
	var req accessplane.ResolveOperationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body: " + err.Error(),
		})
		return
	}

	// Step 4: Validate runner context matches token claims
	if req.Runner.SessionID != claims.SessionID || req.Runner.RunnerID != claims.RunnerID {
		writeJSON(w, http.StatusForbidden, &accessplane.DeniedError{
			Family: req.ToolFamily,
			Reason: "runner context does not match attestation token",
		})
		return
	}

	// Step 5: Build policy input
	policyInput := policy.PolicyInput{
		Actor:                      req.Actor,
		ToolFamily:                 req.ToolFamily,
		LogicalAction:              req.LogicalAction,
		RiskClass:                  req.RiskHint,
		Target:                     req.Target,
		LocalFidelityRequired:      req.LocalFidelityRequired,
		ImplementationAvailability: h.implAvailability,
	}

	// Step 6: Evaluate policy
	decision, err := h.engine.Evaluate(policyInput)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "policy evaluation error: " + err.Error(),
		})
		return
	}

	// Step 7: Build response and audit
	auditEvent := audit.AuditEvent{
		ActorUser:     req.Actor.UserID,
		AgentID:       req.Actor.AgentID,
		SessionID:     req.Runner.SessionID,
		RunnerID:      req.Runner.RunnerID,
		TurnID:        req.Runner.TurnID,
		ToolFamily:    req.ToolFamily,
		LogicalAction: req.LogicalAction,
		SelectedLane:  decision.SelectedLane,
		Decision:      accessplane.Decision(decision.Decision),
		Target:        req.Target.Resource,
		ReasonCode:    decision.Reason,
	}

	if decision.Decision == accessplane.DecisionDeny {
		auditEvent.Result = "denied"
		audit.LogResolveDecision(h.logger, auditEvent)
		writeJSON(w, http.StatusForbidden, &accessplane.DeniedError{
			Family: req.ToolFamily,
			Reason: decision.Reason,
		})
		return
	}

	// Allow
	resp := accessplane.ResolveOperationResponse{
		Decision:            accessplane.Decision(decision.Decision),
		SelectedLane:        decision.SelectedLane,
		DecisionReason:      decision.Reason,
		ImplementationState: decision.ImplementationState,
	}

	if decision.ApprovalRequired {
		resp.ApprovalStatus = "approval_required"
	}

	auditEvent.Result = "allowed"
	audit.LogResolveDecision(h.logger, auditEvent)

	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
