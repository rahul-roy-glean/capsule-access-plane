package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/internal/audit"
	"github.com/rahul-roy-glean/capsule-access-plane/internal/executor"
	"github.com/rahul-roy-glean/capsule-access-plane/internal/grants"
	"github.com/rahul-roy-glean/capsule-access-plane/internal/identity"
	"github.com/rahul-roy-glean/capsule-access-plane/internal/policy"
)

type Server struct {
	attestations   *identity.Verifier
	policy         *policy.Engine
	executor       *executor.Service
	grants         *grants.Service
	audit          *audit.Service
	accessPlaneURL string
	logger         *log.Logger
}

func NewServer(
	verifier *identity.Verifier,
	engine *policy.Engine,
	execution *executor.Service,
	grantService *grants.Service,
	auditService *audit.Service,
	accessPlaneURL string,
	logger *log.Logger,
) *Server {
	return &Server{
		attestations:   verifier,
		policy:         engine,
		executor:       execution,
		grants:         grantService,
		audit:          auditService,
		accessPlaneURL: strings.TrimRight(accessPlaneURL, "/"),
		logger:         logger,
	}
}

type ExecuteOperationRequest struct {
	RunnerAttestation string                  `json:"runner_attestation"`
	ActorContext      policy.ActorContext     `json:"actor_context"`
	TurnID            string                  `json:"turn_id,omitempty"`
	Operation         executor.ExecuteRequest `json:"operation"`
}

type OpenHTTPGrantRequest struct {
	RunnerAttestation string              `json:"runner_attestation"`
	ActorContext      policy.ActorContext `json:"actor_context"`
	TurnID            string              `json:"turn_id,omitempty"`
	Scope             string              `json:"scope"`
	TTLSeconds        int                 `json:"ttl_seconds,omitempty"`
	Domains           []string            `json:"domains"`
	CredentialRef     string              `json:"credential_ref,omitempty"`
	HeaderName        string              `json:"header_name,omitempty"`
	HeaderPrefix      string              `json:"header_prefix,omitempty"`
}

type OpenAuthHelperSessionRequest struct {
	RunnerAttestation string              `json:"runner_attestation"`
	ActorContext      policy.ActorContext `json:"actor_context"`
	TurnID            string              `json:"turn_id,omitempty"`
	Scope             string              `json:"scope"`
	TTLSeconds        int                 `json:"ttl_seconds,omitempty"`
	ToolFamily        string              `json:"tool_family"`
	CredentialRef     string              `json:"credential_ref,omitempty"`
}

type RevokeGrantRequest struct {
	GrantID string `json:"grant_id"`
}

type HelperTokenRequest struct {
	HelperSessionID   string `json:"helper_session_id"`
	RunnerAttestation string `json:"runner_attestation"`
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/v1/operations/execute", s.handleExecuteOperation)
	mux.HandleFunc("/v1/grants/http/open", s.handleOpenHTTPGrant)
	mux.HandleFunc("/v1/helpers/open", s.handleOpenAuthHelperSession)
	mux.HandleFunc("/v1/helpers/token", s.handleHelperToken)
	mux.HandleFunc("/v1/grants/revoke", s.handleRevokeGrant)
	mux.HandleFunc("/v1/grants/", s.handleGrantByID)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleExecuteOperation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ExecuteOperationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err))
		return
	}

	claims, err := s.attestations.Verify(req.RunnerAttestation)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	policyInput := policy.ExecutionPolicyInput{
		Kind:  req.Operation.Kind,
		Actor: req.ActorContext,
	}
	if req.Operation.CLI != nil {
		policyInput.Tool = req.Operation.CLI.Tool
	}
	if req.Operation.HTTP != nil {
		policyInput.URL = req.Operation.HTTP.URL
		policyInput.IsWrite = isWriteMethod(req.Operation.HTTP.Method)
	}
	decision, err := s.policy.AllowExecution(policyInput)
	if err != nil {
		s.recordAudit(r.Context(), claims, req.ActorContext, req.TurnID, "execute_operation", "denied", decision, 0, map[string]any{
			"error": err.Error(),
		})
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	start := time.Now()
	if req.Operation.Stream {
		w.Header().Set("Content-Type", "application/x-ndjson")
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeError(w, http.StatusInternalServerError, "streaming is not supported by this server")
			return
		}
		result, err := s.executor.Stream(r.Context(), req.Operation, w, func() error {
			flusher.Flush()
			return nil
		})
		if err != nil {
			s.recordAudit(r.Context(), claims, req.ActorContext, req.TurnID, "execute_operation", "error", decision, time.Since(start), map[string]any{
				"error": err.Error(),
			})
			return
		}
		s.recordAudit(r.Context(), claims, req.ActorContext, req.TurnID, "execute_operation", "ok", decision, time.Since(start), result)
		return
	}

	result, err := s.executor.Execute(r.Context(), req.Operation)
	if err != nil {
		s.recordAudit(r.Context(), claims, req.ActorContext, req.TurnID, "execute_operation", "error", decision, time.Since(start), map[string]any{
			"error": err.Error(),
		})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.recordAudit(r.Context(), claims, req.ActorContext, req.TurnID, "execute_operation", "ok", decision, time.Since(start), result)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleOpenHTTPGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req OpenHTTPGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err))
		return
	}
	claims, err := s.attestations.Verify(req.RunnerAttestation)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	grant, err := s.grants.OpenHTTPGrant(r.Context(), grants.OpenHTTPGrantRequest{
		Claims:        claims,
		Actor:         req.ActorContext,
		TurnID:        req.TurnID,
		Scope:         req.Scope,
		TTL:           ttlSeconds(req.TTLSeconds),
		Domains:       req.Domains,
		CredentialRef: req.CredentialRef,
		HeaderName:    req.HeaderName,
		HeaderPrefix:  req.HeaderPrefix,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.recordAudit(r.Context(), claims, req.ActorContext, req.TurnID, "open_http_grant", "ok", "allowed", 0, grant)
	writeJSON(w, http.StatusOK, grant)
}

func (s *Server) handleOpenAuthHelperSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req OpenAuthHelperSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err))
		return
	}
	claims, err := s.attestations.Verify(req.RunnerAttestation)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	grant, session, err := s.grants.OpenHelperSession(r.Context(), grants.OpenHelperSessionRequest{
		Claims:            claims,
		Actor:             req.ActorContext,
		TurnID:            req.TurnID,
		Scope:             req.Scope,
		TTL:               ttlSeconds(req.TTLSeconds),
		ToolFamily:        req.ToolFamily,
		CredentialRef:     req.CredentialRef,
		RunnerAttestation: req.RunnerAttestation,
		AccessPlaneURL:    s.accessPlaneURL,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	response := map[string]any{
		"grant":          grant,
		"helper_session": session,
	}
	s.recordAudit(r.Context(), claims, req.ActorContext, req.TurnID, "open_helper_session", "ok", "allowed", 0, response)
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleHelperToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req HelperTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err))
		return
	}
	claims, err := s.attestations.Verify(req.RunnerAttestation)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	grant, err := s.grants.GetGrant(r.Context(), req.HelperSessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if grant.RunnerID != claims.RunnerID || grant.SessionID != claims.SessionID || grant.Type != grants.GrantTypeHelper {
		writeError(w, http.StatusForbidden, "helper session does not match attested runner")
		return
	}
	if time.Now().UTC().After(grant.ExpiresAt) || grant.Status != "active" {
		writeError(w, http.StatusGone, "helper session has expired")
		return
	}
	session, err := s.grants.GetHelperSession(r.Context(), grant.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	token, err := s.grants.ResolveGrantToken(r.Context(), grant)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	expiry := grant.ExpiresAt.UTC()
	switch session.Format {
	case "exec-credential":
		writeJSON(w, http.StatusOK, map[string]any{
			"apiVersion": "client.authentication.k8s.io/v1beta1",
			"kind":       "ExecCredential",
			"status": map[string]any{
				"token":               token,
				"expirationTimestamp": expiry.Format(time.RFC3339),
			},
		})
	case "google-executable-source":
		writeJSON(w, http.StatusOK, map[string]any{
			"version":         1,
			"success":         true,
			"token_type":      "Bearer",
			"access_token":    token,
			"expiration_time": expiry.Unix(),
		})
	default:
		writeError(w, http.StatusInternalServerError, "unsupported helper session format")
	}
}

func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req RevokeGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err))
		return
	}
	if req.GrantID == "" {
		writeError(w, http.StatusBadRequest, "grant_id is required")
		return
	}
	if err := s.grants.RevokeGrant(r.Context(), req.GrantID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleGrantByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	grantID := strings.TrimPrefix(r.URL.Path, "/v1/grants/")
	if grantID == "" {
		writeError(w, http.StatusBadRequest, "grant id is required")
		return
	}
	grant, err := s.grants.GetGrant(r.Context(), grantID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	response := map[string]any{"grant": grant}
	if grant.Type == grants.GrantTypeHelper {
		session, err := s.grants.GetHelperSession(r.Context(), grant.ID)
		if err == nil {
			response["helper_session"] = session
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) recordAudit(ctx context.Context, claims *identity.Claims, actor policy.ActorContext, turnID, action, result, decision string, duration time.Duration, metadata any) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Record(ctx, audit.Event{
		EventType:       "access_plane",
		SessionID:       claims.SessionID,
		RunnerID:        claims.RunnerID,
		TurnID:          turnID,
		ActorUser:       actor.UserID,
		VirtualIdentity: actor.VirtualIdentity,
		AgentID:         actor.AgentID,
		Target:          claims.WorkloadKey,
		Action:          action,
		Result:          result,
		PolicyDecision:  decision,
		Duration:        duration,
		Metadata:        metadata,
	}); err != nil && s.logger != nil {
		s.logger.Printf("audit record failed: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func ttlSeconds(seconds int) time.Duration {
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func isWriteMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func Shutdown(ctx context.Context, server *http.Server) error {
	return server.Shutdown(ctx)
}
