package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/rahul-roy-glean/capsule-access-plane/audit"
	"github.com/rahul-roy-glean/capsule-access-plane/bundle"
	"github.com/rahul-roy-glean/capsule-access-plane/grants"
	"github.com/rahul-roy-glean/capsule-access-plane/identity"
	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
	"github.com/rahul-roy-glean/capsule-access-plane/providers"
	"github.com/rahul-roy-glean/capsule-access-plane/runtime"
)

// GrantHandlers implements the grant lifecycle HTTP endpoints.
type GrantHandlers struct {
	verifier         identity.Verifier
	grants           *grants.Service
	adapter          *runtime.DirectHTTPAdapter
	providers        *providers.Registry
	manifestRegistry manifest.Registry
	logger           *slog.Logger
}

// NewGrantHandlers creates handlers for the grant lifecycle endpoints.
func NewGrantHandlers(
	verifier identity.Verifier,
	grantSvc *grants.Service,
	adapter *runtime.DirectHTTPAdapter,
	providerRegistry *providers.Registry,
	manifestRegistry manifest.Registry,
	logger *slog.Logger,
) *GrantHandlers {
	return &GrantHandlers{
		verifier:         verifier,
		grants:           grantSvc,
		adapter:          adapter,
		providers:        providerRegistry,
		manifestRegistry: manifestRegistry,
		logger:           logger,
	}
}

// ProjectGrant handles POST /v1/grants/project.
func (h *GrantHandlers) ProjectGrant(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authenticate(w, r)
	if !ok {
		return
	}

	var req accessplane.ProjectGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body: " + err.Error(),
		})
		return
	}

	if req.RunnerID != claims.RunnerID {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "runner_id does not match attestation token",
		})
		return
	}

	runnerClaims := grants.RunnerClaims{
		RunnerID:  claims.RunnerID,
		SessionID: claims.SessionID,
	}

	// Resolve credential via provider registry.
	// Look up the manifest to find the named provider, if any.
	var providerName string
	if m, err := h.manifestRegistry.Get(req.ToolFamily); err == nil {
		providerName = m.Provider
	}
	provider, err := h.providers.ForManifest(providerName)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "credential provider unavailable: " + err.Error(),
		})
		return
	}
	resolvedToken, err := provider.ResolveToken(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "credential resolution failed: " + err.Error(),
		})
		return
	}

	resp, err := h.grants.ProjectGrant(r.Context(), &req, runnerClaims, resolvedToken, provider.Name())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
		return
	}

	// Install the proxy adapter for direct_http grants.
	if req.Lane == accessplane.LaneDirectHTTP && h.adapter != nil {
		b := &bundle.ProjectionBundle{
			Version:   "v1",
			GrantID:   resp.GrantID,
			Lane:      req.Lane,
			ExpiresAt: time.Now().Add(15 * time.Minute),
			AuditMetadata: bundle.AuditMetadata{
				UserID:    "system",
				SessionID: req.SessionID,
				RunnerID:  req.RunnerID,
			},
		}

		proxyAddr, err := h.adapter.InstallGrantWithCredential(r.Context(), b, req.ToolFamily, resolvedToken)
		if err != nil {
			h.logger.Error("failed to install proxy", "grant_id", resp.GrantID, "err", err)
		} else {
			resp.ProjectionRef = proxyAddr
		}
	}

	audit.LogGrantOperation(h.logger, "project", audit.AuditEvent{
		RunnerID:   req.RunnerID,
		SessionID:  req.SessionID,
		TurnID:     req.TurnID,
		ToolFamily: req.ToolFamily,
		Result:     "projected",
	})

	writeJSON(w, http.StatusOK, resp)
}

// ExchangeCapability handles POST /v1/grants/exchange.
func (h *GrantHandlers) ExchangeCapability(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authenticate(w, r)
	if !ok {
		return
	}

	var req accessplane.ExchangeCapabilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body: " + err.Error(),
		})
		return
	}

	if req.RunnerID != claims.RunnerID {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "runner_id does not match attestation token",
		})
		return
	}

	resp, err := h.grants.ExchangeCapability(r.Context(), &req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
		return
	}

	audit.LogGrantOperation(h.logger, "exchange", audit.AuditEvent{
		RunnerID:  req.RunnerID,
		SessionID: claims.SessionID,
		Result:    "active",
	})

	writeJSON(w, http.StatusOK, resp)
}

// RefreshGrant handles POST /v1/grants/refresh.
func (h *GrantHandlers) RefreshGrant(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authenticate(w, r)
	if !ok {
		return
	}

	var req accessplane.RefreshGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body: " + err.Error(),
		})
		return
	}

	if req.RunnerID != claims.RunnerID {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "runner_id does not match attestation token",
		})
		return
	}

	resp, err := h.grants.RefreshGrant(r.Context(), &req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
		return
	}

	audit.LogGrantOperation(h.logger, "refresh", audit.AuditEvent{
		RunnerID:  req.RunnerID,
		SessionID: claims.SessionID,
		Result:    "refreshed",
	})

	writeJSON(w, http.StatusOK, resp)
}

// RevokeGrant handles POST /v1/grants/revoke.
func (h *GrantHandlers) RevokeGrant(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authenticate(w, r)
	if !ok {
		return
	}

	var req accessplane.RevokeGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body: " + err.Error(),
		})
		return
	}

	if req.RunnerID != claims.RunnerID {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "runner_id does not match attestation token",
		})
		return
	}

	resp, err := h.grants.RevokeGrant(r.Context(), &req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
		return
	}

	// Also revoke the proxy if it exists.
	if h.adapter != nil {
		_ = h.adapter.RevokeGrant(r.Context(), req.GrantID, req.RunnerID)
	}

	audit.LogGrantOperation(h.logger, "revoke", audit.AuditEvent{
		RunnerID:  req.RunnerID,
		SessionID: claims.SessionID,
		Result:    "revoked",
	})

	writeJSON(w, http.StatusOK, resp)
}

// authenticate extracts and verifies the bearer token from the request.
func (h *GrantHandlers) authenticate(w http.ResponseWriter, r *http.Request) (*identity.Claims, bool) {
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
