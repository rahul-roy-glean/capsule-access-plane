package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
	"github.com/rahul-roy-glean/capsule-access-plane/providers"
	"github.com/rahul-roy-glean/capsule-access-plane/session"
)

// SessionHandlers serves the session policy CRUD endpoints.
type SessionHandlers struct {
	policies         *session.PolicyStore
	manifestRegistry manifest.Registry
	providers        *providers.Registry
	logger           *slog.Logger
}

// NewSessionHandlers creates handlers for session policy management.
func NewSessionHandlers(
	policies *session.PolicyStore,
	manifestRegistry manifest.Registry,
	providerRegistry *providers.Registry,
	logger *slog.Logger,
) *SessionHandlers {
	return &SessionHandlers{
		policies:         policies,
		manifestRegistry: manifestRegistry,
		providers:        providerRegistry,
		logger:           logger,
	}
}

// setPolicyRequest is the JSON body for POST /v1/sessions/{session_id}/policy.
type setPolicyRequest struct {
	Families map[string]*session.FamilyCredential `json:"families"`
}

// SetPolicy handles POST /v1/sessions/{session_id}/policy.
func (h *SessionHandlers) SetPolicy(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("session_id")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "session_id is required",
		})
		return
	}

	var req setPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body: " + err.Error(),
		})
		return
	}

	if len(req.Families) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "families must not be empty",
		})
		return
	}

	// Validate all family names exist in the manifest registry.
	for family := range req.Families {
		if _, err := h.manifestRegistry.Get(family); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "unknown family: " + family,
			})
			return
		}
	}

	// Store the policy.
	p := &session.Policy{
		SessionID: sessionID,
		Families:  req.Families,
		CreatedAt: time.Now(),
	}
	h.policies.Set(sessionID, p)

	// For each family with a token, push it as a per-session delegated token
	// via the matching provider.
	tokensUpdated := 0
	for family, cred := range req.Families {
		if cred == nil || cred.Token == "" {
			continue
		}
		m, err := h.manifestRegistry.Get(family)
		if err != nil {
			continue
		}
		if m.Provider == "" {
			continue
		}
		cp, err := h.providers.Get(m.Provider)
		if err != nil {
			h.logger.Warn("provider not found for family",
				"family", family, "provider", m.Provider, "err", err)
			continue
		}
		dp, ok := cp.(*providers.DelegatedProvider)
		if !ok {
			h.logger.Debug("provider is not delegated, skipping token push",
				"family", family, "provider", m.Provider, "type", cp.Type())
			continue
		}
		st := &providers.SessionToken{
			Token:     cred.Token,
			ExpiresAt: cred.ExpiresAt,
		}
		dp.UpdateToken(sessionID, st)
		tokensUpdated++
	}

	h.logger.Info("session policy set",
		"session_id", sessionID,
		"families", len(req.Families),
		"tokens_pushed", tokensUpdated)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"session_id": sessionID,
		"families":   len(req.Families),
		"status":     "active",
	})
}

// GetPolicy handles GET /v1/sessions/{session_id}/policy.
func (h *SessionHandlers) GetPolicy(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("session_id")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "session_id is required",
		})
		return
	}

	p, ok := h.policies.Get(sessionID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "no policy for session: " + sessionID,
		})
		return
	}

	// Redact tokens in the response — only expose family names and expiry.
	type redactedCred struct {
		HasToken  bool      `json:"has_token"`
		ExpiresAt time.Time `json:"expires_at,omitempty"`
	}
	redacted := make(map[string]*redactedCred, len(p.Families))
	for family, cred := range p.Families {
		rc := &redactedCred{}
		if cred != nil {
			rc.HasToken = cred.Token != ""
			rc.ExpiresAt = cred.ExpiresAt
		}
		redacted[family] = rc
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"session_id": p.SessionID,
		"families":   redacted,
		"created_at": p.CreatedAt,
	})
}

// DeletePolicy handles DELETE /v1/sessions/{session_id}/policy.
func (h *SessionHandlers) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("session_id")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "session_id is required",
		})
		return
	}

	if !h.policies.HasPolicy(sessionID) {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "no policy for session: " + sessionID,
		})
		return
	}

	// Revoke delegated tokens for this session before deleting the policy.
	p, _ := h.policies.Get(sessionID)
	if p != nil {
		for family, cred := range p.Families {
			if cred == nil || cred.Token == "" {
				continue
			}
			m, err := h.manifestRegistry.Get(family)
			if err != nil || m.Provider == "" {
				continue
			}
			cp, err := h.providers.Get(m.Provider)
			if err != nil {
				continue
			}
			if dp, ok := cp.(*providers.DelegatedProvider); ok {
				dp.RevokeSession(sessionID)
			}
		}
	}

	h.policies.Delete(sessionID)

	h.logger.Info("session policy deleted", "session_id", sessionID)

	writeJSON(w, http.StatusOK, map[string]string{
		"session_id": sessionID,
		"status":     "deleted",
	})
}
