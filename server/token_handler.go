package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/identity"
	"github.com/rahul-roy-glean/capsule-access-plane/providers"
)

// TokenUpdateRequest is the body of POST /v1/providers/update-token.
type TokenUpdateRequest struct {
	Provider  string            `json:"provider"`
	SourceIP  string            `json:"source_ip,omitempty"`
	Token     string            `json:"token"`
	ExpiresAt time.Time         `json:"expires_at,omitempty"`
	Identity  *TokenIdentity    `json:"identity,omitempty"`
}

// TokenIdentity carries user identity info to inject into proxied requests.
type TokenIdentity struct {
	UserEmail    string            `json:"user_email,omitempty"`
	ExtraHeaders map[string]string `json:"headers,omitempty"`
}

// TokenHandlers serves the provider token management endpoints.
type TokenHandlers struct {
	providers *providers.Registry
	verifier  identity.Verifier
}

// NewTokenHandlers creates token management handlers.
func NewTokenHandlers(providerRegistry *providers.Registry, verifier identity.Verifier) *TokenHandlers {
	return &TokenHandlers{providers: providerRegistry, verifier: verifier}
}

// UpdateToken handles POST /v1/providers/update-token.
// The host agent pushes delegated tokens here.
func (h *TokenHandlers) UpdateToken(w http.ResponseWriter, r *http.Request) {
	// Authenticate
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "missing or invalid Authorization header",
		})
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if _, err := h.verifier.Verify(token); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "invalid attestation token: " + err.Error(),
		})
		return
	}

	var req TokenUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body: " + err.Error(),
		})
		return
	}

	if req.Provider == "" || req.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "provider and token are required",
		})
		return
	}

	p, err := h.providers.Get(req.Provider)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "unknown provider: " + req.Provider,
		})
		return
	}

	dp, ok := p.(*providers.DelegatedProvider)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "provider " + req.Provider + " is not a delegated provider (type: " + p.Type() + ")",
		})
		return
	}

	st := &providers.SessionToken{
		Token:     req.Token,
		ExpiresAt: req.ExpiresAt,
	}
	if req.Identity != nil {
		st.UserEmail = req.Identity.UserEmail
		st.ExtraHeaders = req.Identity.ExtraHeaders
	}

	dp.UpdateToken(req.SourceIP, st)

	writeJSON(w, http.StatusOK, map[string]string{
		"status":   "updated",
		"provider": req.Provider,
	})
}
