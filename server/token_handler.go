package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/providers"
)

// TokenUpdateRequest is the body of POST /v1/providers/update-token.
type TokenUpdateRequest struct {
	Provider  string    `json:"provider"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// TokenHandlers serves the provider token management endpoints.
type TokenHandlers struct {
	providers *providers.Registry
}

// NewTokenHandlers creates token management handlers.
func NewTokenHandlers(providerRegistry *providers.Registry) *TokenHandlers {
	return &TokenHandlers{providers: providerRegistry}
}

// UpdateToken handles POST /v1/providers/update-token.
// The host agent pushes delegated tokens here.
func (h *TokenHandlers) UpdateToken(w http.ResponseWriter, r *http.Request) {
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

	dp.UpdateToken(req.Token, req.ExpiresAt)

	writeJSON(w, http.StatusOK, map[string]string{
		"status":   "updated",
		"provider": req.Provider,
	})
}
