package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/rahul-roy-glean/capsule-access-plane/identity"
)

// SessionRegistrationHandlers serves the session registration HTTP endpoints.
type SessionRegistrationHandlers struct {
	sessions *SessionStore
	verifier identity.Verifier
}

// NewSessionRegistrationHandlers creates session registration handlers.
func NewSessionRegistrationHandlers(verifier identity.Verifier, store *SessionStore) *SessionRegistrationHandlers {
	return &SessionRegistrationHandlers{
		sessions: store,
		verifier: verifier,
	}
}

// RegisterSession handles POST /v1/sessions/register.
func (h *SessionRegistrationHandlers) RegisterSession(w http.ResponseWriter, r *http.Request) {
	if _, err := h.authenticate(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": err.Error(),
		})
		return
	}

	var reg SessionRegistration
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body: " + err.Error(),
		})
		return
	}

	if reg.SessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "session_id is required",
		})
		return
	}

	if err := h.sessions.Register(&reg); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"status":     "registered",
		"session_id": reg.SessionID,
	})
}

// GetSession handles GET /v1/sessions/{session_id}.
func (h *SessionRegistrationHandlers) GetSession(w http.ResponseWriter, r *http.Request) {
	if _, err := h.authenticate(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": err.Error(),
		})
		return
	}

	sessionID := r.PathValue("session_id")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "session_id is required",
		})
		return
	}

	reg, ok := h.sessions.Get(sessionID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "session not found",
		})
		return
	}

	writeJSON(w, http.StatusOK, reg)
}

// DeregisterSession handles DELETE /v1/sessions/{session_id}.
func (h *SessionRegistrationHandlers) DeregisterSession(w http.ResponseWriter, r *http.Request) {
	if _, err := h.authenticate(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": err.Error(),
		})
		return
	}

	sessionID := r.PathValue("session_id")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "session_id is required",
		})
		return
	}

	if !h.sessions.Deregister(sessionID) {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "session not found",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":     "deregistered",
		"session_id": sessionID,
	})
}

// authenticate extracts and verifies the attestation bearer token.
func (h *SessionRegistrationHandlers) authenticate(r *http.Request) (*identity.Claims, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, fmt.Errorf("missing or invalid Authorization header")
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	return h.verifier.Verify(token)
}
