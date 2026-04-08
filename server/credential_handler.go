package server

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/rahul-roy-glean/capsule-access-plane/identity"
)

// CredentialHandlers serves the credential management API.
// All endpoints require a valid attestation token.
type CredentialHandlers struct {
	verifier identity.Verifier
	db       *sql.DB
	logger   *slog.Logger
}

// NewCredentialHandlers creates credential management handlers.
func NewCredentialHandlers(verifier identity.Verifier, db *sql.DB, logger *slog.Logger) *CredentialHandlers {
	return &CredentialHandlers{verifier: verifier, db: db, logger: logger}
}

// requireAttestation validates the attestation token and returns false if
// the request should be rejected (response already written).
func (h *CredentialHandlers) requireAttestation(w http.ResponseWriter, r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid Authorization header"})
		return false
	}
	if _, err := h.verifier.Verify(strings.TrimPrefix(authHeader, "Bearer ")); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid attestation token: " + err.Error()})
		return false
	}
	return true
}

// UpsertCredential handles POST /v1/credentials.
func (h *CredentialHandlers) UpsertCredential(w http.ResponseWriter, r *http.Request) {
	if !h.requireAttestation(w, r) {
		return
	}
	var req struct {
		ID    string `json:"id"`
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}
	if req.ID == "" || req.Type == "" || req.Value == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id, type, and value are required"})
		return
	}

	_, err := h.db.ExecContext(r.Context(), `
		INSERT INTO credential_records (id, credential_type, credential_value)
		VALUES (?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			credential_type = excluded.credential_type,
			credential_value = excluded.credential_value,
			updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
	`, req.ID, req.Type, req.Value)
	if err != nil {
		h.logger.Error("upsert credential", "id", req.ID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to store credential"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "stored", "id": req.ID})
}

// ListCredentials handles GET /v1/credentials.
func (h *CredentialHandlers) ListCredentials(w http.ResponseWriter, r *http.Request) {
	if !h.requireAttestation(w, r) {
		return
	}
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, credential_type, length(credential_value), created_at, updated_at
		FROM credential_records ORDER BY id
	`)
	if err != nil {
		h.logger.Error("list credentials", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list credentials"})
		return
	}
	defer rows.Close()

	type entry struct {
		ID        string `json:"id"`
		Type      string `json:"type"`
		Size      int    `json:"size"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	}
	var entries []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.ID, &e.Type, &e.Size, &e.CreatedAt, &e.UpdatedAt); err != nil {
			h.logger.Error("scan credential row", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to scan credentials"})
			return
		}
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []entry{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"credentials": entries})
}

// DeleteCredential handles DELETE /v1/credentials/{id}.
func (h *CredentialHandlers) DeleteCredential(w http.ResponseWriter, r *http.Request) {
	if !h.requireAttestation(w, r) {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "credential id is required"})
		return
	}

	res, err := h.db.ExecContext(r.Context(), `DELETE FROM credential_records WHERE id = ?`, id)
	if err != nil {
		h.logger.Error("delete credential", "id", id, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete credential"})
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "credential not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
}
