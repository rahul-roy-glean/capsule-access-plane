package server

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/identity"
	"github.com/rahul-roy-glean/capsule-access-plane/providers"
)

// GCSHandlers serves the GCS credential endpoint.
type GCSHandlers struct {
	verifier  identity.Verifier
	providers *providers.Registry
	logger    *slog.Logger
}

// NewGCSHandlers creates a handler for GCS credential requests.
func NewGCSHandlers(verifier identity.Verifier, providers *providers.Registry, logger *slog.Logger) *GCSHandlers {
	return &GCSHandlers{
		verifier:  verifier,
		providers: providers,
		logger:    logger,
	}
}

// GetCredentials handles GET /v1/credentials/gcs.
// Returns a short-lived GCS access token by resolving the provider that
// matches storage.googleapis.com.
func (h *GCSHandlers) GetCredentials(w http.ResponseWriter, r *http.Request) {
	// Authenticate
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "missing or invalid Authorization header",
		})
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	_, err := h.verifier.Verify(token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "invalid attestation token: " + err.Error(),
		})
		return
	}

	// Find the provider for GCS
	provider, ok := h.providers.ForHost("storage.googleapis.com")
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "no credential provider configured for storage.googleapis.com",
		})
		return
	}

	// Resolve the token
	accessToken, err := provider.ResolveToken(r.Context())
	if err != nil {
		h.logger.Error("failed to resolve GCS token", "provider", provider.Name(), "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to resolve GCS credentials",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(time.Hour.Seconds()),
	})
}
