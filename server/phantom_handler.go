package server

import (
	"net/http"
	"strings"

	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
)

// PhantomHandlers serves the phantom env var endpoint.
type PhantomHandlers struct {
	manifests manifest.Registry
}

// NewPhantomHandlers creates phantom env handlers.
func NewPhantomHandlers(manifests manifest.Registry) *PhantomHandlers {
	return &PhantomHandlers{manifests: manifests}
}

// GetPhantomEnv handles GET /v1/phantom-env?families=github_rest,gcp_cli_read
// Returns the union of phantom env vars needed for the requested tool families.
func (h *PhantomHandlers) GetPhantomEnv(w http.ResponseWriter, r *http.Request) {
	familiesParam := r.URL.Query().Get("families")
	if familiesParam == "" {
		// Return phantom env for all families.
		result := h.collectAll()
		writeJSON(w, http.StatusOK, result)
		return
	}

	families := strings.Split(familiesParam, ",")
	result := make(map[string]string)
	for _, f := range families {
		f = strings.TrimSpace(f)
		m, err := h.manifests.Get(f)
		if err != nil {
			continue
		}
		for k, v := range m.PhantomEnv {
			result[k] = v
		}
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *PhantomHandlers) collectAll() map[string]string {
	result := make(map[string]string)
	for _, m := range h.manifests.List() {
		for k, v := range m.PhantomEnv {
			result[k] = v
		}
	}
	return result
}
