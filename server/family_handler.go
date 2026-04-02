package server

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
)

// FamilyHandlers serves the family CRUD endpoints.
type FamilyHandlers struct {
	registry manifest.MutableRegistry
	logger   *slog.Logger
}

// NewFamilyHandlers creates family CRUD handlers.
func NewFamilyHandlers(registry manifest.MutableRegistry, logger *slog.Logger) *FamilyHandlers {
	return &FamilyHandlers{registry: registry, logger: logger}
}

// ListFamilies handles GET /v1/families.
func (h *FamilyHandlers) ListFamilies(w http.ResponseWriter, r *http.Request) {
	all := h.registry.List()
	type familySummary struct {
		Family       string                `json:"family"`
		Version      string                `json:"version"`
		SurfaceKind  string                `json:"surface_kind"`
		Source       string                `json:"source"`
		Destinations []manifest.Destination `json:"destinations"`
	}
	result := make([]familySummary, 0, len(all))
	for _, m := range all {
		source := "api"
		if h.registry.IsBase(m.Family) {
			source = "yaml"
		}
		result = append(result, familySummary{
			Family:       m.Family,
			Version:      m.Version,
			SurfaceKind:  m.SurfaceKind,
			Source:       source,
			Destinations: m.Destinations,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"families": result,
		"count":    len(result),
	})
}

// GetFamily handles GET /v1/families/{name}.
func (h *FamilyHandlers) GetFamily(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "family name is required"})
		return
	}
	m, err := h.registry.Get(name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	source := "api"
	if h.registry.IsBase(name) {
		source = "yaml"
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"manifest": m,
		"source":   source,
	})
}

// CreateFamily handles POST /v1/families.
func (h *FamilyHandlers) CreateFamily(w http.ResponseWriter, r *http.Request) {
	var m manifest.ToolManifest
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}
	if err := manifest.Validate(&m); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	_, existsErr := h.registry.Get(m.Family)
	exists := existsErr == nil

	if err := h.registry.Upsert(r.Context(), &m); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.logger.Info("family upserted", "family", m.Family)
	status := http.StatusCreated
	if exists {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]string{
		"family": m.Family,
		"status": "ok",
	})
}

// DeleteFamily handles DELETE /v1/families/{name}.
func (h *FamilyHandlers) DeleteFamily(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "family name is required"})
		return
	}
	if h.registry.IsBase(name) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "cannot delete base YAML family: " + name})
		return
	}
	if err := h.registry.Remove(r.Context(), name); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	h.logger.Info("family deleted", "family", name)
	writeJSON(w, http.StatusOK, map[string]string{
		"family": name,
		"status": "deleted",
	})
}
