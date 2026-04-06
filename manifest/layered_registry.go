package manifest

import (
	"context"
	"fmt"
	"sync"
)

// MutableRegistry extends Registry with write operations for dynamic families.
type MutableRegistry interface {
	Registry
	Upsert(ctx context.Context, m *ToolManifest) error
	Remove(ctx context.Context, family string) error
	IsBase(family string) bool
}

// LayeredRegistry provides a two-layer manifest registry: a base layer
// (YAML-loaded, immutable at runtime) and a dynamic layer (API-created,
// persisted in SQLite). Dynamic families override base on name collision.
type LayeredRegistry struct {
	mu      sync.RWMutex
	base    map[string]*ToolManifest
	dynamic map[string]*ToolManifest
	store   *FamilyStore
}

// NewLayeredRegistry creates a LayeredRegistry backed by the given store.
func NewLayeredRegistry(store *FamilyStore) *LayeredRegistry {
	return &LayeredRegistry{
		base:    make(map[string]*ToolManifest),
		dynamic: make(map[string]*ToolManifest),
		store:   store,
	}
}

// Register adds a manifest to the base (YAML) layer. Used during startup.
func (r *LayeredRegistry) Register(m *ToolManifest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.base[m.Family]; exists {
		return fmt.Errorf("manifest already registered: %s", m.Family)
	}
	r.base[m.Family] = m
	return nil
}

// Get retrieves a manifest. Dynamic layer takes precedence over base.
func (r *LayeredRegistry) Get(family string) (*ToolManifest, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if m, ok := r.dynamic[family]; ok {
		return m, nil
	}
	if m, ok := r.base[family]; ok {
		return m, nil
	}
	return nil, fmt.Errorf("manifest not found: %s", family)
}

// List returns all manifests. Dynamic overrides base on name collision.
func (r *LayeredRegistry) List() []*ToolManifest {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := make(map[string]bool)
	var result []*ToolManifest
	for name, m := range r.dynamic {
		seen[name] = true
		result = append(result, m)
	}
	for name, m := range r.base {
		if !seen[name] {
			result = append(result, m)
		}
	}
	return result
}

// Upsert adds or updates a dynamic family and persists to SQLite.
func (r *LayeredRegistry) Upsert(ctx context.Context, m *ToolManifest) error {
	if err := r.store.Upsert(ctx, m); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dynamic[m.Family] = m
	return nil
}

// Remove deletes a dynamic family. Returns error if the family is base-only.
func (r *LayeredRegistry) Remove(ctx context.Context, family string) error {
	r.mu.RLock()
	_, inDynamic := r.dynamic[family]
	_, inBase := r.base[family]
	r.mu.RUnlock()

	if !inDynamic && inBase {
		return fmt.Errorf("cannot delete base YAML family: %s", family)
	}
	if !inDynamic {
		return fmt.Errorf("family not found: %s", family)
	}

	if err := r.store.Delete(ctx, family); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.dynamic, family)
	return nil
}

// IsBase returns true if the family exists in the base (YAML) layer.
func (r *LayeredRegistry) IsBase(family string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.base[family]
	return ok
}

// LoadDynamic loads all persisted dynamic families from SQLite into memory.
// Called once at startup after YAML families are loaded.
func (r *LayeredRegistry) LoadDynamic(ctx context.Context) error {
	families, err := r.store.List(ctx)
	if err != nil {
		return fmt.Errorf("load dynamic families: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range families {
		r.dynamic[m.Family] = m
	}
	return nil
}
