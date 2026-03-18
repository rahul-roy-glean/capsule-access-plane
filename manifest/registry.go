package manifest

import (
	"fmt"
	"sync"
)

// Registry stores and retrieves tool manifests by family name.
type Registry interface {
	Get(family string) (*ToolManifest, error)
	List() []*ToolManifest
	Register(manifest *ToolManifest) error
}

// InMemoryRegistry is a thread-safe in-memory Registry.
type InMemoryRegistry struct {
	mu        sync.RWMutex
	manifests map[string]*ToolManifest
}

// NewInMemoryRegistry creates an empty InMemoryRegistry.
func NewInMemoryRegistry() *InMemoryRegistry {
	return &InMemoryRegistry{
		manifests: make(map[string]*ToolManifest),
	}
}

// Register adds a manifest to the registry. Returns an error if the family is already registered.
func (r *InMemoryRegistry) Register(m *ToolManifest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.manifests[m.Family]; exists {
		return fmt.Errorf("manifest already registered: %s", m.Family)
	}
	r.manifests[m.Family] = m
	return nil
}

// Get retrieves a manifest by family name.
func (r *InMemoryRegistry) Get(family string) (*ToolManifest, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.manifests[family]
	if !ok {
		return nil, fmt.Errorf("manifest not found: %s", family)
	}
	return m, nil
}

// List returns all registered manifests.
func (r *InMemoryRegistry) List() []*ToolManifest {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*ToolManifest, 0, len(r.manifests))
	for _, m := range r.manifests {
		result = append(result, m)
	}
	return result
}
