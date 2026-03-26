package providers

import (
	"fmt"
	"sync"
)

// Registry holds named credential providers and supports lookup by name or host.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]CredentialProvider // name → provider
	def       CredentialProvider            // default provider (used when no named match)
}

// NewRegistry creates an empty provider registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]CredentialProvider),
	}
}

// Register adds a provider to the registry.
func (r *Registry) Register(p CredentialProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[p.Name()]; exists {
		return fmt.Errorf("providers: already registered: %s", p.Name())
	}
	r.providers[p.Name()] = p
	return nil
}

// SetDefault sets the default provider used when no named provider is specified.
func (r *Registry) SetDefault(p CredentialProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.def = p
}

// Get returns the provider with the given name.
func (r *Registry) Get(name string) (CredentialProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("providers: not found: %s", name)
	}
	return p, nil
}

// ForManifest returns the provider for a manifest. If providerName is non-empty,
// it looks up that specific provider. Otherwise it returns the default.
func (r *Registry) ForManifest(providerName string) (CredentialProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if providerName != "" {
		p, ok := r.providers[providerName]
		if !ok {
			return nil, fmt.Errorf("providers: manifest references unknown provider %q", providerName)
		}
		return p, nil
	}

	if r.def != nil {
		return r.def, nil
	}

	return nil, fmt.Errorf("providers: no default provider configured")
}

// ForHost returns the best provider for the given host. Specific host matches
// take priority over catch-all providers (those with empty host lists).
func (r *Registry) ForHost(host string) (CredentialProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.providers {
		if p != r.def && p.Matches(host) {
			return p, true
		}
	}
	if r.def != nil && r.def.Matches(host) {
		return r.def, true
	}
	return nil, false
}

// All returns all registered providers.
func (r *Registry) All() []CredentialProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]CredentialProvider, 0, len(r.providers))
	for _, p := range r.providers {
		result = append(result, p)
	}
	return result
}
