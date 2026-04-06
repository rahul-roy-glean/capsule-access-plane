package session

import (
	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
)

// Resolver maps a session ID to its effective manifest registry based on the
// session's policy. If no policy exists for a session, access is denied by
// returning nil.
type Resolver struct {
	policies *PolicyStore
	registry manifest.Registry
}

// NewResolver creates a Resolver backed by the given policy store and base registry.
func NewResolver(policies *PolicyStore, registry manifest.Registry) *Resolver {
	return &Resolver{
		policies: policies,
		registry: registry,
	}
}

// RegistryForSession returns a ScopedRegistry containing only the families
// allowed by the session's policy. Returns nil if no policy exists (deny by default).
func (r *Resolver) RegistryForSession(sessionID string) manifest.Registry {
	p, ok := r.policies.Get(sessionID)
	if !ok {
		return nil
	}
	families := make([]string, 0, len(p.Families))
	for f := range p.Families {
		families = append(families, f)
	}
	return NewScopedRegistry(r.registry, families)
}

// GetPolicy returns the policy for a session, or nil and false if none exists.
func (r *Resolver) GetPolicy(sessionID string) (*Policy, bool) {
	return r.policies.Get(sessionID)
}
