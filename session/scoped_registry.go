package session

import (
	"fmt"

	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
)

// ScopedRegistry wraps a manifest.Registry and filters access to only the
// allowed set of family names. It satisfies the manifest.Registry interface.
type ScopedRegistry struct {
	inner   manifest.Registry
	allowed map[string]bool
}

// NewScopedRegistry creates a ScopedRegistry that only exposes the given families.
func NewScopedRegistry(inner manifest.Registry, allowedFamilies []string) *ScopedRegistry {
	allowed := make(map[string]bool, len(allowedFamilies))
	for _, f := range allowedFamilies {
		allowed[f] = true
	}
	return &ScopedRegistry{
		inner:   inner,
		allowed: allowed,
	}
}

// Get returns the manifest for the given family only if it is in the allowed set.
func (s *ScopedRegistry) Get(family string) (*manifest.ToolManifest, error) {
	if !s.allowed[family] {
		return nil, fmt.Errorf("family %q not permitted for this session", family)
	}
	return s.inner.Get(family)
}

// List returns only the manifests whose families are in the allowed set.
func (s *ScopedRegistry) List() []*manifest.ToolManifest {
	all := s.inner.List()
	result := make([]*manifest.ToolManifest, 0, len(s.allowed))
	for _, m := range all {
		if s.allowed[m.Family] {
			result = append(result, m)
		}
	}
	return result
}

// Register delegates to the inner registry.
func (s *ScopedRegistry) Register(m *manifest.ToolManifest) error {
	return s.inner.Register(m)
}
