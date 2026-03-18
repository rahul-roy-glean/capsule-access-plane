package manifest

import (
	"fmt"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"gopkg.in/yaml.v3"
)

// validSurfaceKinds enumerates the allowed surface kinds.
var validSurfaceKinds = map[string]bool{
	"cli":  true,
	"http": true,
	"sdk":  true,
	"rpc":  true,
}

// Loader loads a ToolManifest from raw bytes.
type Loader interface {
	Load(data []byte) (*ToolManifest, error)
}

// YAMLLoader implements Loader for YAML-encoded manifests.
type YAMLLoader struct{}

// Load parses YAML data into a ToolManifest and validates it.
func (l *YAMLLoader) Load(data []byte) (*ToolManifest, error) {
	var m ToolManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("yaml unmarshal: %w", err)
	}
	if err := validate(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

func validate(m *ToolManifest) error {
	if m.Family == "" {
		return fmt.Errorf("manifest validation: family must not be empty")
	}
	if len(m.SupportedLanes) == 0 {
		return fmt.Errorf("manifest validation: supported_lanes must not be empty")
	}
	for _, lane := range m.SupportedLanes {
		if !accessplane.ValidLanes[lane] {
			return fmt.Errorf("manifest validation: invalid lane %q", lane)
		}
	}
	if !validSurfaceKinds[m.SurfaceKind] {
		return fmt.Errorf("manifest validation: invalid surface_kind %q", m.SurfaceKind)
	}
	return nil
}
