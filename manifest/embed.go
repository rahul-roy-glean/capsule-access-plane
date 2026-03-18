package manifest

import (
	"embed"
	"fmt"
	"path/filepath"
)

//go:embed families/*.yaml
var FamiliesFS embed.FS

// LoadAllFamilies reads all YAML files from the embedded families directory,
// loads each manifest, and registers it in the given registry.
func LoadAllFamilies(loader Loader, registry Registry) error {
	entries, err := FamiliesFS.ReadDir("families")
	if err != nil {
		return fmt.Errorf("manifest: read embedded families dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		data, err := FamiliesFS.ReadFile("families/" + entry.Name())
		if err != nil {
			return fmt.Errorf("manifest: read embedded file %s: %w", entry.Name(), err)
		}

		m, err := loader.Load(data)
		if err != nil {
			return fmt.Errorf("manifest: load %s: %w", entry.Name(), err)
		}

		if err := registry.Register(m); err != nil {
			return fmt.Errorf("manifest: register %s: %w", entry.Name(), err)
		}
	}

	return nil
}
