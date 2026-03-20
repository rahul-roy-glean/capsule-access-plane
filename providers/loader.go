package providers

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/rahul-roy-glean/capsule-access-plane/grants"
)

// LoadFromFile reads a JSON file containing []ProviderConfig and registers
// each provider in the given registry. Returns the number of providers loaded.
func LoadFromFile(path string, registry *Registry, credResolver *grants.CredentialResolver) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("providers: read config: %w", err)
	}

	var configs []ProviderConfig
	if err := json.Unmarshal(data, &configs); err != nil {
		return 0, fmt.Errorf("providers: parse config: %w", err)
	}

	for _, cfg := range configs {
		p, err := buildProvider(cfg, credResolver)
		if err != nil {
			return 0, fmt.Errorf("providers: build %q: %w", cfg.Name, err)
		}
		if err := registry.Register(p); err != nil {
			return 0, fmt.Errorf("providers: register %q: %w", cfg.Name, err)
		}
	}

	return len(configs), nil
}

func buildProvider(cfg ProviderConfig, credResolver *grants.CredentialResolver) (CredentialProvider, error) {
	switch cfg.Type {
	case "static":
		ref := cfg.Config["credential_ref"]
		if ref == "" {
			return nil, fmt.Errorf("static provider requires config.credential_ref")
		}
		return NewStaticProvider(cfg.Name, credResolver, ref, cfg.Hosts), nil

	case "delegated":
		return NewDelegatedProvider(cfg.Name, cfg.Hosts), nil

	default:
		return nil, fmt.Errorf("unknown provider type %q", cfg.Type)
	}
}
