package providers

// ProviderConfig describes a named credential provider loaded from config.
type ProviderConfig struct {
	Name   string            `json:"name" yaml:"name"`
	Type   string            `json:"type" yaml:"type"`
	Hosts  []string          `json:"hosts" yaml:"hosts"`
	Config map[string]string `json:"config" yaml:"config"`
}
