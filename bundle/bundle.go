package bundle

import (
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
)

// ProjectionBundle is the complete payload delivered to a runner
// when a grant is projected. It contains everything the runner-side
// adapter needs to install a credential lane.
type ProjectionBundle struct {
	Version             string                   `json:"version"`
	GrantID             string                   `json:"grant_id"`
	Lane                accessplane.Lane         `json:"lane"`
	ExpiresAt           time.Time                `json:"expires_at"`
	AuditMetadata       AuditMetadata            `json:"audit_metadata"`
	NetworkRestrictions *NetworkRestrictions     `json:"network_restrictions,omitempty"`
	ProxyConfig         *ProxyConfig             `json:"proxy_config,omitempty"`
	HelperConfig        *HelperConfig            `json:"helper_config,omitempty"`
	MetadataEmulation   *MetadataEmulationConfig `json:"metadata_emulation,omitempty"`
}

// AuditMetadata carries the identity context needed to produce an
// audit trail on the runner side.
type AuditMetadata struct {
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
	RunnerID  string `json:"runner_id"`
	TurnID    string `json:"turn_id,omitempty"`
	AgentID   string `json:"agent_id,omitempty"`
}

// NetworkRestrictions limits outbound connectivity for a projected grant.
type NetworkRestrictions struct {
	AllowedCIDRs []string `json:"allowed_cidrs,omitempty"`
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
	AllowedPorts []int    `json:"allowed_ports,omitempty"`
}

// ProxyConfig describes how the runner should set up a forward proxy
// for the direct_http lane.
type ProxyConfig struct {
	ListenAddr string `json:"listen_addr"`
	TargetURL  string `json:"target_url"`
}

// HelperConfig describes how the runner should set up a credential
// helper for the helper_session lane.
type HelperConfig struct {
	Format     string            `json:"format"`
	SocketPath string            `json:"socket_path"`
	Env        map[string]string `json:"env,omitempty"`
}

// MetadataEmulationConfig describes how the runner should emulate a
// cloud metadata endpoint for the remote_execution lane.
type MetadataEmulationConfig struct {
	Endpoint string            `json:"endpoint"`
	Headers  map[string]string `json:"headers,omitempty"`
}
