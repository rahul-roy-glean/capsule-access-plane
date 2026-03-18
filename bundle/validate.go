package bundle

import (
	"fmt"
	"strings"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
)

// tokenPrefixes are string prefixes that indicate a value is likely
// a secret token and should never appear in a projection bundle.
var tokenPrefixes = []string{
	"ghp_",
	"gho_",
	"Bearer ",
	"ya29.",
	"AKIA",
	"xox",
}

// Validate checks a ProjectionBundle for structural correctness and
// rejects bundles that contain secret material.
func Validate(bundle *ProjectionBundle) error {
	if bundle.Version == "" {
		return fmt.Errorf("bundle: version is required")
	}
	if bundle.Version != "v1" {
		return fmt.Errorf("bundle: unsupported version %q", bundle.Version)
	}
	if bundle.GrantID == "" {
		return fmt.Errorf("bundle: grant_id is required")
	}
	if bundle.Lane == "" {
		return fmt.Errorf("bundle: lane is required")
	}
	if !accessplane.ValidLanes[bundle.Lane] {
		return fmt.Errorf("bundle: invalid lane %q", bundle.Lane)
	}
	if bundle.ExpiresAt.IsZero() {
		return fmt.Errorf("bundle: expires_at is required")
	}

	// Audit metadata required fields.
	if bundle.AuditMetadata.UserID == "" {
		return fmt.Errorf("bundle: audit_metadata.user_id is required")
	}
	if bundle.AuditMetadata.SessionID == "" {
		return fmt.Errorf("bundle: audit_metadata.session_id is required")
	}
	if bundle.AuditMetadata.RunnerID == "" {
		return fmt.Errorf("bundle: audit_metadata.runner_id is required")
	}

	// Scan all string fields for token-like patterns.
	if err := checkForSecrets(bundle); err != nil {
		return err
	}

	return nil
}

// checkForSecrets scans the bundle's string fields for patterns that
// look like embedded credentials or tokens.
func checkForSecrets(b *ProjectionBundle) error {
	fields := map[string]string{
		"grant_id":                 b.GrantID,
		"audit_metadata.user_id":  b.AuditMetadata.UserID,
		"audit_metadata.session_id": b.AuditMetadata.SessionID,
		"audit_metadata.runner_id":  b.AuditMetadata.RunnerID,
		"audit_metadata.turn_id":    b.AuditMetadata.TurnID,
		"audit_metadata.agent_id":   b.AuditMetadata.AgentID,
	}

	if b.ProxyConfig != nil {
		fields["proxy_config.listen_addr"] = b.ProxyConfig.ListenAddr
		fields["proxy_config.target_url"] = b.ProxyConfig.TargetURL
	}
	if b.HelperConfig != nil {
		fields["helper_config.format"] = b.HelperConfig.Format
		fields["helper_config.socket_path"] = b.HelperConfig.SocketPath
		for k, v := range b.HelperConfig.Env {
			fields[fmt.Sprintf("helper_config.env[%s]", k)] = v
		}
	}
	if b.MetadataEmulation != nil {
		fields["metadata_emulation.endpoint"] = b.MetadataEmulation.Endpoint
		for k, v := range b.MetadataEmulation.Headers {
			fields[fmt.Sprintf("metadata_emulation.headers[%s]", k)] = v
		}
	}

	for field, value := range fields {
		if looksLikeToken(value) {
			return fmt.Errorf("bundle: field %q contains what looks like a secret token", field)
		}
	}
	return nil
}

// looksLikeToken returns true if the value starts with a known
// credential prefix.
func looksLikeToken(s string) bool {
	for _, prefix := range tokenPrefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}
