package identity

import "time"

// Claims represents the attestation claims from a runner identity token.
type Claims struct {
	RunnerID      string    `json:"runner_id"`
	SessionID     string    `json:"session_id"`
	WorkloadKey   string    `json:"workload_key"`
	HostID        string    `json:"host_id"`
	BootEpoch     string    `json:"boot_epoch"`
	PolicyVersion string    `json:"policy_version"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	NotBefore     time.Time `json:"not_before,omitempty"`

	// TenantID identifies the tenant this runner belongs to.
	// Each access plane instance is scoped to a single tenant and validates
	// that the token's TenantID matches the instance's configured tenant.
	TenantID string `json:"tenant_id,omitempty"`

	// IdentityMode indicates how the agent's identity is resolved:
	//   "user-direct" (default) — agent acts on behalf of the requesting user.
	//   "virtual" — agent has its own persistent identity.
	IdentityMode string `json:"identity_mode,omitempty"`

	// UserEmail is the human user's email when IdentityMode is "user-direct".
	UserEmail string `json:"user_email,omitempty"`

	// VirtualIdentityID is the agent's own identity when IdentityMode is "virtual".
	VirtualIdentityID string `json:"virtual_identity_id,omitempty"`
}

// EffectiveIdentity returns the identity string for audit and policy purposes.
// For user-direct mode, this is the user email. For virtual mode, the virtual ID.
func (c *Claims) EffectiveIdentity() string {
	if c.IdentityMode == "virtual" && c.VirtualIdentityID != "" {
		return c.VirtualIdentityID
	}
	if c.UserEmail != "" {
		return c.UserEmail
	}
	return c.RunnerID
}
