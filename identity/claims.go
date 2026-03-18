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
}
