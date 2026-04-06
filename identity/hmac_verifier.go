package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// HMACVerifier validates runner attestation tokens signed with HMAC-SHA256.
type HMACVerifier struct {
	secret   []byte
	tenantID string // if non-empty, verify token tenant_id matches
}

// NewHMACVerifier creates a verifier with the given shared secret.
// Returns an error if the secret is empty.
func NewHMACVerifier(secret []byte) (*HMACVerifier, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("identity: secret must not be empty")
	}
	return &HMACVerifier{secret: secret}, nil
}

// WithTenantID returns a copy of the verifier that also validates the token's
// tenant_id matches the given value. If tenantID is empty, no tenant validation
// is performed.
func (v *HMACVerifier) WithTenantID(tenantID string) *HMACVerifier {
	return &HMACVerifier{secret: v.secret, tenantID: tenantID}
}

// Verify validates the attestation token and returns the embedded claims.
func (v *HMACVerifier) Verify(attestation string) (*Claims, error) {
	parts := strings.SplitN(attestation, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("identity: malformed token: expected 2 parts separated by '.'")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("identity: decode payload: %w", err)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("identity: decode signature: %w", err)
	}

	mac := hmac.New(sha256.New, v.secret)
	mac.Write(payloadBytes)
	expectedSig := mac.Sum(nil)

	if !hmac.Equal(sigBytes, expectedSig) {
		return nil, fmt.Errorf("identity: invalid signature")
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("identity: unmarshal claims: %w", err)
	}

	now := time.Now()

	if !claims.ExpiresAt.IsZero() && now.After(claims.ExpiresAt) {
		return nil, fmt.Errorf("identity: token expired")
	}

	if !claims.NotBefore.IsZero() && now.Before(claims.NotBefore) {
		return nil, fmt.Errorf("identity: token not yet valid")
	}

	if claims.RunnerID == "" {
		return nil, fmt.Errorf("identity: missing required field: runner_id")
	}
	if claims.SessionID == "" {
		return nil, fmt.Errorf("identity: missing required field: session_id")
	}
	if claims.WorkloadKey == "" {
		return nil, fmt.Errorf("identity: missing required field: workload_key")
	}

	if v.tenantID != "" && claims.TenantID != v.tenantID {
		return nil, fmt.Errorf("identity: tenant_id mismatch: token has %q, expected %q", claims.TenantID, v.tenantID)
	}

	return &claims, nil
}
