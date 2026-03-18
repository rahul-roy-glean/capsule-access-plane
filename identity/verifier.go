package identity

// Verifier validates runner attestation tokens and extracts claims.
type Verifier interface {
	Verify(attestation string) (*Claims, error)
}
