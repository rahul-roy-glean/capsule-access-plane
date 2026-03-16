package identity

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	RunnerID    string `json:"runner_id"`
	SessionID   string `json:"session_id"`
	WorkloadKey string `json:"workload_key"`
	HostID      string `json:"host_id"`
	jwt.RegisteredClaims
}

type Verifier struct {
	secret []byte
}

func NewVerifier(secret string) *Verifier {
	return &Verifier{secret: []byte(secret)}
}

func (v *Verifier) Verify(attestation string) (*Claims, error) {
	if attestation == "" {
		return nil, fmt.Errorf("runner_attestation is required")
	}

	token, err := jwt.ParseWithClaims(attestation, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}
		return v.secret, nil
	}, jwt.WithLeeway(10*time.Second))
	if err != nil {
		return nil, fmt.Errorf("verify attestation: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid attestation claims")
	}
	if claims.RunnerID == "" || claims.SessionID == "" || claims.WorkloadKey == "" {
		return nil, fmt.Errorf("attestation missing runner/session/workload fields")
	}
	return claims, nil
}
