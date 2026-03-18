package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// SignClaims produces an HMAC-SHA256 signed token from the given claims.
// Format: base64(json_payload).base64(hmac_signature)
func SignClaims(claims *Claims, secret []byte) (string, error) {
	if len(secret) == 0 {
		return "", fmt.Errorf("identity: secret must not be empty")
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("identity: marshal claims: %w", err)
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	sig := mac.Sum(nil)

	token := base64.RawURLEncoding.EncodeToString(payload) +
		"." +
		base64.RawURLEncoding.EncodeToString(sig)

	return token, nil
}
