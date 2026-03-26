package providers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// JWTSource produces a signed JWT for token exchange.
type JWTSource interface {
	// MintJWT returns a signed JWT string.
	MintJWT(ctx context.Context) (string, error)
}

// GCPIAMSource mints JWTs via GCP IAM generateIdToken (existing behavior).
type GCPIAMSource struct {
	ServiceAccount string
	Audience       string
	HTTPClientFunc func(ctx context.Context) HTTPClient
}

func (s *GCPIAMSource) MintJWT(ctx context.Context) (string, error) {
	client := s.HTTPClientFunc(ctx)
	return generateIDToken(ctx, client, s.ServiceAccount, s.Audience)
}

// LocalKeySource signs JWTs with an RSA private key (e.g. GitHub App).
type LocalKeySource struct {
	Issuer     string // JWT "iss" claim (e.g. GitHub App ID)
	PrivateKey *rsa.PrivateKey
}

func (s *LocalKeySource) MintJWT(_ context.Context) (string, error) {
	now := time.Now()
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"iss": s.Issuer,
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("jwt header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jwt claims: %w", err)
	}

	unsigned := base64url(headerJSON) + "." + base64url(claimsJSON)
	hash := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.PrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("jwt sign: %w", err)
	}

	return unsigned + "." + base64url(sig), nil
}

// ParseRSAPrivateKey parses a PEM-encoded RSA private key (PKCS1 or PKCS8).
func ParseRSAPrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	// Try PKCS8 first (broader), then PKCS1.
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("PKCS8 key is not RSA")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return key, nil
}

func base64url(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}
