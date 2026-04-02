package grants

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// CredentialResolver resolves credential references to their actual values.
type CredentialResolver struct {
	db *sql.DB // optional, for stored: refs
}

// NewCredentialResolver creates a new resolver. The db parameter is optional
// and only required for stored: refs.
func NewCredentialResolver(db *sql.DB) *CredentialResolver {
	return &CredentialResolver{db: db}
}

// Resolve looks up the actual credential value from a reference string.
// Supported schemes:
//   - env:VAR_NAME       → os.Getenv(VAR_NAME)
//   - literal:value      → value (for testing only)
//   - stored:id          → look up from credential_records table
//   - sm:project/secret  → fetch from GCP Secret Manager (latest version)
func (r *CredentialResolver) Resolve(ctx context.Context, ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("credential: empty reference")
	}

	scheme, value, ok := strings.Cut(ref, ":")
	if !ok {
		return "", fmt.Errorf("credential: invalid reference format %q (expected scheme:value)", ref)
	}

	switch scheme {
	case "env":
		v := os.Getenv(value)
		if v == "" {
			return "", fmt.Errorf("credential: env var %q is empty or not set", value)
		}
		return v, nil

	case "literal":
		return value, nil

	case "stored":
		if r.db == nil {
			return "", fmt.Errorf("credential: stored refs require a database connection")
		}
		var credValue string
		err := r.db.QueryRowContext(ctx,
			"SELECT credential_value FROM credential_records WHERE id = ?", value,
		).Scan(&credValue)
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("credential: stored credential %q not found", value)
		}
		if err != nil {
			return "", fmt.Errorf("credential: query stored credential: %w", err)
		}
		return credValue, nil

	case "sm":
		return r.resolveSecretManager(ctx, value)

	default:
		return "", fmt.Errorf("credential: unknown scheme %q", scheme)
	}
}

// resolveSecretManager fetches a secret from GCP Secret Manager.
// Format: sm:PROJECT_ID/SECRET_NAME or sm:PROJECT_ID/SECRET_NAME/VERSION
func (r *CredentialResolver) resolveSecretManager(ctx context.Context, ref string) (string, error) {
	parts := strings.SplitN(ref, "/", 3)
	if len(parts) < 2 {
		return "", fmt.Errorf("credential: sm ref must be sm:PROJECT/SECRET or sm:PROJECT/SECRET/VERSION, got %q", ref)
	}

	project := parts[0]
	secret := parts[1]
	version := "latest"
	if len(parts) == 3 {
		version = parts[2]
	}

	url := fmt.Sprintf(
		"https://secretmanager.googleapis.com/v1/projects/%s/secrets/%s/versions/%s:access",
		project, secret, version,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("credential: sm create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("credential: sm API call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("credential: sm API returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Payload struct {
			Data string `json:"data"` // base64-encoded
		} `json:"payload"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("credential: sm decode response: %w", err)
	}

	// Secret Manager returns data as base64
	decoded, err := decodeBase64(result.Payload.Data)
	if err != nil {
		return "", fmt.Errorf("credential: sm decode payload: %w", err)
	}

	return decoded, nil
}

func decodeBase64(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
