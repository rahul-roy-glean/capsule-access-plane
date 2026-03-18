package grants

import (
	"context"
	"database/sql"
	"fmt"
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
//   - env:VAR_NAME   → os.Getenv(VAR_NAME)
//   - literal:value  → value (for testing only)
//   - stored:id      → look up from credential_records table
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

	default:
		return "", fmt.Errorf("credential: unknown scheme %q", scheme)
	}
}
