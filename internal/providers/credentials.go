package providers

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"
)

type CredentialResolver struct {
	db *sql.DB
}

func NewCredentialResolver(db *sql.DB) *CredentialResolver {
	return &CredentialResolver{db: db}
}

func (r *CredentialResolver) Resolve(ctx context.Context, ref string) (string, error) {
	switch {
	case ref == "":
		return "", nil
	case strings.HasPrefix(ref, "env:"):
		value := os.Getenv(strings.TrimPrefix(ref, "env:"))
		if value == "" {
			return "", fmt.Errorf("credential env ref %q resolved empty", ref)
		}
		return value, nil
	case strings.HasPrefix(ref, "literal:"):
		return strings.TrimPrefix(ref, "literal:"), nil
	case strings.HasPrefix(ref, "stored:"):
		return r.lookupStored(ctx, strings.TrimPrefix(ref, "stored:"))
	default:
		return "", fmt.Errorf("unsupported credential ref %q", ref)
	}
}

func (r *CredentialResolver) lookupStored(ctx context.Context, id string) (string, error) {
	var value string
	var expiresAt string
	err := r.db.QueryRowContext(ctx, `SELECT value, expires_at FROM credential_records WHERE id = ?`, id).Scan(&value, &expiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("stored credential %q not found", id)
		}
		return "", fmt.Errorf("lookup stored credential %q: %w", id, err)
	}
	if expiresAt != "" {
		expiry, err := time.Parse(time.RFC3339, expiresAt)
		if err == nil && time.Now().After(expiry) {
			return "", fmt.Errorf("stored credential %q expired at %s", id, expiresAt)
		}
	}
	return value, nil
}
