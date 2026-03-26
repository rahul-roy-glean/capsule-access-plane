// store-credential inserts or updates a credential record in the access-plane SQLite database.
//
// Usage:
//
//	go run ./cmd/store-credential --id github-app-key --type pem --file /path/to/private-key.pem
//	go run ./cmd/store-credential --id github-app-key --type pem --value "literal value"
//	go run ./cmd/store-credential --id my-token --type api-token --value "ghp_xxxx"
//	go run ./cmd/store-credential --db /path/to/capsule-access.db --id github-app-key --type pem --file key.pem
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rahul-roy-glean/capsule-access-plane/store"
)

func main() {
	var (
		dbURL  = flag.String("db", "capsule-access.db", "path to the SQLite database")
		id     = flag.String("id", "", "credential record ID (used in stored:<id> refs)")
		ctype  = flag.String("type", "", "credential type (e.g. pem, api-token, oauth-secret)")
		file   = flag.String("file", "", "read credential value from this file")
		value  = flag.String("value", "", "credential value (use --file for large values)")
		remove = flag.Bool("rm", false, "remove the credential instead of inserting")
		list   = flag.Bool("list", false, "list all credential IDs")
	)
	flag.Parse()

	ctx := context.Background()
	s, err := store.Open(ctx, *dbURL)
	if err != nil {
		fatal("open database: %v", err)
	}
	defer s.Close()

	if *list {
		listCredentials(ctx, s)
		return
	}

	if *id == "" {
		fatal("--id is required")
	}

	if *remove {
		removeCredential(ctx, s, *id)
		return
	}

	credValue := resolveValue(*file, *value)
	if credValue == "" {
		fatal("provide --file or --value")
	}
	if *ctype == "" {
		fatal("--type is required")
	}

	upsertCredential(ctx, s, *id, *ctype, credValue)
}

func resolveValue(filePath, literal string) string {
	if filePath != "" && literal != "" {
		fatal("provide --file or --value, not both")
	}
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			fatal("read file: %v", err)
		}
		return strings.TrimSpace(string(data))
	}
	return literal
}

func upsertCredential(ctx context.Context, s *store.Store, id, ctype, value string) {
	_, err := s.DB().ExecContext(ctx, `
		INSERT INTO credential_records (id, credential_type, credential_value)
		VALUES (?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			credential_type = excluded.credential_type,
			credential_value = excluded.credential_value,
			updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
	`, id, ctype, value)
	if err != nil {
		fatal("upsert credential: %v", err)
	}
	fmt.Printf("stored credential %q (type=%s, %d bytes)\n", id, ctype, len(value))
}

func removeCredential(ctx context.Context, s *store.Store, id string) {
	res, err := s.DB().ExecContext(ctx, `DELETE FROM credential_records WHERE id = ?`, id)
	if err != nil {
		fatal("delete credential: %v", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		fmt.Printf("credential %q not found\n", id)
	} else {
		fmt.Printf("removed credential %q\n", id)
	}
}

func listCredentials(ctx context.Context, s *store.Store) {
	rows, err := s.DB().QueryContext(ctx, `
		SELECT id, credential_type, length(credential_value), created_at, updated_at
		FROM credential_records ORDER BY id
	`)
	if err != nil {
		fatal("list credentials: %v", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var id, ctype, createdAt, updatedAt string
		var size int
		if err := rows.Scan(&id, &ctype, &size, &createdAt, &updatedAt); err != nil {
			fatal("scan row: %v", err)
		}
		fmt.Printf("%-30s type=%-12s size=%-6d updated=%s\n", id, ctype, size, updatedAt)
		count++
	}
	if count == 0 {
		fmt.Println("no credentials stored")
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
