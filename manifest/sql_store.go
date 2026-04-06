package manifest

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// FamilyStore provides SQLite-backed CRUD for dynamic families.
type FamilyStore struct {
	db *sql.DB
}

// NewFamilyStore creates a FamilyStore using the given database connection.
func NewFamilyStore(db *sql.DB) *FamilyStore {
	return &FamilyStore{db: db}
}

// Upsert inserts or updates a dynamic family manifest.
func (s *FamilyStore) Upsert(ctx context.Context, m *ToolManifest) error {
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("family store: marshal manifest: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO families (family, manifest_json, source)
		VALUES (?, ?, 'api')
		ON CONFLICT (family) DO UPDATE SET
			manifest_json = excluded.manifest_json,
			updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
	`, m.Family, string(data))
	return err
}

// Delete removes a dynamic family by name.
func (s *FamilyStore) Delete(ctx context.Context, family string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM families WHERE family = ?`, family)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("family not found: %s", family)
	}
	return nil
}

// List returns all persisted dynamic families.
func (s *FamilyStore) List(ctx context.Context) ([]*ToolManifest, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT manifest_json FROM families ORDER BY family`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*ToolManifest
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var m ToolManifest
		if err := json.Unmarshal([]byte(data), &m); err != nil {
			continue
		}
		result = append(result, &m)
	}
	return result, nil
}
