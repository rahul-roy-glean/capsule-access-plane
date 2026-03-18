package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOpen_CreatesTablesAndMigrates(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	ctx := context.Background()
	s, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Verify grants table exists
	var count int
	err = s.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='grants'",
	).Scan(&count)
	if err != nil {
		t.Fatalf("query grants table: %v", err)
	}
	if count != 1 {
		t.Errorf("grants table count = %d, want 1", count)
	}

	// Verify credential_records table exists
	err = s.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='credential_records'",
	).Scan(&count)
	if err != nil {
		t.Fatalf("query credential_records table: %v", err)
	}
	if count != 1 {
		t.Errorf("credential_records table count = %d, want 1", count)
	}

	// Verify schema_migrations recorded the migration
	err = s.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM schema_migrations",
	).Scan(&count)
	if err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if count < 1 {
		t.Errorf("schema_migrations count = %d, want >= 1", count)
	}
}

func TestOpen_IdempotentMigrations(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	ctx := context.Background()

	// Open twice — second open should not fail on already-applied migrations.
	s1, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	_ = s1.Close()

	s2, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer func() { _ = s2.Close() }()

	var count int
	err = s2.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count < 1 {
		t.Errorf("schema_migrations count = %d, want >= 1", count)
	}
}

func TestOpen_InvalidPath(t *testing.T) {
	ctx := context.Background()
	// Opening a path inside a non-existent directory should fail.
	_, err := Open(ctx, "/nonexistent/dir/test.db")
	if err == nil {
		t.Fatal("expected error for invalid path, got nil")
	}
}

func TestClose(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	ctx := context.Background()

	s, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// DB should be unusable after close
	err = s.DB().PingContext(ctx)
	if err == nil {
		t.Error("expected error after Close, got nil")
	}
}

func TestDB_ReturnsUsableConnection(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	ctx := context.Background()

	s, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	db := s.DB()
	if db == nil {
		t.Fatal("DB() returned nil")
	}

	// Should be able to insert and query
	_, err = db.ExecContext(ctx,
		"INSERT INTO grants (id, lane, tool_family, session_id, runner_id, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
		"test-grant-1", "direct_http", "github_rest", "s1", "r1", "2099-01-01T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	var id string
	err = db.QueryRowContext(ctx, "SELECT id FROM grants WHERE id = ?", "test-grant-1").Scan(&id)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if id != "test-grant-1" {
		t.Errorf("id = %q, want test-grant-1", id)
	}
}

func TestOpen_WALMode(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	ctx := context.Background()

	s, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	var mode string
	err = s.DB().QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode)
	if err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
}

// Verify .db files are cleaned up by .gitignore (existence check only)
func TestTempDB_Cleanup(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "temp.db")

	ctx := context.Background()
	s, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = s.Close()

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("database file should exist after Open")
	}
}
