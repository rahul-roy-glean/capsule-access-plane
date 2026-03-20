package providers

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rahul-roy-glean/capsule-access-plane/grants"
	"github.com/rahul-roy-glean/capsule-access-plane/store"
)

func TestLoadFromFile_StaticAndDelegated(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s.Close() }()

	credResolver := grants.NewCredentialResolver(s.DB())
	t.Setenv("LOADER_TEST_TOKEN", "loaded-secret")

	configJSON := `[
		{
			"name": "gh",
			"type": "static",
			"hosts": ["api.github.com"],
			"config": {"credential_ref": "env:LOADER_TEST_TOKEN"}
		},
		{
			"name": "pushed",
			"type": "delegated",
			"hosts": ["api.internal.com"]
		}
	]`

	dir := t.TempDir()
	path := filepath.Join(dir, "providers.json")
	if err := os.WriteFile(path, []byte(configJSON), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	reg := NewRegistry()
	n, err := LoadFromFile(path, reg, credResolver)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if n != 2 {
		t.Errorf("loaded %d providers, want 2", n)
	}

	// Verify static provider.
	gh, err := reg.Get("gh")
	if err != nil {
		t.Fatalf("get gh: %v", err)
	}
	if gh.Type() != "static" {
		t.Errorf("gh type = %q", gh.Type())
	}
	token, err := gh.ResolveToken(ctx)
	if err != nil {
		t.Fatalf("gh ResolveToken: %v", err)
	}
	if token != "loaded-secret" {
		t.Errorf("token = %q, want loaded-secret", token)
	}

	// Verify delegated provider.
	pushed, err := reg.Get("pushed")
	if err != nil {
		t.Fatalf("get pushed: %v", err)
	}
	if pushed.Type() != "delegated" {
		t.Errorf("pushed type = %q", pushed.Type())
	}
	if !pushed.Matches("api.internal.com") {
		t.Error("pushed should match api.internal.com")
	}
}

func TestLoadFromFile_UnknownType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`[{"name":"x","type":"magic"}]`), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s.Close() }()

	reg := NewRegistry()
	_, err = LoadFromFile(path, reg, grants.NewCredentialResolver(s.DB()))
	if err == nil {
		t.Fatal("expected error for unknown provider type")
	}
}

func TestLoadFromFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`not json`), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s.Close() }()

	reg := NewRegistry()
	_, err = LoadFromFile(path, reg, grants.NewCredentialResolver(s.DB()))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
