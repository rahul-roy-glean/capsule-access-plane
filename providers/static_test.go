package providers

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/rahul-roy-glean/capsule-access-plane/grants"
	"github.com/rahul-roy-glean/capsule-access-plane/store"
)

func TestStaticProvider_ResolveToken_Env(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s.Close() }()

	t.Setenv("STATIC_TEST_TOKEN", "my-secret-token")

	credResolver := grants.NewCredentialResolver(s.DB())
	p := NewStaticProvider("test", credResolver, "env:STATIC_TEST_TOKEN", []string{"api.github.com"})

	if p.Name() != "test" {
		t.Errorf("Name() = %q, want test", p.Name())
	}
	if p.Type() != "static" {
		t.Errorf("Type() = %q, want static", p.Type())
	}

	token, err := p.ResolveToken(ctx)
	if err != nil {
		t.Fatalf("ResolveToken: %v", err)
	}
	if token != "my-secret-token" {
		t.Errorf("token = %q, want my-secret-token", token)
	}
}

func TestStaticProvider_ResolveToken_Literal(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s.Close() }()

	credResolver := grants.NewCredentialResolver(s.DB())
	p := NewStaticProvider("lit", credResolver, "literal:my-literal-token", nil)

	token, err := p.ResolveToken(ctx)
	if err != nil {
		t.Fatalf("ResolveToken: %v", err)
	}
	if token != "my-literal-token" {
		t.Errorf("token = %q, want my-literal-token", token)
	}
}

func TestStaticProvider_Matches(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s.Close() }()

	credResolver := grants.NewCredentialResolver(s.DB())

	// Provider with specific hosts.
	p := NewStaticProvider("gh", credResolver, "literal:tok", []string{"api.github.com"})
	if !p.Matches("api.github.com") {
		t.Error("expected match for api.github.com")
	}
	if p.Matches("evil.com") {
		t.Error("expected no match for evil.com")
	}

	// Default provider (no hosts) matches everything.
	def := NewStaticProvider("default", credResolver, "literal:tok", nil)
	if !def.Matches("anything.example.com") {
		t.Error("default provider should match any host")
	}
}

func TestStaticProvider_InjectCredentials(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s.Close() }()

	credResolver := grants.NewCredentialResolver(s.DB())
	p := NewStaticProvider("test", credResolver, "literal:inject-token", nil)

	req := httptest.NewRequest("GET", "https://api.github.com/repos", nil)
	if err := p.InjectCredentials(req); err != nil {
		t.Fatalf("InjectCredentials: %v", err)
	}

	got := req.Header.Get("Authorization")
	want := "Bearer inject-token"
	if got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
}

func TestStaticProvider_StartStop(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s.Close() }()

	credResolver := grants.NewCredentialResolver(s.DB())
	p := NewStaticProvider("test", credResolver, "literal:tok", nil)

	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	p.Stop() // no-op, should not panic
}

// Ensure StaticProvider implements CredentialProvider.
var _ CredentialProvider = (*StaticProvider)(nil)
