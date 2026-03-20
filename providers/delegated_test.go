package providers

import (
	"context"
	"testing"
	"time"
)

func TestDelegatedProvider_NoToken(t *testing.T) {
	p := NewDelegatedProvider("test", []string{"api.example.com"})

	_, err := p.ResolveToken(context.Background())
	if err == nil {
		t.Fatal("expected error when no token pushed")
	}
	if p.HasToken() {
		t.Error("HasToken should be false before push")
	}
}

func TestDelegatedProvider_PushAndResolve(t *testing.T) {
	p := NewDelegatedProvider("test", []string{"api.example.com"})

	p.UpdateToken("my-token", time.Now().Add(time.Hour))

	if !p.HasToken() {
		t.Error("HasToken should be true after push")
	}

	token, err := p.ResolveToken(context.Background())
	if err != nil {
		t.Fatalf("ResolveToken: %v", err)
	}
	if token != "my-token" {
		t.Errorf("token = %q, want my-token", token)
	}
}

func TestDelegatedProvider_ExpiredToken(t *testing.T) {
	p := NewDelegatedProvider("test", nil)

	p.UpdateToken("old-token", time.Now().Add(-time.Minute))

	_, err := p.ResolveToken(context.Background())
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestDelegatedProvider_TokenReplacement(t *testing.T) {
	p := NewDelegatedProvider("test", nil)

	p.UpdateToken("first", time.Now().Add(time.Hour))
	p.UpdateToken("second", time.Now().Add(time.Hour))

	token, err := p.ResolveToken(context.Background())
	if err != nil {
		t.Fatalf("ResolveToken: %v", err)
	}
	if token != "second" {
		t.Errorf("token = %q, want second", token)
	}
}

func TestDelegatedProvider_Matches(t *testing.T) {
	p := NewDelegatedProvider("test", []string{"api.example.com"})

	if !p.Matches("api.example.com") {
		t.Error("should match api.example.com")
	}
	if p.Matches("evil.com") {
		t.Error("should not match evil.com")
	}

	// Empty hosts = matches everything.
	pAll := NewDelegatedProvider("all", nil)
	if !pAll.Matches("anything.com") {
		t.Error("empty hosts should match everything")
	}
}

func TestDelegatedProvider_NameType(t *testing.T) {
	p := NewDelegatedProvider("github", nil)
	if p.Name() != "github" {
		t.Errorf("Name() = %q", p.Name())
	}
	if p.Type() != "delegated" {
		t.Errorf("Type() = %q", p.Type())
	}
}

var _ CredentialProvider = (*DelegatedProvider)(nil)
