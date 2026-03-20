package providers

import (
	"context"
	"net/http"
	"testing"
)

// fakeProvider is a minimal CredentialProvider for testing.
type fakeProvider struct {
	name  string
	typ   string
	hosts []string
	token string
}

func (p *fakeProvider) Name() string { return p.name }
func (p *fakeProvider) Type() string { return p.typ }
func (p *fakeProvider) Matches(host string) bool {
	for _, h := range p.hosts {
		if h == host {
			return true
		}
	}
	return false
}
func (p *fakeProvider) InjectCredentials(req *http.Request) error {
	req.Header.Set("Authorization", "Bearer "+p.token)
	return nil
}
func (p *fakeProvider) ResolveToken(_ context.Context) (string, error) {
	return p.token, nil
}
func (p *fakeProvider) Start(_ context.Context) error { return nil }
func (p *fakeProvider) Stop()                         {}

func TestRegistry_RegisterAndGet(t *testing.T) {
	reg := NewRegistry()
	p := &fakeProvider{name: "github", typ: "static", token: "tok-1"}

	if err := reg.Register(p); err != nil {
		t.Fatalf("register: %v", err)
	}

	got, err := reg.Get("github")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name() != "github" {
		t.Errorf("name = %q, want github", got.Name())
	}
}

func TestRegistry_DuplicateRegister(t *testing.T) {
	reg := NewRegistry()
	p := &fakeProvider{name: "dup", typ: "static"}
	_ = reg.Register(p)

	err := reg.Register(p)
	if err == nil {
		t.Fatal("expected error for duplicate register")
	}
}

func TestRegistry_GetNotFound(t *testing.T) {
	reg := NewRegistry()
	_, err := reg.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing provider")
	}
}

func TestRegistry_ForManifest_Named(t *testing.T) {
	reg := NewRegistry()
	p := &fakeProvider{name: "github", typ: "static", token: "tok-gh"}
	_ = reg.Register(p)

	got, err := reg.ForManifest("github")
	if err != nil {
		t.Fatalf("ForManifest: %v", err)
	}
	if got.Name() != "github" {
		t.Errorf("name = %q, want github", got.Name())
	}
}

func TestRegistry_ForManifest_Default(t *testing.T) {
	reg := NewRegistry()
	def := &fakeProvider{name: "default", typ: "static", token: "tok-def"}
	reg.SetDefault(def)

	got, err := reg.ForManifest("")
	if err != nil {
		t.Fatalf("ForManifest: %v", err)
	}
	if got.Name() != "default" {
		t.Errorf("name = %q, want default", got.Name())
	}
}

func TestRegistry_ForManifest_NoDefault(t *testing.T) {
	reg := NewRegistry()
	_, err := reg.ForManifest("")
	if err == nil {
		t.Fatal("expected error when no default configured")
	}
}

func TestRegistry_ForHost(t *testing.T) {
	reg := NewRegistry()
	p := &fakeProvider{name: "github", typ: "static", hosts: []string{"api.github.com", "github.com"}}
	_ = reg.Register(p)

	got, ok := reg.ForHost("api.github.com")
	if !ok {
		t.Fatal("expected match for api.github.com")
	}
	if got.Name() != "github" {
		t.Errorf("name = %q, want github", got.Name())
	}

	_, ok = reg.ForHost("evil.example.com")
	if ok {
		t.Error("expected no match for evil.example.com")
	}
}

func TestRegistry_All(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&fakeProvider{name: "a", typ: "static"})
	_ = reg.Register(&fakeProvider{name: "b", typ: "static"})

	all := reg.All()
	if len(all) != 2 {
		t.Errorf("len(All()) = %d, want 2", len(all))
	}
}
