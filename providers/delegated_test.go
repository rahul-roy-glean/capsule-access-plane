package providers

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDelegatedProvider_NoToken(t *testing.T) {
	p := NewDelegatedProvider("test", []string{"api.example.com"})
	_, err := p.ResolveToken(context.Background())
	if err == nil {
		t.Fatal("expected error when no token pushed")
	}
}

func TestDelegatedProvider_GlobalPushAndResolve(t *testing.T) {
	p := NewDelegatedProvider("test", nil)
	p.UpdateToken("", &SessionToken{Token: "global-tok", ExpiresAt: time.Now().Add(time.Hour)})

	if !p.HasToken() {
		t.Fatal("HasToken should be true")
	}
	tok, err := p.ResolveToken(context.Background())
	if err != nil {
		t.Fatalf("ResolveToken: %v", err)
	}
	if tok != "global-tok" {
		t.Errorf("token = %q", tok)
	}
}

func TestDelegatedProvider_SessionScoped(t *testing.T) {
	p := NewDelegatedProvider("test", nil)
	p.UpdateToken("10.0.0.1", &SessionToken{Token: "alice", ExpiresAt: time.Now().Add(time.Hour)})
	p.UpdateToken("10.0.0.2", &SessionToken{Token: "bob", ExpiresAt: time.Now().Add(time.Hour)})

	ctx1 := WithSourceIP(context.Background(), "10.0.0.1")
	tok1, _ := p.ResolveToken(ctx1)
	if tok1 != "alice" {
		t.Errorf("alice = %q", tok1)
	}

	ctx2 := WithSourceIP(context.Background(), "10.0.0.2")
	tok2, _ := p.ResolveToken(ctx2)
	if tok2 != "bob" {
		t.Errorf("bob = %q", tok2)
	}
}

func TestDelegatedProvider_SessionFallsBackToGlobal(t *testing.T) {
	p := NewDelegatedProvider("test", nil)
	p.UpdateToken("", &SessionToken{Token: "fallback", ExpiresAt: time.Now().Add(time.Hour)})

	ctx := WithSourceIP(context.Background(), "10.0.0.99")
	tok, _ := p.ResolveToken(ctx)
	if tok != "fallback" {
		t.Errorf("token = %q", tok)
	}
}

func TestDelegatedProvider_ExpiredSessionToken(t *testing.T) {
	p := NewDelegatedProvider("test", nil)
	p.UpdateToken("10.0.0.1", &SessionToken{Token: "old", ExpiresAt: time.Now().Add(-time.Minute)})

	ctx := WithSourceIP(context.Background(), "10.0.0.1")
	_, err := p.ResolveToken(ctx)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestDelegatedProvider_InjectIdentityHeaders(t *testing.T) {
	p := NewDelegatedProvider("test", nil)
	p.UpdateToken("10.0.0.1", &SessionToken{
		Token:        "tok",
		ExpiresAt:    time.Now().Add(time.Hour),
		UserEmail:    "alice@glean.com",
		ExtraHeaders: map[string]string{"X-Agent": "a1"},
	})

	req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
	req = req.WithContext(WithSourceIP(req.Context(), "10.0.0.1"))
	_ = p.InjectCredentials(req)

	if req.Header.Get("Authorization") != "Bearer tok" {
		t.Errorf("Authorization = %q", req.Header.Get("Authorization"))
	}
	if req.Header.Get("X-Glean-User-Email") != "alice@glean.com" {
		t.Errorf("X-Glean-User-Email = %q", req.Header.Get("X-Glean-User-Email"))
	}
	if req.Header.Get("X-Agent") != "a1" {
		t.Errorf("X-Agent = %q", req.Header.Get("X-Agent"))
	}
}

func TestDelegatedProvider_MultiCredential_Rules(t *testing.T) {
	p := NewDelegatedProvider("slack", []string{"api.slack.com"})
	p.UpdateToken("", &SessionToken{
		ExpiresAt: time.Now().Add(time.Hour),
		Credentials: map[string]string{
			"read":  "read-token",
			"write": "write-token",
		},
		Rules: []CredentialRule{
			{Methods: []string{"GET"}, CredentialKey: "read"},
			{Methods: []string{"POST", "PUT"}, CredentialKey: "write"},
		},
	})

	// GET request → read token.
	req1 := httptest.NewRequest("GET", "https://api.slack.com/api/conversations.list", nil)
	_ = p.InjectCredentials(req1)
	if req1.Header.Get("Authorization") != "Bearer read-token" {
		t.Errorf("GET auth = %q, want read-token", req1.Header.Get("Authorization"))
	}

	// POST request → write token.
	req2 := httptest.NewRequest("POST", "https://api.slack.com/api/chat.postMessage", nil)
	_ = p.InjectCredentials(req2)
	if req2.Header.Get("Authorization") != "Bearer write-token" {
		t.Errorf("POST auth = %q, want write-token", req2.Header.Get("Authorization"))
	}
}

func TestDelegatedProvider_MultiCredential_PathRules(t *testing.T) {
	p := NewDelegatedProvider("gcp", []string{"compute.googleapis.com"})
	p.UpdateToken("", &SessionToken{
		ExpiresAt: time.Now().Add(time.Hour),
		Credentials: map[string]string{
			"viewer": "viewer-token",
			"editor": "editor-token",
		},
		Rules: []CredentialRule{
			{Methods: []string{"GET"}, PathPatterns: []string{"/compute/v1/**"}, CredentialKey: "viewer"},
			{Methods: []string{"POST", "DELETE"}, PathPatterns: []string{"/compute/v1/**"}, CredentialKey: "editor"},
		},
	})

	req1 := httptest.NewRequest("GET", "https://compute.googleapis.com/compute/v1/projects/p/instances", nil)
	_ = p.InjectCredentials(req1)
	if req1.Header.Get("Authorization") != "Bearer viewer-token" {
		t.Errorf("GET auth = %q", req1.Header.Get("Authorization"))
	}

	req2 := httptest.NewRequest("DELETE", "https://compute.googleapis.com/compute/v1/projects/p/instances/i", nil)
	_ = p.InjectCredentials(req2)
	if req2.Header.Get("Authorization") != "Bearer editor-token" {
		t.Errorf("DELETE auth = %q", req2.Header.Get("Authorization"))
	}
}

func TestDelegatedProvider_MultiCredential_FallbackToDefault(t *testing.T) {
	p := NewDelegatedProvider("test", nil)
	p.UpdateToken("", &SessionToken{
		Token:     "default-tok",
		ExpiresAt: time.Now().Add(time.Hour),
		Credentials: map[string]string{
			"special": "special-tok",
		},
		Rules: []CredentialRule{
			{Methods: []string{"DELETE"}, CredentialKey: "special"},
		},
	})

	// GET doesn't match any rule → falls back to Token.
	req := httptest.NewRequest("GET", "https://api.example.com/test", nil)
	_ = p.InjectCredentials(req)
	if req.Header.Get("Authorization") != "Bearer default-tok" {
		t.Errorf("auth = %q, want default-tok", req.Header.Get("Authorization"))
	}
}

func TestDelegatedProvider_RevokeSession(t *testing.T) {
	p := NewDelegatedProvider("test", nil)
	p.UpdateToken("10.0.0.1", &SessionToken{Token: "tok", ExpiresAt: time.Now().Add(time.Hour)})
	p.RevokeSession("10.0.0.1")

	ctx := WithSourceIP(context.Background(), "10.0.0.1")
	_, err := p.ResolveToken(ctx)
	if err == nil {
		t.Fatal("expected error after revocation")
	}
}

var _ CredentialProvider = (*DelegatedProvider)(nil)
