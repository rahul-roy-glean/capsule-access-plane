package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOAuthJWTBearerProvider_FullChain(t *testing.T) {
	// Mock IAM server — returns an identity token.
	iamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify it's a generateIdToken call.
		if !strings.Contains(r.URL.Path, "generateIdToken") {
			t.Errorf("unexpected IAM path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token": "eyJhbGciOiJSUzI1NiJ9.fake-id-token",
		})
	}))
	defer iamServer.Close()

	// Mock MCP OAuth server — accepts JWT bearer, returns access token.
	mcpOAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		gt := r.FormValue("grant_type")
		if gt != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("grant_type = %q", gt)
		}
		assertion := r.FormValue("assertion")
		if assertion == "" {
			t.Error("missing assertion")
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mcp-access-token-123",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer mcpOAuth.Close()

	p := NewOAuthJWTBearerProvider(
		"mcp-test",
		"test@proj.iam",
		"https://mcp.example.com",
		mcpOAuth.URL+"/oauth/token",
		[]string{"mcp.example.com"},
	)

	// Redirect IAM calls to mock.
	p.HTTPClient = &http.Client{
		Transport: &oauthExchangeTestTransport{
			iamTarget: iamServer.URL,
			fallback:  http.DefaultTransport,
		},
	}

	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	// Verify token was obtained.
	token, err := p.ResolveToken(ctx)
	if err != nil {
		t.Fatalf("ResolveToken: %v", err)
	}
	if token != "mcp-access-token-123" {
		t.Errorf("token = %q, want mcp-access-token-123", token)
	}
}

func TestOAuthJWTBearerProvider_InjectCredentials(t *testing.T) {
	iamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "fake-jwt"})
	}))
	defer iamServer.Close()

	mcpOAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "injected-mcp-token",
			"expires_in":   3600,
		})
	}))
	defer mcpOAuth.Close()

	p := NewOAuthJWTBearerProvider("test", "sa@proj.iam", "https://mcp.example.com", mcpOAuth.URL+"/token", nil)
	p.HTTPClient = &http.Client{Transport: &oauthExchangeTestTransport{iamTarget: iamServer.URL, fallback: http.DefaultTransport}}

	_ = p.Start(context.Background())
	defer p.Stop()

	req := httptest.NewRequest("POST", "https://mcp.example.com/mcp", nil)
	if err := p.InjectCredentials(req); err != nil {
		t.Fatalf("InjectCredentials: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer injected-mcp-token" {
		t.Errorf("Authorization = %q", got)
	}
}

func TestOAuthJWTBearerProvider_IAMFailure(t *testing.T) {
	iamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("permission denied"))
	}))
	defer iamServer.Close()

	p := NewOAuthJWTBearerProvider("test", "sa@proj.iam", "https://mcp.example.com", "http://unused/token", nil)
	p.HTTPClient = &http.Client{Transport: &oauthExchangeTestTransport{iamTarget: iamServer.URL, fallback: http.DefaultTransport}}

	err := p.Start(context.Background())
	if err == nil {
		t.Fatal("expected error for IAM 403")
	}
}

func TestOAuthJWTBearerProvider_ExchangeFailure(t *testing.T) {
	iamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "fake-jwt"})
	}))
	defer iamServer.Close()

	mcpOAuth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "token expired",
		})
	}))
	defer mcpOAuth.Close()

	p := NewOAuthJWTBearerProvider("test", "sa@proj.iam", "https://mcp.example.com", mcpOAuth.URL+"/token", nil)
	p.HTTPClient = &http.Client{Transport: &oauthExchangeTestTransport{iamTarget: iamServer.URL, fallback: http.DefaultTransport}}

	err := p.Start(context.Background())
	if err == nil {
		t.Fatal("expected error for exchange failure")
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("error = %q, want to contain invalid_grant", err.Error())
	}
}

func TestOAuthJWTBearerProvider_NotStarted(t *testing.T) {
	p := NewOAuthJWTBearerProvider("test", "sa@proj.iam", "aud", "ep", nil)
	_, err := p.ResolveToken(context.Background())
	if err == nil {
		t.Fatal("expected error before Start")
	}
}

func TestOAuthJWTBearerProvider_Matches(t *testing.T) {
	p := NewOAuthJWTBearerProvider("test", "sa@proj.iam", "aud", "ep", []string{"mcp.example.com"})
	if !p.Matches("mcp.example.com") {
		t.Error("should match")
	}
	if p.Matches("evil.com") {
		t.Error("should not match")
	}
}

// oauthExchangeTestTransport redirects IAM calls to mock, passes others through.
type oauthExchangeTestTransport struct {
	iamTarget string
	fallback  http.RoundTripper
}

func (t *oauthExchangeTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Host, "iamcredentials.googleapis.com") {
		req.URL.Scheme = "http"
		req.URL.Host = t.iamTarget[len("http://"):]
		return t.fallback.RoundTrip(req)
	}
	return t.fallback.RoundTrip(req)
}

var _ CredentialProvider = (*OAuthJWTBearerProvider)(nil)
