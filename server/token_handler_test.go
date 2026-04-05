package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/identity"
	"github.com/rahul-roy-glean/capsule-access-plane/providers"
)

func tokenTestSignToken(t *testing.T) string {
	t.Helper()
	claims := &identity.Claims{
		RunnerID:    "runner-1",
		SessionID:   "session-1",
		WorkloadKey: "workload-1",
		HostID:      "host-1",
		IssuedAt:    time.Now().Add(-time.Minute),
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	token, err := identity.SignClaims(claims, handlerTestSecret)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func setupTokenHandlers(t *testing.T, reg *providers.Registry) *TokenHandlers {
	t.Helper()
	verifier, err := identity.NewHMACVerifier(handlerTestSecret)
	if err != nil {
		t.Fatal(err)
	}
	return NewTokenHandlers(reg, verifier)
}

func TestUpdateToken_GlobalSuccess(t *testing.T) {
	dp := providers.NewDelegatedProvider("mytoken", []string{"api.example.com"})
	reg := providers.NewRegistry()
	_ = reg.Register(dp)

	handler := setupTokenHandlers(t, reg)
	token := tokenTestSignToken(t)

	body, _ := json.Marshal(TokenUpdateRequest{
		Provider:  "mytoken",
		Token:     "new-secret-value",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	req := httptest.NewRequest("POST", "/v1/providers/update-token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.UpdateToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body: %s", rr.Code, rr.Body.String())
	}

	if !dp.HasToken() {
		t.Error("expected token to be stored")
	}
}

func TestUpdateToken_SessionScoped(t *testing.T) {
	dp := providers.NewDelegatedProvider("github", nil)
	reg := providers.NewRegistry()
	_ = reg.Register(dp)

	handler := setupTokenHandlers(t, reg)
	token := tokenTestSignToken(t)

	body, _ := json.Marshal(TokenUpdateRequest{
		Provider:  "github",
		SourceIP:  "10.0.0.1",
		Token:     "alice-token",
		ExpiresAt: time.Now().Add(time.Hour),
		Identity: &TokenIdentity{
			UserEmail:    "alice@glean.com",
			ExtraHeaders: map[string]string{"X-Session": "s1"},
		},
	})

	req := httptest.NewRequest("POST", "/v1/providers/update-token", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.UpdateToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}

	// Verify session-scoped resolution.
	ctx := providers.WithSourceIP(context.Background(), "10.0.0.1")
	tok, err := dp.ResolveToken(ctx)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if tok != "alice-token" {
		t.Errorf("token = %q", tok)
	}
}

func TestUpdateToken_UnknownProvider(t *testing.T) {
	reg := providers.NewRegistry()
	handler := setupTokenHandlers(t, reg)
	token := tokenTestSignToken(t)

	body, _ := json.Marshal(TokenUpdateRequest{
		Provider: "nonexistent",
		Token:    "tok",
	})

	req := httptest.NewRequest("POST", "/v1/providers/update-token", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.UpdateToken(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

func TestUpdateToken_NotDelegated(t *testing.T) {
	fp := &fakeStaticProvider{name: "static-one"}
	reg := providers.NewRegistry()
	_ = reg.Register(fp)

	handler := setupTokenHandlers(t, reg)
	token := tokenTestSignToken(t)

	body, _ := json.Marshal(TokenUpdateRequest{
		Provider: "static-one",
		Token:    "tok",
	})

	req := httptest.NewRequest("POST", "/v1/providers/update-token", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.UpdateToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400. body: %s", rr.Code, rr.Body.String())
	}
}

func TestUpdateToken_MissingFields(t *testing.T) {
	reg := providers.NewRegistry()
	handler := setupTokenHandlers(t, reg)
	token := tokenTestSignToken(t)

	body, _ := json.Marshal(TokenUpdateRequest{Provider: "x"})
	req := httptest.NewRequest("POST", "/v1/providers/update-token", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.UpdateToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestUpdateToken_MissingAuth(t *testing.T) {
	reg := providers.NewRegistry()
	handler := setupTokenHandlers(t, reg)

	body, _ := json.Marshal(TokenUpdateRequest{
		Provider: "mytoken",
		Token:    "tok",
	})

	req := httptest.NewRequest("POST", "/v1/providers/update-token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.UpdateToken(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestUpdateToken_InvalidToken(t *testing.T) {
	reg := providers.NewRegistry()
	handler := setupTokenHandlers(t, reg)

	body, _ := json.Marshal(TokenUpdateRequest{
		Provider: "mytoken",
		Token:    "tok",
	})

	req := httptest.NewRequest("POST", "/v1/providers/update-token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer invalid.token")
	rr := httptest.NewRecorder()
	handler.UpdateToken(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

// fakeStaticProvider is a minimal non-delegated provider for testing.
type fakeStaticProvider struct{ name string }

func (p *fakeStaticProvider) Name() string                                   { return p.name }
func (p *fakeStaticProvider) Type() string                                   { return "static" }
func (p *fakeStaticProvider) Matches(_ string) bool                          { return false }
func (p *fakeStaticProvider) InjectCredentials(_ *http.Request) error        { return nil }
func (p *fakeStaticProvider) ResolveToken(_ context.Context) (string, error) { return "", nil }
func (p *fakeStaticProvider) Start(_ context.Context) error                  { return nil }
func (p *fakeStaticProvider) Stop()                                          {}
