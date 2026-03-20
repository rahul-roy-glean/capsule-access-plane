package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/providers"
)

func TestUpdateToken_Success(t *testing.T) {
	dp := providers.NewDelegatedProvider("mytoken", []string{"api.example.com"})
	reg := providers.NewRegistry()
	_ = reg.Register(dp)

	handler := NewTokenHandlers(reg)

	body, _ := json.Marshal(TokenUpdateRequest{
		Provider:  "mytoken",
		Token:     "new-secret-value",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	req := httptest.NewRequest("POST", "/v1/providers/update-token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.UpdateToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body: %s", rr.Code, rr.Body.String())
	}

	// Verify the token was stored.
	if !dp.HasToken() {
		t.Error("expected token to be stored")
	}
}

func TestUpdateToken_UnknownProvider(t *testing.T) {
	reg := providers.NewRegistry()
	handler := NewTokenHandlers(reg)

	body, _ := json.Marshal(TokenUpdateRequest{
		Provider: "nonexistent",
		Token:    "tok",
	})

	req := httptest.NewRequest("POST", "/v1/providers/update-token", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler.UpdateToken(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

func TestUpdateToken_NotDelegated(t *testing.T) {
	// Register a static provider (not delegated).
	fp := &fakeStaticProvider{name: "static-one"}
	reg := providers.NewRegistry()
	_ = reg.Register(fp)

	handler := NewTokenHandlers(reg)

	body, _ := json.Marshal(TokenUpdateRequest{
		Provider: "static-one",
		Token:    "tok",
	})

	req := httptest.NewRequest("POST", "/v1/providers/update-token", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler.UpdateToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400. body: %s", rr.Code, rr.Body.String())
	}
}

func TestUpdateToken_MissingFields(t *testing.T) {
	reg := providers.NewRegistry()
	handler := NewTokenHandlers(reg)

	body, _ := json.Marshal(TokenUpdateRequest{Provider: "x"})
	req := httptest.NewRequest("POST", "/v1/providers/update-token", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler.UpdateToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// fakeStaticProvider is a minimal non-delegated provider for testing.
type fakeStaticProvider struct{ name string }

func (p *fakeStaticProvider) Name() string                                          { return p.name }
func (p *fakeStaticProvider) Type() string                                          { return "static" }
func (p *fakeStaticProvider) Matches(_ string) bool                                 { return false }
func (p *fakeStaticProvider) InjectCredentials(_ *http.Request) error               { return nil }
func (p *fakeStaticProvider) ResolveToken(_ context.Context) (string, error)        { return "", nil }
func (p *fakeStaticProvider) Start(_ context.Context) error                         { return nil }
func (p *fakeStaticProvider) Stop()                                                 {}
