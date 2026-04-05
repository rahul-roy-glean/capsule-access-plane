package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/identity"
)

var sessionTestSecret = []byte("session-test-secret-32bytes-ok!!")

func setupSessionHandlers(t *testing.T) (*SessionHandlers, *identity.HMACVerifier) {
	t.Helper()

	verifier, err := identity.NewHMACVerifier(sessionTestSecret)
	if err != nil {
		t.Fatal(err)
	}

	store := NewSessionStore()
	handlers := NewSessionHandlers(verifier, store)
	return handlers, verifier
}

func signSessionToken(t *testing.T, claims *identity.Claims) string {
	t.Helper()
	token, err := identity.SignClaims(claims, sessionTestSecret)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func sessionClaims() *identity.Claims {
	return &identity.Claims{
		RunnerID:    "runner-1",
		SessionID:   "session-1",
		WorkloadKey: "workload-1",
		HostID:      "host-1",
		IssuedAt:    time.Now().Add(-time.Minute),
		ExpiresAt:   time.Now().Add(time.Hour),
	}
}

func TestRegisterSession(t *testing.T) {
	handlers, _ := setupSessionHandlers(t)
	token := signSessionToken(t, sessionClaims())

	reg := SessionRegistration{
		SessionID: "sess-001",
		UserEmail: "alice@example.com",
		RunnerID:  "runner-1",
		DomainRules: []DomainRule{
			{
				HostPattern:  "*.googleapis.com",
				ProviderName: "gcp-default",
			},
		},
	}
	body, _ := json.Marshal(reg)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions/register", handlers.RegisterSession)

	req := httptest.NewRequest("POST", "/v1/sessions/register", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201. body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "registered" {
		t.Errorf("status = %q, want registered", resp["status"])
	}
	if resp["session_id"] != "sess-001" {
		t.Errorf("session_id = %q, want sess-001", resp["session_id"])
	}
}

func TestGetSessionByID(t *testing.T) {
	handlers, _ := setupSessionHandlers(t)
	token := signSessionToken(t, sessionClaims())

	// Pre-register a session.
	_ = handlers.sessions.Register(&SessionRegistration{
		SessionID: "sess-002",
		UserEmail: "bob@example.com",
		DomainRules: []DomainRule{
			{HostPattern: "api.github.com", ProviderName: "github"},
		},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sessions/{session_id}", handlers.GetSession)

	req := httptest.NewRequest("GET", "/v1/sessions/sess-002", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body: %s", rr.Code, rr.Body.String())
	}

	var got SessionRegistration
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.SessionID != "sess-002" {
		t.Errorf("session_id = %q, want sess-002", got.SessionID)
	}
	if got.UserEmail != "bob@example.com" {
		t.Errorf("user_email = %q, want bob@example.com", got.UserEmail)
	}
}

func TestDeregisterSession(t *testing.T) {
	handlers, _ := setupSessionHandlers(t)
	token := signSessionToken(t, sessionClaims())

	// Pre-register a session.
	_ = handlers.sessions.Register(&SessionRegistration{
		SessionID: "sess-003",
		UserEmail: "carol@example.com",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /v1/sessions/{session_id}", handlers.DeregisterSession)

	req := httptest.NewRequest("DELETE", "/v1/sessions/sess-003", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body: %s", rr.Code, rr.Body.String())
	}

	// Verify it was actually removed.
	if _, ok := handlers.sessions.Get("sess-003"); ok {
		t.Error("session should have been removed")
	}
}

func TestRegisterDuplicateSession(t *testing.T) {
	handlers, _ := setupSessionHandlers(t)
	token := signSessionToken(t, sessionClaims())

	// Pre-register a session.
	_ = handlers.sessions.Register(&SessionRegistration{
		SessionID: "sess-dup",
		UserEmail: "alice@example.com",
	})

	reg := SessionRegistration{
		SessionID: "sess-dup",
		UserEmail: "alice@example.com",
	}
	body, _ := json.Marshal(reg)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions/register", handlers.RegisterSession)

	req := httptest.NewRequest("POST", "/v1/sessions/register", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409. body: %s", rr.Code, rr.Body.String())
	}
}

func TestGetNonExistentSession(t *testing.T) {
	handlers, _ := setupSessionHandlers(t)
	token := signSessionToken(t, sessionClaims())

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sessions/{session_id}", handlers.GetSession)

	req := httptest.NewRequest("GET", "/v1/sessions/does-not-exist", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404. body: %s", rr.Code, rr.Body.String())
	}
}

func TestSessionEndpoints_AuthRequired(t *testing.T) {
	handlers, _ := setupSessionHandlers(t)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions/register", handlers.RegisterSession)
	mux.HandleFunc("GET /v1/sessions/{session_id}", handlers.GetSession)
	mux.HandleFunc("DELETE /v1/sessions/{session_id}", handlers.DeregisterSession)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"register", "POST", "/v1/sessions/register"},
		{"get", "GET", "/v1/sessions/sess-1"},
		{"deregister", "DELETE", "/v1/sessions/sess-1"},
	}

	for _, tc := range tests {
		t.Run(tc.name+"_no_auth", func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rr.Code)
			}
		})

		t.Run(tc.name+"_bad_token", func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("Authorization", "Bearer invalid.token")
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rr.Code)
			}
		})
	}
}
