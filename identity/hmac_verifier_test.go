package identity

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

var testSecret = []byte("test-secret-key-for-hmac")

func validClaims() *Claims {
	return &Claims{
		RunnerID:    "runner-1",
		SessionID:   "session-1",
		WorkloadKey: "workload-1",
		HostID:      "host-1",
		BootEpoch:   "2026-01-01",
		IssuedAt:    time.Now().Add(-time.Minute),
		ExpiresAt:   time.Now().Add(time.Hour),
	}
}

func TestVerify_ValidToken(t *testing.T) {
	v, err := NewHMACVerifier(testSecret)
	if err != nil {
		t.Fatal(err)
	}

	claims := validClaims()
	token, err := SignClaims(claims, testSecret)
	if err != nil {
		t.Fatal(err)
	}

	got, err := v.Verify(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.RunnerID != claims.RunnerID {
		t.Errorf("RunnerID = %q, want %q", got.RunnerID, claims.RunnerID)
	}
	if got.SessionID != claims.SessionID {
		t.Errorf("SessionID = %q, want %q", got.SessionID, claims.SessionID)
	}
	if got.WorkloadKey != claims.WorkloadKey {
		t.Errorf("WorkloadKey = %q, want %q", got.WorkloadKey, claims.WorkloadKey)
	}
}

func TestVerify_TamperedPayload(t *testing.T) {
	v, _ := NewHMACVerifier(testSecret)
	claims := validClaims()
	token, _ := SignClaims(claims, testSecret)

	parts := strings.SplitN(token, ".", 2)
	// Tamper by changing a byte in the payload
	tampered := "x" + parts[0][1:]
	tamperedToken := tampered + "." + parts[1]

	_, err := v.Verify(tamperedToken)
	if err == nil {
		t.Fatal("expected error for tampered payload")
	}
	if !strings.Contains(err.Error(), "invalid signature") {
		t.Errorf("expected 'invalid signature' error, got: %v", err)
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	v, _ := NewHMACVerifier(testSecret)
	claims := validClaims()
	token, _ := SignClaims(claims, testSecret)

	parts := strings.SplitN(token, ".", 2)
	// Replace sig with garbage
	fakeSig := base64.RawURLEncoding.EncodeToString([]byte("fake-signature-bytes"))
	tamperedToken := parts[0] + "." + fakeSig

	_, err := v.Verify(tamperedToken)
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
	if !strings.Contains(err.Error(), "invalid signature") {
		t.Errorf("expected 'invalid signature' error, got: %v", err)
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	v, _ := NewHMACVerifier(testSecret)
	claims := validClaims()
	claims.ExpiresAt = time.Now().Add(-time.Hour)
	token, _ := SignClaims(claims, testSecret)

	_, err := v.Verify(token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected 'expired' error, got: %v", err)
	}
}

func TestVerify_FutureNotBefore(t *testing.T) {
	v, _ := NewHMACVerifier(testSecret)
	claims := validClaims()
	claims.NotBefore = time.Now().Add(time.Hour)
	token, _ := SignClaims(claims, testSecret)

	_, err := v.Verify(token)
	if err == nil {
		t.Fatal("expected error for future NotBefore")
	}
	if !strings.Contains(err.Error(), "not yet valid") {
		t.Errorf("expected 'not yet valid' error, got: %v", err)
	}
}

func TestVerify_MissingRequiredFields(t *testing.T) {
	v, _ := NewHMACVerifier(testSecret)

	tests := []struct {
		name    string
		modify  func(*Claims)
		wantErr string
	}{
		{"missing RunnerID", func(c *Claims) { c.RunnerID = "" }, "runner_id"},
		{"missing SessionID", func(c *Claims) { c.SessionID = "" }, "session_id"},
		{"missing WorkloadKey", func(c *Claims) { c.WorkloadKey = "" }, "workload_key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := validClaims()
			tt.modify(claims)
			token, _ := SignClaims(claims, testSecret)
			_, err := v.Verify(token)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestVerify_MalformedToken(t *testing.T) {
	v, _ := NewHMACVerifier(testSecret)

	tests := []struct {
		name  string
		token string
	}{
		{"no dot separator", "justabunchoftext"},
		{"empty string", ""},
		{"bad base64 payload", "!!!bad.base64!!!"},
		{"bad base64 signature", base64.RawURLEncoding.EncodeToString([]byte("{}")) + ".!!!"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v.Verify(tt.token)
			if err == nil {
				t.Fatal("expected error for malformed token")
			}
		})
	}
}

func TestNewHMACVerifier_EmptySecret(t *testing.T) {
	_, err := NewHMACVerifier([]byte{})
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
	_, err = NewHMACVerifier(nil)
	if err == nil {
		t.Fatal("expected error for nil secret")
	}
}
