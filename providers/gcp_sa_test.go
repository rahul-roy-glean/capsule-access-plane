package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGCPServiceAccountProvider_RefreshAndResolve(t *testing.T) {
	// Mock IAM server.
	expireTime := time.Now().Add(time.Hour).Format(time.RFC3339)
	iamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"accessToken": "ya29.mock-token",
			"expireTime":  expireTime,
		})
	}))
	defer iamServer.Close()

	p := NewGCPServiceAccountProvider("gcp", "test@proj.iam", []string{"https://www.googleapis.com/auth/cloud-platform"}, []string{"compute.googleapis.com"})

	// Override the IAM endpoint for testing by using a custom HTTP client
	// that redirects IAM calls to our mock.
	p.HTTPClient = &http.Client{
		Transport: &mockIAMTransport{target: iamServer.URL},
	}

	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	token, err := p.ResolveToken(ctx)
	if err != nil {
		t.Fatalf("ResolveToken: %v", err)
	}
	if token != "ya29.mock-token" {
		t.Errorf("token = %q, want ya29.mock-token", token)
	}
}

func TestGCPServiceAccountProvider_InjectCredentials(t *testing.T) {
	expireTime := time.Now().Add(time.Hour).Format(time.RFC3339)
	iamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"accessToken": "ya29.injected",
			"expireTime":  expireTime,
		})
	}))
	defer iamServer.Close()

	p := NewGCPServiceAccountProvider("gcp", "test@proj.iam", nil, nil)
	p.HTTPClient = &http.Client{Transport: &mockIAMTransport{target: iamServer.URL}}

	ctx := context.Background()
	_ = p.Start(ctx)
	defer p.Stop()

	req := httptest.NewRequest("GET", "https://compute.googleapis.com/v1/instances", nil)
	if err := p.InjectCredentials(req); err != nil {
		t.Fatalf("InjectCredentials: %v", err)
	}
	if req.Header.Get("Authorization") != "Bearer ya29.injected" {
		t.Errorf("Authorization = %q", req.Header.Get("Authorization"))
	}
}

func TestGCPServiceAccountProvider_NotStarted(t *testing.T) {
	p := NewGCPServiceAccountProvider("gcp", "test@proj.iam", nil, nil)

	_, err := p.ResolveToken(context.Background())
	if err == nil {
		t.Fatal("expected error before Start")
	}
}

func TestGCPServiceAccountProvider_Matches(t *testing.T) {
	p := NewGCPServiceAccountProvider("gcp", "sa@proj.iam", nil, []string{"compute.googleapis.com"})
	if !p.Matches("compute.googleapis.com") {
		t.Error("should match")
	}
	if p.Matches("evil.com") {
		t.Error("should not match")
	}
}

func TestGCPServiceAccountProvider_IAMError(t *testing.T) {
	iamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("permission denied"))
	}))
	defer iamServer.Close()

	p := NewGCPServiceAccountProvider("gcp", "test@proj.iam", nil, nil)
	p.HTTPClient = &http.Client{Transport: &mockIAMTransport{target: iamServer.URL}}

	err := p.Start(context.Background())
	if err == nil {
		t.Fatal("expected error for IAM 403")
	}
}

// mockIAMTransport redirects IAM API calls to a mock server.
type mockIAMTransport struct {
	target string
}

func (t *mockIAMTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.target[len("http://"):]
	return http.DefaultTransport.RoundTrip(req)
}

var _ CredentialProvider = (*GCPServiceAccountProvider)(nil)
