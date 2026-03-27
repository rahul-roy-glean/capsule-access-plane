package runtime

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/rahul-roy-glean/capsule-access-plane/bundle"
	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
)

func testRegistry(t *testing.T) manifest.Registry {
	t.Helper()
	reg := manifest.NewInMemoryRegistry()
	_ = reg.Register(&manifest.ToolManifest{
		Family:      "github_rest",
		Version:     "1.0",
		SurfaceKind: "http",
		SupportedLanes: []accessplane.Lane{accessplane.LaneDirectHTTP},
		Destinations: []manifest.Destination{
			{Host: "api.github.com", Port: 443, Protocol: "https"},
		},
		MethodConstraints: []manifest.MethodConstraint{
			{Method: "GET", PathPattern: "/repos/**"},
			{Method: "POST", PathPattern: "/repos/*/issues"},
		},
	})
	return reg
}

func testBundle() *bundle.ProjectionBundle {
	return &bundle.ProjectionBundle{
		Version:   "v1",
		GrantID:   "grant-test-001",
		Lane:      accessplane.LaneDirectHTTP,
		ExpiresAt: time.Now().Add(time.Hour),
		AuditMetadata: bundle.AuditMetadata{
			UserID:    "user-1",
			SessionID: "sess-1",
			RunnerID:  "runner-1",
		},
	}
}

func TestInstallGrantStartsProxy(t *testing.T) {
	adapter := NewDirectHTTPAdapter(testRegistry(t))
	ctx := context.Background()

	addr, err := adapter.InstallGrantWithCredential(ctx, testBundle(), "github_rest", "test-token-123")
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	if addr == "" {
		t.Fatal("expected non-empty proxy address")
	}

	// Verify proxy is tracked.
	state, err := adapter.DescribeGrantState(ctx, "runner-1", "grant-test-001")
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if state.Status != "active" {
		t.Errorf("status = %q, want active", state.Status)
	}
}

func TestProxyInjectsAuthHeader(t *testing.T) {
	// Start a plain HTTP test target that echoes the Authorization header.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("Authorization")))
	}))
	defer target.Close()

	// Create a registry with the target's host.
	reg := manifest.NewInMemoryRegistry()
	_ = reg.Register(&manifest.ToolManifest{
		Family:         "test_api",
		Version:        "1.0",
		SurfaceKind:    "http",
		SupportedLanes: []accessplane.Lane{accessplane.LaneDirectHTTP},
		Destinations:   []manifest.Destination{{Host: "127.0.0.1", AllowedIPs: []string{"127.0.0.0/8"}}},
		MethodConstraints: []manifest.MethodConstraint{
			{Method: "GET", PathPattern: "/**"},
		},
	})

	adapter := NewDirectHTTPAdapter(reg)
	ctx := context.Background()

	b := testBundle()
	b.GrantID = "grant-auth-test"
	addr, err := adapter.InstallGrantWithCredential(ctx, b, "test_api", "my-secret-token")
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	// Make a request through the proxy.
	req, _ := http.NewRequest("GET", "http://"+addr+"/test", nil)
	req.Header.Set("X-Target-URL", target.URL+"/test")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "Bearer my-secret-token" {
		t.Errorf("auth header = %q, want 'Bearer my-secret-token'", string(body))
	}
}

func TestProxyRejectsDisallowedHost(t *testing.T) {
	adapter := NewDirectHTTPAdapter(testRegistry(t))
	ctx := context.Background()

	b := testBundle()
	b.GrantID = "grant-host-test"
	addr, err := adapter.InstallGrantWithCredential(ctx, b, "github_rest", "test-token")
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://"+addr+"/test", nil)
	req.Header.Set("X-Target-URL", "https://evil.example.com/steal")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestProxyRejectsDisallowedPort(t *testing.T) {
	adapter := NewDirectHTTPAdapter(testRegistry(t))
	ctx := context.Background()

	b := testBundle()
	b.GrantID = "grant-port-test"
	addr, err := adapter.InstallGrantWithCredential(ctx, b, "github_rest", "test-token")
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://"+addr+"/test", nil)
	req.Header.Set("X-Target-URL", "https://api.github.com:8443/repos/foo/bar")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "port") {
		t.Fatalf("expected port validation error, got %q", string(body))
	}
}

func TestProxyRejectsDisallowedProtocol(t *testing.T) {
	adapter := NewDirectHTTPAdapter(testRegistry(t))
	ctx := context.Background()

	b := testBundle()
	b.GrantID = "grant-protocol-test"
	addr, err := adapter.InstallGrantWithCredential(ctx, b, "github_rest", "test-token")
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://"+addr+"/test", nil)
	req.Header.Set("X-Target-URL", "http://api.github.com/repos/foo/bar")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "https") {
		t.Fatalf("expected protocol validation error, got %q", string(body))
	}
}

func TestProxyRejectsDisallowedMethod(t *testing.T) {
	adapter := NewDirectHTTPAdapter(testRegistry(t))
	ctx := context.Background()

	b := testBundle()
	b.GrantID = "grant-method-test"
	addr, err := adapter.InstallGrantWithCredential(ctx, b, "github_rest", "test-token")
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	req, _ := http.NewRequest("DELETE", "http://"+addr+"/test", nil)
	req.Header.Set("X-Target-URL", "https://api.github.com/repos/foo/bar")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestRevokeGrantStopsProxy(t *testing.T) {
	adapter := NewDirectHTTPAdapter(testRegistry(t))
	ctx := context.Background()

	b := testBundle()
	b.GrantID = "grant-revoke-test"
	_, err := adapter.InstallGrantWithCredential(ctx, b, "github_rest", "test-token")
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	err = adapter.RevokeGrant(ctx, "grant-revoke-test", "runner-1")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	state, err := adapter.DescribeGrantState(ctx, "runner-1", "grant-revoke-test")
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if state.Status != "not_installed" {
		t.Errorf("status = %q, want not_installed", state.Status)
	}
}

func TestDescribeGrantState_NotInstalled(t *testing.T) {
	adapter := NewDirectHTTPAdapter(testRegistry(t))
	ctx := context.Background()

	state, err := adapter.DescribeGrantState(ctx, "runner-1", "nonexistent")
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if state.Status != "not_installed" {
		t.Errorf("status = %q, want not_installed", state.Status)
	}
}
