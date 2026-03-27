package runtime

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/rahul-roy-glean/capsule-access-plane/bundle"
	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
)

// DirectHTTPAdapter manages per-grant forward proxies that inject credentials
// into outbound HTTP requests.
type DirectHTTPAdapter struct {
	mu       sync.Mutex
	proxies  map[string]*runningProxy // grantID → proxy
	registry manifest.Registry
}

type runningProxy struct {
	grantID    string
	listener   net.Listener
	server     *http.Server
	cancel     context.CancelFunc
	credential string
	expiresAt  time.Time
}

// NewDirectHTTPAdapter creates a new adapter backed by the given manifest registry.
func NewDirectHTTPAdapter(registry manifest.Registry) *DirectHTTPAdapter {
	return &DirectHTTPAdapter{
		proxies:  make(map[string]*runningProxy),
		registry: registry,
	}
}

// InstallGrant implements RuntimeAdapter. For DirectHTTPAdapter, use InstallGrantWithCredential instead.
func (a *DirectHTTPAdapter) InstallGrant(ctx context.Context, b *bundle.ProjectionBundle) error {
	return fmt.Errorf("direct_http: use InstallGrantWithCredential instead")
}

// InstallGrantWithCredential starts a local forward proxy for the grant that
// injects the given credential as a Bearer token.
func (a *DirectHTTPAdapter) InstallGrantWithCredential(ctx context.Context, b *bundle.ProjectionBundle, toolFamily string, credential string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.proxies[b.GrantID]; exists {
		return "", fmt.Errorf("direct_http: grant %s already installed", b.GrantID)
	}

	// Look up manifest for allowed destinations and method constraints.
	m, err := a.registry.Get(toolFamily)
	if err != nil {
		return "", fmt.Errorf("direct_http: manifest lookup: %w", err)
	}

	// Start listener on a random local port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("direct_http: listen: %w", err)
	}

	proxyCtx, cancel := context.WithCancel(ctx)

	handler := &proxyHandler{
		credential:        credential,
		allowedHosts:      manifest.BuildAllowedHosts(m.Destinations),
		destinations:      m.Destinations,
		methodConstraints: m.MethodConstraints,
	}

	srv := &http.Server{
		Handler:     handler,
		BaseContext: func(_ net.Listener) context.Context { return proxyCtx },
	}

	rp := &runningProxy{
		grantID:    b.GrantID,
		listener:   listener,
		server:     srv,
		cancel:     cancel,
		credential: credential,
		expiresAt:  b.ExpiresAt,
	}

	a.proxies[b.GrantID] = rp

	go func() {
		_ = srv.Serve(listener)
	}()

	return listener.Addr().String(), nil
}

// RevokeGrant stops the proxy for the given grant.
func (a *DirectHTTPAdapter) RevokeGrant(ctx context.Context, grantID string, runnerID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	rp, exists := a.proxies[grantID]
	if !exists {
		return nil // idempotent
	}

	rp.cancel()
	_ = rp.server.Shutdown(ctx)
	delete(a.proxies, grantID)
	return nil
}

// DescribeGrantState returns the proxy status for a grant.
func (a *DirectHTTPAdapter) DescribeGrantState(ctx context.Context, runnerID string, grantID string) (*GrantState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	rp, exists := a.proxies[grantID]
	if !exists {
		return &GrantState{
			RunnerID: runnerID,
			GrantID:  grantID,
			Status:   "not_installed",
			Lane:     accessplane.LaneDirectHTTP,
		}, nil
	}

	return &GrantState{
		RunnerID:  runnerID,
		GrantID:   grantID,
		Status:    "active",
		Lane:      accessplane.LaneDirectHTTP,
		ExpiresAt: rp.expiresAt,
	}, nil
}

// ProxyAddr returns the local address of the proxy for a grant, or empty string if not found.
func (a *DirectHTTPAdapter) ProxyAddr(grantID string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	rp, exists := a.proxies[grantID]
	if !exists {
		return ""
	}
	return rp.listener.Addr().String()
}

// proxyHandler is the HTTP handler that forwards requests with credential injection.
type proxyHandler struct {
	credential        string
	allowedHosts      map[string]bool
	destinations      []manifest.Destination
	methodConstraints []manifest.MethodConstraint
}

func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The proxy receives requests where the URL path encodes the target.
	// Expected format: GET /https/api.github.com/repos/foo/bar
	// Or via X-Target-URL header.
	targetURL := r.Header.Get("X-Target-URL")
	if targetURL == "" {
		http.Error(w, "missing X-Target-URL header", http.StatusBadRequest)
		return
	}

	// Parse target host.
	targetHost := manifest.ExtractHost(targetURL)
	if targetHost == "" {
		http.Error(w, "invalid target URL", http.StatusBadRequest)
		return
	}

	// Validate destination.
	if !h.allowedHosts[targetHost] {
		http.Error(w, fmt.Sprintf("destination %s not allowed by manifest", targetHost), http.StatusForbidden)
		return
	}
	if err := manifest.ValidateDestinationURL(targetURL, h.destinations); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// SSRF protection — reject private/loopback IPs.
	dest := manifest.FindDestination(h.destinations, targetHost)
	var allowedCIDRs []string
	if dest != nil {
		allowedCIDRs = dest.AllowedIPs
	}
	resolution, err := manifest.ResolveAndValidateDestination(targetHost, allowedCIDRs)
	if err != nil {
		http.Error(w, "SSRF: "+err.Error(), http.StatusForbidden)
		return
	}

	// Validate method and path constraints.
	if len(h.methodConstraints) > 0 {
		targetPath := manifest.ExtractPath(targetURL)
		check := manifest.IsRequestAllowed(r.Method, targetPath, h.methodConstraints)
		if !check.Allowed {
			http.Error(w, check.Reason, http.StatusMethodNotAllowed)
			return
		}
	}

	// Build outbound request.
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "failed to create proxy request", http.StatusInternalServerError)
		return
	}

	// Copy headers from original request, skipping hop-by-hop headers.
	for k, vv := range r.Header {
		if isHopByHop(k) || strings.EqualFold(k, "X-Target-URL") {
			continue
		}
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}

	// Inject credential.
	outReq.Header.Set("Authorization", "Bearer "+h.credential)

	// Forward request.
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: manifest.NewPinnedHTTPTransport(resolution, nil),
	}
	resp, err := client.Do(outReq)
	if err != nil {
		http.Error(w, "proxy request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Copy response headers.
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// hopByHopHeaders are HTTP headers that must not be forwarded by proxies.
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

func isHopByHop(header string) bool {
	return hopByHopHeaders[http.CanonicalHeaderKey(header)]
}
