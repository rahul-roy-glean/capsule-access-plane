package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/audit"
	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
	"github.com/rahul-roy-glean/capsule-access-plane/providers"
)

// ConnectProxy is an HTTP CONNECT proxy with selective SSL bump.
// Hosts that have a matching credential provider are MITM'd (SSL bumped)
// to inject credentials. All other allowed hosts are raw-tunneled.
type ConnectProxy struct {
	CA        *CertAuthority
	Manifests manifest.Registry
	Providers *providers.Registry
	Logger    *slog.Logger

	// UpstreamTLSConfig is the TLS config used for outbound connections to
	// upstream servers during SSL bump. If nil, defaults to system roots.
	UpstreamTLSConfig *tls.Config

	listener net.Listener
}

// ListenAndServe starts the proxy on the given address.
func (p *ConnectProxy) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("proxy: listen: %w", err)
	}
	p.listener = ln
	p.Logger.Info("proxy listening", "addr", ln.Addr().String())
	return p.Serve(ln)
}

// Serve accepts connections on the listener.
func (p *ConnectProxy) Serve(ln net.Listener) error {
	p.listener = ln
	for {
		conn, err := ln.Accept()
		if err != nil {
			// Check for closed listener.
			if ne, ok := err.(*net.OpError); ok && !ne.Temporary() {
				return nil
			}
			p.Logger.Error("proxy accept error", "err", err)
			continue
		}
		go p.handleConn(conn)
	}
}

// Addr returns the listener address, or empty string if not listening.
func (p *ConnectProxy) Addr() string {
	if p.listener != nil {
		return p.listener.Addr().String()
	}
	return ""
}

// Close shuts down the proxy listener.
func (p *ConnectProxy) Close() error {
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

func (p *ConnectProxy) handleConn(clientConn net.Conn) {
	defer func() { _ = clientConn.Close() }()

	// Extract client source IP for session-scoped credential resolution.
	clientIP := ""
	if addr := clientConn.RemoteAddr(); addr != nil {
		clientIP, _, _ = net.SplitHostPort(addr.String())
	}

	br := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		p.handleConnect(clientConn, req, clientIP)
	} else {
		p.handlePlainHTTP(clientConn, req)
	}
}

func (p *ConnectProxy) handleConnect(clientConn net.Conn, req *http.Request, clientIP string) {
	start := time.Now()
	host, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
		port = "443"
	}

	// Extract session_id from Proxy-Authorization header (attestation token).
	// Format: Bearer base64(json_claims).base64(hmac)
	sessionID := extractSessionIDFromProxyAuth(req.Header.Get("Proxy-Authorization"))

	// Step 1: Validate host against manifests.
	if !p.isHostAllowed(host) {
		_, _ = fmt.Fprintf(clientConn, "HTTP/1.1 403 Forbidden\r\n\r\nhost %s not allowed by manifest\r\n", host)
		p.logProxy(host, "denied_host", "host not in manifest", start)
		return
	}

	// Step 2: SSRF protection.
	dest := p.findDestination(host)
	var allowedCIDRs []string
	if dest != nil {
		allowedCIDRs = dest.AllowedIPs
	}
	if err := manifest.CheckSSRF(host, allowedCIDRs); err != nil {
		_, _ = fmt.Fprintf(clientConn, "HTTP/1.1 403 Forbidden\r\n\r\nSSRF: %s\r\n", err.Error())
		p.logProxy(host, "denied_ssrf", err.Error(), start)
		return
	}

	// Step 3: Determine if we should SSL bump.
	// Only MITM hosts that have a matching credential provider.
	provider, hasProvider := p.Providers.ForHost(host)

	// Send 200 Connection Established.
	_, _ = fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	targetAddr := net.JoinHostPort(host, port)

	if hasProvider {
		p.handleBump(clientConn, host, targetAddr, provider, clientIP, sessionID, start)
	} else {
		p.handleTunnel(clientConn, targetAddr, start)
	}
}

// handleBump performs SSL bump (MITM): TLS handshake with client using a
// generated cert, then intercept HTTP requests and inject credentials.
func (p *ConnectProxy) handleBump(clientConn net.Conn, host, targetAddr string, provider providers.CredentialProvider, clientIP, sessionID string, start time.Time) {
	// TLS handshake with client (we present a cert signed by our CA).
	// We pre-generate the cert for the target host because SNI may be empty
	// (e.g. when the client connects to an IP address).
	cert, err := p.CA.GetCertificate(host)
	if err != nil {
		p.Logger.Error("MITM cert generation failed", "host", host, "err", err)
		p.logProxy(host, "error_cert_gen", err.Error(), start)
		return
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "" && hello.ServerName != host {
				return p.CA.GetCertificate(hello.ServerName)
			}
			return cert, nil
		},
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		p.Logger.Error("MITM client handshake failed", "host", host, "err", err)
		p.logProxy(host, "error_client_tls", err.Error(), start)
		return
	}
	defer func() { _ = tlsConn.Close() }()

	// Read HTTP requests from the MITM'd connection and forward them.
	br := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if err != io.EOF {
				p.Logger.Debug("MITM read request error", "host", host, "err", err)
			}
			return
		}

		p.handleMITMRequest(tlsConn, req, host, targetAddr, provider, clientIP, sessionID, start)
	}
}

func (p *ConnectProxy) handleMITMRequest(clientConn net.Conn, req *http.Request, host, targetAddr string, provider providers.CredentialProvider, clientIP, sessionID string, start time.Time) {
	// Validate method+path against manifest constraints.
	if m := p.findManifestForHost(host); m != nil && len(m.MethodConstraints) > 0 {
		check := manifest.IsRequestAllowed(req.Method, req.URL.Path, m.MethodConstraints)
		if !check.Allowed {
			resp := &http.Response{
				StatusCode: http.StatusMethodNotAllowed,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(check.Reason)),
			}
			resp.Header.Set("Content-Type", "text/plain")
			_ = resp.Write(clientConn)
			p.logProxy(host, "denied_method", check.Reason, start)
			return
		}
		if check.Audit {
			p.Logger.Warn("MITM request allowed in audit mode",
				"host", host, "method", req.Method, "path", req.URL.Path)
		}
	}

	// Inject credentials with source IP and session ID context for session-scoped resolution.
	if clientIP != "" {
		req = req.WithContext(providers.WithSourceIP(req.Context(), clientIP))
	}
	if sessionID != "" {
		req = req.WithContext(providers.WithSessionID(req.Context(), sessionID))
	}
	if err := provider.InjectCredentials(req); err != nil {
		p.Logger.Error("credential injection failed", "host", host, "err", err)
		resp := &http.Response{
			StatusCode: http.StatusBadGateway,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("credential injection failed")),
		}
		_ = resp.Write(clientConn)
		return
	}

	// Set the full URL for the outbound request.
	req.URL.Scheme = "https"
	req.URL.Host = targetAddr
	req.RequestURI = ""

	// Forward to target.
	upstreamTLS := p.UpstreamTLSConfig
	if upstreamTLS == nil {
		upstreamTLS = &tls.Config{}
	}
	transport := &http.Transport{
		TLSClientConfig: upstreamTLS.Clone(),
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).DialContext,
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		p.Logger.Error("MITM outbound request failed", "host", host, "err", err)
		errResp := &http.Response{
			StatusCode: http.StatusBadGateway,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("upstream request failed: " + err.Error())),
		}
		_ = errResp.Write(clientConn)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	_ = resp.Write(clientConn)
	p.logProxy(host, fmt.Sprintf("status_%d", resp.StatusCode), "", start)
}

// handleTunnel passes bytes through without inspection.
func (p *ConnectProxy) handleTunnel(clientConn net.Conn, targetAddr string, start time.Time) {
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		p.Logger.Error("tunnel dial failed", "target", targetAddr, "err", err)
		p.logProxy(targetAddr, "error_dial", err.Error(), start)
		return
	}
	defer func() { _ = targetConn.Close() }()

	tunnel(clientConn, targetConn)
	p.logProxy(targetAddr, "tunneled", "", start)
}

// handlePlainHTTP rejects non-CONNECT requests (proxy only supports CONNECT).
func (p *ConnectProxy) handlePlainHTTP(clientConn net.Conn, req *http.Request) {
	_, _ = fmt.Fprintf(clientConn, "HTTP/1.1 405 Method Not Allowed\r\n\r\nonly CONNECT is supported\r\n")
}

// isHostAllowed checks if any manifest destination includes this host.
func (p *ConnectProxy) isHostAllowed(host string) bool {
	for _, m := range p.Manifests.List() {
		for _, d := range m.Destinations {
			if d.Host == host {
				return true
			}
		}
	}
	return false
}

// findDestination finds the Destination across all manifests for a host.
func (p *ConnectProxy) findDestination(host string) *manifest.Destination {
	for _, m := range p.Manifests.List() {
		if d := manifest.FindDestination(m.Destinations, host); d != nil {
			return d
		}
	}
	return nil
}

// findManifestForHost finds the manifest that contains a destination for this host.
func (p *ConnectProxy) findManifestForHost(host string) *manifest.ToolManifest {
	for _, m := range p.Manifests.List() {
		for _, d := range m.Destinations {
			if d.Host == host {
				return m
			}
		}
	}
	return nil
}

func (p *ConnectProxy) logProxy(target, result, reason string, start time.Time) {
	audit.LogProxyOperation(p.Logger, audit.AuditEvent{
		Target:     target,
		Result:     result,
		ReasonCode: reason,
		Duration:   time.Since(start),
	})
}

// extractSessionIDFromProxyAuth extracts the session_id from a Proxy-Authorization
// header carrying an attestation token. Supports two formats:
//   - "Bearer base64(json_claims).base64(hmac)" — direct bearer token
//   - "Basic base64(bearer:token)" — from HTTPS_PROXY URL with embedded credentials
//
// The attestation token format is: base64(json_claims).base64(hmac).
// Returns "" if the header is missing, malformed, or doesn't contain a session_id.
func extractSessionIDFromProxyAuth(header string) string {
	if header == "" {
		return ""
	}

	var token string
	if len(header) > 7 && strings.EqualFold(header[:7], "bearer ") {
		token = header[7:]
	} else if len(header) > 6 && strings.EqualFold(header[:6], "basic ") {
		// Decode Basic auth: base64(user:pass) where user="bearer" and pass=attestation_token
		decoded, err := base64.StdEncoding.DecodeString(header[6:])
		if err != nil {
			return ""
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return ""
		}
		token = parts[1]
	} else {
		return ""
	}

	// Token format: base64(json_claims).base64(hmac) — decode claims part
	claimsPart := strings.SplitN(token, ".", 2)
	if len(claimsPart) < 1 || claimsPart[0] == "" {
		return ""
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(claimsPart[0])
	if err != nil {
		claimsJSON, err = base64.StdEncoding.DecodeString(claimsPart[0])
		if err != nil {
			return ""
		}
	}
	var claims struct {
		SessionID string `json:"session_id"`
	}
	if json.Unmarshal(claimsJSON, &claims) != nil {
		return ""
	}
	return claims.SessionID
}
