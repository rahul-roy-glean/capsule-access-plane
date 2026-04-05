package icap

import (
	"io"
	"net/http"
	"strings"

	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
	"github.com/rahul-roy-glean/capsule-access-plane/providers"
)

// handleOPTIONS returns ICAP OPTIONS capabilities.
func (s *Server) handleOPTIONS(req *ICAPRequest) *ICAPResponse {
	return &ICAPResponse{
		StatusCode: StatusOK,
		Headers: map[string]string{
			"Methods":          MethodREQMOD,
			"Allow":            "204",
			"Preview":          "0",
			"Transfer-Preview": "*",
			"ISTag":            "\"capsule-access-plane\"",
		},
	}
}

// handleREQMOD processes an ICAP REQMOD request. It validates the encapsulated
// HTTP request against manifests, performs SSRF checks, validates method+path
// constraints, and injects credentials when a matching provider exists.
func (s *Server) handleREQMOD(req *ICAPRequest) *ICAPResponse {
	httpReq := req.EncapsulatedReq
	if httpReq == nil {
		return &ICAPResponse{StatusCode: StatusBadRequest}
	}

	host := httpReq.Host
	if host == "" && httpReq.URL != nil {
		host = httpReq.URL.Host
	}
	// Strip port from host for manifest lookups.
	if h, _, ok := strings.Cut(host, ":"); ok {
		host = h
	}

	if host == "" {
		s.Logger.Warn("REQMOD: no host in encapsulated request")
		return &ICAPResponse{StatusCode: StatusBadRequest}
	}

	// Step 1: Validate host against manifests.
	if !s.isHostAllowed(host) {
		s.Logger.Info("REQMOD: host denied", "host", host)
		return denyHTTPResponse(http.StatusForbidden, "host "+host+" not allowed by manifest")
	}

	// Step 2: SSRF protection.
	dest := s.findDestination(host)
	var allowedCIDRs []string
	if dest != nil {
		allowedCIDRs = dest.AllowedIPs
	}
	if err := manifest.CheckSSRF(host, allowedCIDRs); err != nil {
		s.Logger.Info("REQMOD: SSRF denied", "host", host, "err", err)
		return denyHTTPResponse(http.StatusForbidden, "SSRF: "+err.Error())
	}

	// Step 3: Validate method+path against manifest constraints.
	if m := s.findManifestForHost(host); m != nil && len(m.MethodConstraints) > 0 {
		check := manifest.IsRequestAllowed(httpReq.Method, httpReq.URL.Path, m.MethodConstraints)
		if !check.Allowed {
			s.Logger.Info("REQMOD: method denied",
				"host", host, "method", httpReq.Method, "path", httpReq.URL.Path,
				"reason", check.Reason)
			return denyHTTPResponse(http.StatusMethodNotAllowed, check.Reason)
		}
		if check.Audit {
			s.Logger.Warn("REQMOD: request allowed in audit mode",
				"host", host, "method", httpReq.Method, "path", httpReq.URL.Path)
		}
	}

	// Step 4: Look up credential provider.
	provider, hasProvider := s.Providers.ForHost(host)
	if !hasProvider {
		// No provider: return 204 No Modification.
		return &ICAPResponse{StatusCode: StatusNoModification}
	}

	// Step 5: Extract session context from X-Proxy-Token header if present.
	if sessionID := httpReq.Header.Get("X-Proxy-Token"); sessionID != "" {
		httpReq = httpReq.WithContext(providers.WithSourceIP(httpReq.Context(), sessionID))
	}

	// Step 6: Inject credentials.
	if err := provider.InjectCredentials(httpReq); err != nil {
		s.Logger.Error("REQMOD: credential injection failed", "host", host, "err", err)
		return denyHTTPResponse(http.StatusBadGateway, "credential injection failed")
	}

	// Remove the proxy token header so it doesn't leak upstream.
	httpReq.Header.Del("X-Proxy-Token")

	// Return modified request.
	return &ICAPResponse{
		StatusCode:  StatusOK,
		ModifiedReq: httpReq,
	}
}

// isHostAllowed checks if any manifest destination includes this host.
func (s *Server) isHostAllowed(host string) bool {
	for _, m := range s.Manifests.List() {
		for _, d := range m.Destinations {
			if d.Host == host {
				return true
			}
		}
	}
	return false
}

// findDestination finds the Destination across all manifests for a host.
func (s *Server) findDestination(host string) *manifest.Destination {
	for _, m := range s.Manifests.List() {
		if d := manifest.FindDestination(m.Destinations, host); d != nil {
			return d
		}
	}
	return nil
}

// findManifestForHost finds the manifest that contains a destination for this host.
func (s *Server) findManifestForHost(host string) *manifest.ToolManifest {
	for _, m := range s.Manifests.List() {
		for _, d := range m.Destinations {
			if d.Host == host {
				return m
			}
		}
	}
	return nil
}

// denyHTTPResponse creates an ICAP response that encapsulates an HTTP error response.
func denyHTTPResponse(statusCode int, message string) *ICAPResponse {
	return &ICAPResponse{
		StatusCode: StatusOK,
		ErrorResp: &http.Response{
			StatusCode: statusCode,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Content-Type": {"text/plain"},
			},
			Body:          io.NopCloser(strings.NewReader(message)),
			ContentLength: int64(len(message)),
		},
	}
}
