package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/rahul-roy-glean/capsule-access-plane/providers"
)

var defaultHostEndpointCIDRs = []string{
	"127.0.0.0/8",
	"::1/128",
}

// DefaultHostEndpointCIDRs returns the default control-plane CIDRs for
// host-only endpoints. The default is loopback-only to force an explicit
// opt-in before exposing these endpoints beyond the local host.
func DefaultHostEndpointCIDRs() []string {
	out := make([]string, len(defaultHostEndpointCIDRs))
	copy(out, defaultHostEndpointCIDRs)
	return out
}

// HostEndpointGuard restricts host-only endpoints to explicitly trusted
// network ranges and, optionally, a separate bearer token.
type HostEndpointGuard struct {
	allowedNets []net.IPNet
	bearerToken string
}

// NewHostEndpointGuard creates a guard for host-local/control-plane endpoints.
func NewHostEndpointGuard(cidrs []string, bearerToken string) (*HostEndpointGuard, error) {
	if len(cidrs) == 0 {
		cidrs = DefaultHostEndpointCIDRs()
	}

	allowed := make([]net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("host endpoint CIDR %q: %w", cidr, err)
		}
		allowed = append(allowed, *network)
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("at least one host endpoint CIDR must be configured")
	}

	return &HostEndpointGuard{
		allowedNets: allowed,
		bearerToken: bearerToken,
	}, nil
}

// Wrap applies the guard to a host-only handler.
func (g *HostEndpointGuard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, err := remoteIPFromRequest(r)
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "host endpoint requires a trusted client address",
			})
			return
		}
		if !ipInNets(ip, g.allowedNets) {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "host endpoint is restricted to configured control-plane CIDRs",
			})
			return
		}
		if g.bearerToken != "" {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "Bearer "+g.bearerToken {
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "missing or invalid host endpoint bearer token",
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func withRequestSourceIP(ctx context.Context, r *http.Request) context.Context {
	ip, err := remoteIPFromRequest(r)
	if err != nil || ip == nil {
		return ctx
	}
	return providers.WithSourceIP(ctx, ip.String())
}

func remoteIPFromRequest(r *http.Request) (net.IP, error) {
	if r == nil {
		return nil, fmt.Errorf("nil request")
	}
	if r.RemoteAddr == "" {
		return nil, fmt.Errorf("missing remote address")
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid remote IP %q", host)
	}
	return ip, nil
}

func ipInNets(ip net.IP, nets []net.IPNet) bool {
	for _, network := range nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
