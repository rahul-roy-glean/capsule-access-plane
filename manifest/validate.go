package manifest

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// BuildAllowedHosts returns a set of allowed hostnames from the given destinations.
func BuildAllowedHosts(destinations []Destination) map[string]bool {
	hosts := make(map[string]bool, len(destinations))
	for _, d := range destinations {
		hosts[d.Host] = true
	}
	return hosts
}

// ExtractHost extracts the hostname from a URL string, stripping the port.
func ExtractHost(rawURL string) string {
	after, found := strings.CutPrefix(rawURL, "https://")
	if !found {
		after, found = strings.CutPrefix(rawURL, "http://")
		if !found {
			return ""
		}
	}
	host, _, _ := strings.Cut(after, "/")
	host, _, _ = strings.Cut(host, ":") // strip port
	return host
}

// ExtractPath extracts the path component from a URL string.
func ExtractPath(rawURL string) string {
	after, found := strings.CutPrefix(rawURL, "https://")
	if !found {
		after, found = strings.CutPrefix(rawURL, "http://")
		if !found {
			return ""
		}
	}
	_, path, found := strings.Cut(after, "/")
	if !found {
		return "/"
	}
	return "/" + path
}

// IsMethodAllowed checks whether the given HTTP method is in the constraints list.
// Deprecated: use IsRequestAllowed for method+path checking.
func IsMethodAllowed(method string, constraints []MethodConstraint) bool {
	for _, mc := range constraints {
		if strings.EqualFold(mc.Method, method) {
			return true
		}
	}
	return false
}

// RequestCheck is the result of IsRequestAllowed.
type RequestCheck struct {
	Allowed bool   // true if the request is permitted
	Audit   bool   // true if the match was in audit mode (allowed but should be logged)
	Reason  string // human-readable reason for denial
}

// IsRequestAllowed checks method AND path against constraints.
// Returns allowed=true if any constraint matches. If the matching constraint
// has Enforcement=="audit", the request is allowed but Audit is set to true.
func IsRequestAllowed(method, path string, constraints []MethodConstraint) RequestCheck {
	for _, mc := range constraints {
		if !strings.EqualFold(mc.Method, method) {
			continue
		}
		if mc.PathPattern == "" || mc.PathPattern == "/**" {
			if mc.Enforcement == "audit" {
				return RequestCheck{Allowed: true, Audit: true}
			}
			return RequestCheck{Allowed: true}
		}
		if matchPathGlob(mc.PathPattern, path) {
			if mc.Enforcement == "audit" {
				return RequestCheck{Allowed: true, Audit: true}
			}
			return RequestCheck{Allowed: true}
		}
	}
	return RequestCheck{
		Allowed: false,
		Reason:  method + " " + path + " not allowed by manifest constraints",
	}
}

// MatchPathGlob matches a URL path against a glob pattern.
// "*" matches a single path segment. "**" matches zero or more segments.
func MatchPathGlob(pattern, path string) bool {
	return matchPathGlob(pattern, path)
}

// matchPathGlob matches a URL path against a glob pattern.
// "*" matches a single path segment. "**" matches zero or more segments.
func matchPathGlob(pattern, path string) bool {
	patParts := splitPath(pattern)
	pathParts := splitPath(path)
	return globMatch(patParts, pathParts)
}

// splitPath splits a URL path into non-empty segments.
func splitPath(p string) []string {
	var parts []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return parts
}

// globMatch recursively matches pattern segments against path segments.
func globMatch(pattern, path []string) bool {
	for len(pattern) > 0 {
		seg := pattern[0]
		pattern = pattern[1:]

		if seg == "**" {
			// "**" at end matches everything remaining.
			if len(pattern) == 0 {
				return true
			}
			// Try matching the rest of the pattern at every position.
			for i := 0; i <= len(path); i++ {
				if globMatch(pattern, path[i:]) {
					return true
				}
			}
			return false
		}

		if len(path) == 0 {
			return false
		}

		if seg != "*" && seg != path[0] {
			return false
		}

		path = path[1:]
	}
	return len(path) == 0
}

// FindDestination returns the Destination matching the given host, or nil.
func FindDestination(destinations []Destination, host string) *Destination {
	for i := range destinations {
		if destinations[i].Host == host {
			return &destinations[i]
		}
	}
	return nil
}

// ValidateDestinationURL ensures the request URL matches a declared manifest
// destination, including host and any declared protocol/port constraints.
func ValidateDestinationURL(rawURL string, destinations []Destination) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("invalid target URL")
	}

	dest := FindDestination(destinations, parsed.Hostname())
	if dest == nil {
		return fmt.Errorf("destination %s not allowed by manifest", parsed.Hostname())
	}
	if dest.Protocol != "" && !strings.EqualFold(parsed.Scheme, dest.Protocol) {
		return fmt.Errorf("destination %s must use %s", parsed.Hostname(), dest.Protocol)
	}

	port := parsed.Port()
	if port == "" {
		switch strings.ToLower(parsed.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	if dest.Port != 0 {
		wantPort := strconv.Itoa(dest.Port)
		if port != wantPort {
			return fmt.Errorf("destination %s must use port %d", parsed.Hostname(), dest.Port)
		}
	}
	return nil
}

// TargetAddress returns the dial target for a request URL using a pinned IP when
// available, while preserving the original destination port semantics.
func TargetAddress(rawURL string, pinnedIP net.IP) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid target URL: %w", err)
	}

	port := parsed.Port()
	if port == "" {
		switch strings.ToLower(parsed.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			return "", fmt.Errorf("unsupported URL scheme %q", parsed.Scheme)
		}
	}

	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("invalid target URL")
	}
	if pinnedIP != nil {
		host = pinnedIP.String()
	}

	return net.JoinHostPort(host, port), nil
}

// ResolvedDestination carries a host and its validated IPs so callers can pin
// the eventual network dial to the SSRF-checked addresses.
type ResolvedDestination struct {
	Host string
	IPs  []net.IP
}

// ResolveAndValidateDestination resolves a manifest destination host and
// validates the resulting IPs against the SSRF policy.
func ResolveAndValidateDestination(host string, allowedCIDRs []string) (*ResolvedDestination, error) {
	ips, err := ResolveValidatedIPs(host, allowedCIDRs)
	if err != nil {
		return nil, err
	}
	return &ResolvedDestination{
		Host: host,
		IPs:  ips,
	}, nil
}

// ResolveAndValidateTarget resolves the host in a target URL and validates the
// resulting IPs against the SSRF policy.
func ResolveAndValidateTarget(rawURL string, allowedCIDRs []string) (*ResolvedDestination, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("invalid target URL")
	}
	return ResolveAndValidateDestination(host, allowedCIDRs)
}

// ValidateConnectDestination ensures a CONNECT target matches the manifest's
// allowed host and any declared port/protocol constraints.
func ValidateConnectDestination(host, port string, dest *Destination) error {
	if dest == nil {
		return fmt.Errorf("destination %s not allowed by manifest", host)
	}
	if host != dest.Host {
		return fmt.Errorf("destination %s not allowed by manifest", host)
	}
	if dest.Protocol != "" && !strings.EqualFold(dest.Protocol, "https") {
		return fmt.Errorf("destination %s does not permit CONNECT over %s", host, dest.Protocol)
	}
	wantPort := DestinationPortString(dest)
	if wantPort != "" && port != wantPort {
		return fmt.Errorf("destination %s must use port %s", host, wantPort)
	}
	return nil
}

// NewPinnedHTTPTransport creates an HTTP transport that dials only previously
// validated IPs while preserving TLS verification against the original host.
func NewPinnedHTTPTransport(resolution *ResolvedDestination, tlsConfig *tls.Config) *http.Transport {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	return &http.Transport{
		TLSClientConfig: tlsConfig.Clone(),
		DialContext:     NewPinnedDialContext(resolution.Host, resolution.IPs, 10*time.Second),
	}
}
