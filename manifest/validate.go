package manifest

import "strings"

// HostMatcher efficiently matches hostnames against a set of destination hosts
// that may include wildcard patterns (* and **).
type HostMatcher struct {
	exact    map[string]bool // lowercased exact hostnames
	patterns []string        // wildcard patterns (lowercased)
}

// NewHostMatcher creates a HostMatcher from a list of destinations.
// Exact hosts go into a map for O(1) lookup; wildcard patterns are stored
// separately and checked in order.
func NewHostMatcher(destinations []Destination) *HostMatcher {
	m := &HostMatcher{
		exact: make(map[string]bool, len(destinations)),
	}
	for _, d := range destinations {
		h := strings.ToLower(d.Host)
		if strings.HasPrefix(h, "*.") || strings.HasPrefix(h, "**.") {
			m.patterns = append(m.patterns, h)
		} else {
			m.exact[h] = true
		}
	}
	return m
}

// Matches reports whether host matches any destination in this matcher.
func (m *HostMatcher) Matches(host string) bool {
	h := strings.ToLower(host)
	if m.exact[h] {
		return true
	}
	for _, pat := range m.patterns {
		if matchHostGlob(pat, h) {
			return true
		}
	}
	return false
}

// BuildAllowedHosts returns a HostMatcher for the given destinations.
// This replaces the former map[string]bool return value.
func BuildAllowedHosts(destinations []Destination) *HostMatcher {
	return NewHostMatcher(destinations)
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

// MatchHostGlob matches a hostname against a pattern that supports:
//   - Exact match: "api.github.com" matches "api.github.com"
//   - Wildcard prefix: "*.googleapis.com" matches "storage.googleapis.com"
//     but NOT "googleapis.com" (the * requires exactly one label)
//     and NOT "a.b.googleapis.com" (single wildcard matches one label only)
//   - Double wildcard: "**.example.com" matches "a.b.c.example.com",
//     "x.example.com", and "example.com" (zero or more labels)
//
// Matching is case-insensitive (DNS is case-insensitive).
func MatchHostGlob(pattern, host string) bool {
	return matchHostGlob(strings.ToLower(pattern), strings.ToLower(host))
}

// matchHostGlob is the internal implementation; both arguments must already
// be lowercased.
func matchHostGlob(pattern, host string) bool {
	if pattern == host {
		return true
	}

	// Double-wildcard: **.suffix matches zero or more labels before suffix.
	if strings.HasPrefix(pattern, "**.") {
		suffix := pattern[3:] // e.g. "example.com" from "**.example.com"
		if host == suffix {
			return true // zero extra labels
		}
		return strings.HasSuffix(host, "."+suffix)
	}

	// Single-wildcard: *.suffix matches exactly one label before suffix.
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:] // e.g. "googleapis.com" from "*.googleapis.com"
		if !strings.HasSuffix(host, "."+suffix) {
			return false
		}
		prefix := host[:len(host)-len(suffix)-1] // the part before ".suffix"
		// The prefix must be a single DNS label (no dots).
		return len(prefix) > 0 && !strings.Contains(prefix, ".")
	}

	return false
}

// MatchesHost checks if a hostname matches any of the given destination hosts,
// supporting wildcard patterns.
func MatchesHost(destinations []Destination, host string) bool {
	h := strings.ToLower(host)
	for _, d := range destinations {
		if matchHostGlob(strings.ToLower(d.Host), h) {
			return true
		}
	}
	return false
}

// FindDestination returns the first Destination whose host pattern matches the
// given host, or nil. Supports wildcard patterns (* and **).
func FindDestination(destinations []Destination, host string) *Destination {
	h := strings.ToLower(host)
	for i := range destinations {
		if matchHostGlob(strings.ToLower(destinations[i].Host), h) {
			return &destinations[i]
		}
	}
	return nil
}
