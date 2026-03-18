package manifest

import "strings"

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

// IsMethodAllowed checks whether the given HTTP method is in the constraints list.
func IsMethodAllowed(method string, constraints []MethodConstraint) bool {
	for _, mc := range constraints {
		if strings.EqualFold(mc.Method, method) {
			return true
		}
	}
	return false
}
