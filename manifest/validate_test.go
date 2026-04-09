package manifest

import "testing"

func TestMatchHostGlob(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		want    bool
	}{
		// Exact matches
		{"api.github.com", "api.github.com", true},
		{"api.github.com", "evil.github.com", false},
		{"api.github.com", "api.github.com.evil.com", false},

		// Case insensitivity
		{"API.GitHub.COM", "api.github.com", true},
		{"api.github.com", "API.GITHUB.COM", true},
		{"*.GitHub.COM", "api.github.com", true},
		{"**.GitHub.COM", "api.github.com", true},

		// Single wildcard *.suffix
		{"*.googleapis.com", "storage.googleapis.com", true},
		{"*.googleapis.com", "compute.googleapis.com", true},
		{"*.googleapis.com", "googleapis.com", false},     // * requires at least one label
		{"*.googleapis.com", "a.b.googleapis.com", false}, // * matches exactly one label
		{"*.foo.bar.com", "x.foo.bar.com", true},
		{"*.foo.bar.com", "foo.bar.com", false},
		{"*.foo.bar.com", "a.b.foo.bar.com", false},

		// Double wildcard **.suffix
		{"**.googleapis.com", "storage.googleapis.com", true},
		{"**.googleapis.com", "a.b.googleapis.com", true},
		{"**.googleapis.com", "googleapis.com", true}, // ** matches zero labels
		{"**.googleapis.com", "a.b.c.d.googleapis.com", true},
		{"**.example.com", "example.com", true},
		{"**.example.com", "sub.example.com", true},
		{"**.example.com", "deep.sub.example.com", true},

		// Edge cases
		{"", "", true},            // empty pattern matches empty host (exact match)
		{"", "anything", false},   // empty pattern does not match non-empty host
		{"anything", "", false},   // non-empty pattern does not match empty host
		{"*", "anything", false},  // bare * is not a valid wildcard prefix pattern; no "." follows
		{"**", "anything", false}, // bare ** is not a valid wildcard prefix pattern; no "." follows

		// Patterns that are NOT wildcards (no dot after *)
		{"*foo.com", "xfoo.com", false},  // not a valid pattern — treated as literal
		{"**foo.com", "xfoo.com", false}, // not a valid pattern — treated as literal

		// Host must not partially match the suffix
		{"*.example.com", "notexample.com", false},
		{"**.example.com", "notexample.com", false},
	}

	for _, tt := range tests {
		got := MatchHostGlob(tt.pattern, tt.host)
		if got != tt.want {
			t.Errorf("MatchHostGlob(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
		}
	}
}

func TestHostMatcher(t *testing.T) {
	m := NewHostMatcher([]Destination{
		{Host: "api.github.com"},
		{Host: "*.googleapis.com"},
		{Host: "**.internal.example.com"},
	})

	tests := []struct {
		host string
		want bool
	}{
		// Exact match
		{"api.github.com", true},
		{"API.GITHUB.COM", true},
		{"evil.github.com", false},

		// Single wildcard
		{"storage.googleapis.com", true},
		{"compute.googleapis.com", true},
		{"googleapis.com", false},
		{"a.b.googleapis.com", false},

		// Double wildcard
		{"internal.example.com", true},
		{"foo.internal.example.com", true},
		{"a.b.c.internal.example.com", true},

		// Not allowed
		{"evil.com", false},
	}

	for _, tt := range tests {
		got := m.Matches(tt.host)
		if got != tt.want {
			t.Errorf("HostMatcher.Matches(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestHostMatcher_Empty(t *testing.T) {
	m := NewHostMatcher(nil)
	if m.Matches("anything.com") {
		t.Error("empty HostMatcher should not match anything")
	}
}

func TestMatchesHost(t *testing.T) {
	destinations := []Destination{
		{Host: "api.github.com"},
		{Host: "*.googleapis.com"},
	}

	if !MatchesHost(destinations, "api.github.com") {
		t.Error("expected exact match")
	}
	if !MatchesHost(destinations, "storage.googleapis.com") {
		t.Error("expected wildcard match")
	}
	if MatchesHost(destinations, "evil.com") {
		t.Error("expected no match for evil.com")
	}
}

func TestFindDestination_Wildcard(t *testing.T) {
	destinations := []Destination{
		{Host: "api.github.com", Port: 443},
		{Host: "*.googleapis.com", Port: 443},
		{Host: "**.internal.example.com", Port: 8080},
	}

	// Exact match
	d := FindDestination(destinations, "api.github.com")
	if d == nil || d.Host != "api.github.com" {
		t.Error("expected to find api.github.com")
	}

	// Single wildcard match
	d = FindDestination(destinations, "storage.googleapis.com")
	if d == nil || d.Host != "*.googleapis.com" {
		t.Errorf("expected *.googleapis.com, got %v", d)
	}

	// Double wildcard match
	d = FindDestination(destinations, "deep.internal.example.com")
	if d == nil || d.Host != "**.internal.example.com" {
		t.Errorf("expected **.internal.example.com, got %v", d)
	}

	// No match
	d = FindDestination(destinations, "evil.com")
	if d != nil {
		t.Errorf("expected nil for evil.com, got %v", d)
	}
}

func TestBuildAllowedHosts_ReturnsHostMatcher(t *testing.T) {
	destinations := []Destination{
		{Host: "exact.com"},
		{Host: "*.wildcard.com"},
	}
	m := BuildAllowedHosts(destinations)
	if !m.Matches("exact.com") {
		t.Error("expected exact match")
	}
	if !m.Matches("foo.wildcard.com") {
		t.Error("expected wildcard match")
	}
	if m.Matches("evil.com") {
		t.Error("expected no match")
	}
}

func TestMatchPathGlob(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Exact matches
		{"/repos", "/repos", true},
		{"/repos/foo", "/repos/foo", true},
		{"/repos/foo", "/repos/bar", false},

		// Single wildcard *
		{"/repos/*", "/repos/foo", true},
		{"/repos/*", "/repos/foo/bar", false},
		{"/repos/*/issues", "/repos/foo/issues", true},
		{"/repos/*/issues", "/repos/foo/bar", false},
		{"/repos/*/pulls/*/merge", "/repos/foo/pulls/123/merge", true},
		{"/repos/*/pulls/*/merge", "/repos/foo/pulls/123/close", false},

		// Double wildcard **
		{"/repos/**", "/repos/foo", true},
		{"/repos/**", "/repos/foo/bar", true},
		{"/repos/**", "/repos/foo/bar/baz", true},
		{"/repos/**", "/repos", true},
		{"/**", "/anything/at/all", true},
		{"/**", "/", true},

		// ** in the middle
		{"/repos/**/merge", "/repos/foo/pulls/123/merge", true},
		{"/repos/**/merge", "/repos/merge", true},
		{"/repos/**/merge", "/repos/foo/close", false},

		// Edge cases
		{"/", "/", true},
		{"/", "/foo", false},
		{"/repos", "/repos/extra", false},
		{"/repos/*/issues", "/repos", false},
	}

	for _, tt := range tests {
		got := matchPathGlob(tt.pattern, tt.path)
		if got != tt.want {
			t.Errorf("matchPathGlob(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

func TestIsRequestAllowed_MethodAndPath(t *testing.T) {
	constraints := []MethodConstraint{
		{Method: "GET", PathPattern: "/repos/**"},
		{Method: "POST", PathPattern: "/repos/*/issues"},
		{Method: "PUT", PathPattern: "/repos/*/pulls/*/merge"},
	}

	tests := []struct {
		method string
		path   string
		want   bool
	}{
		{"GET", "/repos/foo/bar", true},
		{"GET", "/repos/foo", true},
		{"POST", "/repos/myrepo/issues", true},
		{"POST", "/repos/myrepo/pulls", false},
		{"PUT", "/repos/myrepo/pulls/42/merge", true},
		{"PUT", "/repos/myrepo/pulls/42/close", false},
		{"DELETE", "/repos/foo", false},
		{"GET", "/users/foo", false},
	}

	for _, tt := range tests {
		check := IsRequestAllowed(tt.method, tt.path, constraints)
		if check.Allowed != tt.want {
			t.Errorf("IsRequestAllowed(%s, %s) allowed=%v, want %v (reason: %s)",
				tt.method, tt.path, check.Allowed, tt.want, check.Reason)
		}
	}
}

func TestIsRequestAllowed_EmptyPattern(t *testing.T) {
	// Empty path pattern matches any path for that method.
	constraints := []MethodConstraint{
		{Method: "GET", PathPattern: ""},
	}

	check := IsRequestAllowed("GET", "/anything/at/all", constraints)
	if !check.Allowed {
		t.Error("empty path pattern should match any path")
	}
}

func TestIsRequestAllowed_WildcardPattern(t *testing.T) {
	constraints := []MethodConstraint{
		{Method: "GET", PathPattern: "/**"},
	}

	check := IsRequestAllowed("GET", "/deep/nested/path", constraints)
	if !check.Allowed {
		t.Error("/** should match any path")
	}
}

func TestIsRequestAllowed_CaseInsensitiveMethod(t *testing.T) {
	constraints := []MethodConstraint{
		{Method: "get", PathPattern: "/repos/**"},
	}

	check := IsRequestAllowed("GET", "/repos/foo", constraints)
	if !check.Allowed {
		t.Error("method matching should be case-insensitive")
	}
}

func TestIsRequestAllowed_AuditMode(t *testing.T) {
	constraints := []MethodConstraint{
		{Method: "DELETE", PathPattern: "/repos/**", Enforcement: "audit"},
	}

	check := IsRequestAllowed("DELETE", "/repos/foo", constraints)
	if !check.Allowed {
		t.Error("audit mode should still allow the request")
	}
	if !check.Audit {
		t.Error("audit mode should set Audit=true")
	}
}

func TestIsRequestAllowed_EnforceMode(t *testing.T) {
	constraints := []MethodConstraint{
		{Method: "GET", PathPattern: "/repos/**", Enforcement: "enforce"},
	}

	check := IsRequestAllowed("GET", "/repos/foo", constraints)
	if !check.Allowed {
		t.Error("enforce mode should allow matching requests")
	}
	if check.Audit {
		t.Error("enforce mode should not set Audit=true")
	}
}

func TestIsRequestAllowed_DefaultEnforcementIsEnforce(t *testing.T) {
	constraints := []MethodConstraint{
		{Method: "GET", PathPattern: "/repos/**"},
	}

	check := IsRequestAllowed("GET", "/repos/foo", constraints)
	if !check.Allowed {
		t.Error("default enforcement should allow matching requests")
	}
	if check.Audit {
		t.Error("default enforcement should not set Audit=true")
	}
}

func TestIsRequestAllowed_NoConstraints(t *testing.T) {
	// With no constraints, nothing matches — callers should skip the check.
	check := IsRequestAllowed("GET", "/anything", nil)
	if check.Allowed {
		t.Error("no constraints should match nothing (callers gate on len > 0)")
	}
}

func TestExtractPath(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://api.github.com/repos/foo/bar", "/repos/foo/bar"},
		{"https://api.github.com/", "/"},
		{"https://api.github.com", "/"},
		{"http://localhost:8080/test", "/test"},
		{"ftp://invalid", ""},
	}

	for _, tt := range tests {
		got := ExtractPath(tt.url)
		if got != tt.want {
			t.Errorf("ExtractPath(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}
