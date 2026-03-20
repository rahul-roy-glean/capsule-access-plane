package manifest

import "testing"

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
