package providers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
)

// SessionToken holds credentials and identity for a specific session/source.
// For single-credential use, set Token directly.
// For multi-credential use, set Credentials and Rules.
type SessionToken struct {
	// Single credential (backward compatible).
	Token     string
	ExpiresAt time.Time

	// Identity headers.
	UserEmail    string
	ExtraHeaders map[string]string

	// Multi-credential: named credentials with routing rules.
	// If non-empty, Rules determine which credential key to use per request.
	Credentials map[string]string // key → token value
	Rules       []CredentialRule  // evaluated in order
}

// CredentialRule maps request patterns to a named credential key.
type CredentialRule struct {
	Methods       []string `json:"methods"`        // HTTP methods (empty = all)
	PathPatterns  []string `json:"path_patterns"`  // glob patterns (empty = all)
	CredentialKey string   `json:"credential_key"` // key into SessionToken.Credentials
}

// DelegatedProvider stores tokens that are pushed externally (e.g. by the
// host agent after an OAuth flow or control plane token issuance).
// Tokens are keyed by source IP for per-session credential isolation.
// A global fallback token is used when no source-specific token exists.
type DelegatedProvider struct {
	name  string
	hosts map[string]bool

	mu       sync.RWMutex
	global   *SessionToken            // fallback for non-session-scoped use
	sessions map[string]*SessionToken // sourceIP → token
}

// NewDelegatedProvider creates a provider that waits for tokens to be pushed
// via UpdateToken.
func NewDelegatedProvider(name string, hosts []string) *DelegatedProvider {
	hostSet := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}
	return &DelegatedProvider{
		name:     name,
		hosts:    hostSet,
		sessions: make(map[string]*SessionToken),
	}
}

func (p *DelegatedProvider) Name() string { return p.name }
func (p *DelegatedProvider) Type() string { return "delegated" }

func (p *DelegatedProvider) Matches(host string) bool {
	if len(p.hosts) == 0 {
		return true
	}
	return p.hosts[host]
}

func (p *DelegatedProvider) InjectCredentials(req *http.Request) error {
	st, err := p.resolveSession(req.Context())
	if err != nil {
		return err
	}

	token := st.resolveToken(req.Method, req.URL.Path)
	if token == "" {
		return fmt.Errorf("delegated: no credential matched for %s %s", req.Method, req.URL.Path)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	if st.UserEmail != "" {
		req.Header.Set("X-Glean-User-Email", st.UserEmail)
	}
	for k, v := range st.ExtraHeaders {
		req.Header.Set(k, v)
	}
	return nil
}

func (p *DelegatedProvider) ResolveToken(ctx context.Context) (string, error) {
	st, err := p.resolveSession(ctx)
	if err != nil {
		return "", err
	}
	// For ResolveToken (no request context), return the default token.
	if st.Token != "" {
		return st.Token, nil
	}
	// If multi-credential, return the first credential as default.
	for _, v := range st.Credentials {
		return v, nil
	}
	return "", fmt.Errorf("delegated: provider %q has no default token", p.name)
}

func (p *DelegatedProvider) Start(_ context.Context) error { return nil }
func (p *DelegatedProvider) Stop()                         {}

// UpdateToken stores a token. If sourceIP is non-empty, the token is scoped
// to that source. Otherwise it's set as the global fallback.
func (p *DelegatedProvider) UpdateToken(sourceIP string, st *SessionToken) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if sourceIP == "" {
		p.global = st
	} else {
		p.sessions[sourceIP] = st
	}
}

// RevokeSession removes the token for a specific source IP.
func (p *DelegatedProvider) RevokeSession(sourceIP string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.sessions, sourceIP)
}

// HasToken reports whether any token has been pushed (global or session).
func (p *DelegatedProvider) HasToken() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.global != nil || len(p.sessions) > 0
}

// resolveSession finds the best session token for the given context.
func (p *DelegatedProvider) resolveSession(ctx context.Context) (*SessionToken, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if sourceIP := SourceIPFromContext(ctx); sourceIP != "" {
		if st, ok := p.sessions[sourceIP]; ok {
			if !st.ExpiresAt.IsZero() && time.Now().After(st.ExpiresAt) {
				return nil, fmt.Errorf("delegated: provider %q token for %s expired", p.name, sourceIP)
			}
			return st, nil
		}
	}

	if p.global == nil {
		return nil, fmt.Errorf("delegated: provider %q has no token (none pushed yet)", p.name)
	}
	if !p.global.ExpiresAt.IsZero() && time.Now().After(p.global.ExpiresAt) {
		return nil, fmt.Errorf("delegated: provider %q global token expired", p.name)
	}
	return p.global, nil
}

// resolveToken selects the right credential for a request.
// For single-credential tokens, returns Token directly.
// For multi-credential tokens, evaluates Rules in order.
func (st *SessionToken) resolveToken(method, path string) string {
	if len(st.Credentials) == 0 {
		return st.Token
	}
	for _, rule := range st.Rules {
		if rule.matchesRequest(method, path) {
			if tok, ok := st.Credentials[rule.CredentialKey]; ok {
				return tok
			}
		}
	}
	// No rule matched — return default Token if set.
	return st.Token
}

func (r *CredentialRule) matchesRequest(method, path string) bool {
	if len(r.Methods) > 0 && !containsFold(r.Methods, method) {
		return false
	}
	if len(r.PathPatterns) > 0 {
		for _, pat := range r.PathPatterns {
			if manifest.MatchPathGlob(pat, path) {
				return true
			}
		}
		return false
	}
	return true
}

func containsFold(ss []string, s string) bool {
	for _, v := range ss {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// contextKey is an unexported type for context keys in this package.
type contextKey int

const sourceIPKey contextKey = iota

// WithSourceIP returns a context carrying the client's source IP.
func WithSourceIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, sourceIPKey, ip)
}

// SourceIPFromContext extracts the source IP from a context, or "".
func SourceIPFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(sourceIPKey).(string); ok {
		return v
	}
	return ""
}
