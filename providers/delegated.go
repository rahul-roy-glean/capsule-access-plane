package providers

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// DelegatedProvider stores tokens that are pushed externally (e.g. by the
// host agent after an OAuth flow or control plane token issuance).
type DelegatedProvider struct {
	name  string
	hosts map[string]bool

	mu        sync.RWMutex
	token     string
	expiresAt time.Time
}

// NewDelegatedProvider creates a provider that waits for tokens to be pushed
// via UpdateToken.
func NewDelegatedProvider(name string, hosts []string) *DelegatedProvider {
	hostSet := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}
	return &DelegatedProvider{
		name:  name,
		hosts: hostSet,
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
	token, err := p.ResolveToken(req.Context())
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (p *DelegatedProvider) ResolveToken(_ context.Context) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.token == "" {
		return "", fmt.Errorf("delegated: provider %q has no token (none pushed yet)", p.name)
	}
	if !p.expiresAt.IsZero() && time.Now().After(p.expiresAt) {
		return "", fmt.Errorf("delegated: provider %q token expired at %s", p.name, p.expiresAt)
	}
	return p.token, nil
}

func (p *DelegatedProvider) Start(_ context.Context) error { return nil }
func (p *DelegatedProvider) Stop()                         {}

// UpdateToken stores a new token, replacing any previous value.
func (p *DelegatedProvider) UpdateToken(token string, expiresAt time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.token = token
	p.expiresAt = expiresAt
}

// HasToken reports whether a token has been pushed.
func (p *DelegatedProvider) HasToken() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.token != ""
}
