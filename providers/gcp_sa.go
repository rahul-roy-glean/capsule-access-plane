package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// GCPServiceAccountProvider mints short-lived access tokens by impersonating
// a GCP service account via the IAM Credentials API (generateAccessToken).
// It caches the token and refreshes in the background before expiry.
type GCPServiceAccountProvider struct {
	name           string
	hosts          map[string]bool
	serviceAccount string
	scopes         []string

	// HTTPClient is used for IAM API calls. If nil, http.DefaultClient is used.
	// Set this for testing or to use a custom transport (e.g., workload identity).
	HTTPClient *http.Client

	mu        sync.RWMutex
	token     string
	expiresAt time.Time
	cancel    context.CancelFunc
}

// NewGCPServiceAccountProvider creates a provider that impersonates the given
// service account to mint scoped access tokens.
func NewGCPServiceAccountProvider(name string, serviceAccount string, scopes []string, hosts []string) *GCPServiceAccountProvider {
	hostSet := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}
	return &GCPServiceAccountProvider{
		name:           name,
		hosts:          hostSet,
		serviceAccount: serviceAccount,
		scopes:         scopes,
	}
}

func (p *GCPServiceAccountProvider) Name() string { return p.name }
func (p *GCPServiceAccountProvider) Type() string { return "gcp-sa" }

func (p *GCPServiceAccountProvider) Matches(host string) bool {
	if len(p.hosts) == 0 {
		return true
	}
	return p.hosts[host]
}

func (p *GCPServiceAccountProvider) InjectCredentials(req *http.Request) error {
	token, err := p.ResolveToken(req.Context())
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (p *GCPServiceAccountProvider) ResolveToken(_ context.Context) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.token == "" {
		return "", fmt.Errorf("gcp-sa: provider %q has no token (not yet refreshed)", p.name)
	}
	if time.Now().After(p.expiresAt) {
		return "", fmt.Errorf("gcp-sa: provider %q token expired", p.name)
	}
	return p.token, nil
}

// Start performs the initial token fetch and starts the background refresh loop.
func (p *GCPServiceAccountProvider) Start(ctx context.Context) error {
	if err := p.refresh(ctx); err != nil {
		return fmt.Errorf("gcp-sa: initial token fetch: %w", err)
	}

	refreshCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel

	go p.refreshLoop(refreshCtx)
	return nil
}

// Stop terminates the background refresh loop.
func (p *GCPServiceAccountProvider) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
}

func (p *GCPServiceAccountProvider) refreshLoop(ctx context.Context) {
	for {
		p.mu.RLock()
		expiresAt := p.expiresAt
		p.mu.RUnlock()

		// Refresh at 75% of the token's lifetime.
		ttl := time.Until(expiresAt)
		refreshIn := ttl * 3 / 4
		if refreshIn < 30*time.Second {
			refreshIn = 30 * time.Second
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(refreshIn):
			if err := p.refresh(ctx); err != nil {
				// Log but don't stop — the old token may still be valid.
				continue
			}
		}
	}
}

func (p *GCPServiceAccountProvider) refresh(ctx context.Context) error {
	token, expiresAt, err := p.generateAccessToken(ctx)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.token = token
	p.expiresAt = expiresAt
	return nil
}

// generateAccessToken calls the IAM Credentials API to mint a short-lived token.
func (p *GCPServiceAccountProvider) generateAccessToken(ctx context.Context) (string, time.Time, error) {
	url := fmt.Sprintf(
		"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
		p.serviceAccount,
	)

	body := fmt.Sprintf(`{"scope":[%s],"lifetime":"3600s"}`, p.formatScopes())
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("gcp-sa: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := p.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("gcp-sa: IAM API call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", time.Time{}, fmt.Errorf("gcp-sa: IAM API returned %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		AccessToken string `json:"accessToken"`
		ExpireTime  string `json:"expireTime"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("gcp-sa: decode response: %w", err)
	}

	expiresAt, err := time.Parse(time.RFC3339, result.ExpireTime)
	if err != nil {
		// Default to 1 hour if parse fails.
		expiresAt = time.Now().Add(time.Hour)
	}

	return result.AccessToken, expiresAt, nil
}

func (p *GCPServiceAccountProvider) formatScopes() string {
	var quoted []string
	for _, s := range p.scopes {
		quoted = append(quoted, fmt.Sprintf("%q", s))
	}
	return strings.Join(quoted, ",")
}

// GenerateIDToken calls the IAM Credentials API to mint a Google-signed OIDC
// identity token (JWT) for the given audience. This is different from
// generateAccessToken — the result is a JWT that can be used as an assertion
// in OAuth token exchange flows (e.g., JWT bearer grant).
func (p *GCPServiceAccountProvider) GenerateIDToken(ctx context.Context, audience string, includeEmail bool) (string, error) {
	url := fmt.Sprintf(
		"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken",
		p.serviceAccount,
	)

	body := fmt.Sprintf(`{"audience":%q,"includeEmail":%t}`, audience, includeEmail)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("gcp-sa: create id token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := p.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("gcp-sa: generateIdToken call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("gcp-sa: generateIdToken returned %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("gcp-sa: decode id token response: %w", err)
	}

	return result.Token, nil
}
