package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OAuthJWTBearerProvider chains GCP identity token minting with OAuth JWT
// bearer exchange to produce access tokens for MCP servers (or any OAuth
// resource server that accepts JWT bearer assertions).
//
// Flow:
//  1. Call IAM generateIdToken to get a Google-signed OIDC JWT for the target audience
//  2. POST to the target's /oauth/token with grant_type=jwt-bearer, assertion=<jwt>
//  3. Cache the resulting access token, refresh before expiry
type OAuthJWTBearerProvider struct {
	name           string
	hosts          map[string]bool
	serviceAccount string
	audience       string // target audience for the identity token
	tokenEndpoint  string // target's OAuth token exchange endpoint

	// HTTPClient for both IAM and exchange calls. If nil, http.DefaultClient.
	HTTPClient *http.Client

	mu        sync.RWMutex
	token     string
	expiresAt time.Time
	cancel    context.CancelFunc
}

// NewOAuthJWTBearerProvider creates a composite provider.
func NewOAuthJWTBearerProvider(name, serviceAccount, audience, tokenEndpoint string, hosts []string) *OAuthJWTBearerProvider {
	hostSet := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}
	return &OAuthJWTBearerProvider{
		name:           name,
		hosts:          hostSet,
		serviceAccount: serviceAccount,
		audience:       audience,
		tokenEndpoint:  tokenEndpoint,
	}
}

func (p *OAuthJWTBearerProvider) Name() string { return p.name }
func (p *OAuthJWTBearerProvider) Type() string { return "oauth-jwt-bearer" }

func (p *OAuthJWTBearerProvider) Matches(host string) bool {
	if len(p.hosts) == 0 {
		return true
	}
	return p.hosts[host]
}

func (p *OAuthJWTBearerProvider) InjectCredentials(req *http.Request) error {
	token, err := p.ResolveToken(req.Context())
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (p *OAuthJWTBearerProvider) ResolveToken(_ context.Context) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.token == "" {
		return "", fmt.Errorf("oauth-jwt-bearer: provider %q has no token (not yet exchanged)", p.name)
	}
	if time.Now().After(p.expiresAt) {
		return "", fmt.Errorf("oauth-jwt-bearer: provider %q token expired", p.name)
	}
	return p.token, nil
}

// Start performs the initial token exchange and starts the background refresh.
func (p *OAuthJWTBearerProvider) Start(ctx context.Context) error {
	if err := p.refresh(ctx); err != nil {
		return fmt.Errorf("oauth-jwt-bearer: initial exchange: %w", err)
	}

	refreshCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	go p.refreshLoop(refreshCtx)
	return nil
}

func (p *OAuthJWTBearerProvider) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
}

func (p *OAuthJWTBearerProvider) refreshLoop(ctx context.Context) {
	for {
		p.mu.RLock()
		expiresAt := p.expiresAt
		p.mu.RUnlock()

		ttl := time.Until(expiresAt)
		refreshIn := ttl * 3 / 4
		if refreshIn < 30*time.Second {
			refreshIn = 30 * time.Second
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(refreshIn):
			_ = p.refresh(ctx)
		}
	}
}

func (p *OAuthJWTBearerProvider) refresh(ctx context.Context) error {
	// Step 1: Mint GCP identity token (requires GCP-authenticated client).
	iamClient := p.HTTPClient
	if iamClient == nil {
		var err error
		iamClient, err = gcpAuthenticatedClient(ctx)
		if err != nil {
			return fmt.Errorf("gcp auth for IAM: %w", err)
		}
	}
	idToken, err := p.generateIDToken(ctx, iamClient)
	if err != nil {
		return fmt.Errorf("mint id token: %w", err)
	}

	// Step 2: Exchange for access token (public OAuth endpoint, no GCP auth needed).
	exchangeClient := p.HTTPClient
	if exchangeClient == nil {
		exchangeClient = http.DefaultClient
	}
	accessToken, expiresIn, err := p.exchangeJWTBearer(ctx, exchangeClient, idToken)
	if err != nil {
		return fmt.Errorf("jwt bearer exchange: %w", err)
	}

	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.token = accessToken
	p.expiresAt = expiresAt
	return nil
}

func (p *OAuthJWTBearerProvider) generateIDToken(ctx context.Context, client *http.Client) (string, error) {
	iamURL := fmt.Sprintf(
		"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken",
		p.serviceAccount,
	)

	body := fmt.Sprintf(`{"audience":%q,"includeEmail":true}`, p.audience)
	req, err := http.NewRequestWithContext(ctx, "POST", iamURL, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("generateIdToken returned %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Token, nil
}

func (p *OAuthJWTBearerProvider) exchangeJWTBearer(ctx context.Context, client *http.Client, assertion string) (string, int, error) {
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", 0, fmt.Errorf("token exchange returned %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, err
	}
	if result.Error != "" {
		return "", 0, fmt.Errorf("exchange error: %s: %s", result.Error, result.ErrorDesc)
	}
	if result.ExpiresIn == 0 {
		result.ExpiresIn = 3600 // default 1 hour
	}

	return result.AccessToken, result.ExpiresIn, nil
}
