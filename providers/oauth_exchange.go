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

// OAuthJWTBearerProvider produces access tokens by minting a JWT (via a
// JWTSource) and exchanging it (via a TokenExchanger). It caches the
// resulting token and refreshes it before expiry.
//
// Two configurations:
//
//	jwt_source=gcp-iam (default): GCP IAM generateIdToken → OAuth form-post exchange
//	jwt_source=local-key:         Local RSA key signing → configurable exchange style
type OAuthJWTBearerProvider struct {
	name  string
	hosts map[string]bool

	jwtSource JWTSource
	exchanger TokenExchanger

	// HTTPClient for exchange calls. If nil, http.DefaultClient.
	HTTPClient *http.Client

	mu        sync.RWMutex
	token     string
	expiresAt time.Time
	cancel    context.CancelFunc
}

// NewOAuthJWTBearerProvider creates a provider with GCP IAM JWT source and
// form-post exchange (backward compatible).
func NewOAuthJWTBearerProvider(name, serviceAccount, audience, tokenEndpoint string, hosts []string) *OAuthJWTBearerProvider {
	p := newProvider(name, hosts, nil, &FormPostExchanger{TokenEndpoint: tokenEndpoint})
	// Lazy-init: JWTSource uses the provider's HTTPClient if set, falling back to GCP ADC.
	p.jwtSource = &GCPIAMSource{
		ServiceAccount: serviceAccount,
		Audience:       audience,
		HTTPClientFunc: func(ctx context.Context) HTTPClient {
			if p.HTTPClient != nil {
				return p.HTTPClient
			}
			c, err := gcpAuthenticatedClient(ctx)
			if err != nil {
				return http.DefaultClient
			}
			return c
		},
	}
	return p
}

// NewLocalKeyProvider creates a provider that signs JWTs with a local RSA key
// and exchanges them via Bearer header (e.g. GitHub App installation tokens).
func NewLocalKeyProvider(name, issuer, tokenEndpoint string, privateKey string, hosts []string) (*OAuthJWTBearerProvider, error) {
	key, err := ParseRSAPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("local-key: %w", err)
	}
	return newProvider(name, hosts,
		&LocalKeySource{Issuer: issuer, PrivateKey: key},
		&BearerHeaderExchanger{TokenEndpoint: tokenEndpoint},
	), nil
}

func newProvider(name string, hosts []string, source JWTSource, exchanger TokenExchanger) *OAuthJWTBearerProvider {
	hostSet := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}
	return &OAuthJWTBearerProvider{
		name:      name,
		hosts:     hostSet,
		jwtSource: source,
		exchanger: exchanger,
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
	jwt, err := p.jwtSource.MintJWT(ctx)
	if err != nil {
		return fmt.Errorf("mint jwt: %w", err)
	}

	client := HTTPClient(http.DefaultClient)
	if p.HTTPClient != nil {
		client = p.HTTPClient
	}
	accessToken, expiresIn, err := p.exchanger.Exchange(ctx, client, jwt)
	if err != nil {
		return fmt.Errorf("token exchange: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.token = accessToken
	p.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	return nil
}

// generateIDToken calls GCP IAM to mint an OIDC identity token.
// Extracted as a package-level function for use by GCPIAMSource.
func generateIDToken(ctx context.Context, client HTTPClient, serviceAccount, audience string) (string, error) {
	iamURL := fmt.Sprintf(
		"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken",
		serviceAccount,
	)

	body := fmt.Sprintf(`{"audience":%q,"includeEmail":true}`, audience)
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
