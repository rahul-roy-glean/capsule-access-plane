package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// HTTPClient is the interface for HTTP requests (allows testing).
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// TokenExchanger exchanges a JWT for an access token.
type TokenExchanger interface {
	// Exchange sends the JWT to the token endpoint and returns (access_token, expires_in_seconds, error).
	Exchange(ctx context.Context, client HTTPClient, jwt string) (string, int, error)
}

// FormPostExchanger uses the standard OAuth2 JWT Bearer grant (RFC 7523).
// POST with grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<jwt>
type FormPostExchanger struct {
	TokenEndpoint string
}

func (e *FormPostExchanger) Exchange(ctx context.Context, client HTTPClient, jwt string) (string, int, error) {
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {jwt},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", e.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return parseTokenResponse(client, req)
}

// BearerHeaderExchanger sends the JWT as a Bearer token in the Authorization header.
// Used by GitHub App installation token exchange.
type BearerHeaderExchanger struct {
	TokenEndpoint string
}

func (e *BearerHeaderExchanger) Exchange(ctx context.Context, client HTTPClient, jwt string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", e.TokenEndpoint, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")

	return parseTokenResponse(client, req)
}

func parseTokenResponse(client HTTPClient, req *http.Request) (string, int, error) {
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", 0, fmt.Errorf("token exchange returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		// Standard OAuth2 response
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
		// GitHub installation token response
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, err
	}
	if result.Error != "" {
		return "", 0, fmt.Errorf("exchange error: %s: %s", result.Error, result.ErrorDesc)
	}

	token := result.AccessToken
	if token == "" {
		token = result.Token
	}
	if token == "" {
		return "", 0, fmt.Errorf("no token in exchange response")
	}

	expiresIn := result.ExpiresIn
	if expiresIn == 0 {
		expiresIn = 3600
	}

	return token, expiresIn, nil
}
