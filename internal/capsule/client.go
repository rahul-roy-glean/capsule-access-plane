package capsule

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

type InstallGrantRequest struct {
	GrantID     string            `json:"grant_id"`
	GrantType   string            `json:"grant_type"`
	RunnerID    string            `json:"runner_id"`
	SessionID   string            `json:"session_id"`
	TurnID      string            `json:"turn_id,omitempty"`
	Scope       string            `json:"scope"`
	Domains     []string          `json:"domains,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Token       string            `json:"token,omitempty"`
	ExpiresAt   string            `json:"expires_at"`
	ToolFamily  string            `json:"tool_family,omitempty"`
	HelperEnv   map[string]string `json:"helper_env,omitempty"`
	HelperFiles []HelperFile      `json:"helper_files,omitempty"`
}

type HelperFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    string `json:"mode,omitempty"`
}

type RevokeGrantRequest struct {
	GrantID   string `json:"grant_id"`
	GrantType string `json:"grant_type"`
	RunnerID  string `json:"runner_id"`
}

type GrantState struct {
	RunnerID       string            `json:"runner_id"`
	GrantID        string            `json:"grant_id"`
	GrantType      string            `json:"grant_type"`
	Status         string            `json:"status"`
	InstalledHosts []string          `json:"installed_hosts,omitempty"`
	HelperFiles    []HelperFile      `json:"helper_files,omitempty"`
	HelperEnv      map[string]string `json:"helper_env,omitempty"`
}

func (c *Client) InstallGrant(ctx context.Context, req InstallGrantRequest) error {
	return c.doJSON(ctx, http.MethodPost, "/api/v1/access/grants/install", nil, req, nil)
}

func (c *Client) RevokeGrant(ctx context.Context, req RevokeGrantRequest) error {
	return c.doJSON(ctx, http.MethodPost, "/api/v1/access/grants/revoke", nil, req, nil)
}

func (c *Client) DescribeGrantState(ctx context.Context, runnerID, grantID string) (*GrantState, error) {
	query := url.Values{}
	query.Set("runner_id", runnerID)
	query.Set("grant_id", grantID)
	var out GrantState
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/access/grants/state", query, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) doJSON(ctx context.Context, method, endpoint string, query url.Values, body any, out any) error {
	if c.baseURL == "" {
		return fmt.Errorf("capsule control plane URL is not configured")
	}
	fullURL := c.baseURL + endpoint
	if len(query) > 0 {
		fullURL += "?" + query.Encode()
	}

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal capsule request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, reader)
	if err != nil {
		return fmt.Errorf("create capsule request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("execute capsule request: %w", err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read capsule response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("capsule request failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	if out != nil && len(payload) > 0 {
		if err := json.Unmarshal(payload, out); err != nil {
			return fmt.Errorf("decode capsule response: %w", err)
		}
	}
	return nil
}
