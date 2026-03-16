package providers

import (
	"fmt"
	"strings"
	"time"
)

type ProjectedFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    string `json:"mode,omitempty"`
}

type HelperBootstrap struct {
	Format string            `json:"format"`
	Env    map[string]string `json:"env,omitempty"`
	Files  []ProjectedFile   `json:"files,omitempty"`
}

type HelperBootstrapRequest struct {
	AccessPlaneURL    string
	HelperSessionID   string
	RunnerAttestation string
	ToolFamily        string
	Scope             string
	TTL               time.Duration
}

func BuildHelperBootstrap(req HelperBootstrapRequest) (HelperBootstrap, error) {
	helperScript := fmt.Sprintf(`#!/bin/sh
set -eu
curl -fsS \
  -X POST \
  -H 'Content-Type: application/json' \
  %q/v1/helpers/token \
  -d '{
    "helper_session_id": "%s",
    "runner_attestation": "%s"
  }'
`, req.AccessPlaneURL, req.HelperSessionID, req.RunnerAttestation)

	switch strings.ToLower(req.ToolFamily) {
	case "kubectl":
		return HelperBootstrap{
			Format: "exec-credential",
			Env: map[string]string{
				"KUBECONFIG": "/tmp/capsule/kubeconfig",
			},
			Files: []ProjectedFile{
				{
					Path:    "/tmp/capsule/bin/capsule-access-helper",
					Mode:    "0755",
					Content: helperScript,
				},
				{
					Path: "/tmp/capsule/kubeconfig",
					Mode: "0644",
					Content: `apiVersion: v1
kind: Config
clusters: []
contexts: []
current-context: ""
users:
  - name: capsule-access
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1beta1
        command: /tmp/capsule/bin/capsule-access-helper
`,
				},
			},
		}, nil
	case "google-adc", "gcloud":
		return HelperBootstrap{
			Format: "google-executable-source",
			Env: map[string]string{
				"GOOGLE_APPLICATION_CREDENTIALS": "/tmp/capsule/google-adc.json",
			},
			Files: []ProjectedFile{
				{
					Path:    "/tmp/capsule/bin/capsule-access-helper",
					Mode:    "0755",
					Content: helperScript,
				},
				{
					Path: "/tmp/capsule/google-adc.json",
					Mode: "0644",
					Content: `{
  "type": "external_account",
  "audience": "//capsule-access-plane",
  "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_url": "https://sts.invalid/token",
  "credential_source": {
    "executable": {
      "command": "/tmp/capsule/bin/capsule-access-helper",
      "timeout_millis": 30000
    }
  }
}`,
				},
			},
		}, nil
	default:
		return HelperBootstrap{}, fmt.Errorf("unsupported tool family %q", req.ToolFamily)
	}
}
