# Multi-Provider Setup

Run the access plane with multiple credential providers serving different
hosts. Each tool family references its provider by name in the manifest.

## Scenario

| Provider | Type | Hosts | Credential source |
|----------|------|-------|-------------------|
| `default` | static | (all) | `CREDENTIAL_REF` env var |
| `github` | delegated | api.github.com, github.com | Pushed by host agent |
| `internal` | static | api.internal.corp | `INTERNAL_TOKEN` env var |

## providers.json

```json
[
  {
    "name": "github",
    "type": "delegated",
    "hosts": ["api.github.com", "github.com"]
  },
  {
    "name": "internal",
    "type": "static",
    "hosts": ["api.internal.corp"],
    "config": {
      "credential_ref": "env:INTERNAL_TOKEN"
    }
  }
]
```

## Start

```bash
export ATTESTATION_SECRET="my-secret"
export CREDENTIAL_REF="env:FALLBACK_TOKEN"
export FALLBACK_TOKEN="fallback-for-unmatched-families"
export INTERNAL_TOKEN="corp-api-key-123"
export PROVIDERS_CONFIG="./providers.json"
export PROXY_ADDR=":3128"

go run .
# INFO loaded provider configs count=2 path=./providers.json
# INFO starting CONNECT proxy addr=:3128
# INFO starting access plane addr=:8080
```

## How providers are selected

### Remote execution (`POST /v1/execute/http`)

The execute handler looks up the manifest for the tool family. If the
manifest has a `provider` field, it uses that named provider. Otherwise
it falls back to the default.

```yaml
# Manifest with explicit provider:
family: github_rest
provider: github      # ← uses the "github" delegated provider
destinations:
  - host: api.github.com

# Manifest without provider field:
family: gcp_adc
destinations:          # ← falls back to "default" static provider
  - host: oauth2.googleapis.com
```

### CONNECT proxy

The proxy checks `providers.ForHost(host)`. If a registered provider
matches the CONNECT target host, the connection is SSL-bumped and
credentials are injected. Otherwise it's raw-tunneled.

```
curl -x http://localhost:3128 https://api.github.com/repos/foo
  → proxy sees CONNECT api.github.com:443
  → "github" provider matches api.github.com
  → SSL bump, inject Bearer token from delegated provider

curl -x http://localhost:3128 https://pypi.org/simple/
  → proxy sees CONNECT pypi.org:443
  → no provider matches pypi.org
  → if pypi.org is in a manifest destination: raw tunnel
  → if not in any manifest: 403 rejected
```

### Grant lifecycle

The grant handler looks up the manifest for `req.ToolFamily`, reads
`m.Provider`, and resolves the credential through that provider.

## Push tokens for delegated providers

```bash
# GitHub App installation token (rotated every ~55 minutes by host agent)
curl -s -X POST http://localhost:8080/v1/providers/update-token \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "github",
    "token": "ghs_installation_token",
    "expires_at": "2026-03-20T11:00:00Z"
  }'
```

Static providers like `internal` resolve their token on every call via
`CredentialResolver` (reading from env, literal, or SQLite). No push needed.
