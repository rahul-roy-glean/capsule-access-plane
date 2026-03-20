# Delegated Token Push

The host agent runs the OAuth/token-exchange flow externally and pushes the
resulting access token to the access plane. The access plane never sees
client secrets or refresh tokens.

## Flow

```
Control Plane            Host Agent              Access Plane         VM
     │                       │                       │                │
     │── issue token ──────►│                       │                │
     │◄── access_token ─────│                       │                │
     │                       │                       │                │
     │                       │── POST /v1/providers/ │                │
     │                       │   update-token ──────►│                │
     │                       │  {provider: "github", │                │
     │                       │   token: "gho_xxx"}   │                │
     │                       │◄── 200 updated ──────│                │
     │                       │                       │                │
     │                       │                       │◄── CONNECT ───│
     │                       │                       │    (injects    │
     │                       │                       │     gho_xxx)   │
     │                       │                       │                │
     │                       │                       │   (token       │
     │                       │                       │    expires)    │
     │                       │                       │                │
     │── refresh token ────►│                       │                │
     │◄── new access_token ─│                       │                │
     │                       │── POST update-token ─►│                │
     │                       │   {token: "gho_yyy"} │                │
```

## Setup

### providers.json

```json
[
  {
    "name": "github",
    "type": "delegated",
    "hosts": ["api.github.com", "github.com"]
  },
  {
    "name": "gcp",
    "type": "delegated",
    "hosts": ["storage.googleapis.com", "compute.googleapis.com"]
  }
]
```

### Start

```bash
export ATTESTATION_SECRET="my-secret"
export PROVIDERS_CONFIG="./providers.json"
export PROXY_ADDR=":3128"
go run .
```

### Push tokens (from host agent)

```bash
# Push GitHub token (e.g. from a GitHub App installation token exchange)
curl -s -X POST http://localhost:8080/v1/providers/update-token \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "github",
    "token": "ghs_installation_token_here",
    "expires_at": "2026-03-20T11:00:00Z"
  }'

# Push GCP token (e.g. from workload identity federation)
curl -s -X POST http://localhost:8080/v1/providers/update-token \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "gcp",
    "token": "ya29.gcp_access_token_here",
    "expires_at": "2026-03-20T10:45:00Z"
  }'
```

### Token refresh

When the host agent detects a token is nearing expiry, it repeats the
push with a fresh token. The access plane atomically replaces the old
value. In-flight requests using the old token complete normally; new
requests pick up the new token.

```bash
# 50 minutes later, refresh the GitHub token:
curl -s -X POST http://localhost:8080/v1/providers/update-token \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "github",
    "token": "ghs_refreshed_token_here",
    "expires_at": "2026-03-20T12:00:00Z"
  }'
```

### Error cases

```bash
# Provider doesn't exist:
curl -s -X POST http://localhost:8080/v1/providers/update-token \
  -d '{"provider":"nonexistent","token":"tok"}'
# => 404 {"error":"unknown provider: nonexistent"}

# Provider is not delegated (e.g. static):
curl -s -X POST http://localhost:8080/v1/providers/update-token \
  -d '{"provider":"default","token":"tok"}'
# => 400 {"error":"provider default is not a delegated provider (type: static)"}

# Token has expired — requests through the proxy get:
# => 502 "credential injection failed"
# (the delegated provider returns an error on ResolveToken)
```
