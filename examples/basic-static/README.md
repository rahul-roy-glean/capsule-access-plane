# Basic Static Provider

Minimal setup: one static credential, remote execution endpoint.

## Setup

```bash
# Build the binary
go build -o capsule-access-plane .

# Set required env vars
export ATTESTATION_SECRET="my-secret-key"
export CREDENTIAL_REF="env:GITHUB_TOKEN"
export GITHUB_TOKEN="ghp_your_github_pat_here"

# Start the server
./capsule-access-plane
```

## Generate an attestation token

```bash
go run ./cmd/gentoken -secret "my-secret-key" -runner-id runner-1 -session-id session-1
```

Save the output as `$TOKEN`.

## Usage

### Check health

```bash
curl http://localhost:8080/healthz
# {"status":"ok"}
```

### Resolve which lane to use

```bash
curl -s -X POST http://localhost:8080/v1/resolve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "actor": {"user_id": "user-1"},
    "runner": {"session_id": "session-1", "runner_id": "runner-1", "turn_id": "turn-1"},
    "tool_family": "github_rest",
    "logical_action": "read_repo"
  }'
# {"decision":"allow","selected_lane":"direct_http","implementation_state":"implemented",...}
```

### Execute an API call (remote execution lane)

The access plane makes the outbound call on your behalf, injecting credentials:

```bash
curl -s -X POST http://localhost:8080/v1/execute/http \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "runner_id": "runner-1",
    "session_id": "session-1",
    "turn_id": "turn-1",
    "tool_family": "github_rest",
    "method": "GET",
    "url": "https://api.github.com/repos/octocat/Hello-World"
  }'
# Returns: {"status_code":200,"headers":{...},"body":"{...}","audit_correlation_id":"exec-..."}
```

The `Authorization: Bearer ghp_...` header is injected by the access plane.
Your client never sees or handles the credential.

### Grant lifecycle (direct HTTP lane)

```bash
# 1. Project a grant — starts a per-grant proxy
GRANT=$(curl -s -X POST http://localhost:8080/v1/grants/project \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "runner_id": "runner-1",
    "session_id": "session-1",
    "turn_id": "turn-1",
    "tool_family": "github_rest",
    "lane": "direct_http",
    "scope": "repo:read"
  }')

GRANT_ID=$(echo $GRANT | jq -r .grant_id)
PROXY_ADDR=$(echo $GRANT | jq -r .projection_ref)
echo "Grant: $GRANT_ID, Proxy: $PROXY_ADDR"

# 2. Use the proxy — credential is injected automatically
curl -s http://$PROXY_ADDR/repos \
  -H "X-Target-URL: https://api.github.com/repos/octocat/Hello-World"
# The proxy adds Authorization: Bearer ghp_... and forwards

# 3. Revoke when done
curl -s -X POST http://localhost:8080/v1/grants/revoke \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"grant_id\": \"$GRANT_ID\", \"runner_id\": \"runner-1\"}"
```
