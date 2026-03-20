# Remote Execution

The access plane acts as a broker: the client describes the HTTP call it
wants to make, and the access plane executes it after validating the
request against the manifest and injecting credentials.

The credential never reaches the client.

## When to use remote execution vs direct HTTP

| | Remote Execution | Direct HTTP / CONNECT Proxy |
|-|-----------------|----------------------------|
| **How** | Client sends request spec as JSON | Client makes actual HTTP/HTTPS calls |
| **Credential exposure** | Never leaves access plane | Never leaves access plane |
| **Client complexity** | Must use access plane API | Standard HTTP client / `HTTPS_PROXY` |
| **Best for** | Single API calls, tools that can use a broker | Streaming, long-lived connections, standard tools |

## Setup

```bash
export ATTESTATION_SECRET="my-secret"
export CREDENTIAL_REF="env:GITHUB_TOKEN"
export GITHUB_TOKEN="ghp_your_pat"
go run .
```

## Generate a token

```bash
TOKEN=$(go run ./cmd/gentoken -secret "my-secret" -runner-id r1 -session-id s1)
```

## Examples

### Read a GitHub repo

```bash
curl -s -X POST http://localhost:8080/v1/execute/http \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "runner_id": "r1",
    "session_id": "s1",
    "turn_id": "t1",
    "tool_family": "github_rest",
    "method": "GET",
    "url": "https://api.github.com/repos/octocat/Hello-World"
  }' | jq .
```

Response:
```json
{
  "status_code": 200,
  "headers": {
    "Content-Type": "application/json; charset=utf-8",
    "X-Ratelimit-Remaining": "4999"
  },
  "body": "{\"id\":1296269,\"name\":\"Hello-World\",...}",
  "audit_correlation_id": "exec-s1-t1-1710921234567"
}
```

### Create a GitHub issue

```bash
curl -s -X POST http://localhost:8080/v1/execute/http \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "runner_id": "r1",
    "session_id": "s1",
    "turn_id": "t2",
    "tool_family": "github_rest",
    "method": "POST",
    "url": "https://api.github.com/repos/octocat/Hello-World/issues",
    "headers": {"Accept": "application/vnd.github.v3+json"},
    "body": "{\"title\":\"Bug report\",\"body\":\"Something broke\"}"
  }' | jq .status_code
# 201
```

### What gets blocked

```bash
# Wrong host (not in github_rest manifest):
curl -s -X POST http://localhost:8080/v1/execute/http \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "runner_id":"r1","session_id":"s1","turn_id":"t3",
    "tool_family":"github_rest","method":"GET",
    "url":"https://evil.example.com/steal"
  }' | jq .error
# "destination evil.example.com not allowed by manifest"

# Wrong method (github_rest allows GET, POST, PUT but not DELETE):
curl -s -X POST http://localhost:8080/v1/execute/http \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "runner_id":"r1","session_id":"s1","turn_id":"t4",
    "tool_family":"github_rest","method":"DELETE",
    "url":"https://api.github.com/repos/octocat/Hello-World"
  }' | jq .error
# "DELETE /repos/octocat/Hello-World not allowed by manifest constraints"

# Wrong path (POST only allowed to /repos/*/issues):
curl -s -X POST http://localhost:8080/v1/execute/http \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "runner_id":"r1","session_id":"s1","turn_id":"t5",
    "tool_family":"github_rest","method":"POST",
    "url":"https://api.github.com/repos/octocat/Hello-World/hooks"
  }' | jq .error
# "POST /repos/octocat/Hello-World/hooks not allowed by manifest constraints"

# SSRF (DNS resolves to private IP):
# The access plane resolves DNS and blocks requests to 10.x, 172.16.x, 127.x, 169.254.x
```

## Path patterns in manifests

The `github_rest` manifest defines these constraints:

```yaml
method_constraints:
  - method: GET
    path_pattern: "/repos/**"        # any depth under /repos
  - method: POST
    path_pattern: "/repos/*/issues"  # exactly /repos/{owner}/issues
  - method: PUT
    path_pattern: "/repos/*/pulls/*/merge"
```

Pattern syntax:
- `*` matches exactly one path segment
- `**` matches zero or more segments
- Empty pattern or `/**` matches any path for that method
