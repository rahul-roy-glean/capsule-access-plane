# Access Plane Usage Guide

How to set up, configure, and integrate the Capsule Access Plane with workloads.

---

## Concepts

### Families

A **family** is a named group of API endpoints that a tool needs to function. Each family declares:

- **Destinations** — which hosts the tool talks to (e.g. `api.github.com`, `*.googleapis.com`)
- **Method constraints** — which HTTP methods and URL paths are allowed (e.g. `GET /repos/**`)
- **Phantom env** — fake environment variables that trick CLIs into thinking credentials are present (the real credentials are injected at the network layer by the proxy)
- **Provider** — which credential provider handles authentication for this family

Families are the unit of access control. When a session is allowed to use `github_rest`, it can reach `api.github.com` and `github.com` with the methods declared in that family's manifest — nothing else.

**Shipped families:**

| Family | What it covers | Destinations |
|--------|---------------|-------------|
| `github_rest` | GitHub REST API + GraphQL | `api.github.com`, `github.com` |
| `github_git` | Git clone/push over HTTPS | (credential helper, no destinations) |
| `gcp_cli_read` | gcloud, gsutil, GCP APIs | `*.googleapis.com` |
| `gcp_adc` | GCP Application Default Credentials | (credential helper) |
| `kubectl` | Kubernetes CLI | (credential helper) |
| `slack_api` | Slack API | `*.slack.com` |
| `internal_admin_cli` | Internal admin tools | (remote execution only) |

You can also create custom families via the API (see [Dynamic Families](#dynamic-families)).

### Providers

A **provider** is a credential source. It knows how to produce an authentication token for a set of hosts. Providers are configured per access plane deployment in a JSON file.

**Provider types:**

| Type | How it works | Use case |
|------|-------------|----------|
| `delegated` | External service pushes tokens via API or at allocation time | GitHub installation tokens, user-scoped OAuth tokens |
| `gcp-sa` | Auto-mints GCP access tokens by impersonating a service account | GCP API access (gcloud, storage, compute) |
| `static` | Reads a token from an environment variable or literal | Fixed API keys, long-lived tokens |
| `oauth-jwt-bearer` | Exchanges a GCP identity token for an OAuth access token | Third-party services with OAuth federation |

### Session Policies

A **session policy** declares which families a specific VM session is allowed to use. The control plane pushes a session policy to the access plane after allocating a runner.

Sessions without a policy are denied all access. This is the enforcement point — even if a family exists in the registry, a session can only use it if the policy says so.

### How It All Fits Together

```mermaid
sequenceDiagram
    participant Caller as External Caller
    participant CP as Control Plane
    participant AP as Access Plane
    participant VM as Firecracker VM
    participant GH as GitHub / GCP

    Caller->>CP: POST /runners/allocate<br/>{workload_key, family_tokens: {github_rest: "ghs_..."}}
    CP->>CP: Resolve workload config<br/>(families: github_rest, gcp_cli_read)
    CP->>AP: POST /v1/sessions/{id}/policy<br/>{github_rest: {token}, gcp_cli_read: {}}
    AP-->>CP: 200 OK
    CP->>VM: Allocate runner on host<br/>(MMDS: proxy addr, attestation token)
    CP-->>Caller: {runner_id, session_id}

    Note over VM: VM boots, thaw agent runs
    VM->>AP: GET /v1/ca.pem
    AP-->>VM: CA certificate (for SSL bump)
    VM->>AP: GET /v1/phantom-env?session_id=...
    AP-->>VM: {GH_TOKEN: "phantom", CLOUDSDK_AUTH_ACCESS_TOKEN: "phantom"}
    Note over VM: Sets HTTPS_PROXY=bearer:TOKEN@AP:3128

    VM->>AP: CONNECT api.github.com:443<br/>(via HTTPS_PROXY)
    AP->>AP: Extract session_id from token<br/>Check policy → github_rest allowed<br/>SSL bump → inject real token
    AP->>GH: GET /repos/org/repo<br/>Authorization: Bearer ghs_...
    GH-->>AP: 200 {repo data}
    AP-->>VM: {repo data}

    VM->>AP: CONNECT evil.com:443
    AP->>AP: Check policy → no family allows evil.com
    AP-->>VM: 403 Forbidden
```

```mermaid
graph TB
    subgraph "Control Plane (central)"
        LC[Layered Config<br/>families: github_rest, gcp_cli_read]
        SCHED[Scheduler]
    end

    subgraph "Access Plane (per project)"
        REG[Family Registry<br/>YAML base + dynamic API]
        PROV[Provider Registry<br/>delegated, gcp-sa, static]
        PS[Session Policy Store<br/>session → allowed families]
        PROXY[CONNECT Proxy :3128<br/>SSL bump + credential injection]
    end

    subgraph "Firecracker VM"
        AGENT[Agent / CLI tools]
    end

    LC -->|pushSessionPolicy| PS
    SCHED -->|allocate + push policy| PS
    AGENT -->|HTTPS_PROXY| PROXY
    PROXY -->|check policy| PS
    PROXY -->|lookup family| REG
    PROXY -->|resolve credential| PROV
    PROXY -->|inject token| EXT[External APIs]
```

---

## Setup

### 1. Deploy the Access Plane

One access plane per project. Minimum configuration:

```bash
export ATTESTATION_SECRET="shared-secret-with-control-plane"
export PROXY_ADDR=":3128"
export PROVIDERS_CONFIG="/etc/capsule/providers.json"
```

### 2. Configure Providers

Create a `providers.json` with the credential sources your workloads need:

```json
[
  {
    "name": "github",
    "type": "delegated",
    "hosts": ["api.github.com", "github.com"]
  },
  {
    "name": "gcp",
    "type": "gcp-sa",
    "hosts": ["*.googleapis.com"],
    "config": {
      "service_account": "agent-sa@my-project.iam.gserviceaccount.com",
      "scopes": "https://www.googleapis.com/auth/cloud-platform"
    }
  }
]
```

**Delegated providers** require no config — tokens are pushed at runtime. Use for tokens that are per-session or short-lived (GitHub App installation tokens, user OAuth tokens).

**GCP-SA providers** auto-mint tokens. The access plane pod must have IAM permission to impersonate the target service account (typically via Workload Identity on GKE). No token push needed.

### 3. Register the Access Plane with the Control Plane

```bash
curl -X POST http://control-plane:8080/api/v1/access-planes \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "my-project",
    "access_plane_addr": "http://10.0.16.7:8080",
    "proxy_addr": "10.0.16.7:3128",
    "attestation_secret_ref": "shared-secret-with-control-plane",
    "tenant_id": "my-project"
  }'
```

### 4. Register a Workload Config with Families

```json
{
  "display_name": "my-dev-sandbox",
  "project_id": "my-project",
  "base_image": "ubuntu:22.04",
  "layers": [
    {
      "name": "setup",
      "init_commands": [{"type": "shell", "args": ["apt-get install -y curl git gh"]}]
    }
  ],
  "config": {
    "tier": "m",
    "auto_pause": true,
    "families": {
      "github_rest": {},
      "gcp_cli_read": {}
    }
  }
}
```

The `families` block declares which families this workload uses. Each key is a family name. The value controls how credentials are sourced:

| Value | Meaning | Example |
|-------|---------|---------|
| `{}` | Delegated (token from caller at allocation) or auto-minting (provider handles it) | `"github_rest": {}` |
| `{"credential_ref": "sm:project/secret"}` | Managed — access plane resolves the secret reference | `"slack_api": {"credential_ref": "sm:my-project/slack-token"}` |

How does the access plane know which one? It depends on the **provider type** configured for that family:
- If the family's provider is `delegated` → expects a token from the caller
- If the family's provider is `gcp-sa` → auto-mints, no token needed
- If the family has a `credential_ref` → access plane resolves it

### 5. Allocate a Runner with Tokens

For delegated families, pass the token at allocation time:

```bash
curl -X POST http://control-plane:8080/api/v1/runners/allocate \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "req-1",
    "workload_key": "bf583f0c952897a5",
    "session_id": "sess-123",
    "family_tokens": {
      "github_rest": "ghs_xxxxxxxxxxxx"
    }
  }'
```

The control plane:
1. Allocates a runner on a host
2. Pushes session policy to the access plane (`POST /v1/sessions/sess-123/policy`) with:
   - `github_rest` → `{"token": "ghs_xxxx"}` (from `family_tokens`)
   - `gcp_cli_read` → `{}` (auto-minting, no token needed)
3. Packs access plane connection info into VM metadata
4. VM boots → thaw agent sets `HTTPS_PROXY`, fetches phantom env

For auto-minting families like `gcp_cli_read`, nothing extra is needed — the provider mints tokens automatically.

---

## What Happens Inside the VM

After allocation, the VM has:

```bash
# Proxy with attestation token embedded (set by thaw agent)
HTTPS_PROXY=http://bearer:ATTESTATION_TOKEN@10.0.16.7:3128

# Phantom env vars (fetched from access plane at boot)
GH_TOKEN=phantom              # tricks gh CLI into not prompting for login
GITHUB_TOKEN=phantom
CLOUDSDK_AUTH_ACCESS_TOKEN=phantom  # tricks gcloud into thinking it's authed
CLOUDSDK_CORE_PROJECT=phantom
```

When the agent runs `gh repo list`:
1. `gh` sees `GH_TOKEN=phantom` → doesn't prompt for login
2. `gh` makes HTTPS request to `api.github.com`
3. Request goes through `HTTPS_PROXY` → CONNECT proxy
4. Proxy extracts `session_id` from attestation token
5. Proxy looks up session policy → `github_rest` is allowed
6. Proxy does SSL bump (MITM with Capsule CA)
7. Proxy injects `Authorization: Bearer ghs_xxxx` (the real token)
8. Request reaches GitHub → response flows back to VM
9. Agent never sees the real token

When the agent runs `gcloud storage ls`:
1. `gcloud` sees `CLOUDSDK_AUTH_ACCESS_TOKEN=phantom`
2. Makes request to `storage.googleapis.com`
3. Proxy checks session policy → `gcp_cli_read` is allowed
4. Proxy's `gcp-sa` provider auto-mints a fresh GCP access token
5. Proxy injects the real token → request reaches GCP

When the agent tries `curl https://evil.com`:
1. Request goes through proxy
2. Proxy checks session policy → no family allows `evil.com`
3. **403 Forbidden** — request blocked

---

## Provider Configuration Reference

### Delegated

Tokens pushed externally. Use for per-session credentials.

```json
{
  "name": "github",
  "type": "delegated",
  "hosts": ["api.github.com", "github.com"]
}
```

No `config` needed. Tokens arrive via:
- `POST /v1/sessions/{id}/policy` with `{"token": "..."}` (from control plane)
- `POST /v1/providers/update-token` (direct push)

### GCP Service Account

Auto-mints GCP access tokens by impersonating a service account.

```json
{
  "name": "gcp",
  "type": "gcp-sa",
  "hosts": ["*.googleapis.com"],
  "config": {
    "service_account": "agent-sa@my-project.iam.gserviceaccount.com",
    "scopes": "https://www.googleapis.com/auth/cloud-platform"
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `service_account` | Yes | Email of the GCP service account to impersonate |
| `scopes` | No | Comma-separated OAuth scopes (defaults to `cloud-platform`) |

**Prerequisites:** The access plane pod must be able to call `iamcredentials.googleapis.com` and have the `iam.serviceAccountTokenCreator` role on the target service account. On GKE, use Workload Identity.

### Static

Reads a fixed token from an environment variable.

```json
{
  "name": "internal",
  "type": "static",
  "hosts": ["api.internal.corp"],
  "config": {
    "credential_ref": "env:INTERNAL_API_TOKEN"
  }
}
```

Credential ref formats:
- `env:VAR_NAME` — read from environment variable
- `literal:token-value` — hardcoded value (avoid in production)

### OAuth JWT Bearer

Exchanges a GCP identity token for an OAuth access token.

```json
{
  "name": "mcp-server",
  "type": "oauth-jwt-bearer",
  "hosts": ["mcp.example.com"],
  "config": {
    "service_account": "agent-sa@my-project.iam.gserviceaccount.com",
    "audience": "https://mcp.example.com",
    "token_endpoint": "https://mcp.example.com/oauth/token"
  }
}
```

---

## Dynamic Families

Besides the YAML-shipped families, you can create custom families via the API.

### Create a family

```bash
curl -X POST http://access-plane:8080/v1/families \
  -H "Content-Type: application/json" \
  -d '{
    "family": "jira_api",
    "version": "1.0",
    "surface_kind": "http",
    "supported_lanes": ["direct_http", "remote_execution"],
    "destinations": [
      {"host": "mycompany.atlassian.net", "port": 443, "protocol": "https"}
    ],
    "method_constraints": [
      {"method": "GET", "path_pattern": "/**"},
      {"method": "POST", "path_pattern": "/rest/api/*/issue"}
    ],
    "phantom_env": {
      "JIRA_TOKEN": "phantom"
    }
  }'
```

### List families

```bash
curl http://access-plane:8080/v1/families
```

Returns both YAML (source: `yaml`) and API-created (source: `api`) families.

### Delete a dynamic family

```bash
curl -X DELETE http://access-plane:8080/v1/families/jira_api
```

YAML families cannot be deleted (returns 409).

---

## Family Manifest Reference

A family manifest declares what a tool can do and how the access plane should handle it.

```yaml
family: github_rest            # Unique name
version: "1.0"                 # Manifest version
surface_kind: http             # "http", "cli", or "sdk"

# What the tool can do
logical_actions:
  - name: read_repo
    risk_class: standard       # "standard", "elevated", or "admin"
    write: false
  - name: merge_pr
    risk_class: elevated
    write: true

# How the tool executes
supported_lanes:
  - direct_http                # CONNECT proxy / forward proxy
  - remote_execution           # Access plane makes the call
preferred_lane:
  default: direct_http

# Authentication
auth_patterns:
  - bearer_token
provider: "github"             # Named provider from providers.json

# Network
destinations:
  - host: api.github.com
    port: 443
    protocol: https
  - host: github.com
    port: 443
    protocol: https

# HTTP method/path enforcement
method_constraints:
  - method: GET
    path_pattern: "/repos/**"  # ** = any depth
  - method: POST
    path_pattern: "/repos/*/issues"  # * = one segment
  - method: GET
    path_pattern: "/user"

# Phantom env vars (injected into VM at boot)
phantom_env:
  GH_TOKEN: "phantom"
  GITHUB_TOKEN: "phantom"

# CLI tool matching (for credential helpers)
binary_matchers:
  - gh
  - git
```

### Key fields

| Field | Purpose |
|-------|---------|
| `destinations` | Which hosts are allowed. Wildcard supported (`*.googleapis.com`). The CONNECT proxy rejects any host not in any family's destinations. |
| `method_constraints` | Which HTTP methods and URL paths are allowed. Checked during SSL bump. `**` matches any depth, `*` matches one segment. |
| `phantom_env` | Fake env vars injected at VM boot. They exist only to satisfy CLI tools that check for credentials locally before making HTTP calls. The proxy replaces them with real tokens at the network layer. |
| `provider` | Which named provider supplies credentials. If not set, falls back to the default provider. |
| `supported_lanes` | Which execution lanes this family works with. |

---

## Session Policy API

### Set a session's policy

Called by the control plane after allocating a runner.

```bash
POST /v1/sessions/{session_id}/policy
{
  "families": {
    "github_rest": {"token": "ghs_xxxx"},
    "gcp_cli_read": {"credential_ref": "sm:my-project/gcp-key"},
    "slack_api": {}
  }
}
```

Per-family values:

| Value | Meaning |
|-------|---------|
| `{"token": "..."}` | Delegated token — use this for credential injection |
| `{"credential_ref": "sm:..."}` | Managed — access plane resolves the secret reference |
| `{}` | Auto-minting — the provider handles token generation |

### Get a session's policy

```bash
GET /v1/sessions/{session_id}/policy
```

### Revoke a session's policy

```bash
DELETE /v1/sessions/{session_id}/policy
```

---

## Network Policy

When a workload has an access plane configured, the control plane auto-applies an `access-plane-only` network policy to the VM:

- **Default egress: deny all**
- **Allow:** access plane IP on ports 8080 (API) and 3128 (proxy)
- **Allow:** DNS (UDP/TCP port 53)
- **Block:** everything else, including all other RFC1918 addresses

This means the VM can only reach the internet through the access plane proxy. Direct egress is blocked.

---

## Common Patterns

### GitHub with installation tokens (delegated)

Provider config:
```json
{"name": "github", "type": "delegated", "hosts": ["api.github.com", "github.com"]}
```

Workload config:
```json
"families": {"github_rest": {}}
```

Allocation:
```json
"family_tokens": {"github_rest": "ghs_installation_token"}
```

### GCP with service account impersonation (auto-minting)

Provider config:
```json
{"name": "gcp", "type": "gcp-sa", "hosts": ["*.googleapis.com"], "config": {"service_account": "sa@proj.iam.gserviceaccount.com"}}
```

Workload config:
```json
"families": {"gcp_cli_read": {}}
```

Allocation — no `family_tokens` needed:
```json
{}
```

### Both GitHub + GCP

Provider config:
```json
[
  {"name": "github", "type": "delegated", "hosts": ["api.github.com", "github.com"]},
  {"name": "gcp", "type": "gcp-sa", "hosts": ["*.googleapis.com"], "config": {"service_account": "sa@proj.iam.gserviceaccount.com"}}
]
```

Workload config:
```json
"families": {"github_rest": {}, "gcp_cli_read": {}}
```

Allocation:
```json
"family_tokens": {"github_rest": "ghs_xxxx"}
```

### Custom API with static token

Provider config:
```json
{"name": "internal", "type": "static", "hosts": ["api.internal.corp"], "config": {"credential_ref": "env:INTERNAL_TOKEN"}}
```

Create a dynamic family:
```bash
curl -X POST http://access-plane:8080/v1/families -d '{
  "family": "internal_api",
  "version": "1.0",
  "surface_kind": "http",
  "supported_lanes": ["direct_http"],
  "provider": "internal",
  "destinations": [{"host": "api.internal.corp", "port": 443, "protocol": "https"}],
  "method_constraints": [{"method": "GET", "path_pattern": "/**"}]
}'
```

Workload config:
```json
"families": {"internal_api": {}}
```

---

## Troubleshooting

### VM can't reach access plane

Check that the network policy allows the access plane IP. The `access-plane-only` policy allowlists the IP extracted from the access plane address. If the access plane is on an RFC1918 address (e.g. `10.0.x.x`), it must be explicitly allowed before the RFC1918 drop rules.

### Proxy returns 502

The access plane can reach the proxy target but the outbound connection failed. Check:
- Access plane pod has internet egress (GKE Network Policy, firewall rules)
- DNS resolution works from the access plane pod

### Proxy returns 403

The target host is not in any allowed family's destinations, or the session has no policy set. Check:
- `GET /v1/sessions/{id}/policy` — does the session have a policy?
- `GET /v1/families` — is the target host covered by a family?

### `gh auth status` says "not logged in"

This is expected. `gh auth status` checks local credential storage, not the proxy. Use `gh repo list` or `gh api user` to test — these make actual API calls that go through the proxy.

### Phantom env not set in VM

Check thaw agent logs (`journalctl -u capsule-thaw-agent`). Look for:
- `Failed to fetch phantom env vars from access plane` — VM can't reach access plane API
- `Failed to fetch CA cert from access plane` — same network issue
- Verify MMDS data has `proxy.api_endpoint` and `proxy.attestation_token`
