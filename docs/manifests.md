# Tool Family Manifests

Manifests are YAML files that declare what a tool family is allowed to do. They
are the central policy artifact in the access plane — every outbound call is
validated against the manifest for its tool family.

## Schema

```yaml
family: string              # unique identifier (e.g., "github_rest")
version: string             # manifest version
surface_kind: string        # "http" or "cli"
provider: string            # optional — named credential provider (e.g., "github")

logical_actions:            # named operations the tool can perform
  - name: string
    risk_class: string      # "standard", "elevated", "admin"
    write: bool

supported_lanes:            # which execution lanes this family supports
  - direct_http
  - remote_execution
  - helper_session

preferred_lane:             # lane preference by risk class
  default: string           # fallback lane
  standard: string          # optional per-class override
  elevated: string
  admin: string

auth_patterns:              # how credentials are injected
  - bearer_token
  - github_app

destinations:               # allowed target hosts
  - host: string
    port: int               # optional
    protocol: string        # optional ("https")
    allowed_ips:            # optional — CIDR allowlist for SSRF (overrides default blocking)
      - "140.82.112.0/20"

method_constraints:         # allowed HTTP methods and path patterns
  - method: string          # "GET", "POST", "PUT", "DELETE", etc.
    path_pattern: string    # glob pattern (e.g., "/repos/**")
    enforcement: string     # "enforce" (default) or "audit"

execution_hints:            # operator-facing flags
  require_approval: "true"
  audit_level: "full"

helper_support:             # credential helper config (for helper_session lane)
  format: string            # "exec-credential", "git-credential", etc.
  protocol: string
  env:
    KEY: value

binary_matchers:            # CLI binary names this family applies to
  - string
```

## Path Patterns

Method constraints support glob patterns for URL path enforcement:

| Pattern | Matches | Does not match |
|---------|---------|----------------|
| `/repos/**` | `/repos/foo`, `/repos/foo/bar/baz` | `/users/foo` |
| `/repos/*/issues` | `/repos/myrepo/issues` | `/repos/myrepo/pulls` |
| `/repos/*/pulls/*/merge` | `/repos/r/pulls/42/merge` | `/repos/r/pulls/42/close` |
| `/**` | anything | — |
| (empty) | anything for that method | — |

- `*` matches exactly one path segment
- `**` matches zero or more segments (any depth)

## Enforcement Modes

Each method constraint can specify an enforcement mode:

- **`enforce`** (default) — reject requests that don't match
- **`audit`** — allow the request but log a warning; useful for rolling out
  new constraints without breaking existing clients

## SSRF Protection via AllowedIPs

By default, `CheckSSRF` blocks any destination that DNS-resolves to a private
IP (RFC 1918, loopback, link-local). This prevents DNS rebinding attacks.

If a destination needs to reach private infrastructure (e.g., a local test
server), set `allowed_ips` to a CIDR allowlist:

```yaml
destinations:
  - host: internal-api.corp
    allowed_ips: ["10.0.0.0/8"]
```

When `allowed_ips` is set, resolved IPs must fall within those CIDRs (the
default private-IP blocking is replaced by the explicit allowlist).

## Provider Field

The `provider` field references a named credential provider from the provider
registry. When set, the execute handler and grant handler use that specific
provider instead of the default.

```yaml
family: github_rest
provider: github    # uses the "github" provider from PROVIDERS_CONFIG
```

If `provider` is empty, the default provider is used (from `CREDENTIAL_REF`).

## Shipped Families

### github_rest

HTTP API access to GitHub. Supports `direct_http` and `remote_execution`.

| Field | Value |
|-------|-------|
| Surface | http |
| Destinations | `api.github.com:443` |
| Methods | GET `/repos/**`, POST `/repos/*/issues`, PUT `/repos/*/pulls/*/merge` |
| Default lane | direct_http |
| Actions | read_repo (standard), create_issue (standard), merge_pr (elevated) |

### github_git

Git protocol access to GitHub. Supports `helper_session` and `direct_http`.

### gcp_cli_read

Read-only GCP CLI access. Supports `helper_session` and `remote_execution`.

### gcp_adc

GCP Application Default Credentials. Supports `helper_session` and `direct_http`.

### kubectl

Kubernetes CLI access. Supports `remote_execution` and `helper_session`.

| Field | Value |
|-------|-------|
| Surface | cli |
| Default lane | remote_execution |
| Helper format | exec-credential |
| Actions | get_pods (standard), apply_manifest (elevated), port_forward (elevated) |

### internal_admin_cli

Internal admin operations. Supports `remote_execution` only.

| Field | Value |
|-------|-------|
| Surface | cli |
| Default lane | remote_execution |
| Approval required | Yes |
| Audit level | full |
| Actions | rotate_secrets (admin), drain_node (admin) |

## How Manifests Are Used

### At resolve time

The policy engine looks up the manifest to:
- determine the preferred lane based on risk class
- check if approval is required
- report whether the selected lane is implemented

### At grant/execute time

The handler looks up the manifest to:
- validate the target host is in the `destinations` list
- run SSRF check using the destination's `allowed_ips`
- validate the HTTP method and URL path against `method_constraints` (with glob matching)
- resolve credential from the named `provider` (or fall back to default)

### At CONNECT proxy time

The proxy checks all manifest destinations to:
- validate the CONNECT target host
- run SSRF check
- find a credential provider via `providers.ForHost()`
- enforce method+path on MITM'd requests

### Adding a new family

1. Create `manifest/families/your_family.yaml`
2. Declare destinations, method constraints, supported lanes, and actions
3. Rebuild — manifests are embedded at compile time via `go:embed`
4. The new family is immediately available to resolve, grant, and execute

## What's Not Enforced Yet

- **Auth patterns** — `auth_patterns` is informational. The access plane
  currently always injects Bearer tokens regardless of this field.
- **Port/protocol** — `destinations[].port` and `protocol` are stored but
  only the `host` is used for validation.
