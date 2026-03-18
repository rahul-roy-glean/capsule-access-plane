# Tool Family Manifests

Manifests are YAML files that declare what a tool family is allowed to do. They
are the central policy artifact in the access plane — every outbound call is
validated against the manifest for its tool family.

## Schema

```yaml
family: string              # unique identifier (e.g., "github_rest")
version: string             # manifest version
surface_kind: string        # "http" or "cli"

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

method_constraints:         # allowed HTTP methods and path patterns
  - method: string          # "GET", "POST", "PUT", "DELETE", etc.
    path_pattern: string    # glob pattern (e.g., "/repos/**")

execution_hints:            # operator-facing flags
  require_approval: "true"  # requires human approval before execution
  audit_level: "full"       # audit verbosity

helper_support:             # credential helper config (for helper_session lane)
  format: string            # "exec-credential", "git-credential", etc.
  protocol: string
  env:
    KEY: value

binary_matchers:            # CLI binary names this family applies to
  - string
```

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
- validate the HTTP method is in the `method_constraints` list
- (planned) validate the URL path matches the `path_pattern`

### Adding a new family

1. Create `manifest/families/your_family.yaml`
2. Declare destinations, method constraints, supported lanes, and actions
3. Rebuild — manifests are embedded at compile time via `go:embed`
4. The new family is immediately available to resolve, grant, and execute

## What's Not Enforced Yet

- **Path patterns** — `method_constraints[].path_pattern` is declared but not
  checked at runtime. Only the method is validated. Path enforcement is planned.
- **Auth patterns** — `auth_patterns` is informational. The access plane
  currently always injects Bearer tokens regardless of this field.
- **Port/protocol** — `destinations[].port` and `protocol` are stored but
  only the `host` is used for validation.
