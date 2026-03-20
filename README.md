# Capsule Access Plane

The access plane is a security boundary between AI agent sandboxes and external
services. It ensures that credentials never enter the sandbox, every outbound
call is policy-checked against a tool manifest, and every operation is
audit-logged.

## Why This Exists

When an AI agent running inside a [Capsule](https://github.com/rahul-roy-glean/capsule)
microVM needs to call GitHub, kubectl, or any authenticated API, the naive
approach is to inject credentials into the sandbox. That creates a blast radius:
a compromised or misbehaving agent can exfiltrate tokens, call endpoints it
shouldn't, or use HTTP methods the operator never intended.

The access plane eliminates this class of risk:

- **Credentials stay outside the sandbox.** The agent never sees a raw token.
  It either uses a CONNECT proxy that injects credentials transparently, gets a
  scoped local proxy (direct HTTP), or asks the access plane to make the call
  on its behalf (remote execution).
- **Every call is manifest-validated.** Allowed destinations, HTTP methods, URL
  paths, and logical actions are declared per tool family in YAML manifests.
  Anything outside the manifest is rejected before a network connection is made.
- **SSRF protection.** DNS resolution is validated on every outbound connection.
  Private IPs (RFC 1918, loopback, link-local, GCP metadata) are blocked unless
  explicitly allowlisted per destination.
- **Policy is evaluated on every request.** A pluggable policy engine decides
  allow/deny and selects the execution lane based on risk class, tool family,
  and operator configuration.
- **Full audit trail.** Every resolve, grant, execute, and proxy operation is
  structured-logged with session, runner, and correlation identifiers.

## How It Works

```text
┌─────────────────────────────────────────────────────────────────┐
│                     Capsule microVM                             │
│                                                                 │
│  Agent ──► HTTPS_PROXY=172.16.0.1:3128                          │
│            curl https://api.github.com/repos/foo/bar            │
│                 └── CONNECT proxy: SSL bump, inject credential  │
│                                                                 │
│  Agent ──► POST /v1/execute/http ──► access plane makes the     │
│            call, returns response ──► agent never sees token     │
│                                                                 │
│  Agent ──► POST /v1/grants/project ──► proxy on :54321          │
│            sandbox calls proxy ──► proxy injects credential      │
└─────────────────────────────────────────────────────────────────┘
```

## Execution Lanes

### Lane 1: Remote Execution (recommended default)

The agent sends "make this HTTP call for me." The access plane validates
everything, injects the credential, makes the call, and returns the response.
The credential never leaves the access plane process.

**Status: Implemented** — `POST /v1/execute/http`

### Lane 2: Direct HTTP

Two modes:

**CONNECT Proxy (SSL bump):** The VM sets `HTTPS_PROXY` and makes standard
HTTPS requests. The proxy selectively MITM's connections to hosts with a
credential provider (injecting tokens), and raw-tunnels everything else.

**Status: Implemented** — `PROXY_ADDR` env var

**Grant-based forward proxy:** The agent gets a grant, receives a local proxy
address, and sends requests with `X-Target-URL` headers. The proxy enforces
the manifest and injects credentials.

**Status: Implemented** — grant lifecycle + forward proxy

### Lane 3: Helper Session

For CLI tools (kubectl, git) that use credential helpers or exec-credential
protocols.

**Status: Not yet implemented**

## Tool Family Manifests

Each tool family is declared in a YAML manifest under `manifest/families/`:

```yaml
# manifest/families/github_rest.yaml
family: github_rest
version: "1.0"
surface_kind: http
logical_actions:
  - name: read_repo
    risk_class: standard
    write: false
  - name: merge_pr
    risk_class: elevated
    write: true
supported_lanes:
  - direct_http
  - remote_execution
destinations:
  - host: api.github.com
    port: 443
    protocol: https
    allowed_ips:                    # optional CIDR allowlist for SSRF
      - "140.82.112.0/20"
method_constraints:
  - method: GET
    path_pattern: "/repos/**"       # ** matches any depth
  - method: POST
    path_pattern: "/repos/*/issues" # * matches one segment
    enforcement: enforce            # "enforce" (default) or "audit"
```

Shipped families: `github_rest`, `github_git`, `gcp_cli_read`, `gcp_adc`,
`kubectl`, `internal_admin_cli`.

## API Reference

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/healthz` | GET | Health check |
| `/v1/resolve` | POST | Policy decision — returns selected lane + implementation state |
| `/v1/grants/project` | POST | Create a grant and start a credential-injecting proxy |
| `/v1/grants/exchange` | POST | Validate a projected grant is active |
| `/v1/grants/refresh` | POST | Extend grant lifetime |
| `/v1/grants/revoke` | POST | Revoke grant and stop proxy |
| `/v1/execute/http` | POST | Remote broker execution — make an HTTP call on behalf of the agent |
| `/v1/providers/update-token` | POST | Push a delegated credential token (from host agent) |
| `/v1/events/runner` | POST | Runner lifecycle events (not yet implemented) |

All endpoints except `/healthz` and `/v1/providers/update-token` require an
HMAC-signed attestation token in the `Authorization: Bearer <token>` header.

## Project Structure

```text
accessplane/          Domain types — requests, responses, lanes, decisions
audit/                Structured audit logging
bundle/               Projection bundles for grant lifecycle
cmd/gentoken/         CLI tool to generate signed attestation tokens (for dev/test)
dev/                  Docker Compose, env template, smoke test script
examples/             Usage examples (basic setup, CONNECT proxy, delegated tokens, etc.)
grants/               Grant lifecycle service
identity/             HMAC attestation token signing and verification
manifest/             Tool family manifests, registry, validation, SSRF protection
  families/           YAML manifest definitions (embedded at build time)
policy/               Policy engine — manifest-based allow/deny + lane selection
providers/            Credential provider framework (static, delegated, registry, config loader)
proxy/                HTTPS CONNECT proxy with selective SSL bump
runtime/              Runtime adapters (direct HTTP forward proxy)
server/               HTTP handlers (resolve, grants, execute, token update)
store/                SQLite persistence
```

## Getting Started

### Prerequisites

- Go 1.25+
- Docker (optional, for containerized testing)

### Run locally

```bash
export ATTESTATION_SECRET=local-dev-secret
export GITHUB_TOKEN=ghp_your_token_here
go run .
```

### Run with CONNECT proxy

```bash
export ATTESTATION_SECRET=local-dev-secret
export CREDENTIAL_REF="env:GITHUB_TOKEN"
export GITHUB_TOKEN=ghp_your_token_here
export PROXY_ADDR=":3128"
go run .
```

### Run with provider config

```bash
export ATTESTATION_SECRET=local-dev-secret
export PROVIDERS_CONFIG=./examples/multi-provider/providers.json
export PROXY_ADDR=":3128"
go run .
```

### Run the test suite

```bash
make ci          # lint + vet + test (with race detector) + build
make test        # just tests
make lint        # just linting
```

## Configuration

| Environment Variable | Required | Default | Description |
|---------------------|----------|---------|-------------|
| `ATTESTATION_SECRET` | Yes | — | Shared HMAC secret for runner attestation tokens |
| `LISTEN_ADDR` | No | `:8080` | HTTP API listen address |
| `DATABASE_URL` | No | `capsule-access.db` | SQLite database path |
| `CREDENTIAL_REF` | No | `env:GITHUB_TOKEN` | Default credential reference (`env:`, `literal:`, `stored:`) |
| `PROVIDERS_CONFIG` | No | — | Path to JSON file with `[]ProviderConfig` for named providers |
| `PROXY_ADDR` | No | — | CONNECT proxy listen address (e.g. `:3128`). Empty = no proxy. |

## What's Missing

The following are designed but not yet implemented:

- [ ] **Helper session lane** — credential helper protocol for CLI tools (kubectl, git)
- [ ] **Denial feedback pipeline** — aggregate denied requests, propose manifest additions, approve/reject workflow
- [ ] **Runner lifecycle events** — `POST /v1/events/runner` for allocation, release, pause, resume signals
- [ ] **Approval workflow** — policy can flag `approval_required` but there is no approval UI or API
- [ ] **Rate limiting** — per-runner, per-tool-family request rate limits
- [ ] **Metrics endpoint** — Prometheus-compatible `/metrics`
- [ ] **GCP metadata emulation** — `gatewayIP:80` metadata server for GCP workloads

## Documentation

- [docs/architecture.md](docs/architecture.md) — system design, request flows, component model
- [docs/lanes.md](docs/lanes.md) — detailed lane comparison and selection logic
- [docs/manifests.md](docs/manifests.md) — manifest schema, authoring guide, shipped families
- [docs/api.md](docs/api.md) — endpoint reference with request/response examples
- [examples/](examples/) — runnable examples with curl commands and config files

## Relationship to Capsule

The access plane is a companion service to the
[Capsule](https://github.com/rahul-roy-glean/capsule) workload platform. Capsule
manages microVM lifecycle (snapshot, restore, pause, resume). The access plane
manages what those microVMs are allowed to do once running — specifically, how
they access external authenticated services.

The two systems communicate through:
- **Attestation tokens** — Capsule's control plane issues HMAC tokens that the
  access plane verifies
- **Provider token push** — the host agent pushes delegated tokens via
  `POST /v1/providers/update-token`
- **Runner lifecycle events** — Capsule notifies the access plane when runners
  are allocated, released, or paused (planned)

They are deployed independently and have no compile-time dependency on each other.

## License

Apache 2.0
