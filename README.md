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
  It either gets a scoped local proxy (direct HTTP) or asks the access plane to
  make the call on its behalf (remote execution).
- **Every call is manifest-validated.** Allowed destinations, HTTP methods, and
  logical actions are declared per tool family in YAML manifests. Anything
  outside the manifest is rejected before a network connection is made.
- **Policy is evaluated on every request.** A pluggable policy engine decides
  allow/deny and selects the execution lane based on risk class, tool family,
  and operator configuration.
- **Full audit trail.** Every resolve, grant, and execute operation is
  structured-logged with session, runner, and correlation identifiers.

## How It Works

```text
┌─────────────────────────────────────────────────────────────┐
│                     Capsule microVM                         │
│                                                             │
│  Agent ──► POST /v1/resolve ──► "use direct_http"           │
│         │                                                   │
│         ├► POST /v1/grants/project ──► proxy on :54321      │
│         │     └── sandbox calls proxy ──► proxy injects     │
│         │         credential ──► api.github.com             │
│         │                                                   │
│         └► POST /v1/execute/http ──► access plane makes     │
│               the call, returns response ──► agent gets     │
│               status + headers + body, never the credential │
└─────────────────────────────────────────────────────────────┘
```

The access plane sits between the sandbox and the outside world. It validates
identity via HMAC attestation tokens, checks policy, and then either starts a
local credential-injecting proxy or makes the outbound call directly.

## Execution Lanes

The access plane supports three execution lanes. Each represents a different
trust/fidelity tradeoff:

### Lane 1: Remote Execution (recommended default)

```text
Agent ──► POST /v1/execute/http ──► Access Plane ──► External API
                                        │
                              credential injected here
                              manifest + policy checked
                              response returned to agent
```

The agent sends "make this HTTP call for me." The access plane validates
everything, injects the credential, makes the call, and returns the response.
The credential never leaves the access plane process.

**Status: Implemented** — `POST /v1/execute/http`

### Lane 2: Direct HTTP (local proxy)

```text
Agent ──► POST /v1/grants/project ──► proxy starts on localhost:N
Agent ──► GET http://localhost:N (X-Target-URL: https://api.github.com/...)
              └── proxy validates host + method
              └── proxy injects Bearer token
              └── proxy forwards to target
```

The agent gets a grant, receives a local proxy address, and makes HTTP calls
through it. The proxy enforces the manifest and injects credentials
transparently. The agent sees the credential in transit through the local proxy,
but it is scoped to the grant's lifetime and the manifest's allowed destinations.

**Status: Implemented** — grant lifecycle + forward proxy

### Lane 3: Helper Session

For CLI tools (kubectl, git) that use credential helpers or exec-credential
protocols. The access plane would manage helper processes that feed credentials
to the CLI tool on demand.

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
preferred_lane:
  default: direct_http
destinations:
  - host: api.github.com
    port: 443
    protocol: https
method_constraints:
  - method: GET
    path_pattern: "/repos/**"
  - method: POST
    path_pattern: "/repos/*/issues"
```

Shipped families: `github_rest`, `github_git`, `gcp_cli_read`, `gcp_adc`,
`kubectl`, `internal_admin_cli`.

The manifest is the source of truth for:
- which hosts the agent can reach
- which HTTP methods are allowed
- which lanes are supported
- what risk class each action carries
- whether approval is required

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
| `/v1/events/runner` | POST | Runner lifecycle events (not yet implemented) |

All endpoints except `/healthz` require an HMAC-signed attestation token in the
`Authorization: Bearer <token>` header.

## Project Structure

```text
accessplane/          Domain types — requests, responses, lanes, decisions
audit/                Structured audit logging
bundle/               Projection bundles for grant lifecycle
cmd/gentoken/         CLI tool to generate signed attestation tokens (for dev/test)
dev/                  Docker Compose, env template, smoke test script
grants/               Grant lifecycle service + credential resolution
identity/             HMAC attestation token signing and verification
manifest/             Tool family manifests, registry, validation helpers
  families/           YAML manifest definitions (embedded at build time)
policy/               Policy engine — manifest-based allow/deny + lane selection
runtime/              Runtime adapters (direct HTTP forward proxy)
server/               HTTP handlers (resolve, grants, execute)
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

### Run with Docker

```bash
cp dev/env.example .env    # edit .env with your values
docker compose -f dev/docker-compose.yml up --build
```

### Run the smoke test

```bash
# Against a running server on localhost:8080
./dev/smoke-test.sh

# Against a custom address
./dev/smoke-test.sh http://localhost:9090
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
| `GITHUB_TOKEN` | Yes | — | Credential injected into outbound API calls |
| `LISTEN_ADDR` | No | `:8080` | Server listen address |
| `DATABASE_URL` | No | `capsule-access.db` | SQLite database path |
| `CREDENTIAL_REF` | No | `env:GITHUB_TOKEN` | Credential reference (supports `env:`, `literal:`, `stored:`) |

## What's Missing

The following are designed but not yet implemented:

- [ ] **Helper session lane** — credential helper protocol for CLI tools (kubectl, git)
- [ ] **Runner lifecycle events** — `POST /v1/events/runner` for allocation, release, pause, resume signals
- [ ] **Multi-credential support** — per-tool-family credential references (currently one global ref)
- [ ] **Path pattern enforcement** — method constraints declare `path_pattern` but only the method is currently checked
- [ ] **Approval workflow** — policy can flag `approval_required` but there is no approval UI or API
- [ ] **Token scoping / short-lived credentials** — credential rotation, OAuth token exchange
- [ ] **Rate limiting** — per-runner, per-tool-family request rate limits
- [ ] **Metrics endpoint** — Prometheus-compatible `/metrics`

## Documentation

- [docs/architecture.md](docs/architecture.md) — system design, request flows, component model
- [docs/lanes.md](docs/lanes.md) — detailed lane comparison and selection logic
- [docs/manifests.md](docs/manifests.md) — manifest schema, authoring guide, shipped families
- [docs/api.md](docs/api.md) — endpoint reference with request/response examples

## Relationship to Capsule

The access plane is a companion service to the
[Capsule](https://github.com/rahul-roy-glean/capsule) workload platform. Capsule
manages microVM lifecycle (snapshot, restore, pause, resume). The access plane
manages what those microVMs are allowed to do once running — specifically, how
they access external authenticated services.

The two systems communicate through:
- **Attestation tokens** — Capsule's control plane issues HMAC tokens that the
  access plane verifies
- **Runner lifecycle events** — Capsule notifies the access plane when runners
  are allocated, released, or paused (planned)

They are deployed independently and have no compile-time dependency on each other.

## License

Apache 2.0
