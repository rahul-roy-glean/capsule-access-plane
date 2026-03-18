# Architecture

This document describes the design of the Capsule Access Plane: what problem it
solves, how the components fit together, and how a request flows through the
system.

## Problem Statement

AI agents running inside Capsule microVMs need to interact with external
authenticated services (GitHub, GCP, Kubernetes, internal APIs). The security
goal is:

1. Agents must never hold raw credentials
2. Every outbound call must be validated against a declared manifest
3. Every operation must be audit-logged with full context
4. Operators must be able to control what each tool family is allowed to do

## System Context

```text
┌───────────────────────────────────────────────────────────────────────┐
│ Capsule Control Plane                                               │
│   - issues attestation tokens to runners                            │
│   - manages runner lifecycle (allocate, pause, release)             │
└───────────────────────────────────────────────────────────────────────┘
        │ attestation token
        ▼
┌───────────────────────────────────────────────────────────────────────┐
│ Agent (inside Capsule microVM)                                      │
│   - holds attestation token                                        │
│   - calls access plane to reach external services                  │
│   - never holds raw credentials                                    │
└───────────────────────────────────────────────────────────────────────┘
        │ resolve / grant / execute
        ▼
┌───────────────────────────────────────────────────────────────────────┐
│ Capsule Access Plane                                                │
│ ┌─────────────┐ ┌────────────┐ ┌─────────────┐ ┌──────────────┐ │
│ │  Identity   │ │  Manifest  │ │   Policy    │ │  Credential  │ │
│ │  Verifier   │ │  Registry  │ │   Engine    │ │  Resolver    │ │
│ └─────────────┘ └────────────┘ └─────────────┘ └──────────────┘ │
│                                                                     │
│ ┌───────────────────────────────────────────────────────────────┐ │
│ │ HTTP Handlers                                                   │ │
│ │  ResolveHandler │ GrantHandlers │ ExecuteHandler              │ │
│ └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│ ┌─────────────────────────────┐ ┌─────────────────────────────┐ │
│ │ Direct HTTP Proxy Adapter │ │ Audit Logger                │ │
│ │ (per-grant localhost      │ │ (structured slog output)    │ │
│ │  forward proxies)         │ │                             │ │
│ └─────────────────────────────┘ └─────────────────────────────┘ │
│                                                                     │
│ ┌─────────────┐                                                    │
│ │  SQLite DB  │  grants, credential records                        │
│ └─────────────┘                                                    │
└───────────────────────────────────────────────────────────────────────┘
        │ outbound HTTP (with credential)
        ▼
┌───────────────────────────────────────────────────────────────────────┐
│ External Services                                                   │
│   api.github.com  │  *.googleapis.com  │  k8s clusters  │  ...   │
└───────────────────────────────────────────────────────────────────────┘
```

## Request Lifecycle

Every access-plane interaction follows the same pattern:

```text
1. Authenticate   ──  verify HMAC attestation token, extract runner_id + session_id
2. Authorize      ──  decode request, validate runner context matches token claims
3. Validate       ──  look up tool family manifest, check host + method constraints
4. Policy         ──  evaluate policy engine (allow/deny, lane selection, approval)
5. Act            ──  resolve credential, make outbound call or start proxy
6. Audit          ──  structured log with correlation ID, duration, outcome
7. Respond        ──  return result to agent
```

### Resolve Flow

```text
Agent ──► POST /v1/resolve
           │
           ├─ verify attestation token
           ├─ validate runner context
           ├─ evaluate policy (tool family + risk class → lane)
           ├─ check implementation availability
           ├─ audit log
           │
           └─► { decision: "allow", selected_lane: "direct_http",
                implementation_state: "implemented" }
```

The agent calls resolve first to learn which lane to use. The response tells
it whether the lane is implemented and whether approval is required.

### Grant + Proxy Flow (Direct HTTP Lane)

```text
Agent ──► POST /v1/grants/project (tool_family, lane, scope)
           │
           ├─ create grant record in SQLite
           ├─ resolve credential
           ├─ start localhost forward proxy on random port
           ├─ audit log
           │
           └─► { grant_id: "...", projection_ref: "127.0.0.1:54321" }

Agent ──► GET http://127.0.0.1:54321/path
           Headers: X-Target-URL: https://api.github.com/repos/foo/bar
           │
           ├─ extract + validate target host against manifest destinations
           ├─ validate HTTP method against manifest constraints
           ├─ inject Authorization: Bearer <credential>
           ├─ forward to target
           │
           └─► proxied response from api.github.com

Agent ──► POST /v1/grants/revoke
           │
           └─ stop proxy, revoke grant, audit log
```

### Execute Flow (Remote Execution Lane)

```text
Agent ──► POST /v1/execute/http
           { tool_family, method, url, headers, body }
           │
           ├─ verify attestation token
           ├─ validate runner context
           ├─ look up manifest → validate host + method
           ├─ evaluate policy
           ├─ resolve credential
           ├─ make outbound HTTP call with injected credential
           ├─ read response (capped at 10 MB)
           ├─ audit log with correlation ID + duration
           │
           └─► { status_code: 200, headers: {...}, body: "...",
                audit_correlation_id: "exec-s1-t1-1710801234567" }
```

## Component Model

### Identity Verifier (`identity/`)

Validates HMAC-SHA256 signed attestation tokens. Tokens are issued by the
Capsule control plane and contain runner_id, session_id, workload_key, and
expiry. The access plane verifies the signature and checks expiry before
processing any request.

Token format: `base64(json_payload).base64(hmac_signature)`

### Manifest Registry (`manifest/`)

Stores tool family manifests loaded from embedded YAML files at startup.
Manifests declare:

- **destinations** — allowed target hosts (e.g., `api.github.com`)
- **method_constraints** — allowed HTTP methods and path patterns
- **supported_lanes** — which execution lanes this family supports
- **preferred_lane** — default lane selection by risk class
- **logical_actions** — named operations with risk classifications
- **execution_hints** — flags like `require_approval`
- **helper_support** — credential helper protocol for CLI tools

Manifests are the central policy artifact. Adding a new tool family means
adding a YAML file to `manifest/families/`.

### Policy Engine (`policy/`)

Evaluates allow/deny decisions and selects execution lanes. The current
implementation (`ManifestBasedEngine`) uses manifests directly:

1. Reject if actor UserID is empty
2. Reject if tool family is unknown
3. Resolve risk class from logical action
4. Select lane from preferred_lane map or supported_lanes list
5. Check if approval is required
6. Check implementation availability for the selected lane

The engine is behind a `PolicyEngine` interface, so it can be replaced with
OPA, Cedar, or any other policy framework.

### Credential Resolver (`grants/credential.go`)

Resolves credential references to actual values. Supports three schemes:

- `env:VAR_NAME` — read from environment variable
- `literal:value` — inline value (testing only)
- `stored:id` — look up from SQLite credential_records table

### Grant Service (`grants/`)

Manages the grant lifecycle (project, exchange, refresh, revoke). Grants are
stored in SQLite with runner_id scoping — a grant can only be operated on by
the runner that created it.

### Direct HTTP Adapter (`runtime/direct_http.go`)

Manages per-grant forward proxies. Each proxy:
- listens on a random localhost port
- validates target host and HTTP method against the manifest
- injects the credential as a Bearer token
- forwards the request and streams the response

Proxies are created when a grant is projected and destroyed when it is revoked.

### Execute Handler (`server/execute_handler.go`)

The remote execution endpoint. Unlike the proxy path, this is a single
synchronous request/response: the agent sends the request parameters, the
access plane makes the outbound call, and returns the complete response.
The credential never leaves the access plane process.

### Audit Logger (`audit/`)

All operations emit structured log records via `slog`. Each record includes
session, runner, turn, tool family, target, result, duration, and a correlation
ID that ties the audit trail back to the original request.

## Data Model

SQLite stores two categories of data:

- **Grants** — grant_id, runner_id, session_id, tool_family, lane, scope,
  status, created_at, expires_at
- **Credential records** — for `stored:` credential references

Manifests and policy decisions are stateless (loaded from embedded YAML,
evaluated per-request).

## Deployment Model

The access plane is a single Go binary with no external dependencies beyond
SQLite. It is designed to run:

- **Sidecar** — one per Capsule host, co-located with the runners it serves
- **Standalone** — as a shared service for multiple hosts (requires network
  access from runners)

Configuration is entirely via environment variables. The embedded manifests
mean no config files need to be mounted.

## Security Model

| Layer | Mechanism |
|-------|-----------|
| Identity | HMAC-SHA256 attestation tokens with expiry |
| Authorization | Runner context must match token claims |
| Manifest validation | Destination host + HTTP method allowlist |
| Policy | Pluggable engine (currently manifest-based) |
| Credential isolation | Credentials resolved server-side, never sent to agent |
| Audit | Every operation logged with full context |
| Grant scoping | Grants bound to runner_id, time-limited, revocable |
