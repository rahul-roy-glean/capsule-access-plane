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
5. DNS-based SSRF attacks must be blocked

## System Context

```text
┌───────────────────────────────────────────────────────────────────────┐
│ Capsule Host Agent                                                   │
│   - starts access plane subprocess                                   │
│   - pushes delegated tokens via /v1/providers/update-token           │
│   - passes provider config file (PROVIDERS_CONFIG)                   │
└───────────────────────────────────────────────────────────────────────┘
        │ attestation token, provider tokens
        ▼
┌───────────────────────────────────────────────────────────────────────┐
│ Agent (inside Capsule microVM)                                       │
│   - holds attestation token                                          │
│   - uses HTTPS_PROXY for transparent credential injection            │
│   - calls access plane API for remote execution / grants             │
│   - never holds raw credentials                                      │
└───────────────────────────────────────────────────────────────────────┘
        │ CONNECT / resolve / grant / execute
        ▼
┌───────────────────────────────────────────────────────────────────────┐
│ Capsule Access Plane                                                 │
│ ┌─────────────┐ ┌────────────┐ ┌─────────────┐ ┌──────────────────┐ │
│ │  Identity   │ │  Manifest  │ │   Policy    │ │    Provider      │ │
│ │  Verifier   │ │  Registry  │ │   Engine    │ │    Registry      │ │
│ └─────────────┘ └────────────┘ └─────────────┘ └──────────────────┘ │
│                                                                      │
│ ┌───────────────────────────────────────────────────────────────────┐ │
│ │ HTTP Handlers                                                     │ │
│ │  ResolveHandler │ GrantHandlers │ ExecuteHandler │ TokenHandlers │ │
│ └───────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│ ┌─────────────────────┐ ┌─────────────────────┐ ┌────────────────┐ │
│ │ CONNECT Proxy       │ │ Direct HTTP Adapter │ │ Audit Logger   │ │
│ │ (SSL bump + tunnel) │ │ (per-grant proxies) │ │ (structured    │ │
│ │                     │ │                     │ │  slog output)  │ │
│ └─────────────────────┘ └─────────────────────┘ └────────────────┘ │
│                                                                      │
│ ┌──────────────────────┐ ┌────────────────────┐                     │
│ │ SSRF Protection      │ │  SQLite DB         │                     │
│ │ (DNS + IP validation)│ │  grants, creds     │                     │
│ └──────────────────────┘ └────────────────────┘                     │
└───────────────────────────────────────────────────────────────────────┘
        │ outbound HTTP/HTTPS (with credential)
        ▼
┌───────────────────────────────────────────────────────────────────────┐
│ External Services                                                    │
│   api.github.com  │  *.googleapis.com  │  k8s clusters  │  ...     │
└───────────────────────────────────────────────────────────────────────┘
```

## Request Lifecycle

Every access-plane interaction follows the same pattern:

```text
1. Authenticate   ──  verify HMAC attestation token, extract runner_id + session_id
2. Authorize      ──  decode request, validate runner context matches token claims
3. Validate       ──  look up tool family manifest, check host + method + path
4. SSRF check     ──  resolve DNS, reject private/loopback/link-local IPs
5. Policy         ──  evaluate policy engine (allow/deny, lane selection, approval)
6. Credential     ──  resolve credential via provider registry (static, delegated, or named)
7. Act            ──  make outbound call, start proxy, or MITM connection
8. Audit          ──  structured log with correlation ID, duration, outcome
9. Respond        ──  return result to agent
```

### CONNECT Proxy Flow (SSL Bump)

```text
VM ──► CONNECT api.github.com:443 ──► Access Plane Proxy
        │
        ├─ validate host against all manifest destinations
        ├─ SSRF check (DNS resolve, reject private IPs)
        ├─ 200 Connection Established
        │
        ├─ credential provider exists for host?
        │   YES → SSL bump:
        │     ├─ TLS handshake with client (CA-signed leaf cert)
        │     ├─ read HTTP request from decrypted stream
        │     ├─ validate method + path against manifest constraints
        │     ├─ inject credentials via provider.InjectCredentials()
        │     ├─ forward to real target over TLS
        │     └─ relay response back to client
        │
        │   NO → raw tunnel:
        │     └─ bidirectional byte copy (no inspection)
        │
        └─ audit log
```

### Execute Flow (Remote Execution Lane)

```text
Agent ──► POST /v1/execute/http
           { tool_family, method, url, headers, body }
           │
           ├─ verify attestation token
           ├─ validate runner context
           ├─ look up manifest → validate host + method + path
           ├─ SSRF check (DNS resolve, reject private IPs)
           ├─ evaluate policy
           ├─ resolve credential via provider registry
           ├─ make outbound HTTP call with injected credential
           ├─ read response (capped at 10 MB)
           ├─ audit log with correlation ID + duration
           │
           └─► { status_code: 200, headers: {...}, body: "...",
                audit_correlation_id: "exec-s1-t1-1710801234567" }
```

### Grant + Proxy Flow (Direct HTTP Lane)

```text
Agent ──► POST /v1/grants/project (tool_family, lane, scope)
           │
           ├─ resolve credential via provider registry
           ├─ create grant record in SQLite
           ├─ start localhost forward proxy on random port
           ├─ audit log
           │
           └─► { grant_id: "...", projection_ref: "127.0.0.1:54321" }

Agent ──► GET http://127.0.0.1:54321/path
           Headers: X-Target-URL: https://api.github.com/repos/foo/bar
           │
           ├─ validate target host against manifest destinations
           ├─ SSRF check
           ├─ validate method + path against manifest constraints
           ├─ strip hop-by-hop headers
           ├─ inject Authorization: Bearer <credential>
           ├─ forward to target
           │
           └─► proxied response from api.github.com

Agent ──► POST /v1/grants/revoke
           └─ stop proxy, revoke grant, audit log
```

## Component Model

### Identity Verifier (`identity/`)

Validates HMAC-SHA256 signed attestation tokens. Tokens are issued by the
Capsule control plane and contain runner_id, session_id, workload_key, and
expiry. Tokens also carry optional identity fields:

- **IdentityMode** — `"user-direct"` (agent acts on behalf of a user) or
  `"virtual"` (agent has its own persistent identity)
- **UserEmail** — the human user's email (user-direct mode)
- **VirtualIdentityID** — the agent's own identity (virtual mode)

`Claims.EffectiveIdentity()` resolves the right identity string for audit
and policy purposes.

Token format: `base64(json_payload).base64(hmac_signature)`

### Manifest Registry (`manifest/`)

Stores tool family manifests loaded from embedded YAML files at startup.
Manifests declare:

- **destinations** — allowed target hosts with optional CIDR allowlists
- **method_constraints** — allowed HTTP methods, path glob patterns, enforcement mode
- **supported_lanes** — which execution lanes this family supports
- **preferred_lane** — default lane selection by risk class
- **logical_actions** — named operations with risk classifications
- **provider** — named credential provider for this family

### SSRF Protection (`manifest/ssrf.go`)

Every outbound connection (execute handler, direct HTTP proxy, CONNECT proxy)
passes through `CheckSSRF`:

1. If the host is an IP literal, validate directly (no DNS)
2. Otherwise, resolve via DNS
3. If `AllowedIPs` is set on the destination, resolved IPs must fall within those CIDRs
4. Otherwise, reject private IPs (RFC 1918, loopback, link-local including 169.254.169.254)

### Policy Engine (`policy/`)

Evaluates allow/deny decisions and selects execution lanes. The current
implementation (`ManifestBasedEngine`) uses manifests directly. The engine
is behind a `PolicyEngine` interface for future replacement (OPA, Cedar, etc.).

### Provider Registry (`providers/`)

Manages credential providers. Each provider implements `CredentialProvider`:

| Method | Purpose |
|--------|---------|
| `Name()` | Unique identifier |
| `Type()` | Provider type (static, delegated, etc.) |
| `Matches(host)` | Whether this provider handles a given host |
| `InjectCredentials(req)` | Modify HTTP request to include credential |
| `ResolveToken(ctx)` | Return raw token value |
| `Start(ctx)` / `Stop()` | Lifecycle management |

Built-in provider types:

- **static** — wraps `CredentialResolver` (env/literal/stored schemes)
- **delegated** — accepts externally-pushed tokens via `UpdateToken()`.
  Supports session-scoped tokens keyed by source IP, per-user identity headers
  (`X-Glean-User-Email`, custom headers), and multi-credential routing rules
  (different tokens for different HTTP methods/paths on the same domain).
- **gcp-sa** — mints short-lived GCP access tokens by impersonating a service
  account via the IAM Credentials API (`generateAccessToken`). Background
  refresh loop keeps the token fresh (refreshes at 75% of lifetime).

The registry supports:
- Named lookup (`Get`, `ForManifest`) for manifest-driven credential selection
- Host-based lookup (`ForHost`) for CONNECT proxy credential injection
- Session-scoped resolution via source IP context for per-user isolation
- Default provider fallback for backward compatibility
- JSON config file loading (`PROVIDERS_CONFIG`)

### CONNECT Proxy (`proxy/`)

An HTTPS CONNECT proxy with selective SSL bump:

- **CA generation** — ECDSA P-256 self-signed CA created at startup
- **Dynamic leaf certs** — per-hostname cert cache with IP SAN support
- **Selective MITM** — only bump hosts with a credential provider; tunnel the rest
- **Credential injection** — `provider.InjectCredentials(req)` on every MITM'd request
- **Full validation** — host, SSRF, method+path enforcement on every connection
- **Audit logging** — every CONNECT logged with result and duration

### Grant Service (`grants/`)

Manages the grant lifecycle (project, exchange, refresh, revoke). Grants are
stored in SQLite with runner_id scoping.

### Direct HTTP Adapter (`runtime/direct_http.go`)

Manages per-grant forward proxies. Each proxy validates host, SSRF, method+path,
strips hop-by-hop headers, and injects credentials.

### Audit Logger (`audit/`)

All operations emit structured log records via `slog`. Each record includes
session, runner, turn, tool family, target, result, duration, and a correlation
ID.

## Security Model

| Layer | Mechanism |
|-------|-----------|
| Identity | HMAC-SHA256 attestation tokens with user-direct and virtual identity modes |
| Authorization | Runner context must match token claims |
| Manifest validation | Destination host + HTTP method + URL path glob allowlist |
| SSRF protection | DNS resolution + private IP blocking + CIDR allowlists |
| Policy | Pluggable engine (currently manifest-based, CEL interface ready) |
| Credential isolation | Credentials resolved server-side via provider registry, per-session scoping |
| Multi-credential | Request-level credential selection (method+path rules) for same-domain dual-token scenarios |
| Proxy security | Hop-by-hop header stripping, selective SSL bump, identity header injection |
| Audit | Every operation logged with full context + identity mode attribution |
| Grant scoping | Grants bound to runner_id, time-limited, revocable |
