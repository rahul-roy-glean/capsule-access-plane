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

```mermaid
graph TB
    subgraph HOST["Capsule Host Agent"]
        HA["Starts access plane subprocess<br/>Pushes delegated tokens via /v1/providers/update-token<br/>Passes provider config file (PROVIDERS_CONFIG)"]
    end

    subgraph VM["Agent (inside Capsule microVM)"]
        AG["Holds attestation token<br/>Uses HTTPS_PROXY for transparent credential injection<br/>Calls access plane API for remote execution / grants<br/><b>Never holds raw credentials</b>"]
    end

    subgraph AP["Capsule Access Plane"]
        direction TB
        subgraph CORE["Core Services"]
            IV["Identity<br/>Verifier"]
            MR["Manifest<br/>Registry"]
            PE["Policy<br/>Engine"]
            PR["Provider<br/>Registry"]
        end
        subgraph HANDLERS["HTTP Handlers"]
            RH["ResolveHandler"]
            GH["GrantHandlers"]
            EH["ExecuteHandler"]
            TH["TokenHandlers"]
            SH["SessionHandlers"]
        end
        subgraph TRANSPORT["Transport Layer"]
            CP["CONNECT Proxy<br/>(SSL bump + tunnel)"]
            ICAP["ICAP Server<br/>(Squid integration)"]
            DHA["Direct HTTP Adapter<br/>(per-grant proxies)"]
        end
        subgraph INFRA["Infrastructure"]
            SSRF["SSRF Protection<br/>(DNS + IP + PinnedDialer)"]
            AL["Audit Logger"]
            DB["SQLite DB"]
        end
    end

    subgraph EXT["External Services"]
        GIT["api.github.com"]
        GCP["*.googleapis.com"]
        K8S["k8s clusters"]
        OTHER["..."]
    end

    HA -->|"attestation token, provider tokens"| AG
    AG -->|"CONNECT / resolve / grant / execute"| AP
    AP -->|"outbound HTTP/HTTPS (with credential)"| EXT
```

## Request Lifecycle

Every access-plane interaction follows the same pattern:

```mermaid
flowchart TD
    A["1. Authenticate<br/>Verify HMAC attestation token,<br/>extract runner_id + session_id"] --> B["2. Authorize<br/>Decode request, validate runner<br/>context matches token claims"]
    B --> C["3. Validate<br/>Look up tool family manifest,<br/>check host + method + path"]
    C --> D["4. SSRF Check<br/>Resolve DNS, reject private/<br/>loopback/link-local IPs"]
    D --> E["5. Policy<br/>Evaluate policy engine<br/>(allow/deny, lane selection, approval)"]
    E --> F["6. Credential<br/>Resolve credential via provider registry<br/>(static, delegated, gcp-sa, oauth)"]
    F --> G["7. Act<br/>Make outbound call, start proxy,<br/>or MITM connection"]
    G --> H["8. Audit<br/>Structured log with correlation ID,<br/>duration, outcome"]
    H --> I["9. Respond<br/>Return result to agent"]
```

### CONNECT Proxy Flow (SSL Bump)

```mermaid
sequenceDiagram
    participant VM as VM Agent
    participant AP as Access Plane Proxy
    participant EXT as External API

    VM->>AP: CONNECT api.github.com:443
    AP->>AP: Validate host against manifest destinations
    AP->>AP: SSRF check (DNS resolve via PinnedDialer, reject private IPs)
    AP-->>VM: 200 Connection Established

    alt Credential provider exists for host
        Note over VM,AP: SSL Bump (MITM)
        AP->>VM: TLS handshake (CA-signed leaf cert)
        VM->>AP: HTTP request (decrypted)
        AP->>AP: Validate method + path against manifest
        AP->>AP: Inject credentials via provider.InjectCredentials()
        AP->>EXT: Forward request over TLS
        EXT-->>AP: Response
        AP-->>VM: Relay response
    else No credential provider
        Note over VM,EXT: Raw Tunnel
        VM->>EXT: Bidirectional byte copy (no inspection)
    end
    AP->>AP: Audit log
```

### Execute Flow (Remote Execution Lane)

```mermaid
sequenceDiagram
    participant Agent
    participant AP as Access Plane
    participant EXT as External API

    Agent->>AP: POST /v1/execute/http<br/>{tool_family, method, url, headers, body}
    AP->>AP: Verify attestation token
    AP->>AP: Validate runner context
    AP->>AP: Look up manifest → validate host + method + path
    AP->>AP: SSRF check (DNS resolve, reject private IPs)
    AP->>AP: Evaluate policy
    AP->>AP: Resolve credential via provider registry
    AP->>EXT: Outbound HTTP call with injected credential
    EXT-->>AP: Response
    AP->>AP: Read response (capped at 10 MB)
    AP->>AP: Audit log with correlation ID + duration
    AP-->>Agent: {status_code, headers, body, audit_correlation_id}
```

### Grant + Proxy Flow (Direct HTTP Lane)

```mermaid
sequenceDiagram
    participant Agent
    participant AP as Access Plane
    participant Proxy as Forward Proxy<br/>(localhost:54321)
    participant EXT as External API

    Note over Agent,AP: Step 1: Create Grant
    Agent->>AP: POST /v1/grants/project<br/>{tool_family, lane, scope}
    AP->>AP: Resolve credential via provider registry
    AP->>AP: Create grant record in SQLite
    AP->>Proxy: Start localhost forward proxy on random port
    AP->>AP: Audit log
    AP-->>Agent: {grant_id, projection_ref: "127.0.0.1:54321"}

    Note over Agent,EXT: Step 2: Use Proxy
    Agent->>Proxy: GET http://127.0.0.1:54321/path<br/>X-Target-URL: https://api.github.com/repos/foo/bar
    Proxy->>Proxy: Validate target host against manifest
    Proxy->>Proxy: SSRF check
    Proxy->>Proxy: Validate method + path against manifest
    Proxy->>Proxy: Strip hop-by-hop headers
    Proxy->>Proxy: Inject Authorization: Bearer credential
    Proxy->>EXT: Forward to target
    EXT-->>Proxy: Response
    Proxy-->>Agent: Proxied response

    Note over Agent,AP: Step 3: Revoke
    Agent->>AP: POST /v1/grants/revoke
    AP->>AP: Stop proxy, revoke grant, audit log
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

**Tenant scoping:** When `TENANT_ID` is set, the verifier validates that the
token's `tenant_id` claim matches. This ensures tokens issued for one tenant
cannot be used against another tenant's access plane in multi-tenant deployments.

**Minimum secret size:** The HMAC secret must be at least 32 bytes to prevent
brute-force attacks on short secrets.

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

### SSRF Protection (`manifest/ssrf.go`, `manifest/dialer.go`)

Every outbound connection (execute handler, direct HTTP proxy, CONNECT proxy,
ICAP handler) passes through `CheckSSRF`:

1. If the host is an IP literal, validate directly (no DNS)
2. Otherwise, resolve via DNS
3. If `AllowedIPs` is set on the destination, resolved IPs must fall within those CIDRs
4. Otherwise, reject private IPs (RFC 1918, loopback, link-local including 169.254.169.254)

**DNS rebinding protection:** `CheckSSRF` returns the resolved IP addresses,
which are then passed to `PinnedDialer`. The `PinnedDialer` creates a
`DialContext` function that connects directly to the pre-resolved IPs instead
of performing DNS resolution again. This prevents TOCTOU (time-of-check-to-time-of-use)
attacks where a DNS response changes between the SSRF check and the actual
connection.

```mermaid
flowchart LR
    A["Host: api.example.com"] --> B["CheckSSRF<br/>DNS resolve → 93.184.216.34"]
    B -->|"resolved IPs"| C["PinnedDialer<br/>connects to 93.184.216.34 directly"]
    C --> D["Outbound Connection<br/>(no second DNS lookup)"]
    
    B -->|"private IP detected"| E["BLOCKED<br/>SSRF denied"]
```

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
- **oauth-jwt-bearer** — exchanges a GCP identity token for an OAuth access
  token via a configured token endpoint. Used for third-party services that
  accept federated OAuth tokens.

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

### ICAP Server (`icap/`)

An ICAP/1.0 REQMOD server for integration with Squid (or any ICAP-capable proxy).
This is an alternative to the built-in CONNECT proxy for deployments that already
use Squid as their HTTP proxy.

```mermaid
sequenceDiagram
    participant VM as VM Agent
    participant Squid
    participant ICAP as ICAP Server
    participant EXT as External API

    VM->>Squid: HTTP request
    Squid->>ICAP: REQMOD (encapsulated HTTP request)
    ICAP->>ICAP: Validate host against manifests
    ICAP->>ICAP: SSRF check
    ICAP->>ICAP: Validate method + path constraints
    alt Credential provider found
        ICAP->>ICAP: Inject credentials into request
        ICAP-->>Squid: 200 OK (modified request)
    else No provider for host
        ICAP-->>Squid: 204 No Modification
    end
    alt Host denied by manifest
        ICAP-->>Squid: 200 OK (HTTP 403 error response)
    end
    Squid->>EXT: Forward (modified) request
    EXT-->>Squid: Response
    Squid-->>VM: Response
```

The ICAP server handles:

- **OPTIONS** — advertises REQMOD capabilities
- **REQMOD** — intercepts HTTP requests: validates against manifests, performs
  SSRF checks, enforces method+path constraints, and injects credentials
- **Session context** — extracts session ID from `X-Proxy-Token` header for
  per-session credential scoping
- **Error responses** — returns encapsulated HTTP error responses (403, 405)
  when requests are denied

Enable with `ICAP_ADDR=:1344`. The ICAP server implements the `ProxyBackend`
interface alongside the CONNECT proxy.

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
| Identity | HMAC-SHA256 attestation tokens with user-direct and virtual identity modes; minimum 32-byte secret |
| Tenant isolation | Optional `TENANT_ID` scoping — tokens must carry matching `tenant_id` claim |
| Authorization | Runner context must match token claims |
| Manifest validation | Destination host (with wildcard/glob matching) + HTTP method + URL path glob allowlist |
| SSRF protection | DNS resolution + private IP blocking + CIDR allowlists + PinnedDialer (DNS rebinding prevention) |
| Policy | Pluggable engine (currently manifest-based, CEL interface ready) |
| Credential isolation | Credentials resolved server-side via provider registry, per-session scoping |
| Multi-credential | Request-level credential selection (method+path rules) for same-domain dual-token scenarios |
| Proxy security | Hop-by-hop header stripping, selective SSL bump, identity header injection |
| ICAP integration | Squid-delegated request modification with full manifest validation |
| Audit | Every operation logged with full context + identity mode attribution |
| Grant scoping | Grants bound to runner_id, time-limited, revocable |
