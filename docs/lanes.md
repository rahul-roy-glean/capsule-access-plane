# Execution Lanes

The access plane routes every tool operation through an **execution lane** — the
mechanism by which the agent's intent is translated into an authenticated
outbound call. The lane determines where the credential lives, how much the
agent can see, and what level of control the access plane retains.

## Lane Comparison

| | Remote Execution (Lane 1) | Direct HTTP (Lane 2) | Helper Session (Lane 3) |
|---|---|---|---|
| Credential visible to agent? | No | No — injected on outbound leg only | In helper only |
| Agent makes own HTTP calls? | No | Yes (HTTPS_PROXY or grant proxy) | Yes (via CLI) |
| Streaming support | No (sync req/res) | Yes (full proxy) | Yes (native CLI) |
| SSRF protection | Yes | Yes | N/A |
| Path enforcement | Yes (glob) | Yes (glob) | N/A |
| Surface kind | http | http | cli |
| Audit granularity | Per-request | Per-request | Per-session |
| Proxy modes | N/A | CONNECT proxy, ICAP/Squid, grant proxy | N/A |
| Status | Implemented | Implemented | Not implemented |

## Lane 1: Remote Execution

**Endpoint:** `POST /v1/execute/http`

The agent sends the full HTTP request parameters (method, URL, headers, body)
to the access plane. The access plane validates everything, injects the
credential, makes the outbound call, and returns the complete response.

```mermaid
sequenceDiagram
    participant Agent
    participant AP as Access Plane
    participant EXT as External API

    Agent->>AP: POST /v1/execute/http<br/>{method, url, headers}
    AP->>AP: Validate manifest
    AP->>AP: SSRF check
    AP->>AP: Enforce method + path
    AP->>AP: Evaluate policy
    AP->>AP: Resolve credential
    AP->>EXT: GET https://api.github.com<br/>Authorization: Bearer ***
    EXT-->>AP: 200 + response body
    AP-->>Agent: {status_code, headers, body, correlation_id}
```

**When to use:** Default for HTTP-surface tools. Best credential isolation.
The agent never sees the token in any form.

**Limitations:** Synchronous only. Response body capped at 10 MB. No streaming.

## Lane 2: Direct HTTP

Two modes are available:

### CONNECT Proxy (SSL Bump)

The VM sets `HTTPS_PROXY` and makes standard HTTPS calls. The access plane
proxy intercepts CONNECT requests and selectively MITM's them.

```mermaid
sequenceDiagram
    participant VM
    participant AP as Access Plane Proxy
    participant EXT as External API

    VM->>AP: CONNECT host:443
    AP-->>VM: 200 Established
    Note over VM,AP: TLS handshake (CA-signed leaf cert)
    VM->>AP: GET /repos/foo
    AP->>EXT: GET /repos/foo + Bearer token
    EXT-->>AP: Response
    AP-->>VM: Response
```

**Selective bump:** Only hosts with a credential provider are MITM'd. Other
allowed hosts are raw-tunneled (no inspection, no credential injection).
Hosts not in any manifest are rejected with 403.

**When to use:** When the agent should use standard HTTP clients/libraries
with no code changes. Best for transparent credential injection at scale.

### Grant-Based Forward Proxy

The agent requests a grant, receives a local proxy address, and sends requests
with `X-Target-URL` headers.

```mermaid
sequenceDiagram
    participant Agent
    participant Proxy as Proxy (localhost:N)
    participant EXT as External API

    Agent->>Proxy: POST /v1/grants/project
    Proxy-->>Agent: projection_ref=:54321
    Agent->>Proxy: GET localhost:54321<br/>X-Target-URL: https://api.github.com/repos/foo
    Proxy->>Proxy: Validate + SSRF + inject
    Proxy->>EXT: Forward request
    EXT-->>Proxy: Response
    Proxy-->>Agent: Response
```

**When to use:** When the agent needs explicit grant lifecycle control
(project, exchange, refresh, revoke) or when the CONNECT proxy is not available.

### ICAP/Squid Integration

For deployments that already use Squid as their HTTP proxy, the access plane
provides an ICAP REQMOD server that integrates with Squid's request adaptation
framework. Squid forwards HTTP requests to the ICAP server, which validates
them against manifests and injects credentials before Squid forwards the
request to the target.

```mermaid
sequenceDiagram
    participant VM as VM Agent
    participant Squid
    participant ICAP as ICAP Server<br/>(Access Plane)
    participant EXT as External API

    VM->>Squid: HTTP request via proxy
    Squid->>ICAP: REQMOD (encapsulated request)
    ICAP->>ICAP: Validate host + SSRF + method/path
    ICAP->>ICAP: Inject credentials
    ICAP-->>Squid: Modified request (or 403 deny)
    Squid->>EXT: Forward modified request
    EXT-->>Squid: Response
    Squid-->>VM: Response
```

**When to use:** When Squid is already deployed as the network proxy and you
want to avoid running a separate CONNECT proxy. Configured via `ICAP_ADDR`
environment variable.

## Lane 3: Helper Session (not yet implemented)

For CLI tools that use credential helper protocols — `git credential fill`,
kubectl exec-credential plugins, `gcloud auth print-access-token`, etc.

**Families that need this:** `github_git`, `kubectl`, `gcp_cli_read`, `gcp_adc`.

## Lane Selection

The policy engine selects the lane for each request based on:

1. **Manifest preferred_lane** — per risk-class or default preference
2. **Supported lanes** — what the tool family supports
3. **Implementation availability** — whether the lane is actually built

The selection happens during `/v1/resolve`. The agent then uses the appropriate
endpoint for the selected lane.

```mermaid
flowchart TD
    A["Manifest preferred_lane"] --> B{"Preferred lane for<br/>resolved risk class?"}
    B -->|"Yes"| C["Use risk-class lane"]
    B -->|"No"| D{"preferred_lane.default<br/>set?"}
    D -->|"Yes"| E["Use default lane"]
    D -->|"No"| F["Use first entry in<br/>supported_lanes"]
    C --> G["Check implementation<br/>availability"]
    E --> G
    F --> G
    G --> H["Return selected lane +<br/>implementation state"]
```

Example manifest:

```yaml
preferred_lane:
  default: direct_http        # standard risk uses proxy
  elevated: remote_execution  # elevated risk uses broker
```
