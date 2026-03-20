# Execution Lanes

The access plane routes every tool operation through an **execution lane** — the
mechanism by which the agent's intent is translated into an authenticated
outbound call. The lane determines where the credential lives, how much the
agent can see, and what level of control the access plane retains.

## Lane Comparison

```text
                     ┌──────────────────┬────────────────────┬──────────────────┐
                     │ Remote Execution │ Direct HTTP        │ Helper Session   │
                     │ (Lane 1)         │ (Lane 2)           │ (Lane 3)         │
┌────────────────────┼──────────────────┼────────────────────┼──────────────────┤
│ Credential visible │ No               │ No (CONNECT proxy) │ In helper only   │
│ to agent?          │                  │ In transit (grant)  │                  │
├────────────────────┼──────────────────┼────────────────────┼──────────────────┤
│ Agent makes own    │ No               │ Yes (HTTPS_PROXY    │ Yes (via CLI)    │
│ HTTP calls?        │                  │  or grant proxy)    │                  │
├────────────────────┼──────────────────┼────────────────────┼──────────────────┤
│ Streaming support  │ No (sync req/res)│ Yes (full proxy)    │ Yes (native CLI) │
├────────────────────┼──────────────────┼────────────────────┼──────────────────┤
│ SSRF protection    │ Yes              │ Yes                 │ N/A              │
├────────────────────┼──────────────────┼────────────────────┼──────────────────┤
│ Path enforcement   │ Yes (glob)       │ Yes (glob)          │ N/A              │
├────────────────────┼──────────────────┼────────────────────┼──────────────────┤
│ Surface kind       │ http             │ http                │ cli              │
├────────────────────┼──────────────────┼────────────────────┼──────────────────┤
│ Audit granularity  │ Per-request      │ Per-request         │ Per-session      │
├────────────────────┼──────────────────┼────────────────────┼──────────────────┤
│ Status             │ Implemented      │ Implemented         │ Not implemented  │
└────────────────────┴──────────────────┴────────────────────┴──────────────────┘
```

## Lane 1: Remote Execution

**Endpoint:** `POST /v1/execute/http`

The agent sends the full HTTP request parameters (method, URL, headers, body)
to the access plane. The access plane validates everything, injects the
credential, makes the outbound call, and returns the complete response.

```text
Agent                    Access Plane                External API
  │                          │                           │
  │ POST /v1/execute/http    │                           │
  │ {method, url, headers}   │                           │
  │─────────────────────────►│                           │
  │                          │ validate manifest         │
  │                          │ SSRF check                │
  │                          │ enforce method + path     │
  │                          │ evaluate policy           │
  │                          │ resolve credential        │
  │                          │                           │
  │                          │ GET https://api.github.com│
  │                          │ Authorization: Bearer *** │
  │                          │──────────────────────────►│
  │                          │◄──────────────────────────│
  │                          │ 200 + response body       │
  │                          │                           │
  │◄─────────────────────────│                           │
  │ {status_code, headers,   │                           │
  │  body, correlation_id}   │                           │
```

**When to use:** Default for HTTP-surface tools. Best credential isolation.
The agent never sees the token in any form.

**Limitations:** Synchronous only. Response body capped at 10 MB. No streaming.

## Lane 2: Direct HTTP

Two modes are available:

### CONNECT Proxy (SSL Bump)

The VM sets `HTTPS_PROXY` and makes standard HTTPS calls. The access plane
proxy intercepts CONNECT requests and selectively MITM's them.

```text
VM                       Access Plane Proxy           External API
  │                          │                           │
  │ CONNECT host:443         │                           │
  │─────────────────────────►│                           │
  │◄─ 200 Established ──────│                           │
  │                          │                           │
  │◄── TLS handshake ──────►│ (CA-signed leaf cert)     │
  │                          │                           │
  │── GET /repos/foo ───────►│                           │
  │                          │── GET /repos/foo ────────►│
  │                          │   + Bearer token          │
  │                          │◄─────────────────────────│
  │◄─────────────────────────│                           │
```

**Selective bump:** Only hosts with a credential provider are MITM'd. Other
allowed hosts are raw-tunneled (no inspection, no credential injection).
Hosts not in any manifest are rejected with 403.

**When to use:** When the agent should use standard HTTP clients/libraries
with no code changes. Best for transparent credential injection at scale.

### Grant-Based Forward Proxy

The agent requests a grant, receives a local proxy address, and sends requests
with `X-Target-URL` headers.

```text
Agent                    Proxy (localhost:N)          External API
  │ POST /v1/grants/project                              │
  │─────────────────────►│ start proxy                   │
  │◄─────────────────────│ projection_ref=:54321         │
  │                      │                               │
  │ GET localhost:54321  │                               │
  │ X-Target-URL: https://api.github.com/repos/foo       │
  │─────────────────────►│ validate + SSRF + inject      │
  │                      │──────────────────────────────►│
  │◄─────────────────────│◄──────────────────────────────│
```

**When to use:** When the agent needs explicit grant lifecycle control
(project, exchange, refresh, revoke) or when the CONNECT proxy is not available.

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

```text
Manifest says:
  preferred_lane:
    default: direct_http        ← standard risk uses proxy
    elevated: remote_execution  ← elevated risk uses broker

Policy engine:
  1. Look up preferred lane for the resolved risk class
  2. Fall back to preferred_lane.default
  3. Fall back to first entry in supported_lanes
  4. Check implementation_availability map
  5. Return selected lane + implementation state
```
