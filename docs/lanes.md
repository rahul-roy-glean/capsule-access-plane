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
│ Credential visible │ No               │ In proxy transit   │ In helper only   │
│ to agent?          │                  │                    │                  │
├────────────────────┼──────────────────┼────────────────────┼──────────────────┤
│ Agent makes own    │ No               │ Yes (via proxy)    │ Yes (via CLI)    │
│ HTTP calls?        │                  │                    │                  │
├────────────────────┼──────────────────┼────────────────────┼──────────────────┤
│ Streaming support  │ No (sync req/res)│ Yes (full proxy)   │ Yes (native CLI) │
├────────────────────┼──────────────────┼────────────────────┼──────────────────┤
│ Surface kind       │ http             │ http               │ cli              │
├────────────────────┼──────────────────┼────────────────────┼──────────────────┤
│ Audit granularity  │ Per-request      │ Per-grant          │ Per-session      │
├────────────────────┼──────────────────┼────────────────────┼──────────────────┤
│ Status             │ Implemented      │ Implemented        │ Not implemented  │
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
  │                          │ evaluate policy           │
  │                          │ resolve credential        │
  │                          │                           │
  │                          │ GET https://api.github.com│
  │                          │ Authorization: Bearer *** │
  │                          │──────────────────────────►│
  │                          │                           │
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
Not suitable for large file downloads or WebSocket connections.

## Lane 2: Direct HTTP

**Endpoints:** Grant lifecycle (`/v1/grants/*`)

The agent requests a grant, receives a local proxy address, and makes its own
HTTP calls through the proxy. The proxy validates each request against the
manifest and injects the credential.

```text
Agent                    Proxy (localhost:N)          External API
  │                          │                           │
  │ POST /v1/grants/project  │                           │
  │─────────────────────────►│ start proxy               │
  │◄─────────────────────────│                           │
  │ projection_ref=:54321    │                           │
  │                          │                           │
  │ GET http://localhost:54321                            │
  │ X-Target-URL: https://api.github.com/repos/foo/bar   │
  │─────────────────────────►│                           │
  │                          │ validate host + method    │
  │                          │ inject Bearer token       │
  │                          │──────────────────────────►│
  │                          │◄──────────────────────────│
  │◄─────────────────────────│ streamed response         │
  │                          │                           │
  │ POST /v1/grants/revoke   │                           │
  │─────────────────────────►│ stop proxy                │
```

**When to use:** When the agent needs streaming, multiple sequential requests
against the same API, or when the tool expects to make its own HTTP calls
(e.g., SDK clients).

**Limitations:** The credential passes through the local proxy, so a
sufficiently motivated agent could observe it in transit. The proxy runs on
localhost inside the microVM. Grants are time-limited and revocable.

## Lane 3: Helper Session (not yet implemented)

For CLI tools that use credential helper protocols — `git credential fill`,
kubectl exec-credential plugins, `gcloud auth print-access-token`, etc.

The access plane would manage helper processes or serve a credential-helper
protocol endpoint. The CLI tool calls the helper, receives a short-lived
credential, and proceeds with its native protocol.

```text
Agent (CLI)              Access Plane Helper          External Service
  │                          │                           │
  │ git credential fill      │                           │
  │─────────────────────────►│                           │
  │◄─────────────────────────│                           │
  │ username + password       │                           │
  │                          │                           │
  │ git push (native HTTPS)  │                           │
  │──────────────────────────────────────────────────────►│
```

**When to use:** CLI tools that don't speak HTTP directly — git, kubectl,
gcloud. These tools expect credentials through well-defined helper protocols.

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

The policy engine never falls back to a different lane if the selected one is
unimplemented — it returns the correct lane with `implementation_deferred` so
the caller knows the lane exists but isn't ready yet.
