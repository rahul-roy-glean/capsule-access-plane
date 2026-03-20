# CONNECT Proxy with SSL Bump

Run the access plane as an HTTPS CONNECT proxy. VMs set `HTTPS_PROXY` and
make normal `curl`/`wget`/library HTTPS calls. The proxy selectively MITM's
connections to hosts that have a credential provider, injecting tokens
transparently.

## How it works

```
VM                          Access Plane (CONNECT proxy)        Target
 │                                │                               │
 │─ CONNECT api.github.com:443 ─►│                               │
 │◄─ 200 Connection Established ─│                               │
 │                                │                               │
 │◄─── TLS handshake ───────────►│ (cert signed by built-in CA)  │
 │                                │                               │
 │── GET /repos/foo ────────────►│                               │
 │   (plain HTTP over MITM TLS)  │── GET /repos/foo ────────────►│
 │                                │   Authorization: Bearer ghp.. │
 │                                │◄─ 200 OK ────────────────────│
 │◄─ 200 OK ─────────────────────│                               │
```

Hosts without a credential provider are raw-tunneled (no MITM, no inspection).

## Setup

### providers.json

```json
[
  {
    "name": "github",
    "type": "delegated",
    "hosts": ["api.github.com", "github.com"]
  }
]
```

### Start the access plane

```bash
export ATTESTATION_SECRET="my-secret"
export PROVIDERS_CONFIG="./providers.json"
export PROXY_ADDR=":3128"

go run .
# => INFO starting access plane addr=:8080
# => INFO starting CONNECT proxy addr=:3128
```

### Push a token (simulating host agent)

```bash
curl -s -X POST http://localhost:8080/v1/providers/update-token \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "github",
    "token": "ghp_your_github_pat_here",
    "expires_at": "2026-03-21T00:00:00Z"
  }'
# {"provider":"github","status":"updated"}
```

### Use the proxy from a VM

```bash
# The VM just sets HTTPS_PROXY and makes normal requests.
# The access plane's CA cert must be trusted by the client.

export HTTPS_PROXY=http://localhost:3128

# With curl: trust the CA (in production, the CA cert is injected into the VM)
# For testing, use -k to skip verification:
curl -k https://api.github.com/repos/octocat/Hello-World
# The response comes back with the credential injected by the proxy.
# Your curl never sees the token.
```

### What gets blocked

```bash
# Host not in any manifest destination:
curl -k -x http://localhost:3128 https://evil.example.com/steal
# => 403 Forbidden: host evil.example.com not allowed by manifest

# Private IP (SSRF):
# If a manifest host DNS-resolves to 10.x.x.x, the proxy blocks it.

# Wrong HTTP method (if manifest only allows GET):
# The proxy returns 405 after MITM inspection.
```

## Selective bump vs tunnel

| Scenario | Behavior |
|----------|----------|
| Host has a credential provider | SSL bump: MITM, inject creds, enforce method+path |
| Host in manifest, no provider | Raw tunnel: bytes pass through, no inspection |
| Host not in any manifest | Rejected with 403 |
