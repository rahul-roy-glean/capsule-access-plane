#!/usr/bin/env bash
#
# Smoke test for the capsule access plane.
# Usage:
#   ./dev/smoke-test.sh              # test against localhost:8080
#   ./dev/smoke-test.sh http://host:port  # test against custom base URL
#
set -euo pipefail

# Resolve repo root (one level up from dev/).
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

BASE="${1:-http://localhost:8080}"
SECRET="${ATTESTATION_SECRET:-local-dev-secret}"
PASS=0
FAIL=0

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }

check() {
  local label="$1" want="$2" got="$3"
  if [ "$got" = "$want" ]; then
    green "  ✓ $label (status $got)"
    PASS=$((PASS + 1))
  else
    red "  ✗ $label — want $want, got $got"
    FAIL=$((FAIL + 1))
  fi
}

# Build the token generator (once).
GENTOKEN_BIN=$(mktemp)
go build -o "$GENTOKEN_BIN" "$REPO_ROOT/cmd/gentoken"
trap "rm -f $GENTOKEN_BIN" EXIT

TOKEN=$("$GENTOKEN_BIN" -secret "$SECRET" -runner-id r1 -session-id s1)

echo ""
echo "=== Capsule Access Plane — Smoke Test ==="
echo "Base URL : $BASE"
echo "Secret   : $SECRET"
echo ""

# ── healthz ──────────────────────────────────────────
echo "── GET /healthz"
status=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/healthz")
check "healthz returns 200" "200" "$status"

# ── resolve ──────────────────────────────────────────
echo "── POST /v1/resolve"
status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST "$BASE/v1/resolve" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "actor":{"user_id":"smoke-user"},
    "runner":{"session_id":"s1","runner_id":"r1","turn_id":"t1"},
    "tool_family":"github_rest",
    "logical_action":"read_repo"
  }')
check "resolve returns 200" "200" "$status"

echo "── POST /v1/resolve (no auth)"
status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST "$BASE/v1/resolve" \
  -H "Content-Type: application/json" \
  -d '{"actor":{"user_id":"u1"},"runner":{"session_id":"s1","runner_id":"r1"},"tool_family":"github_rest"}')
check "resolve without auth returns 401" "401" "$status"

echo "── POST /v1/resolve (unknown family)"
status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST "$BASE/v1/resolve" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "actor":{"user_id":"smoke-user"},
    "runner":{"session_id":"s1","runner_id":"r1","turn_id":"t1"},
    "tool_family":"nonexistent"
  }')
check "resolve unknown family returns 403" "403" "$status"

# ── grant lifecycle ──────────────────────────────────
echo "── POST /v1/grants/project"
project_resp=$(curl -s -w '\n%{http_code}' \
  -X POST "$BASE/v1/grants/project" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "runner_id":"r1","session_id":"s1","turn_id":"t1",
    "tool_family":"github_rest","lane":"direct_http","scope":"repo:read"
  }')
project_status=$(echo "$project_resp" | tail -1)
project_body=$(echo "$project_resp" | sed '$d')
check "project grant returns 200" "200" "$project_status"

GRANT_ID=$(echo "$project_body" | grep -o '"grant_id":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -n "$GRANT_ID" ]; then
  green "  ✓ got grant_id=$GRANT_ID"

  echo "── POST /v1/grants/exchange"
  status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST "$BASE/v1/grants/exchange" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"grant_id\":\"$GRANT_ID\",\"runner_id\":\"r1\"}")
  check "exchange returns 200" "200" "$status"

  echo "── POST /v1/grants/refresh"
  status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST "$BASE/v1/grants/refresh" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"grant_id\":\"$GRANT_ID\",\"runner_id\":\"r1\"}")
  check "refresh returns 200" "200" "$status"

  echo "── POST /v1/grants/revoke"
  status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST "$BASE/v1/grants/revoke" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"grant_id\":\"$GRANT_ID\",\"runner_id\":\"r1\"}")
  check "revoke returns 200" "200" "$status"
else
  red "  ✗ could not extract grant_id from project response"
  FAIL=$((FAIL + 1))
fi

# ── execute/http ─────────────────────────────────────
echo "── POST /v1/execute/http (disallowed host)"
status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST "$BASE/v1/execute/http" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "runner_id":"r1","session_id":"s1","turn_id":"t1",
    "tool_family":"github_rest","method":"GET",
    "url":"https://evil.example.com/steal"
  }')
check "execute disallowed host returns 403" "403" "$status"

echo "── POST /v1/execute/http (disallowed method)"
status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST "$BASE/v1/execute/http" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "runner_id":"r1","session_id":"s1","turn_id":"t1",
    "tool_family":"github_rest","method":"DELETE",
    "url":"https://api.github.com/repos/foo/bar"
  }')
check "execute disallowed method returns 405" "405" "$status"

echo "── POST /v1/execute/http (no auth)"
status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST "$BASE/v1/execute/http" \
  -H "Content-Type: application/json" \
  -d '{"runner_id":"r1","session_id":"s1","tool_family":"github_rest","method":"GET","url":"https://api.github.com/repos/foo/bar"}')
check "execute without auth returns 401" "401" "$status"

# ── summary ──────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
