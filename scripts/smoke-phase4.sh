#!/usr/bin/env bash
# Phase 4 smoke (Linux/macOS): pairing + Bearer with REQUIRE_AUTH=1
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release/vault_daemon"
if [[ ! -x "$BIN" ]]; then
  echo "Build first: cargo build -p vault-daemon --release" >&2
  exit 1
fi

BIND="127.0.0.1:18081"
BASE="http://$BIND"
TMP="$(mktemp -d)"
VAULT="$TMP/s.vault"
cleanup() {
  if [[ -n "${PID:-}" ]] && kill -0 "$PID" 2>/dev/null; then
    kill "$PID" || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

VAULT_DAEMON_BIND="$BIND" VAULT_DAEMON_REQUIRE_AUTH=1 "$BIN" >/tmp/kv-daemon-smoke.log 2>&1 &
PID=$!

for i in $(seq 1 50); do
  if curl -sf "$BASE/health" >/dev/null; then
    break
  fi
  sleep 0.1
done
curl -sf "$BASE/health" >/dev/null

MODE=$(curl -sf "$BASE/v1/auth/mode")
echo "auth mode: $MODE"

PAIR=$(curl -sf -X POST "$BASE/v1/pairing/create" -H 'Content-Type: application/json' -d '{}')
PAIRING_ID=$(echo "$PAIR" | python3 -c "import sys,json; print(json.load(sys.stdin)['offer']['pairing_id'])")
TOKEN=$(echo "$PAIR" | python3 -c "import sys,json; print(json.load(sys.stdin)['offer']['token'])")

CLAIM=$(curl -sf -X POST "$BASE/v1/pairing/claim" -H 'Content-Type: application/json' \
  -d "{\"pairing_id\":\"$PAIRING_ID\",\"token\":\"$TOKEN\",\"label\":\"smoke\"}")
DEVICE_TOKEN=$(echo "$CLAIM" | python3 -c "import sys,json; print(json.load(sys.stdin)['api_token'])")
echo "claimed device token acquired"

AUTH=( -H "Authorization: Bearer $DEVICE_TOKEN" )

UNLOCK=$(curl -sS -w "\n%{http_code}" -X POST "$BASE/v1/unlock" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d "{\"path\":\"$VAULT\",\"password\":\"test-master-password-32chars!!\",\"create\":true}")
UNLOCK_CODE=$(echo "$UNLOCK" | tail -n1)
UNLOCK_BODY=$(echo "$UNLOCK" | sed '$d')
echo "unlock http=$UNLOCK_CODE body=$UNLOCK_BODY"
test "$UNLOCK_CODE" = "200"

ADD=$(curl -sS -w "\n%{http_code}" -X POST "$BASE/v1/items" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"title":"Smoke","username":"u","password":"pass-smoke-1","url":"https://example.com"}')
ADD_CODE=$(echo "$ADD" | tail -n1)
ADD_BODY=$(echo "$ADD" | sed '$d')
echo "add http=$ADD_CODE body=$ADD_BODY"
test "$ADD_CODE" = "200"
ITEM_ID=$(echo "$ADD_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

REV=$(curl -sS -w "\n%{http_code}" -X POST "$BASE/v1/reveal" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d "{\"id\":\"$ITEM_ID\",\"purpose\":\"smoke\"}")
REV_CODE=$(echo "$REV" | tail -n1)
REV_BODY=$(echo "$REV" | sed '$d')
echo "reveal http=$REV_CODE body=$REV_BODY"
test "$REV_CODE" = "200"
echo "$REV_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('password')=='pass-smoke-1', d"

curl -sf -X POST "$BASE/v1/items/update" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d "{\"id\":\"$ITEM_ID\",\"title\":\"Smoke-Updated\",\"password\":\"pass-smoke-2\"}" >/dev/null
REV2=$(curl -sf -X POST "$BASE/v1/reveal" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d "{\"id\":\"$ITEM_ID\"}")
echo "$REV2" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('password')=='pass-smoke-2', d"

EXP=$(curl -sf -X POST "$BASE/v1/export" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"passphrase":"export-pass-12+"}')
BACKUP=$(echo "$EXP" | python3 -c "import sys,json; print(json.load(sys.stdin)['backup'])")
test -n "$BACKUP"

curl -sf -X POST "$BASE/v1/items/delete" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d "{\"id\":\"$ITEM_ID\"}" >/dev/null

# JSON-escape backup for import
IMP_JSON=$(python3 -c "import json,sys; print(json.dumps({'passphrase':'export-pass-12+','backup':sys.argv[1],'merge':True}))" "$BACKUP")
IMP=$(curl -sf -X POST "$BASE/v1/import" "${AUTH[@]}" -H 'Content-Type: application/json' -d "$IMP_JSON")
echo "$IMP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('written',0)>=1"

CSV_JSON=$(python3 -c 'import json; print(json.dumps({"csv":"name,url,username,password\nSmokeCSV,https://csv.example,csvuser,csv-pass"}))')
CSV_IMP=$(curl -sf -X POST "$BASE/v1/import/csv" "${AUTH[@]}" -H 'Content-Type: application/json' -d "$CSV_JSON")
echo "$CSV_IMP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('written',0)>=1"

curl -sf -X POST "$BASE/v1/change-password" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"current_password":"test-master-password-32chars!!","new_password":"test-master-password-CHANGED1"}' >/dev/null

ADD2=$(curl -sf -X POST "$BASE/v1/items" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"title":"WithTOTP","username":"t","password":"pw","totp":"JBSWY3DPEHPK3PXP"}')
TOTP_ID=$(echo "$ADD2" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
TOTP=$(curl -sf -X POST "$BASE/v1/totp" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d "{\"id\":\"$TOTP_ID\"}")
echo "$TOTP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert len(d.get('code',''))>=6"

CSV_OUT=$(curl -sf "$BASE/v1/export/csv" "${AUTH[@]}")
echo "$CSV_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'name,url' in d.get('csv','')"

HEALTH=$(curl -sf "$BASE/v1/health/passwords" "${AUTH[@]}")
echo "password health: $HEALTH"

# No bearer must fail
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/items" || true)
if [[ "$CODE" != "401" ]]; then
  echo "expected 401 without bearer, got $CODE" >&2
  exit 1
fi

echo "SMOKE PHASE4 PASS"
