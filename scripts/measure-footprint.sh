#!/usr/bin/env bash
# Measure release binary sizes and optional daemon idle RSS (Linux/macOS).
# Usage (repo root):
#   cargo build -p vault-daemon -p vault-ffi --release
#   cargo build -p keyvault-desktop --release   # optional
#   ./scripts/measure-footprint.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

LIMIT_MB=15
OUT_DIR="$ROOT/Docs"
mkdir -p "$OUT_DIR"
REPORT_JSON="$OUT_DIR/footprint-report.json"

measured_at="$(date -Iseconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S%z)"
platform="$(uname -s) $(uname -m)"
rustc_ver="$(rustc --version 2>/dev/null || echo unknown)"

echo "== Binary sizes =="

# Collect targets as name|path pairs
targets=(
  "vault_daemon|target/release/vault_daemon"
  "vault_ffi|target/release/libvault_ffi.so"
  "vault_ffi_dylib|target/release/libvault_ffi.dylib"
  "vault_native_host|target/release/vault_native_host"
  "keyvault-desktop|target/release/keyvault-desktop"
)

json_targets=""
first=1
measure() {
  local name="$1" path="$2"
  if [[ ! -f "$path" ]]; then
    echo "SKIP $name (missing $path)"
    local entry
    entry=$(printf '{"name":"%s","path":"%s","present":false}' "$name" "$path")
    if [[ $first -eq 1 ]]; then
      json_targets="$entry"
      first=0
    else
      json_targets="$json_targets,$entry"
    fi
    return
  fi
  local bytes mb ok under
  bytes=$(wc -c <"$path" | tr -d ' ')
  mb=$(python3 -c "print(round($bytes/1024/1024, 3))")
  ok="OK"
  under=true
  if ! python3 -c "import sys; sys.exit(0 if $mb < $LIMIT_MB else 1)"; then
    ok="OVER LIMIT"
    under=false
  fi
  printf "%-20s %8s MB  %s\n" "$name" "$mb" "$ok"
  local entry
  entry=$(printf '{"name":"%s","path":"%s","present":true,"bytes":%s,"megabytes":%s,"limit_mb":%s,"under_limit":%s}' \
    "$name" "$path" "$bytes" "$mb" "$LIMIT_MB" "$under")
  if [[ $first -eq 1 ]]; then
    json_targets="$entry"
    first=0
  else
    json_targets="$json_targets,$entry"
  fi
}

for t in "${targets[@]}"; do
  name="${t%%|*}"
  path="${t#*|}"
  # Skip dylib skip noise if .so present on Linux and vice versa: still report SKIP
  measure "$name" "$path"
done

daemon_idle_json="null"
daemon_bin="target/release/vault_daemon"
if [[ -f "$daemon_bin" ]]; then
  echo ""
  echo "== Daemon idle RSS (approx) =="
  bind="127.0.0.1:18099"
  VAULT_DAEMON_BIND="$bind" "./$daemon_bin" >/tmp/vault_daemon_fp.log 2>&1 &
  dpid=$!
  healthy=false
  for _ in $(seq 1 40); do
    sleep 0.1
    if curl -sf "http://$bind/health" >/dev/null 2>&1; then
      healthy=true
      break
    fi
  done
  sleep 0.5
  rss_kb=""
  if [[ -r "/proc/$dpid/status" ]]; then
    rss_kb=$(awk '/VmRSS:/ {print $2}' "/proc/$dpid/status" || true)
  elif command -v ps >/dev/null 2>&1; then
    # macOS: rss is in KB with -o rss=
    rss_kb=$(ps -o rss= -p "$dpid" 2>/dev/null | tr -d ' ' || true)
  fi
  kill "$dpid" 2>/dev/null || true
  wait "$dpid" 2>/dev/null || true
  if [[ -n "$rss_kb" ]]; then
    rss_bytes=$((rss_kb * 1024))
    rss_mb=$(python3 -c "print(round($rss_bytes/1024/1024, 3))")
    under=true
    if ! python3 -c "import sys; sys.exit(0 if $rss_mb < $LIMIT_MB else 1)"; then
      under=false
    fi
    echo "WorkingSet/RSS ~ ${rss_mb} MB (healthy=$healthy)"
    daemon_idle_json=$(printf '{"healthy":%s,"working_set_bytes":%s,"working_set_mb":%s,"under_limit":%s,"note":"RSS after /health; not full product idle with UI"}' \
      "$healthy" "$rss_bytes" "$rss_mb" "$under")
  else
    echo "Could not read RSS for pid $dpid (healthy=$healthy)"
    daemon_idle_json=$(printf '{"healthy":%s,"working_set_bytes":null,"under_limit":null,"note":"RSS unavailable"}' "$healthy")
  fi
fi

cat >"$REPORT_JSON" <<EOF
{
  "measured_at": "$measured_at",
  "platform": "$platform",
  "rustc": "$rustc_ver",
  "targets": [$json_targets],
  "constraints": {
    "idle_ram_mb": $LIMIT_MB,
    "desktop_binary_mb": $LIMIT_MB
  },
  "daemon_idle": $daemon_idle_json
}
EOF

echo ""
echo "Wrote $REPORT_JSON"
echo "Targets: desktop binary < ${LIMIT_MB} MB, idle RAM < ${LIMIT_MB} MB."
