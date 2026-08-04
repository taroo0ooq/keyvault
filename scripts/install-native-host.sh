#!/usr/bin/env bash
# Register Chrome native messaging host for KeyVault (current user).
# Usage:
#   cargo build -p vault-native-host --release
#   ./scripts/install-native-host.sh <chrome-extension-id>
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXT_ID="${1:-}"
if [[ -z "$EXT_ID" ]]; then
  echo "Usage: $0 <chrome-extension-id>" >&2
  exit 1
fi

HOST_BIN="${VAULT_NATIVE_HOST:-$ROOT/target/release/vault_native_host}"
if [[ ! -x "$HOST_BIN" && ! -f "$HOST_BIN" ]]; then
  echo "Host binary not found: $HOST_BIN" >&2
  echo "Run: cargo build -p vault-native-host --release" >&2
  exit 1
fi
HOST_BIN="$(cd "$(dirname "$HOST_BIN")" && pwd)/$(basename "$HOST_BIN")"

INSTALL_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/google-chrome/NativeMessagingHosts"
mkdir -p "$INSTALL_DIR"
MANIFEST="$INSTALL_DIR/app.keyvault.native.json"

cat >"$MANIFEST" <<EOF
{
  "name": "app.keyvault.native",
  "description": "KeyVault native messaging host — proxies to loopback vault_daemon",
  "path": "$HOST_BIN",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://${EXT_ID}/"
  ]
}
EOF

# Chromium alternate path
CHROMIUM_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/chromium/NativeMessagingHosts"
if [[ -d "${XDG_CONFIG_HOME:-$HOME/.config}/chromium" ]]; then
  mkdir -p "$CHROMIUM_DIR"
  cp "$MANIFEST" "$CHROMIUM_DIR/app.keyvault.native.json"
fi

echo "Installed: $MANIFEST"
echo "Host: $HOST_BIN"
echo "Origin: chrome-extension://${EXT_ID}/"
echo "Restart the browser; ensure vault_daemon is on 127.0.0.1:8080."
