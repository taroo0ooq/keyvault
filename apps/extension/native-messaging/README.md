# Native messaging (KI-031)

KeyVault MV3 extension talks to `vault_daemon` primarily over **loopback HTTP**
(`http://127.0.0.1:8080`). When browser policy blocks extension → loopback
`fetch`, the extension falls back to a **native messaging host**.

## Host binary

```bash
cargo build -p vault-native-host --release
# → target/release/vault_native_host(.exe)
```

The host speaks Chrome/Firefox length-prefixed JSON on stdin/stdout and proxies
commands to the daemon (`VAULT_DAEMON_URL`, optional `VAULT_DAEMON_TOKEN`).

### Commands

| cmd | Description |
|-----|-------------|
| `ping` | Host alive (no daemon required) |
| `health` / `status` / `auth_mode` | Daemon endpoints |
| `items` / `search` | Redacted list |
| `reveal` | One-shot secret (same as `/v1/reveal`) |
| `unlock` / `lock` | Session |
| `proxy` | Generic `method` + `path` + optional `body` |

## Install (Windows / Chrome)

1. Load the unpacked extension from `apps/extension/dist` and copy its **ID**.
2. Build the host (release).
3. Run from repo root:

```powershell
.\scripts\install-native-host.ps1 -ExtensionId <your-extension-id>
```

This writes a filled host manifest under `%LOCALAPPDATA%\KeyVault\` and registers
`HKCU\Software\Google\Chrome\NativeMessagingHosts\app.keyvault.native`.

## Install (Linux)

```bash
chmod +x scripts/install-native-host.sh
./scripts/install-native-host.sh <extension-id>
# Registers ~/.config/google-chrome/NativeMessagingHosts/app.keyvault.native.json
```

## Firefox

Use the same host binary; register under Firefox’s native messaging path and set
`allowed_extensions` instead of `allowed_origins` (see Mozilla docs). Manifest
template remains Chrome-oriented; adjust when packaging for Firefox.

## Security notes

- Host only dials loopback daemon URL (default `127.0.0.1:8080`).
- Secrets still flow only through one-shot `reveal`; do not cache in the host.
- Keep `allowed_origins` pinned to your extension ID.
