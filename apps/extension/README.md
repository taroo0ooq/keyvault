# KeyVault Browser Extension (Manifest V3)

Local-first autofill client for KeyVault. Talks **only** to `vault_daemon` on `127.0.0.1:8080`.

## Architecture

```
Content script (form detect + overlay)
        │ chrome.runtime.sendMessage
        ▼
Service worker (status poll, match host)
        │ fetch (loopback)
        ▼
vault_daemon (127.0.0.1 only) → vault-core
```

List endpoints return **redacted passwords** (`••••••••`).  
**Autofill:** content script requests `REVEAL_ITEM` → service worker calls `POST /v1/reveal` (rate-limited, `ttl_ms=15000`) → password is filled once and not cached in the SW.

Native messaging: `crates/vault-native-host` + `native-messaging/` install docs.
Loopback HTTP remains primary; extension falls back to `app.keyvault.native` when fetch fails.
See `scripts/install-native-host.ps1` / `.sh`.

## Develop

```bash
# Terminal 1 — daemon
cargo run -p vault-daemon --release

# Terminal 2 — extension
cd apps/extension
npm install
npm run build
```

Load unpacked in Chrome/Edge: `chrome://extensions` → Developer mode → **Load unpacked** → select `apps/extension/dist`.

## Test

```bash
npm run test:unit
npm run build
npx playwright test
```

## Security notes

- Daemon refuses non-loopback binds.
- Extension host_permissions limited to loopback daemon URLs.
- CSP: `script-src 'self'` on extension pages.
- No remote vault servers.
