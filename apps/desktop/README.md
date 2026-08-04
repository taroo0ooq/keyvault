# KeyVault Desktop (Tauri v2)

Native desktop shell for KeyVault. All cryptography runs in Rust via `vault-core`.

## Requirements

- Node.js 18+
- Rust toolchain
- Platform WebView (WebView2 on Windows)

## Develop

```bash
cd apps/desktop
npm install
npm run tauri dev
```

## Build release

```bash
cd apps/desktop
npm run tauri build
```

## Architecture

```
WebView UI (HTML/CSS/JS)
    │  Tauri IPC invoke()
    ▼
src-tauri commands (Rust)
    │
    ▼
vault-core  (Argon2id, AES-GCM, vault DB)
```

Default vault path: `{data_dir}/KeyVault/vault.db` (e.g. `%APPDATA%\KeyVault\vault.db` on Windows).

## Remote access (Phase 4)

1. Start the loopback daemon: `cargo run -p vault-daemon --release`
2. In the desktop app (unlocked), open **Remote**
3. Start cloudflared/ngrok (binary must be on PATH) or paste a public URL
4. **Create QR pairing** → share `qr_json` with the mobile client
5. When a tunnel is running, vault APIs require `Authorization: Bearer` (operator token printed by the daemon, or a claimed device token)

Smoke test:

```powershell
.\scripts\smoke-phase4.ps1
```
