# KeyVault release notes (draft)

## 0.1.0 — development snapshot (2026-08-05)

Local-first, zero-knowledge password manager spanning Rust core, desktop, mobile shell, browser extension, and loopback daemon.

### Highlights

- **vault-core:** Argon2id (64 MiB / t=3 / p=4), AES-256-GCM & XChaCha20-Poly1305, encrypted vault CRUD, password generator + entropy, OS key wrap (DPAPI / software-dev), enclave MK sidecar
- **vault_daemon:** loopback-only HTTP API, full item CRUD, encrypted backup export/import, unlock/list/reveal, tunnel agent, QR pairing, Bearer auth when tunnel active
- **Desktop (Tauri v2):** full vault UI, auto-lock, clipboard clear, PIN mode, Remote panel, encrypted Backup dialog
- **Portable backup:** AEAD envelope sealed under a separate export passphrase (`keyvault-backup-v1`)
- **Change master password:** re-encrypts vault under new Argon2id key (desktop Security + `/v1/change-password`)
- **CSV import:** Chrome / Bitwarden-style columns (desktop + `/v1/import/csv`)
- **TOTP / 2FA:** base32 or `otpauth://` secrets; live codes (`/v1/totp`, desktop countdown); schema v2 `totp_enc`
- **Password change:** automatically clears OS enclave quick-unlock sidecar
- **Mobile TOTP:** Flutter UI + `kv_vault_totp_json` / save with `totp` via vault_ffi; pure-Dart codes in mock mode
- **Extension TOTP:** popup **Copy TOTP** when item has 2FA (via `/v1/totp`)
- **CSV export:** Chrome-style `name,url,username,password,notes,totp` (`GET /v1/export/csv`, desktop)
- **Password health:** offline weak + reused scan (`GET /v1/health/passwords`, desktop Security)
- **Trash:** soft-delete with restore / purge / empty trash (schema v3 `deleted_at`)
- **HIBP:** optional k-anonymity check `POST /v1/health/pwned` (SHA-1 prefix only; network)
- **Mobile (Flutter):** UI shell + vault_ffi dart:ffi + local_auth gate for enclave unlock
- **Extension (MV3):** form overlay autofill via one-shot `/v1/reveal`; optional native messaging host fallback
- **vault_native_host:** Chrome/Firefox stdio host proxies to loopback daemon (`install-native-host` scripts)
- **CI:** SAST, DAST probes, Playwright, vault-ffi Android artifacts, `phase5-gates.yml` (includes footprint gate)

### Footprint targets

| Artifact | Target | Notes |
|----------|--------|--------|
| Desktop binary | &lt; 15 MB | Release `keyvault-desktop` |
| Daemon / core libs | minimize | Release strip + LTO |
| Idle RAM | &lt; 15 MB | Product goal; daemon measured, full UI later |

### Measured (Windows release, 2026-08-04)

| Artifact | Size | Limit | Status |
|----------|------|-------|--------|
| vault_daemon.exe | ~1.60 MB | 15 MB | OK |
| vault_ffi.dll | ~2.26 MB | 15 MB | OK |
| vault_native_host.exe | ~0.58 MB | 15 MB | OK |
| keyvault-desktop.exe | ~3.83 MB | 15 MB | OK |
| Daemon idle WorkingSet | ~5.99 MB | 15 MB | OK (daemon only) |

Run `scripts/measure-footprint.ps1` (Windows) or `scripts/measure-footprint.sh` after release builds. Report written to `docs/footprint-report.json`. Compliance: [COMPLIANCE.md](./COMPLIANCE.md). Packaging: [PACKAGING.md](./PACKAGING.md).

### Known limitations

- SQLCipher native C library not linked (field-level AEAD interim)
- Android `libvault_ffi.so` via CI artifacts, not committed
- Native messaging host requires install script + extension ID registration
- mTLS client certs not yet implemented (Bearer pairing tokens)
- Tauri desktop not built on Linux CI

### Security posture

- Master password never leaves device in plaintext
- No server-side vault storage
- Daemon refuses non-loopback binds
- List endpoints redact passwords; reveal is rate-limited with TTL advisory
