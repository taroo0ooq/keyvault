# KeyVault packaging notes (0.1.0 development)

## Artifacts to ship

| Component | Build | Output (Windows) | Notes |
|-----------|-------|------------------|-------|
| Daemon | `cargo build -p vault-daemon --release` | `target/release/vault_daemon.exe` | Loopback default `127.0.0.1:8080` |
| Native host | `cargo build -p vault-native-host --release` | `target/release/vault_native_host.exe` | Chrome NM; install via scripts |
| FFI | `cargo build -p vault-ffi --release` | `target/release/vault_ffi.dll` | Mobile / native clients |
| Desktop | `cd apps/desktop && npm run tauri build` | `keyvault-desktop.exe` (+ installer if configured) | Tauri v2 |
| Extension | `cd apps/extension && npm run build` | `apps/extension/dist/` | Sideload / store packaging TBD |
| Mobile | `cd apps/mobile && flutter build apk` (or iOS) | Platform packages | Requires `libvault_ffi` via CI jniLibs |

## Pre-release checklist

1. [ ] `cargo test -p vault-core -p vault-ffi` (and daemon unit tests if any)
2. [ ] `cargo clippy` on workspace crates used in CI (exclude desktop host on Linux CI)
3. [ ] `.\scripts\measure-footprint.ps1` (or `.sh`) — all binaries under 15 MB
4. [ ] `.\scripts\smoke-phase4.ps1` (or `.sh`) against local daemon
5. [ ] Extension Playwright: `cd apps/extension && npx playwright test`
6. [ ] Flutter: `cd apps/mobile && flutter analyze && flutter test`
7. [ ] Review [RELEASE_NOTES.md](./RELEASE_NOTES.md) and [COMPLIANCE.md](./COMPLIANCE.md)
8. [ ] Confirm CI green: `sast-scan`, `dast-scan`, `e2e-playwright`, `phase5-gates`, `vault-ffi`
9. [ ] Update Miro board / [miro-board-seed.md](./miro-board-seed.md)

## Not productized yet

- Code-signed installers (Authenticode / notarization)
- Store listings (Chrome Web Store, Play, App Store)
- mTLS packaging of client certs
- Multi-arch Linux desktop AppImage/deb

## Version

Development snapshot: **0.1.0** — see release notes. Bump when cutting a formal tag.
