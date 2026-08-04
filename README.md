# KeyVault

Local-first, zero-knowledge password manager.

[![CI](https://github.com/taroo0ooq/keyvault/actions/workflows/ci.yml/badge.svg)](https://github.com/taroo0ooq/keyvault/actions/workflows/ci.yml)
[![SAST](https://github.com/taroo0ooq/keyvault/actions/workflows/sast-scan.yml/badge.svg)](https://github.com/taroo0ooq/keyvault/actions/workflows/sast-scan.yml)
[![DAST](https://github.com/taroo0ooq/keyvault/actions/workflows/dast-scan.yml/badge.svg)](https://github.com/taroo0ooq/keyvault/actions/workflows/dast-scan.yml)

| Constraint | Target |
|------------|--------|
| Idle RAM | &lt; 15 MB |
| Desktop binary | &lt; 15 MB |
| Trust model | Master password never leaves the device in plaintext |
| Vault storage | Local only (no server-side vault) |
| **Merge gate** | **GitHub Actions `CI / required-gate` (primary path)** |

## Architecture

```
Core Engine (Rust) ──FFI──► Native clients (Tauri v2 / Flutter)
                 └──IPC──► Browser extensions (Manifest V3)
                 └──WSS──► Secure tunnel gateway (cloudflared / ngrok)
```

See [docs/passwordmanager.md](docs/passwordmanager.md) for the full product prompt and phase plan.

## Workspace

| Path | Role |
|------|------|
| `crates/vault-core` | Cryptographic engine, KDF, vault crypto, password generator, SQL schema |
| `crates/vault-daemon` | Local loopback health/API daemon for remote clients & DAST |
| `crates/vault-native-host` | Chrome/Firefox native messaging host → loopback daemon |
| `apps/desktop` | Tauri v2 desktop shell (Phase 2) — vault-core + auto-lock |
| `apps/mobile` | Flutter UI + vault_ffi (dart:ffi → vault-core) |
| `crates/vault-ffi` | C ABI for mobile / non-Rust clients |
| `apps/extension` | Manifest V3 extension — loopback + optional native host + autofill |
| `.handover/` | Phase handover YAML documents |
| `.github/workflows/` | **Primary CI** + hardwired SAST/DAST/E2E/gates/vault-ffi |
| `Docs/CI.md` | CI/CD policy — GitHub Actions is source of truth |

## Phase status

| Phase | Name | Status |
|-------|------|--------|
| 1 | Core Crypt Engine & Vault Architecture | **Completed** (see `.handover/handover_phase_1.yaml`) |
| 2 | Desktop & Mobile UI | **In progress** — see `.handover/handover_phase_2.yaml` |
| 3 | Browser Extension & Autofill | **In progress** — MV3 autofill + reveal (see `.handover/handover_phase_3.yaml`) |
| 4 | Secure Tunneling & Pairing | **In progress** — see `.handover/handover_phase_4.yaml` |
| 5 | Automated Testing, SAST, DAST | **In progress** — see `.handover/handover_phase_5.yaml` + `phase5-gates.yml` |
| 6 | Hardening, Benchmarking & Handover | **Near complete** — footprint, compliance, packaging notes (see `.handover/handover_phase_6.yaml`) |
| 7 | CRUD API & portable backup | **Engineering complete** — see `.handover/handover_phase_7.yaml` |
| 8 | Change password & CSV import | **Engineering complete** — see `.handover/handover_phase_8.yaml` |
| 9 | TOTP 2FA + enclave clear | **Engineering complete** — see `.handover/handover_phase_9.yaml` |
| 10 | Mobile TOTP (vault_ffi) | **Engineering complete** — see `.handover/handover_phase_10.yaml` |
| 11 | Dart mock TOTP + extension TOTP | **Engineering complete** — see `.handover/handover_phase_11.yaml` |
| 12 | CSV export + password health | **Engineering complete** — see `.handover/handover_phase_12.yaml` |
| 13 | Trash + HIBP k-anonymity | **Engineering complete** — see `.handover/handover_phase_13.yaml` |

## CI/CD (primary development path)

**All merges require a green [CI](.github/workflows/ci.yml) run.** Local builds are for iteration only.

| Gate | Tools (fail-closed) |
|------|---------------------|
| **SAST** | TruffleHog, Gitleaks, CodeQL, cargo-audit, cargo-deny, clippy, Semgrep, npm audit, Flutter analyze |
| **DAST** | OWASP ZAP baseline (`fail_action: true`) + loopback auth probes |
| **Gates** | Unit/integration tests, footprint &lt; 15 MB, smoke-phase4 |
| **E2E** | Playwright (extension) |
| **FFI** | vault-ffi host + Android jniLibs |

Details: [Docs/CI.md](Docs/CI.md) · Dependency matrix: [Docs/DEPENDENCY_MATRIX.md](Docs/DEPENDENCY_MATRIX.md)

```bash
# Typical contributor flow
git checkout -b feat/my-change
# … edit …
git push -u origin HEAD
gh pr create   # wait for CI / required-gate
```

## Build (local iteration)

```bash
# Phase 1 core
cargo test -p vault-core
cargo build -p vault-daemon --release
./target/release/vault_daemon   # listens on 127.0.0.1:8080

# Phase 2 desktop
cd apps/desktop && npm install && npm run tauri build

# Phase 2 mobile + native core
cargo build -p vault-ffi --release
# Windows: set VAULT_FFI_PATH to target/release/vault_ffi.dll
cd apps/mobile && flutter pub get && flutter run
```

## Security

- Argon2id KDF (m=64 MiB, t=3, p=4)
- AES-256-GCM / XChaCha20-Poly1305 record encryption
- Platform secure-key wrappers (DPAPI / Keychain / KeyStore stubs)
- Sensitive material zeroized on drop

## Footprint

```powershell
cargo build -p vault-daemon -p vault-ffi --release
cargo build -p keyvault-desktop --release   # optional
.\scripts\measure-footprint.ps1
# → docs/footprint-report.json
```

| Windows release (sample) | Size |
|--------------------------|------|
| vault_daemon.exe | ~1.60 MB |
| vault_ffi.dll | ~2.26 MB |
| vault_native_host.exe | ~0.58 MB |
| keyvault-desktop.exe | ~3.83 MB |
| Daemon idle WorkingSet | ~5.99 MB |

Draft notes: [docs/RELEASE_NOTES.md](docs/RELEASE_NOTES.md) · Compliance: [docs/COMPLIANCE.md](docs/COMPLIANCE.md) · Packaging: [docs/PACKAGING.md](docs/PACKAGING.md)

## Miro board

Project journey board: [PasswordManager](https://miro.com/app/board/uXjVH1LjUrs=/)  
Offline seed (use when MCP quota exhausted): [docs/miro-board-seed.md](docs/miro-board-seed.md)
