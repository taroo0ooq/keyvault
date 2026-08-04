# KeyVault

Local-first, zero-knowledge password manager.

| Constraint | Target |
|------------|--------|
| Idle RAM | &lt; 15 MB |
| Desktop binary | &lt; 15 MB |
| Trust model | Master password never leaves the device in plaintext |
| Vault storage | Local only (no server-side vault) |

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
| `apps/desktop` | Tauri v2 (Phase 2) |
| `apps/mobile` | Flutter + flutter_rust_bridge (Phase 2) |
| `apps/extension` | Manifest V3 browser extension (Phase 3) |
| `.handover/` | Phase handover YAML documents |
| `.github/workflows/` | SAST / DAST / Playwright security gates |

## Phase status

| Phase | Name | Status |
|-------|------|--------|
| 1 | Core Crypt Engine & Vault Architecture | **Completed** (see `.handover/handover_phase_1.yaml`) |
| 2 | Desktop & Mobile UI | Pending |
| 3 | Browser Extension & Autofill | Pending |
| 4 | Secure Tunneling & Pairing | Pending |
| 5 | Automated Testing, SAST, DAST | Pending |
| 6 | Hardening, Benchmarking & Handover | Pending |

## Build (Phase 1)

```bash
cargo test -p vault-core
cargo build -p vault-daemon --release
./target/release/vault_daemon   # listens on 127.0.0.1:8080
```

## Security

- Argon2id KDF (m=64 MiB, t=3, p=4)
- AES-256-GCM / XChaCha20-Poly1305 record encryption
- Platform secure-key wrappers (DPAPI / Keychain / KeyStore stubs)
- Sensitive material zeroized on drop

## Miro board

Project journey board: [PasswordManager](https://miro.com/app/board/uXjVH1LjUrs=/)
