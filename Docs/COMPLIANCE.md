# KeyVault architectural compliance checklist

**Phase:** 6 — Hardening, Benchmarking & Handover  
**Last review:** 2026-08-05  
**Evidence report:** [footprint-report.json](./footprint-report.json)

Product constraints from the system architecture (see [passwordmanager.md](./passwordmanager.md)):

| ID | Requirement | Status | Evidence |
|----|-------------|--------|----------|
| C-01 | Idle RAM &lt; 15 MB | **Partial** | Daemon WorkingSet ~6 MB after `/health` (Windows). Full product idle with desktop UI not yet automated. |
| C-02 | Desktop binary &lt; 15 MB | **PASS** | `keyvault-desktop.exe` ~3.83 MB release (Windows). |
| C-03 | Master password never leaves device in plaintext | **PASS** | Local Argon2id only; no network vault store; UI never receives raw MK. |
| C-04 | No server-side vault storage | **PASS** | Local SQLite + field-level AEAD; tunnel is access path only. |
| C-05 | Daemon loopback-only bind | **PASS** | Non-loopback bind exits with code 2 (`vault-daemon`). |
| C-06 | SAST/DAST gates before merge | **PASS (configured)** | `sast-scan`, `dast-scan`, `e2e-playwright`, `phase5-gates`, `vault-ffi`. |
| C-07 | Crypto isolated from UI | **PASS** | `vault-core` only; Tauri IPC / dart:ffi / loopback daemon. |
| C-08 | List endpoints redact secrets | **PASS** | `/v1/entries` redacted; secrets via `/v1/reveal` with TTL. |
| C-09 | Tunnel requires authentication | **PASS** | Bearer token when tunnel active; pairing HMAC/QR. |
| C-10 | Auto-lock / MK zeroize | **PASS** | Desktop auto-lock; secure_key / zeroize on drop. |

## Footprint snapshot (Windows release, 2026-08-04)

| Artifact | Size | Limit | Status |
|----------|------|-------|--------|
| vault_daemon.exe | ~1.60 MB | 15 MB | OK |
| vault_ffi.dll | ~2.26 MB | 15 MB | OK |
| vault_native_host.exe | ~0.58 MB | 15 MB | OK |
| keyvault-desktop.exe | ~3.83 MB | 15 MB | OK |
| Daemon idle WorkingSet | ~5.99 MB | 15 MB | OK (daemon only) |

Re-measure:

```powershell
cargo build -p vault-daemon -p vault-ffi --release
cargo build -p keyvault-desktop --release
.\scripts\measure-footprint.ps1
```

```bash
cargo build -p vault-daemon -p vault-ffi --release
./scripts/measure-footprint.sh
```

## Open compliance gaps

| Gap | Severity | Plan |
|-----|----------|------|
| Multi-platform footprint (macOS/Linux desktop) | Low | Run measure scripts on each release host |
| Full UI idle RAM automation | Medium | Extend measure script or CI job with desktop smoke |
| SQLCipher native C lib | Medium | Optional `--features sqlcipher` + Linux CI canary; default field-level AEAD; see SQLCIPHER.md (KI-001) |
| mTLS client certs (vs Bearer) | Low | Optional hardening after pairing tokens |
| Android `libvault_ffi.so` not in git | Medium | CI artifacts via `vault-ffi.yml` |

## Sign-off

| Role | Name | Date | Result |
|------|------|------|--------|
| Lead Software Architect | _pending_ | | |
| Security reviewer | _pending_ | | |

Handover YAML: [`.handover/handover_phase_6.yaml`](../.handover/handover_phase_6.yaml)
