# Miro board seed — PasswordManager

**Board:** [PasswordManager](https://miro.com/app/board/uXjVH1LjUrs=/)  
**Board ID:** `uXjVH1LjUrs=`

This document is the offline seed for the living Miro journey board. Apply via Miro MCP tools once OAuth is authenticated (`/mcps` → miro → `i`).

---

## Frame 1 — System Architecture

Title: **KeyVault System Architecture**

Layers (top → bottom):

1. **Core Engine (Rust)**  
   Argon2id KDF · AES-256-GCM / XChaCha20-Poly1305 · Biometric Enclave Bridge · SQLCipher schema engine

2. **Native Clients** (FFI / C-ABI)  
   Desktop: Tauri v2 · Mobile: Flutter + flutter_rust_bridge

3. **Browser Extensions** (Local WebSocket / IPC)  
   Manifest V3 · Content scripts · Autofill overlay

4. **Secure Tunnel Gateway Agent**  
   cloudflared · ngrok wrapper · mTLS / token handshake

Constraints sticky notes:
- Idle RAM &lt; 15 MB
- Desktop binary &lt; 15 MB
- Master password never leaves device plaintext
- No server-side vault storage

---

## Frame 2 — Phase Roadmap

| Phase | Name | Status | Depends on |
|-------|------|--------|------------|
| 1 | Core Crypt Engine & Vault Architecture | **IN PROGRESS** | — |
| 2 | Desktop & Mobile UI | Pending | Phase 1 handover |
| 3 | Browser Extension & Autofill | Pending | Phase 2 handover |
| 4 | Secure Tunneling & Pairing | Pending | Phase 3 handover |
| 5 | Automated Testing, SAST, DAST | Pending | Phase 4 handover |
| 6 | Hardening, Benchmarking & Handover | Pending | Phase 5 handover |

---

## Frame 3 — Cryptographic Key Flow

```
Master Password
      │
      ▼
 Argon2id (64 MiB, t=3, p=4)
      │
      ▼
 Master Key (MK, 32 B) ──encrypt──► Vault records (unique IV each)
      │
      ├── wrap ──► Account Key (AK) ──► OS Secure Enclave (DPAPI / Keychain / KeyStore)
      │
      └── verifier blob stored in vault_meta (no plaintext MK on disk)

Auto-lock timer → zeroize MK/AK from process memory
```

---

## Frame 4 — CI/CD Gates

```
PR / push → [1] SAST Secret+CodeQL+audit+clippy  → must PASS
         → [2] DAST ZAP baseline (vault_daemon)  → must PASS (PR to main)
         → [3] Playwright E2E + auto issue       → must PASS
         → merge to main only if all green
```

Workflows:
- `.github/workflows/sast-scan.yml`
- `.github/workflows/dast-scan.yml`
- `.github/workflows/e2e-playwright.yml`

---

## Frame 5 — Feature Status Matrix

| ID | Title | Phase | Status |
|----|-------|-------|--------|
| FEAT-001 | Argon2id KDF (product params) | 1 | Implementing |
| FEAT-002 | AES-256-GCM / XChaCha20-Poly1305 envelopes | 1 | Implementing |
| FEAT-003 | SQLCipher-compatible vault schema + CRUD | 1 | Implementing |
| FEAT-004 | Password generator + entropy scoring | 1 | Implementing |
| FEAT-005 | OS secure-key wrappers (DPAPI first) | 1 | Implementing |
| FEAT-006 | vault_daemon loopback health API | 1 | Implementing |
| FEAT-007 | CI SAST / DAST / Playwright gates | 1 | Implementing |
| FEAT-010 | Tauri v2 desktop shell | 2 | Planned |
| FEAT-020 | Flutter mobile + FFI | 2 | Planned |
| FEAT-030 | MV3 extension + autofill | 3 | Planned |
| FEAT-040 | cloudflared / ngrok + QR pairing | 4 | Planned |

---

## Frame 6 — Risk & Security Board

| Risk | Severity | Mitigation | Status |
|------|----------|------------|--------|
| MK retained in memory too long | High | Auto-lock + zeroize on drop | Designed |
| SQLCipher native link on Windows | Med | Field-level AEAD + schema-compatible DDL | Accepted interim |
| Tunnel exposure if bind misconfig | Critical | Hard-refuse non-loopback bind | Implemented |
| Extension XSS / injection | High | MV3 isolation + native messaging only | Phase 3 |
| Weak master password | Med | Entropy scoring + onboarding guidance | Partial (core) |

---

## Frame 7 — Phase Handover Tracking

| Phase | Handover file | Approved |
|-------|---------------|----------|
| 1 | `.handover/handover_phase_1.yaml` | Pending completion |
| 2–6 | TBD | — |

---

## Frame 8 — Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-08-04 | Use existing Miro board PasswordManager (`uXjVH1LjUrs=`) | User-designated single source of truth |
| 2026-08-04 | Field-level AES-GCM + SQLCipher schema (not linked SQLCipher C lib yet) | Portability on Windows MSVC CI; zero-knowledge preserved |
| 2026-08-04 | vault_daemon refuses non-loopback binds | Prevent accidental remote exposure |
| 2026-08-04 | Product Argon2id params in create path; tests accept real cost | Security parity with production |

---

## Frame 9 — Open Issues

- Miro MCP OAuth must be completed in Grok (`/mcps` → miro → press `i`) before live board updates.
- Rust MSVC build tools required on Windows for full native linking.
- Phase 2+ apps are directory placeholders only.
