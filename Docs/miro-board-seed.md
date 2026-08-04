# Miro board seed — PasswordManager

**Board:** [PasswordManager](https://miro.com/app/board/uXjVH1LjUrs=/)  
**Board ID:** `uXjVH1LjUrs=`

Offline seed / mirror for the living Miro journey board.  
**Last intended sync:** 2026-08-05 — Phase 1–6 + native host + CI footprint.  
**Live apply status:** **BLOCKED** — Miro MCP Free plan daily limit (100 tool calls) exhausted. Both `miro` and `miro_board` servers reject all board API calls until the quota resets (typically next calendar day UTC) or the Miro org plan is upgraded.

### Re-apply when Miro is available

Ask again: *“Resync the PasswordManager Miro board from docs/miro-board-seed.md”*

Apply order for the agent (once MCP works):

1. `context_explore` board → list frames  
2. Per frame: `layout_read` / `context_get`  
3. Update or create stickies/tables to match Frames 1–9 + Footprint + Compliance below  
4. Confirm roadmap statuses (Phase 1 Complete; 2–6 Near complete) and FEAT-033 / FEAT-064

---

## Frame 1 — System Architecture

1. **Core Engine (Rust)** — Argon2id · AES-GCM/XChaCha · Enclave · vault schema  
2. **Native Clients** — Tauri v2 · Flutter + vault_ffi  
3. **Browser Extensions** — MV3 + daemon reveal autofill  
4. **Secure Tunnel Gateway** — cloudflared / ngrok → 127.0.0.1 only  

Constraints: Idle RAM &lt; 15 MB · Desktop binary &lt; 15 MB · No off-device master password · No server vault · Loopback daemon

---

## Frame 2 — Phase Roadmap

| Phase | Name | Status | Depends on |
|-------|------|--------|------------|
| 1 | Core Crypt Engine & Vault Architecture | **Complete** | — |
| 2 | Desktop & Mobile UI | **Near complete** | Phase 1 done |
| 3 | Browser Extension & Autofill | **Near complete** | MV3 + reveal live |
| 4 | Secure Tunneling & Pairing | **Near complete** | Tunnel + Bearer + Remote UI |
| 5 | Automated Testing, SAST, DAST | **Near complete** | phase5-gates.yml |
| 6 | Hardening, Benchmarking & Handover | **Near complete** | Footprint + compliance + notes |
| 7 | CRUD API & portable backup | **Complete (eng.)** | Phase 6 near-complete |
| 8 | Change password & CSV import | **Complete (eng.)** | Phase 7 |
| 9 | TOTP + enclave clear | **Complete (eng.)** | Phase 8 |
| 10 | Mobile TOTP (vault_ffi) | **Complete (eng.)** | Phase 9 |
| 11 | Dart mock TOTP + extension TOTP | **Complete (eng.)** | Phase 10 |
| 12 | CSV export + password health | **Complete (eng.)** | Phase 11 |
| 13 | Trash + HIBP k-anonymity | **Complete (eng.)** | Phase 12 |

Approvals: Phase 1 approved; Phases 2–13 pending stakeholder sign-off.

---

## Frame 3 — Cryptographic Key Flow

Master Password → Argon2id → MK → AEAD vault · enclave sidecar · auto-lock zeroize  
Extension: redacted list · `/v1/reveal` TTL  
Remote: Bearer when tunnel on · QR HMAC pairing

---

## Frame 4 — CI/CD Gates

- sast-scan · dast-scan · e2e-playwright · vault-ffi · **phase5-gates**  
- smoke-phase4 · measure-footprint  

---

## Frame 5 — Feature Status Matrix

| ID | Title | Phase | Status |
|----|-------|-------|--------|
| FEAT-001–007 | Phase 1 core | 1 | **Done** |
| FEAT-010 | Tauri desktop | 2 | **Done** |
| FEAT-020 | Flutter + vault_ffi | 2 | Implementing |
| FEAT-021–022 | Enclave / ffi CI | 2 | Done / Implementing |
| FEAT-030–032 | MV3 + reveal autofill | 3 | **Done** |
| FEAT-033 | Native messaging host + fallback | 3 | **Done** |
| FEAT-040–044 | Tunnel, pairing, Bearer, scrape, Remote UI | 4 | **Done** |
| FEAT-050–052 | Phase 5 CI gates | 5 | **Done** |
| FEAT-060 | Footprint measurement scripts | 6 | **Done** |
| FEAT-061 | Draft release notes | 6 | **Done** |
| FEAT-062 | Compliance checklist | 6 | **Done** |
| FEAT-063 | Handover YAML set 1–6 | 6 | **Done** |
| FEAT-064 | CI footprint gate | 6 | **Done** |
| FEAT-070 | Daemon item update/delete | 7 | **Done** |
| FEAT-071 | Encrypted portable backup (core/daemon/desktop) | 7 | **Done** |
| FEAT-080 | Change master password | 8 | **Done** |
| FEAT-081 | CSV import | 8 | **Done** |
| FEAT-090 | TOTP 2FA codes | 9 | **Done** |
| FEAT-091 | Clear enclave on password change | 9 | **Done** |
| FEAT-100 | vault-ffi TOTP API | 10 | **Done** |
| FEAT-101 | Flutter mobile TOTP UI | 10 | **Done** |
| FEAT-110 | Pure-Dart TOTP (mock) | 11 | **Done** |
| FEAT-111 | Extension TOTP copy | 11 | **Done** |
| FEAT-120 | CSV export | 12 | **Done** |
| FEAT-121 | Offline password health | 12 | **Done** |
| FEAT-130 | Soft-delete trash | 13 | **Done** |
| FEAT-131 | HIBP k-anonymity check | 13 | **Done** |

---

## Frame 6 — Risk & Security Board

| Risk | Severity | Status |
|------|----------|--------|
| MK in memory too long | High | Implemented (auto-lock) |
| SQLCipher native | Med | Accepted interim |
| Non-loopback bind | Critical | Implemented |
| Tunnel without auth | Critical | Implemented (Bearer) |
| Content-script secrets | High | Implemented (reveal TTL) |
| Android ffi missing | Med | Designed (CI artifacts) |
| Miro sync lag | Low | **Active** — MCP daily limit; seed is SoT until resync |

---

## Frame 7 — Phase Handover Tracking

| Phase | File | Approved |
|-------|------|----------|
| 1 | handover_phase_1.yaml | **Approved** |
| 2–5 | handover_phase_N.yaml | Pending |
| 6 | handover_phase_6.yaml | Pending (engineering ready) |

---

## Frame 8 — Decision Log (latest)

- Phase 5: phase5-gates; exclude Tauri from Linux cargo test  
- Phase 4: external tunnel only; Bearer; URL scrape; Desktop Remote  
- Phase 6: measure-footprint (Win+Unix JSON); COMPLIANCE.md; PACKAGING.md; RELEASE_NOTES with measured sizes  
- Post-Phase-6: vault_native_host + extension fallback (KI-031); phase5-gates footprint gate  
- FEAT-070/071: daemon CRUD (`/v1/items/update|delete`) + encrypted backup export/import  
- FEAT-080/081: change master password + CSV import  
- FEAT-090/091: TOTP (RFC 6238) + clear enclave sidecar on password change  
- FEAT-100/101: vault_ffi `kv_vault_totp_json` + Flutter mobile TOTP UI  
- FEAT-110/111: pure-Dart TotpDart mock + extension Copy TOTP  
- FEAT-120/121: CSV export + offline password health (weak/reused)  
- FEAT-130/131: soft-delete trash + HIBP k-anonymity  


---

## Frame 9 — Status & Open Issues

**Done:** Phases 1 core; 2 desktop; 3 autofill; 4 tunnel/auth/UI; 5 CI gates; 6 footprint + compliance + packaging notes  

**Measured (Windows release):**  
- vault_daemon ~1.60 MB  
- vault_ffi.dll ~2.26 MB  
- keyvault-desktop ~3.83 MB (**&lt; 15 MB**)  
- daemon idle WorkingSet ~5.98 MB (**&lt; 15 MB**, daemon only)

**Open:**  
- KI-001 SQLCipher native  
- KI-010 Android .so not in git  
- KI-031 Native messaging (mitigated — host + install scripts)  

- Multi-platform footprint matrix  
- Full UI idle RAM automation  
- Handover approvals 2–6  
- Live Miro resync (**blocked — Free MCP 100/day limit**)  
- Next: re-run resync after quota reset; stakeholder sign-off / formal 0.1.0 tag  

---

## Footprint table (for board table widget)

| Artifact | Size (MB) | Limit | Status |
|----------|-----------|-------|--------|
| vault_daemon.exe | ~1.60 | 15 | OK |
| vault_ffi.dll | ~2.26 | 15 | OK |
| vault_native_host.exe | ~0.58 | 15 | OK |
| keyvault-desktop.exe | ~3.83 | 15 | OK |
| Daemon idle WorkingSet | ~5.99 | 15 | OK |

## Compliance summary (for board sticky)

C-02..C-10 PASS · C-01 Partial (daemon OK, UI idle TBD) · See docs/COMPLIANCE.md
