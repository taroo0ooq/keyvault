# KeyVault dependency matrix

Four linked matrices: **component graph**, **library deps**, **feature → stack**, and **external services**. Read “depends on” as runtime/build edges, not optional docs.

---

## 1. Component dependency graph

```
                    ┌─────────────────┐
                    │   vault-core    │
                    │  (crypto + DB)  │
                    └────────┬────────┘
           ┌─────────────────┼─────────────────┐
           ▼                 ▼                 ▼
    ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐
    │ vault-daemon│  │  vault-ffi   │  │ keyvault-desktop │
    │ (HTTP API)  │  │  (C ABI)     │  │ (Tauri + core)   │
    └──────┬──────┘  └──────┬───────┘  └──────────────────┘
           │                │
           │         ┌──────▼──────┐
           │         │ Flutter app │
           │         │ dart:ffi    │
           │         └─────────────┘
           │
     ┌─────┴──────────────────────────┐
     ▼                                ▼
┌──────────────────┐          ┌─────────────────┐
│ vault-native-host│          │ cloudflared/ngrok│
│ (NM stdio proxy) │          │ (external bins) │
└────────┬─────────┘          └─────────────────┘
         ▼
┌─────────────────┐
│ MV3 extension   │──── also ──► vault_daemon (loopback HTTP)
└─────────────────┘
```

### Component → depends on (product layer)

| Component | Depends on | Coupling |
|-----------|------------|----------|
| **vault-core** | Crypto crates, rusqlite, OS crypto APIs | Base (no app deps) |
| **vault-daemon** | vault-core, tiny_http, ureq | Process; loopback only |
| **vault-ffi** | vault-core, serde_json, parking_lot | Shared lib for mobile |
| **vault-native-host** | ureq → **vault_daemon** HTTP | No vault-core link |
| **keyvault-desktop** | vault-core (in-process), Tauri, Vite UI | Direct core embed |
| **Flutter mobile** | vault-ffi (native), local_auth, Flutter SDK | FFI load of `.dll`/`.so` |
| **MV3 extension** | vault_daemon (HTTP) **or** native-host | Out-of-process |
| **cloudflared / ngrok** | vault_daemon port (spawned by core/daemon) | External binaries on PATH |
| **HIBP API** | vault_daemon (opt-in network) | Only `/v1/health/pwned` |

---

## 2. Library / framework matrix

| Consumer | Dependency | Kind | Used for |
|----------|------------|------|----------|
| **vault-core** | argon2 | lib | Argon2id KDF |
| | aes-gcm | lib | AES-256-GCM |
| | chacha20poly1305 | lib | XChaCha20-Poly1305 |
| | rusqlite (bundled) | lib | Local vault DB |
| | zeroize | lib | Wipe keys |
| | sha1 / sha2 / hmac | lib | TOTP, HIBP prefix, pairing |
| | base64, subtle, getrandom, rand | lib | Encoding, crypto helpers |
| | serde / serde_json / uuid / chrono | lib | Data models |
| | tracing / thiserror | lib | Logs / errors |
| | windows-sys (Win) | OS | DPAPI |
| | proptest, tempfile | test | Property / temp DB tests |
| **vault-daemon** | vault-core | crate | All vault ops |
| | tiny_http | lib | Loopback HTTP server |
| | ureq (tls) | lib | HIBP + tunnel helpers |
| | chrono, uuid, sha1, serde_json | lib | API payloads |
| **vault-ffi** | vault-core | crate | Exposed C ABI |
| | serde_json, parking_lot, once_cell | lib | JSON surface, locks |
| **vault-native-host** | ureq, serde_json | lib | Proxy to daemon |
| **desktop (Rust)** | vault-core, tauri 2.x | crate | Shell + crypto |
| | arboard, dirs, ureq | lib | Clipboard, paths, HTTP |
| **desktop (JS)** | @tauri-apps/api + plugins | npm | IPC |
| | vite 6 | build | Frontend bundler |
| **extension** | typescript, esbuild | build | MV3 bundle |
| | @playwright/test | test | E2E |
| **mobile** | flutter, ffi, path_provider | pkg | UI + native load |
| | local_auth | pkg | Biometric gate |
| | crypto (Dart) | pkg | Mock TOTP helpers |

**Interim vs planned**

| Planned dependency | Actual today | Impact |
|--------------------|--------------|--------|
| SQLCipher native | rusqlite + field AEAD | KI-001 |
| flutter_rust_bridge | dart:ffi + vault-ffi | Simpler bridge |
| mTLS client certs | Bearer + QR HMAC | Tunnel auth model |
| Appium / Flutter Driver | Not primary CI | Mobile E2E gap |

---

## 3. Module → feature matrix (vault-core)

| Module | Features | Phase |
|--------|----------|-------|
| `kdf` | Argon2id master key | 1 |
| `vault_crypto` | AEAD encrypt/decrypt | 1 |
| `vault_db` | Encrypted CRUD, schema v1–v3, trash | 1, 7, 13 |
| `password` | Generator + entropy (zxcvbn-style) | 1, 12 |
| `secure_key` | DPAPI / software enclave wrap | 1, 2, 9 |
| `pairing` | QR offer, HMAC, device API tokens | 4 |
| `tunnel` | cloudflared / ngrok process control | 4 |
| `totp` | RFC 6238 codes | 9–11 |
| `error` | Shared error types | 1 |

---

## 4. Feature → component dependency matrix

Legend: **P** = primary implementer · **C** = consumer · **T** = tests/CI · **—** = not involved

| FEAT | Title | Phase | core | daemon | ffi | desktop | mobile | ext | NM host | CI |
|------|-------|-------|:----:|:------:|:---:|:-------:|:------:|:---:|:-------:|:--:|
| 001–007 | Crypto, DB, password, enclave stubs | 1 | **P** | C | — | — | — | — | — | T |
| 010 | Tauri desktop vault UI | 2 | C | — | — | **P** | — | — | — | — |
| 020–022 | Flutter + vault_ffi + enclave CI | 2 | C | — | **P** | — | **P** | — | — | T |
| 030–032 | MV3 shell, reveal, autofill | 3 | — | C | — | — | — | **P** | — | T |
| 033 | Native messaging host | 3 | — | C | — | — | — | C | **P** | T |
| 040–044 | Tunnel, pairing, Bearer, Remote UI | 4 | **P** | **P** | — | C | — | C | — | T |
| 050–052 | SAST / DAST / Playwright gates | 5 | T | T | T | — | T | T | T | **P** |
| 060–064 | Footprint, compliance, packaging | 6 | T | T | T | T | — | — | T | **P** |
| 070 | Item update/delete API | 7 | C | **P** | — | C | — | — | — | T |
| 071 | Encrypted portable backup | 7 | **P** | **P** | — | C | — | — | — | T |
| 080 | Change master password | 8 | **P** | **P** | — | C | — | — | — | T |
| 081 | CSV import | 8 | **P** | **P** | — | C | — | — | — | T |
| 090 | TOTP 2FA | 9 | **P** | **P** | — | C | — | — | — | T |
| 091 | Clear enclave on pw change | 9 | **P** | C | — | C | — | — | — | T |
| 100–101 | FFI TOTP + Flutter TOTP UI | 10 | C | — | **P** | — | **P** | — | — | T |
| 110 | Pure-Dart TOTP (mock) | 11 | — | — | — | — | **P** | — | — | T |
| 111 | Extension Copy TOTP | 11 | — | C | — | — | — | **P** | C | T |
| 120 | CSV export | 12 | **P** | **P** | — | C | — | — | — | T |
| 121 | Offline password health | 12 | **P** | **P** | — | C | — | — | — | T |
| 130 | Soft-delete trash | 13 | **P** | **P** | — | C | — | — | — | T |
| 131 | HIBP k-anonymity | 13 | C | **P** | — | C | — | — | — | — |

---

## 5. External service dependency matrix

| Service | Called by | Trigger | Required for core vault? | Network / install |
|---------|-----------|---------|--------------------------|-------------------|
| **cloudflared** | vault-core `tunnel` / daemon | User starts tunnel | No (loopback works alone) | Binary on PATH |
| **ngrok** | same | User selects provider | No | Binary on PATH |
| **api.pwnedpasswords.com** | vault-daemon | `POST /v1/health/pwned` | No (opt-in) | HTTPS out |
| **Miro** | Agent / MCP (dev process) | Phase/docs updates | No (product runtime) | MCP quota-limited |
| **GitHub Actions** | CI | push/PR | No | Cloud CI |
| **TruffleHog / CodeQL / ZAP** | GH workflows | SAST/DAST | No (dev/gate) | CI images |
| **Playwright Chromium** | extension CI + local | E2E | No | Dev/CI |
| **Android NDK** | vault-ffi.yml | Android `.so` build | No (host ffi works) | CI / local NDK |

---

## 6. CI tool → target matrix

| Tool | Workflow | Targets |
|------|----------|---------|
| TruffleHog | sast-scan | Full repo history |
| CodeQL | sast-scan | vault-core, daemon, ffi (+ JS/TS) |
| cargo-audit | sast-scan | Cargo.lock deps |
| clippy + cargo test | sast / phase5-gates | core, daemon, ffi, native-host |
| Flutter analyzer | sast-scan | apps/mobile |
| OWASP ZAP baseline | dast-scan | vault_daemon `:8080` |
| Playwright | e2e + phase5-gates | apps/extension |
| measure-footprint | phase5-gates | release binaries &lt; 15 MB |
| smoke-phase4 | phase5-gates | pairing + Bearer |
| cargo-ndk + NDK | vault-ffi | Android ABIs → jniLibs |

---

## 7. Runtime data-path matrix (who talks to whom)

| From → To | Protocol | Auth | Secrets exposure |
|-----------|----------|------|------------------|
| Desktop UI → vault-core | Tauri IPC / in-process | Master pw / enclave | Keys stay in core |
| Mobile UI → vault-ffi | dart:ffi | Master pw / biometric+enclave | Keys in native lib |
| Extension → daemon | HTTP `127.0.0.1` | None on loopback*; Bearer if tunnel | List redacted; `/v1/reveal` TTL |
| Extension → native-host → daemon | Native Messaging + HTTP | same | same |
| Remote client → public URL → daemon | Tunnel + HTTP | Bearer (pairing token) | same as reveal policy |
| Daemon → HIBP | HTTPS GET range | N/A | SHA-1 **prefix only** |
| Daemon/core → cloudflared/ngrok | subprocess stdout scrape | Provider-specific | Public URL only |

\*Local loopback is trusted-device boundary; remote requires Bearer when tunnel active.

---

## 8. Phase → dependency stack (rollup)

| Phase | Stack that must exist | New deps introduced |
|-------|----------------------|---------------------|
| **1** | Rust + vault-core crypto/DB | argon2, AEAD, rusqlite, zeroize |
| **2** | + Tauri/Vite + Flutter + vault-ffi | tauri, vite, flutter, ffi, local_auth, NDK CI |
| **3** | + MV3 extension + native-host | esbuild, TS, Playwright, ureq host |
| **4** | + tunnel agent + pairing | cloudflared/ngrok binaries, Bearer |
| **5–6** | + full CI gates + footprint | TruffleHog, CodeQL, ZAP, measure scripts |
| **7–8** | + CRUD/backup/CSV/change-pw | (mostly core/daemon APIs) |
| **9–11** | + TOTP across surfaces | hmac/sha1 already in core |
| **12–13** | + health + trash + HIBP | ureq → pwnedpasswords.com |

---

## 9. Critical path (hard dependencies)

These edges are **required** for a working product slice:

1. **Any secure vault op** → `vault-core`
2. **Desktop unlock/CRUD** → `vault-core` (not daemon)
3. **Mobile real vault** → `vault-ffi` → `vault-core` (+ platform lib load)
4. **Extension autofill/reveal** → `vault_daemon` → `vault-core` (or NM host → daemon)
5. **Remote access** → tunnel binary **and** Bearer pairing **and** daemon
6. **CI merge gates** → sast + dast + e2e + phase5-gates (policy)

Soft / optional edges: HIBP, Miro MCP, App Store packaging, full SQLCipher, mTLS.

---

## How to use this matrix

| Question | Use section |
|----------|-------------|
| What breaks if I remove X? | §1, §9 |
| What crate owns a feature? | §4 |
| What libs are in the binary? | §2 |
| What needs network? | §5, §7 |
| What CI owns which surface? | §6 |

## Related docs

- [passwordmanager.md](./passwordmanager.md) — product prompt & phase plan
- [COMPLIANCE.md](./COMPLIANCE.md) — architectural constraints
- [PACKAGING.md](./PACKAGING.md) — ship artifacts
- [RELEASE_NOTES.md](./RELEASE_NOTES.md) — feature summary
- [miro-board-seed.md](./miro-board-seed.md) — visual journey seed
- [../README.md](../README.md) — workspace overview
