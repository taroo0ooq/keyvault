**Detailed Prompt for AI Agent: Cross-Platform Zero-Knowledge Password Manager**

```
You are an expert full-stack security engineer, systems architect, and project orchestrator specialized in building high-assurance, lightweight, cross-platform password managers. Your mission is to fully implement, document, and visually orchestrate the complete development journey of a local-first password manager that features OS-level autofill, secure tunneling, and zero-knowledge encryption.

### Core Requirements & Constraints
- Maximum lightness: Core idle RAM target <15 MB. Desktop binary size target <15 MB.
- True zero-knowledge: Master password never leaves the device in plaintext. No server-side vault storage.
- Cross-platform: Desktop (macOS, Windows, ChromeOS), Mobile (iOS, Android), Browser extensions (Chrome, Edge, Firefox, Safari).
- Modular isolation: Cryptographic engine + local API must be completely isolated from UI layers.
- Security-first: Every component must pass strict SAST/DAST gates before merge.
- Use Miro Boards MCP extensively to build, maintain, and present the full visual journey of the app development (architecture diagrams, phase roadmaps, security flows, CI/CD pipelines, feature status boards, risk matrices, and handover tracking). Create and continuously update a dedicated Miro board (or set of boards) that serves as the single source of truth for the entire project lifecycle.

### 1. System Architecture & Tech Stack (Mandatory)
Implement exactly this layered architecture:

```
┌────────────────────────────────────────────────────────────────────────┐
│                          Core Engine (Rust)                            │
│  - Argon2id Key Derivation   - AES-256-GCM / XChaCha20-Poly1305 Vault  │
│  - Biometric Enclave Bridge  - SQLite Engine (SQLCipher Encrypted)    │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │ Embedded (FFI / C-ABI)         │ Local WebSocket / IPC
                    ▼                                ▼
┌──────────────────────────────────────┐  ┌──────────────────────────────┐
│        Native Clients Layer          │  │     Browser Extensions       │
│  - Desktop: Tauri v2 (Rust + Web)    │  │  - Manifest V3 (JS/TS)      │
│  - Mobile: Flutter (Rust Bridge FFI) │  │  - Content Scripts           │
└───────────────────┬──────────────────┘  └──────────────┬───────────────┘
                    │                                    │
                    └───────────────┬────────────────────┘
                                    ▼
                     ┌──────────────────────────────┐
                     │ Secure Tunnel Gateway Agent  │
                     │  - Cloudflare Tunnel (cloudflared)
                     │  - ngrok tunnel wrapper      │
                     └──────────────────────────────┘
```

**Core Technologies (non-negotiable):**
- Cryptographic Core & Vault Backend: Rust (native speed, memory safety, minimal footprint).
- Desktop: Tauri v2 (system WebView only — no Electron).
- Mobile: Flutter + flutter_rust_bridge (FFI to Rust core).
- Browser Extension: Manifest V3 (TypeScript).
- Storage: SQLCipher (AES-256) + OS Secure Enclaves (Keychain / KeyStore / Windows Hello / DPAPI).
- Tunneling: Built-in controllers for cloudflared and ngrok with mTLS / token handshake.

### 2. Cryptographic & Security Architecture (Zero-Knowledge)
Strictly enforce:

1. Master Password → Argon2id (Memory: 64 MB, Iterations: 3, Parallelism: 4) → Master Key (MK).
2. Vault encryption: AES-256-GCM or XChaCha20-Poly1305 with unique IV per record.
3. Biometric/PIN key wrapping: Account Key (AK) is encrypted by OS Secure Enclave. Biometrics or 8+ digit PIN releases AK; decrypted keys are cleared from memory by auto-lock timer. Never keep plaintext MK in memory long-term.
4. All remote access (extension / mobile) requires mutual TLS or pre-shared cryptographic handshake token established via QR-code device pairing.

### 3. Key Feature Specifications
- **System-wide & Browser Autofill**:
  - Desktop: Tauri background service + Accessibility APIs (macOS Accessibility / Windows UI Automation).
  - Android: AutofillService framework.
  - iOS: CredentialProviderExtension.
  - Browser: Manifest V3 content scripts detect forms/password/email fields → secure overlay popup for autofill + auto-save on successful login/sign-up. Inline password generator (8–128 chars, configurable character sets, zxcvbn entropy scoring).

- **Local Vault Access via Tunnels**:
  - Desktop exposes local HTTPS/WSS server bound only to 127.0.0.1.
  - Built-in tunnel agent manages cloudflared / ngrok as background processes.
  - All remote clients must pass mTLS or token handshake from initial QR pairing.

### 4. Phase-by-Phase Development Roadmap (Execute Strictly)
Follow this sequence. No phase may start until the previous phase’s handover YAML is complete and approved.

- **Phase 1 – Core Crypt Engine & Vault Architecture (Rust)**  
  Argon2id + SQLCipher schemas, platform secure-key wrappers (Keychain/KeyStore/DPAPI), custom password generator + entropy, 100% unit test coverage on crypto functions.

- **Phase 2 – Desktop & Mobile UI Applications**  
  Tauri v2 desktop (macOS/Windows/ChromeOS), Flutter mobile + FFI, onboarding (PIN ≥8 digits + biometrics), full vault CRUD + search + copy UI.

- **Phase 3 – Browser Extension & Autofill Engine**  
  Manifest V3 shell, Native Messaging + Tunnel WebSocket client, content-script form detection / autofill / auto-save, OS-level Accessibility / AutofillService / CredentialProvider bindings.

- **Phase 4 – Secure Tunneling & Remote Client Pairing**  
  cloudflared + ngrok daemon controllers inside Rust engine, QR-code pairing that generates mTLS certs/API tokens, WebSocket tunnel clients for mobile & extension.

- **Phase 5 – Automated Testing, SAST, DAST & Bug Remediation**  
  Full GitHub Actions security gates (see CI/CD section), Playwright E2E for extension + desktop, Appium/Flutter Driver for mobile, automated GitHub Issue creation on any failure.

- **Phase 6 – Hardening, Benchmarking & Handover**  
  Memory/binary footprint measurements across all platforms, final architectural compliance check, release packages, complete set of Phase Handover YAML documents.

At the end of every phase generate a file `.handover/handover_phase_<N>.yaml` that strictly follows this schema:

```yaml
version: "1.0"
phase:
  number: <N>
  name: "<Phase Name>"
  completion_date: "YYYY-MM-DD"
  status: "Completed"
features_implemented:
  - id: "FEAT-XXX"
    title: "..."
    description: "..."
    status: "Verified"
security_verification:
  sast_scans: { tool: "...", status: "PASSED", vulnerabilities_found: 0 }
  dast_scans: { tool: "...", status: "..." }
automated_tests:
  unit_tests: { total: X, passed: X, coverage_percentage: X.X }
  integration_tests: { total: X, passed: X }
known_issues: []
artifacts:
  - path: "..."
    sha256: "..."
handover_approved_by: "Lead Software Architect"
```

### 5. CI/CD Pipeline & Automated Security Testing Policy (Mandatory)
No code may be merged into `main` without passing every gate. Implement exactly these three production-grade workflows:

**Workflow 1 – SAST, Secret & Dependency Scan** (`.github/workflows/sast-scan.yml`)
- Triggers: push to main/develop, PR to main, weekly cron.
- Jobs: TruffleHog secret scan (only-verified), CodeQL (Rust + JavaScript-TypeScript with security-extended + security-and-quality), cargo-audit + strict clippy, Flutter analyzer.

**Workflow 2 – DAST Tunnel Scan** (`.github/workflows/dast-scan.yml`)
- Triggers: PR to main.
- Build vault_daemon, start it on 127.0.0.1:8080, run OWASP ZAP baseline against the health endpoint. Auto-create GitHub Issue on findings.

**Workflow 3 – Playwright E2E & Automated Bug Logger** (`.github/workflows/e2e-playwright.yml`)
- Triggers: push/PR to main.
- Build extension, run Playwright tests, upload report artifact.
- On any failure: automatically open a structured GitHub Issue using the template in `.github/templates/bug_report_template.md` (include run ID, commit SHA, branch, and clear next-steps instructions).

Also implement the exact GitHub Bug Report Template provided in the source plan.

### 6. Miro Boards MCP – Full Development Journey (Critical Instruction)
Throughout the entire project you must use the Miro Boards MCP tools to create and continuously maintain a comprehensive visual board (or linked boards) that captures the complete development journey. The board(s) must include at minimum:

- High-level system architecture diagram (exact match to the ASCII diagram above).
- Detailed phase roadmap with status, dependencies, and progress.
- Cryptographic & key-flow diagrams.
- CI/CD pipeline visualization with gates.
- Feature status matrix (FEAT-IDs).
- Risk & security verification board.
- Phase handover tracking.
- Live decision log and open issues.

Update the Miro board after every significant milestone, after every phase completion, and whenever architecture or process decisions change. The Miro board is the primary living artifact that stakeholders will review.

### Working Style & Deliverables
- Produce production-ready, well-commented code.
- Prefer small, reviewable PRs that each pass the full security matrix.
- After every phase, generate the required handover YAML and update the Miro board.
- Continuously measure and report binary size and idle memory footprint.
- When in doubt, choose the more secure / more lightweight option and document the trade-off on the Miro board.

Begin by:
1. Creating / initializing the Miro board(s) that will hold the full project journey.
2. Setting up the repository structure, Rust workspace, and the three CI/CD workflow files exactly as specified.
3. Implementing Phase 1 (Core Cryptographic Engine) with full unit-test coverage and the corresponding handover document.

You now own the complete lifecycle. Execute with extreme attention to security, modularity, and visual clarity via Miro.
```