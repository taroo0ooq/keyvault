# KeyVault CI/CD — primary development path

**Policy (hard gate — non-negotiable):**

1. No change lands on `main` / `develop` without a green **CI** run (`required-gate`).
2. **SAST + DAST + Playwright + product gates + vault-ffi** are hardwired and fail-closed.
3. **Do not start the next product phase** while:
   - any open PR for the current phase has a red `required-gate`, or
   - any **open** GitHub Issue labeled `automated` (DAST / E2E / SAST) remains unfixed.
4. Local builds are for iteration only; **GitHub Actions is the source of truth**.

See [Phase gate checklist](#phase-gate-checklist) below.

## Primary workflow

| Workflow | File | Role |
|----------|------|------|
| **CI** | `.github/workflows/ci.yml` | **Required merge gate** — calls all scanners + tests |
| SAST | `.github/workflows/sast-scan.yml` | Secrets, CodeQL, audit, deny, clippy, Semgrep, npm, Flutter |
| DAST | `.github/workflows/dast-scan.yml` | OWASP ZAP baseline (**fail_action: true**) + probes |
| Gates | `.github/workflows/phase5-gates.yml` | Tests, footprint &lt; 15 MB, smoke-phase4 |
| E2E | `.github/workflows/e2e-playwright.yml` | Extension Playwright |
| vault-ffi | `.github/workflows/vault-ffi.yml` | Host + Android jniLibs |
| **SQLCipher** (optional) | `.github/workflows/sqlcipher.yml` | Ubuntu `--features sqlcipher` tests + daemon smoke — **not** required-gate |

Branch protection must require:

```text
required-gate
```

(GitHub reports the nested CI job as `required-gate`.)

## Hardwired scanners (SAST)

| Tool | Job | Fail closed? |
|------|-----|--------------|
| TruffleHog (verified) | `secret-trufflehog` | Yes (`--fail`) |
| Gitleaks | `secret-gitleaks` | Yes |
| CodeQL (Rust + JS/TS, security-extended + quality) | `codeql` | Yes |
| cargo-audit (`--deny warnings`) | `rust-audit` | Yes |
| cargo-deny (licenses / bans / sources) | `rust-deny` | Yes (`deny.toml`) |
| clippy `-D warnings` | `rust-clippy-test` | Yes |
| Semgrep (`p/ci`, `p/security-audit`, `p/secrets`, `p/rust`) | `semgrep` | Yes (`--error`) |
| npm audit (`--audit-level=high`) | extension + desktop | Yes |
| Flutter analyze + test | `flutter-analyzer` | Yes |

## Hardwired scanners (DAST)

| Tool | Job | Fail closed? |
|------|-----|--------------|
| Curl probes (health, auth, reveal denial) | pre-ZAP step | Yes |
| OWASP ZAP baseline | `zap-baseline` | Yes (`fail_action: true`) |
| Auto GitHub Issue on failure | post step | Best-effort |

ZAP noise rules: `.github/zap-rules.tsv` (document any OUTOFSCOPE entry).

## Triggers

| Event | What runs |
|-------|-----------|
| **Push / PR** to `main`, `develop` | **CI only** (`.github/workflows/ci.yml`) — single primary path |
| **Schedule** | SAST Mon 06:00 UTC; DAST Mon 07:00 UTC; SQLCipher Mon 08:00 UTC (standalone) |
| **workflow_dispatch** | Any modular workflow (SAST/DAST/Gates/E2E/FFI/SQLCipher) for focused re-runs |
| **Path-filtered PR/push** | `sqlcipher.yml` when `vault-core` / SQLCipher docs change |

Modular workflows (`sast-scan`, `dast-scan`, `phase5-gates`, `e2e-playwright`, `vault-ffi`) are **not** auto-triggered on push/PR by themselves — they are **`workflow_call`ed by CI** so the Actions queue is not flooded. SQLCipher is a separate optional workflow (see [SQLCIPHER.md](./SQLCIPHER.md)).

## Dependabot

`.github/dependabot.yml` — weekly updates for Cargo, npm (desktop + extension), pub (mobile), GitHub Actions.

## Developer workflow

```bash
# 1. Feature branch
git checkout -b feat/my-change

# 2. Iterate locally (optional fast loop)
cargo test -p vault-core -p vault-daemon -p vault-ffi
cd apps/extension && npm test
cd apps/mobile && flutter test

# 3. Open PR → wait for required-gate
# 4. Merge only when required-gate is green
```

Do **not** treat a green local build as merge-ready without CI.

## Phase gate checklist

Before declaring a phase complete or starting the next phase:

```bash
# 1. Primary CI on the phase PR must be green
gh pr checks <PR>   # required-gate must be success

# 2. No open automated CI bug issues
gh issue list --state open --label automated

# 3. Main still green after merge
gh run list --branch main --workflow CI --limit 1
```

| Gate | Must be |
|------|---------|
| `CI / required-gate` | success |
| SAST (all scanners) | success |
| DAST (ZAP + probes) | success |
| E2E Playwright | success |
| Product gates | success |
| vault-ffi | success |
| Open `automated` issues | **zero** (close only after fix + re-green CI) |

Optional SQLCipher canary (`.github/workflows/sqlcipher.yml`) is **not** part of `required-gate` but should be green when vault-core storage changes.

## Required status check setup

After the first green run on `main`:

```bash
gh api -X PUT repos/OWNER/REPO/branches/main/protection \
  --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["required-gate"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 0
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
```

(Adjust review count as the team grows.)

## Related

- [COMPLIANCE.md](./COMPLIANCE.md)
- [DEPENDENCY_MATRIX.md](./DEPENDENCY_MATRIX.md)
- [PACKAGING.md](./PACKAGING.md)
- [passwordmanager.md](./passwordmanager.md)
