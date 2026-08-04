# KeyVault CI/CD — primary development path

**Policy:** No change lands on `main` / `develop` without a green **CI** run.  
Local builds are for iteration only; **GitHub Actions is the source of truth**.

## Primary workflow

| Workflow | File | Role |
|----------|------|------|
| **CI** | `.github/workflows/ci.yml` | **Required merge gate** — calls all scanners + tests |
| SAST | `.github/workflows/sast-scan.yml` | Secrets, CodeQL, audit, deny, clippy, Semgrep, npm, Flutter |
| DAST | `.github/workflows/dast-scan.yml` | OWASP ZAP baseline (**fail_action: true**) + probes |
| Gates | `.github/workflows/phase5-gates.yml` | Tests, footprint &lt; 15 MB, smoke-phase4 |
| E2E | `.github/workflows/e2e-playwright.yml` | Extension Playwright |
| vault-ffi | `.github/workflows/vault-ffi.yml` | Host + Android jniLibs |

Branch protection must require:

```text
CI / required-gate
```

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

- **Push** to `main`, `develop`
- **Pull request** into `main`, `develop`
- **Schedule:** SAST weekly Mon 06:00 UTC; DAST weekly Mon 07:00 UTC
- **workflow_dispatch** on all security workflows

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

# 3. Open PR → wait for CI / required-gate
# 4. Merge only when required-gate is green
```

Do **not** treat a green local build as merge-ready without CI.

## Required status check setup

After the first green run on `main`:

```bash
gh api -X PUT repos/OWNER/REPO/branches/main/protection \
  --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["CI / required-gate"]
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
