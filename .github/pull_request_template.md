## Summary

<!-- What does this PR change and why? -->

## Type of change

- [ ] Feature
- [ ] Bug fix
- [ ] Security hardening
- [ ] CI / tooling
- [ ] Docs only

## CI/CD gate checklist (required)

Primary path is **CI** (`.github/workflows/ci.yml`). Merge only when green:

- [ ] **SAST** — TruffleHog, Gitleaks, CodeQL, cargo-audit, cargo-deny, clippy, npm audit, Flutter analyze
- [ ] **DAST** — OWASP ZAP baseline + loopback probes (`fail_action: true`)
- [ ] **Gates** — unit/integration tests, footprint &lt; 15 MB, smoke-phase4
- [ ] **E2E** — Playwright (extension)
- [ ] **vault-ffi** — host + Android jniLibs (when core/ffi touched)

## Security notes

- [ ] No secrets, vault DBs, or private keys committed
- [ ] Crypto stays in `vault-core` / daemon / ffi (no reimplementation in JS/Dart)
- [ ] Daemon remains loopback-only for binds

## Test plan

1.
2.

## Related

- Issue:
- Phase / FEAT:
