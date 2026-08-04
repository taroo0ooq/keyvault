---
name: Bug Report
about: Structured bug report for KeyVault (used by humans and CI automation)
title: "[BUG] "
labels: ["bug"]
---

## Summary

<!-- One-sentence description of the failure. -->

## Environment

| Field | Value |
| --- | --- |
| Workflow | `{{WORKFLOW}}` |
| Run ID | `{{RUN_ID}}` |
| Run URL | {{RUN_URL}} |
| Commit SHA | `{{COMMIT_SHA}}` |
| Branch | `{{BRANCH}}` |
| Actor | `{{ACTOR}}` |
| OS / Browser | <!-- e.g. Ubuntu + Chromium --> |

## Steps to Reproduce

1.
2.
3.

## Expected Behavior

<!-- What should have happened -->

## Actual Behavior

<!-- What actually happened (include logs / screenshots) -->

## Logs / Artifacts

<!-- Link to Playwright report, ZAP report, cargo test output, etc. -->

## Impact & Severity

- [ ] Security / crypto
- [ ] Data loss
- [ ] Crash / hang
- [ ] Functional regression
- [ ] Cosmetic

**Severity:** Critical / High / Medium / Low

## Next Steps (for assignee)

1. Confirm reproduction on the commit SHA above.
2. Identify root cause (core / UI / extension / tunnel / CI flake).
3. Add or extend a regression test before fix merge.
4. Ensure SAST / DAST / E2E gates are green on the fix PR.
5. Update Miro board **PasswordManager** decision log if architecture changes.

## Related

- Miro board: https://miro.com/app/board/uXjVH1LjUrs=/
- Phase handover: `.handover/`
