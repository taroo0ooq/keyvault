#!/usr/bin/env python3
"""Fail when a cargo-audit ignore in .cargo/audit.toml is past its expiry.

cargo-audit ignore entries are bare advisory ids and have no expiry field.
Each ignored id must be preceded by a comment line `expires: YYYY-MM-DD`.
The cargo-audit SAST job runs this script, so an ignore cannot outlive the
date written next to it. The last valid day is the expires date; the next day
fails the job.
"""

from __future__ import annotations

import re
import sys
import tomllib
from datetime import date
from pathlib import Path

EXPIRES_RE = re.compile(r"expires:\s*(\d{4}-\d{2}-\d{2})\b")
IGNORE_RE = re.compile(r'"([^"]+)"')
DEFAULT_PATH = Path(".cargo/audit.toml")


def check_ignores(text: str, today: date) -> list[str]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return [f".cargo/audit.toml is not valid TOML: {exc}"]

    advisories = data.get("advisories", {})
    if not isinstance(advisories, dict):
        return ["advisories must be a table"]
    ignores = advisories.get("ignore", [])
    if not isinstance(ignores, list) or not all(isinstance(item, str) for item in ignores):
        return ["advisories.ignore must be a list of advisory ids"]

    expiries: dict[str, date] = {}
    pending: date | None = None
    errors: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            match = EXPIRES_RE.search(stripped)
            if match:
                pending = date.fromisoformat(match.group(1))
            continue
        match = IGNORE_RE.search(stripped)
        if not match:
            continue
        advisory_id = match.group(1)
        if pending is None:
            errors.append(f"{advisory_id} is ignored with no expires: YYYY-MM-DD comment")
            continue
        expiries[advisory_id] = pending
        pending = None

    if pending is not None:
        errors.append(f"expires comment {pending.isoformat()} is not attached to an ignore")

    for advisory_id in ignores:
        expiry = expiries.get(advisory_id)
        if expiry is None:
            if not any(advisory_id in error for error in errors):
                errors.append(f"{advisory_id} is ignored with no expires: YYYY-MM-DD comment")
            continue
        if today > expiry:
            errors.append(
                f"{advisory_id} ignore expired on {expiry.isoformat()}; "
                "remove it or move the crate to a patched release"
            )
    return errors


def _self_test() -> int:
    fresh = """
[advisories]
ignore = [
    # expires: 2027-02-18
    "RUSTSEC-2024-0429",
]
"""
    assert check_ignores(fresh, date(2027, 2, 18)) == []
    expired = check_ignores(fresh, date(2027, 2, 19))
    assert expired and "expired" in expired[0], expired

    missing = """
[advisories]
ignore = [
    "RUSTSEC-2024-0429",
]
"""
    assert any("no expires" in error for error in check_ignores(missing, date(2026, 11, 18)))
    print("check_cargo_audit_ignores self-test passed")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return _self_test()
    path = Path(argv[0]) if argv else DEFAULT_PATH
    errors = check_ignores(path.read_text(), date.today())
    if errors:
        print("cargo-audit ignore policy failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"cargo-audit ignores are within their expiry ({path})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
