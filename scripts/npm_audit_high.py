#!/usr/bin/env python3
"""Fail on high/critical npm advisories, honoring a time-boxed allowlist.

Mirrors `npm audit --audit-level=high`: moderate and below do not fail the
process. Allowlisted advisory ids are ignored only until their expiry date.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import date
from pathlib import Path


def advisory_ids(vuln: dict) -> list[str]:
    found: list[str] = []
    for via in vuln.get("via") or []:
        if not isinstance(via, dict):
            continue
        url = via.get("url") or ""
        marker = "/advisories/"
        if marker in url:
            found.append(url.rsplit("/", 1)[-1])
    return found


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allowlist", type=Path, required=True)
    args = parser.parse_args()

    allow_doc = json.loads(args.allowlist.read_text())
    allowed: dict[str, str] = {}
    for entry in allow_doc.get("advisories") or []:
        adv_id = entry["id"]
        expires = entry["expires"]
        date.fromisoformat(expires)
        allowed[adv_id] = expires

    proc = subprocess.run(
        ["npm", "audit", "--json"],
        check=False,
        text=True,
        capture_output=True,
    )
    if proc.returncode not in (0, 1):
        sys.stderr.write(proc.stderr)
        sys.stdout.write(proc.stdout)
        print(f"npm audit failed unexpectedly (exit {proc.returncode})", file=sys.stderr)
        return proc.returncode or 1

    try:
        report = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        sys.stderr.write(proc.stderr)
        sys.stdout.write(proc.stdout)
        print("npm audit did not return JSON", file=sys.stderr)
        return 1

    today = date.today()
    blocking: list[str] = []
    tolerated: list[str] = []
    for name, vuln in (report.get("vulnerabilities") or {}).items():
        severity = vuln.get("severity")
        if severity not in ("high", "critical"):
            continue
        ids = advisory_ids(vuln)
        if not ids:
            # Transitive rollup ("depends on picomatch") with no advisory of its own.
            continue
        for adv_id in ids:
            expiry = allowed.get(adv_id)
            if expiry is None:
                blocking.append(f"{severity} {name} {adv_id}")
                continue
            if date.fromisoformat(expiry) < today:
                blocking.append(f"{severity} {name} {adv_id} (allowlist expired {expiry})")
                continue
            tolerated.append(f"{name} {adv_id} until {expiry}")

    if tolerated:
        print("Tolerated npm advisories (time-boxed allowlist):")
        for line in tolerated:
            print(f"  - {line}")
    if blocking:
        print("npm audit found high or critical advisories:", file=sys.stderr)
        for line in blocking:
            print(f"  - {line}", file=sys.stderr)
        return 1
    print("npm audit: no unexpected high or critical advisories")
    return 0


if __name__ == "__main__":
    sys.exit(main())
