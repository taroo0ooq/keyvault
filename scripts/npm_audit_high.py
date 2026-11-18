#!/usr/bin/env python3
"""Fail on high/critical npm advisories, honoring a time-boxed allowlist.

Mirrors `npm audit --audit-level=high`: moderate and below do not fail the
process. An allowlisted advisory is ignored only until its expiry date, and
only when both the advisory id and the package name match.

Fail closed: a high or critical finding is skipped only when its `via` list is
entirely string references to other packages (a transitive rollup). An advisory
object with no parseable GitHub advisory id fails the run, as does a malformed
allowlist entry.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

GHSA_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")
ALLOWLIST_KEYS = ("id", "package", "expires", "reason")
TOP_LEVEL_KEYS = {"note", "advisories"}


class AllowlistError(Exception):
    """The committed allowlist is missing a required field or has an unknown one."""


def load_allowlist(doc: object) -> dict[tuple[str, str], date]:
    if not isinstance(doc, dict):
        raise AllowlistError("allowlist must be a JSON object")
    unknown = set(doc) - TOP_LEVEL_KEYS
    if unknown:
        raise AllowlistError(f"unknown allowlist fields: {', '.join(sorted(unknown))}")
    entries = doc.get("advisories")
    if not isinstance(entries, list):
        raise AllowlistError("allowlist advisories must be a list")

    allowed: dict[tuple[str, str], date] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise AllowlistError(f"allowlist entry {index} is not an object")
        extra = set(entry) - set(ALLOWLIST_KEYS)
        if extra:
            raise AllowlistError(
                f"allowlist entry {index} has unknown fields: {', '.join(sorted(extra))}"
            )
        missing = [
            key
            for key in ALLOWLIST_KEYS
            if not isinstance(entry.get(key), str) or not entry[key].strip()
        ]
        if missing:
            raise AllowlistError(
                f"allowlist entry {index} is missing {', '.join(missing)}"
            )
        adv_id = entry["id"].strip()
        package = entry["package"].strip()
        if not GHSA_RE.fullmatch(adv_id):
            raise AllowlistError(f"allowlist entry {index} has a malformed advisory id")
        try:
            expires = date.fromisoformat(entry["expires"].strip())
        except ValueError as exc:
            raise AllowlistError(
                f"allowlist entry {index} has a malformed expires date"
            ) from exc
        key = (package, adv_id)
        if key in allowed:
            raise AllowlistError(f"duplicate allowlist entry for {package} {adv_id}")
        allowed[key] = expires
    return allowed


def _advisory_id(url: object) -> str | None:
    if not isinstance(url, str):
        return None
    marker = "/advisories/"
    if marker not in url:
        return None
    adv_id = url.split(marker, 1)[1].split("/", 1)[0].split("?", 1)[0].strip()
    if not GHSA_RE.fullmatch(adv_id):
        return None
    return adv_id


def inspect_vulnerability(vuln: object) -> tuple[str, list[str]]:
    """Classify one npm audit vulnerability.

    Returns ("rollup", []) when `via` is only non-empty strings, ("ids", [...])
    when every advisory object yielded a GitHub advisory id, or ("block", [])
    for anything else (missing via, non-string rollup, advisory object with no
    parseable id).
    """
    if not isinstance(vuln, dict):
        return ("block", [])
    vias = vuln.get("via")
    if not isinstance(vias, list) or not vias:
        return ("block", [])
    if all(isinstance(item, str) and item.strip() for item in vias):
        return ("rollup", [])

    ids: list[str] = []
    for item in vias:
        if isinstance(item, str):
            if not item.strip():
                return ("block", [])
            continue
        if not isinstance(item, dict):
            return ("block", [])
        adv_id = _advisory_id(item.get("url"))
        if adv_id is None:
            return ("block", [])
        ids.append(adv_id)
    if not ids:
        return ("block", [])
    return ("ids", ids)


def evaluate(
    report: object, allowed: dict[tuple[str, str], date], today: date
) -> tuple[list[str], list[str]]:
    if not isinstance(report, dict):
        return (["npm audit report is not a JSON object"], [])
    vulns = report.get("vulnerabilities") or {}
    if not isinstance(vulns, dict):
        return (["npm audit vulnerabilities field is not an object"], [])

    blocking: list[str] = []
    tolerated: list[str] = []
    for name, vuln in vulns.items():
        if not isinstance(name, str) or not name.strip():
            blocking.append("npm audit vulnerability name is missing")
            continue
        severity = vuln.get("severity") if isinstance(vuln, dict) else None
        if severity not in ("high", "critical"):
            continue
        kind, ids = inspect_vulnerability(vuln)
        if kind == "rollup":
            continue
        if kind != "ids":
            blocking.append(f"{severity} {name} has no extractable advisory id")
            continue
        for adv_id in ids:
            expiry = allowed.get((name, adv_id))
            if expiry is None:
                blocking.append(f"{severity} {name} {adv_id}")
                continue
            if expiry < today:
                blocking.append(
                    f"{severity} {name} {adv_id} (allowlist expired {expiry.isoformat()})"
                )
                continue
            tolerated.append(f"{name} {adv_id} until {expiry.isoformat()}")
    return (blocking, tolerated)


def _self_test() -> int:
    today = date(2026, 11, 18)
    picomatch = {
        "severity": "high",
        "via": [
            {
                "name": "picomatch",
                "url": "https://github.com/advisories/GHSA-fc5q-39xc-vjpf",
            }
        ],
    }
    rollup = {"severity": "high", "via": ["picomatch"]}
    allow_doc = {
        "note": "test",
        "advisories": [
            {
                "id": "GHSA-fc5q-39xc-vjpf",
                "package": "picomatch",
                "expires": "2027-02-18",
                "reason": "no patched release",
            }
        ],
    }
    allowed = load_allowlist(allow_doc)

    blocking, tolerated = evaluate(
        {"vulnerabilities": {"picomatch": picomatch, "vite": rollup, "fdir": rollup}},
        allowed,
        today,
    )
    assert blocking == [], blocking
    assert tolerated == ["picomatch GHSA-fc5q-39xc-vjpf until 2027-02-18"], tolerated

    blocking, _ = evaluate(
        {"vulnerabilities": {"vite": picomatch}},
        allowed,
        today,
    )
    assert blocking == ["high vite GHSA-fc5q-39xc-vjpf"], blocking

    unparsed = {
        "severity": "critical",
        "via": [{"source": 1, "title": "missing url"}],
    }
    blocking, _ = evaluate({"vulnerabilities": {"leftpad": unparsed}}, allowed, today)
    assert blocking == ["critical leftpad has no extractable advisory id"], blocking

    blocking, _ = evaluate(
        {"vulnerabilities": {"leftpad": {"severity": "high", "via": []}}},
        allowed,
        today,
    )
    assert blocking == ["high leftpad has no extractable advisory id"], blocking

    blocking, _ = evaluate(
        {
            "vulnerabilities": {
                "leftpad": {
                    "severity": "high",
                    "via": ["other", {"url": "https://example.test/not-an-advisory"}],
                }
            }
        },
        allowed,
        today,
    )
    assert blocking == ["high leftpad has no extractable advisory id"], blocking

    moderate = {"severity": "moderate", "via": [{"url": "nope"}]}
    blocking, tolerated = evaluate(
        {"vulnerabilities": {"leftpad": moderate}}, allowed, today
    )
    assert blocking == [] and tolerated == [], (blocking, tolerated)

    expired = json.loads(json.dumps(allow_doc))
    expired["advisories"][0]["expires"] = "2026-11-17"
    blocking, _ = evaluate(
        {"vulnerabilities": {"picomatch": picomatch}},
        load_allowlist(expired),
        today,
    )
    assert "allowlist expired 2026-11-17" in blocking[0], blocking

    for broken in (
        {"advisories": [{"id": "GHSA-fc5q-39xc-vjpf", "expires": "2027-02-18", "reason": "x"}]},
        {"advisories": [{"id": "GHSA-fc5q-39xc-vjpf", "package": "picomatch", "expires": "2027-02-18"}]},
        {"advisories": [{"id": "GHSA-fc5q-39xc-vjpf", "package": " ", "expires": "2027-02-18", "reason": "x"}]},
        {"advisories": [{"id": "not-a-ghsa", "package": "picomatch", "expires": "2027-02-18", "reason": "x"}]},
        {"advisories": [{"id": "GHSA-fc5q-39xc-vjpf", "package": "picomatch", "expires": "soon", "reason": "x"}]},
        {"extra": True, "advisories": []},
        {"advisories": [{"id": "GHSA-fc5q-39xc-vjpf", "package": "picomatch", "expires": "2027-02-18", "reason": "x", "cve": "CVE"}]},
    ):
        try:
            load_allowlist(broken)
        except AllowlistError:
            continue
        raise AssertionError(f"malformed allowlist was accepted: {broken}")

    print("npm_audit_high self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allowlist", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    if args.allowlist is None:
        print("npm audit allowlist path is required", file=sys.stderr)
        return 1

    try:
        allowed = load_allowlist(json.loads(args.allowlist.read_text()))
    except (OSError, json.JSONDecodeError, AllowlistError) as exc:
        print(f"npm audit allowlist is not usable: {exc}", file=sys.stderr)
        return 1

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

    blocking, tolerated = evaluate(report, allowed, date.today())
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
