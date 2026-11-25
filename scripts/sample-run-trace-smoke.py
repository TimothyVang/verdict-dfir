#!/usr/bin/env python3
"""Regression smoke for the committed /home-free custody fixture.

Guards ``docs/release-evidence/sample-run/`` — the public, deterministic VERDICT
run committed so a judge can verify custody offline. The fixture must keep three
invariants, all checked here against the four committed files:

1. ``scripts/trace-finding`` exits 0 (TRACE OK): the audit chain re-verifies and
   the single finding resolves to its tool execution and Merkle leaves.
2. ``manifest_verify.json`` reports ``overall: true``.
3. No committed file leaks an absolute ``/home/...`` path (provenance fields are
   relativized to basenames by ``find_evil_auto._release_path``).

This is the sibling of ``scripts/trace-finding-smoke.py`` (which exercises tamper
detection on synthetic runs); this one pins the real, committed fixture instead.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TRACE = REPO / "scripts" / "trace-finding"
SAMPLE_RUN = REPO / "docs" / "release-evidence" / "sample-run"
REQUIRED_FILES = (
    "audit.jsonl",
    "verdict.json",
    "run.manifest.json",
    "manifest_verify.json",
)


def _check_files_present() -> int:
    missing = [name for name in REQUIRED_FILES if not (SAMPLE_RUN / name).is_file()]
    if missing:
        print(
            f"sample-run missing required files: {', '.join(missing)}", file=sys.stderr
        )
        return 1
    return 0


def _check_trace_finding() -> int:
    proc = subprocess.run(
        [sys.executable, str(TRACE), str(SAMPLE_RUN)],
        cwd=REPO,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        print(
            "trace-finding did not exit 0 against the committed sample-run",
            file=sys.stderr,
        )
        print(proc.stdout, file=sys.stderr)
        print(proc.stderr, file=sys.stderr)
        return 1
    if "TRACE OK" not in proc.stdout:
        print("trace-finding exit 0 but no TRACE OK diagnostic", file=sys.stderr)
        print(proc.stdout, file=sys.stderr)
        return 1
    return 0


def _check_manifest_verify_overall() -> int:
    data = json.loads((SAMPLE_RUN / "manifest_verify.json").read_text(encoding="utf-8"))
    if data.get("overall") is not True:
        print(
            f"manifest_verify.json overall is not true: {data.get('overall')!r}",
            file=sys.stderr,
        )
        return 1
    return 0


def _check_no_home_leak() -> int:
    offenders = []
    for name in REQUIRED_FILES:
        text = (SAMPLE_RUN / name).read_text(encoding="utf-8")
        if "/home" in text:
            offenders.append(name)
    if offenders:
        print(
            f"absolute /home path leaked into: {', '.join(offenders)}", file=sys.stderr
        )
        return 1
    return 0


def main() -> int:
    for check in (
        _check_files_present,
        _check_trace_finding,
        _check_manifest_verify_overall,
        _check_no_home_leak,
    ):
        rc = check()
        if rc != 0:
            return rc
    print(
        "sample-run-trace-smoke: TRACE OK, manifest_verify overall=true, no /home leak"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
