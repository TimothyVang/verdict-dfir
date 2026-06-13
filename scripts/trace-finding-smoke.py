#!/usr/bin/env python3
"""Regression smoke for scripts/trace-finding tamper detection."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
TRACE = REPO / "scripts" / "trace-finding"
SAMPLE = REPO / "docs" / "sample-run" / "attack-samples-evtx"


def _run_trace(run_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TRACE), str(run_dir)],
        cwd=REPO,
        text=True,
        capture_output=True,
        check=False,
    )


def _tamper_verdict(run_dir: Path) -> None:
    verdict_path = run_dir / "verdict.json"
    verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
    findings = verdict.get("findings") or []
    if not findings:
        raise RuntimeError("sample verdict has no findings to tamper")
    cloned = dict(findings[0])
    cloned["finding_id"] = "tampered-reused-tool-call"
    cloned["description"] = "tampered finding that reuses a real tool_call_id"
    verdict["findings"] = [*findings, cloned]
    verdict_path.write_text(
        json.dumps(verdict, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="trace-finding-smoke-") as tmp:
        run_dir = Path(tmp) / "run"
        shutil.copytree(SAMPLE, run_dir)

        baseline = _run_trace(run_dir)
        if baseline.returncode != 0:
            print("baseline trace unexpectedly failed", file=sys.stderr)
            print(baseline.stdout, file=sys.stderr)
            print(baseline.stderr, file=sys.stderr)
            return 1

        _tamper_verdict(run_dir)
        tampered = _run_trace(run_dir)
        if tampered.returncode == 0:
            print("tampered verdict unexpectedly traced successfully", file=sys.stderr)
            print(tampered.stdout, file=sys.stderr)
            print(tampered.stderr, file=sys.stderr)
            return 1

    print("trace-finding-smoke: tampered verdict rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
