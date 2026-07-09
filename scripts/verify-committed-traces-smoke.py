#!/usr/bin/env python3
"""Regression smoke for scripts/verify-committed-traces.

The committed release-evidence traces under docs/release-evidence/*.jsonl are the
offline-checkable proof that VERDICT's audit chain is real. This smoke pins the
trace verifier's behaviour:

  * the clean committed traces verify (exit 0);
  * a one-byte mutation of a hash-chained record breaks the chain (exit non-zero);
  * a flipped tool-output hash that no longer matches the summary spot-check is
    rejected (exit non-zero).

It copies the real committed traces into a temp dir, runs the verifier there, and
mutates copies so the committed evidence is never touched.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VERIFIER = REPO / "scripts" / "verify-committed-traces.py"
EVIDENCE = REPO / "docs" / "release-evidence"

CHAINED_TRACE = "natural-self-correction-trace.jsonl"
CHAINED_SUMMARY = "natural-self-correction-summary.json"
FLAT_TRACE = "evtx-security-log-clear-trace.jsonl"
FLAT_SUMMARY = "evtx-security-log-clear-trace-summary.json"


def _run(evidence_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(evidence_dir)],
        cwd=REPO,
        text=True,
        capture_output=True,
        check=False,
    )


def _stage(tmp: Path) -> Path:
    evidence_dir = tmp / "release-evidence"
    evidence_dir.mkdir(parents=True)
    for name in (CHAINED_TRACE, CHAINED_SUMMARY, FLAT_TRACE, FLAT_SUMMARY):
        shutil.copy2(EVIDENCE / name, evidence_dir / name)
    return evidence_dir


def _tamper_chain(evidence_dir: Path) -> None:
    """Flip a digit inside a hash-chained record so canonical bytes change."""
    path = evidence_dir / CHAINED_TRACE
    lines = path.read_text(encoding="utf-8").splitlines()
    target = json.loads(lines[-1])
    target["seq"] = target["seq"] + 1000
    lines[-1] = json.dumps(
        target, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _tamper_flat_spot_check(evidence_dir: Path) -> None:
    """Flip the spot-checked tool output hash so it diverges from the summary."""
    path = evidence_dir / FLAT_TRACE
    summary = json.loads((evidence_dir / FLAT_SUMMARY).read_text(encoding="utf-8"))
    target_seq = summary["spot_check"]["tool_output_seq"]
    lines = path.read_text(encoding="utf-8").splitlines()
    for index, raw in enumerate(lines):
        record = json.loads(raw)
        if record.get("seq") == target_seq:
            record["output_hash"] = "0" * 64
            lines[index] = json.dumps(record, separators=(",", ":"))
            break
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="verify-committed-traces-smoke-") as tmp:
        root = Path(tmp)

        clean = _stage(root / "clean")
        baseline = _run(clean)
        if baseline.returncode != 0:
            print("clean committed traces unexpectedly failed", file=sys.stderr)
            print(baseline.stdout, file=sys.stderr)
            print(baseline.stderr, file=sys.stderr)
            return 1

        chain = _stage(root / "chain")
        _tamper_chain(chain)
        chain_result = _run(chain)
        if chain_result.returncode == 0:
            print("tampered hash chain unexpectedly verified", file=sys.stderr)
            print(chain_result.stdout, file=sys.stderr)
            return 1

        flat = _stage(root / "flat")
        _tamper_flat_spot_check(flat)
        flat_result = _run(flat)
        if flat_result.returncode == 0:
            print("flipped spot-check hash unexpectedly verified", file=sys.stderr)
            print(flat_result.stdout, file=sys.stderr)
            return 1

    print("verify-committed-traces-smoke: clean traces verify; tampering rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
