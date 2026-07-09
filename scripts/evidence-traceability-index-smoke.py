#!/usr/bin/env python3
"""Regression smoke for scripts/evidence_traceability_index.

The traceability index is a deterministic, no-LLM, read-only join over a run's
verdict.json + audit.jsonl. It maps every Finding's claim/entities -> finding_id
-> each cited tool_call_id -> the exact audit.jsonl line number + output_sha256.
This smoke pins three properties:

  1. A clean fixture resolves every finding to its citation chain with the right
     audit line numbers, output hashes, and a RESOLVED status (exit 0).
  2. Tampering the cited tool_call_output line (breaking the canonical/hash chain)
     surfaces the finding as UNRESOLVED (exit 1).
  3. Re-running over the same directory is byte-identical (deterministic).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_MODULE = "scripts.evidence_traceability_index"
_CANONICAL_SEPARATORS = (",", ":")


def _canonicalize(obj: object) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=_CANONICAL_SEPARATORS, ensure_ascii=True
    ).encode("ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_sample_run(run_dir: Path) -> None:
    """Smallest run the index should accept: one tool call, one finding citing it."""
    run_dir.mkdir(parents=True, exist_ok=True)
    verdict = {
        "case_id": "eti-smoke",
        "verdict": "SUSPICIOUS",
        "findings": [
            {
                "finding_id": "f-eti-smoke",
                "confidence": "CONFIRMED",
                "tool_call_id": "tc-evtx-1",
                "derived_from": ["tc-evtx-1"],
                "mitre_technique": "T1070.001",
                "host": "WS-01",
                "artifact_path": "C:/Windows/System32/winevt/Logs/Security.evtx",
                "description": "Windows Security event log clear event observed.",
            }
        ],
    }
    (run_dir / "verdict.json").write_bytes(_canonicalize(verdict) + b"\n")

    output_hash = "b" * 64
    records: list[dict[str, object]] = []
    prev_hash = ""
    for kind, payload in (
        (
            "tool_call_start",
            {"tool": "evtx_query", "tool_call_id": "tc-evtx-1"},
        ),
        (
            "tool_call_output",
            {
                "tool": "evtx_query",
                "tool_call_id": "tc-evtx-1",
                "output_hash": output_hash,
            },
        ),
        (
            "finding_approved",
            {"finding_id": "f-eti-smoke", "finding": verdict["findings"][0]},
        ),
    ):
        record = {
            "kind": kind,
            "payload": payload,
            "prev_hash": prev_hash,
            "seq": len(records),
            "ts": "2026-06-30T00:00:00Z",
        }
        raw = _canonicalize(record)
        records.append(record)
        prev_hash = _sha256(raw)

    (run_dir / "audit.jsonl").write_bytes(
        b"\n".join(_canonicalize(r) for r in records) + b"\n"
    )


def _run_index(run_dir: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", _MODULE, str(run_dir), *extra],
        cwd=REPO,
        text=True,
        capture_output=True,
        check=False,
    )


def _tamper_audit_output_line(run_dir: Path) -> None:
    """Hand-edit the tool_call_output line, the way a tamperer would.

    The mutated value is re-serialized with default (non-canonical) JSON spacing,
    so the line no longer reproduces its canonical bytes -- exactly the in-place
    edit the hash-chain verification is designed to catch.
    """
    audit_path = run_dir / "audit.jsonl"
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines:
        obj = json.loads(line)
        if obj.get("kind") == "tool_call_output":
            obj["payload"]["output_hash"] = "c" * 64
            out.append(json.dumps(obj))  # default spacing -> non-canonical
        else:
            out.append(
                json.dumps(obj, sort_keys=True, separators=_CANONICAL_SEPARATORS)
            )
    audit_path.write_text("\n".join(out) + "\n", encoding="utf-8")


def main() -> int:
    failures: list[str] = []

    with tempfile.TemporaryDirectory() as tmp:
        clean = Path(tmp) / "clean-run"
        _write_sample_run(clean)

        # 1. clean fixture -> RESOLVED join table, exit 0.
        proc = _run_index(clean, "--json")
        if proc.returncode != 0:
            failures.append(
                f"clean run exited {proc.returncode}, expected 0\n{proc.stderr}"
            )
        try:
            index = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            failures.append(f"clean --json output is not valid JSON: {exc}")
            index = {}

        findings = index.get("findings", [])
        if len(findings) != 1:
            failures.append(f"expected 1 finding, got {len(findings)}")
        elif findings[0].get("status") != "RESOLVED":
            failures.append(f"clean finding status: {findings[0].get('status')}")
        else:
            cits = findings[0].get("citations", [])
            if not cits:
                failures.append("clean finding has no citations")
            else:
                cit = cits[0]
                if cit.get("status") != "RESOLVED":
                    failures.append(f"citation status: {cit.get('status')}")
                if cit.get("audit_line") != 2:
                    failures.append(
                        f"expected tool_call_output on audit_line 2, got "
                        f"{cit.get('audit_line')}"
                    )
                if cit.get("output_sha256") != "b" * 64:
                    failures.append(
                        f"expected output_sha256 'bbbb...', got {cit.get('output_sha256')}"
                    )
        summary = index.get("summary", {})
        if summary.get("resolved") != 1 or summary.get("unresolved") != 0:
            failures.append(f"clean summary unexpected: {summary}")

        # 3. deterministic: two runs byte-identical.
        proc_a = _run_index(clean, "--json")
        proc_b = _run_index(clean, "--json")
        if proc_a.stdout != proc_b.stdout:
            failures.append("two runs over the same dir are not byte-identical")

    with tempfile.TemporaryDirectory() as tmp:
        tampered = Path(tmp) / "tampered-run"
        _write_sample_run(tampered)
        _tamper_audit_output_line(tampered)
        proc = _run_index(tampered, "--json")
        if proc.returncode == 0:
            failures.append("tampered run exited 0, expected non-zero")
        try:
            index = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            failures.append(f"tampered --json output is not valid JSON: {exc}")
            index = {}
        findings = index.get("findings", [])
        if not findings or findings[0].get("status") != "UNRESOLVED":
            status = findings[0].get("status") if findings else "<none>"
            failures.append(f"tampered finding status: {status}, expected UNRESOLVED")

    if failures:
        print("evidence-traceability-index-smoke FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("evidence-traceability-index-smoke OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
