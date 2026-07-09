"""Tests for the mechanical verifier-discipline smoke.

``scripts/verifier-discipline-smoke.py`` is an LLM-free, deterministic gate that
loads a completed run's ``audit.jsonl`` + ``verdict.json`` and asserts the
verifier actually disciplined every shipped Finding:

* every shipped ``Finding.tool_call_id`` resolves to a real ``tool_call_output``
  record (the tool actually executed — not a fabricated id);
* every shipped CONFIRMED/INFERRED Finding has a matching ``verifier_action``
  record and none ship with ``action == "rejected"``;
* per-stage finding tallies reconcile (shipped == ``finding_approved`` ==
  approved ``verifier_action``; reconciled, never pinned to a literal count);
* every recovery record (``course_correction`` / ``verdict_revision``) that
  cites a tool-call id points at a tool call that actually executed.

These tests exercise the reusable ``audit_violations`` checker against a clean
synthetic run (passes) and two broken runs (one absent ``tool_call_id``, one
fabricated recovery citation) — the negative cases the smoke must catch.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
_SMOKE = _REPO / "scripts" / "verifier-discipline-smoke.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location("verifier_discipline_smoke", _SMOKE)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_run(
    run_dir: Path,
    *,
    records: list[dict],
    findings: list[dict],
) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    audit = run_dir / "audit.jsonl"
    audit.write_text(
        "".join(json.dumps(r) + "\n" for r in records),
        encoding="utf-8",
    )
    (run_dir / "verdict.json").write_text(
        json.dumps({"verdict": "SUSPICIOUS", "findings": findings}),
        encoding="utf-8",
    )
    return run_dir


def _clean_records() -> list[dict]:
    return [
        {"kind": "tool_call_start", "payload": {"tool": "case_open", "tool_call_id": "tc-001"}},
        {
            "kind": "tool_call_output",
            "payload": {"tool_call_id": "tc-001", "output_hash": "a" * 64},
        },
        {"kind": "tool_call_start", "payload": {"tool": "evtx_query", "tool_call_id": "tc-002"}},
        {
            "kind": "tool_call_output",
            "payload": {"tool_call_id": "tc-002", "output_hash": "b" * 64},
        },
        {
            "kind": "verifier_action",
            "payload": {"action": "approved", "finding_id": "f-1", "reason": "entailed"},
        },
        {"kind": "finding_approved", "payload": {"finding_id": "f-1", "confidence": "CONFIRMED"}},
    ]


def _clean_findings() -> list[dict]:
    return [
        {
            "finding_id": "f-1",
            "tool_call_id": "tc-002",
            "confidence": "CONFIRMED",
            "description": "EVTX 1102 log clear",
        }
    ]


def test_clean_run_has_no_violations(tmp_path: Path) -> None:
    mod = _load_checker()
    run = _write_run(
        tmp_path / "clean",
        records=_clean_records(),
        findings=_clean_findings(),
    )
    assert mod.audit_violations(run) == []


def test_finding_tool_call_id_absent_is_flagged(tmp_path: Path) -> None:
    mod = _load_checker()
    findings = _clean_findings()
    findings[0]["tool_call_id"] = "tc-404"  # never an executed tool_call_output
    run = _write_run(
        tmp_path / "absent_tcid",
        records=_clean_records(),
        findings=findings,
    )
    violations = mod.audit_violations(run)
    assert violations, "absent finding tool_call_id must be flagged"
    assert any("tc-404" in v for v in violations)


def test_course_correction_fabricated_tool_call_id_is_flagged(tmp_path: Path) -> None:
    mod = _load_checker()
    records = _clean_records()
    records.append(
        {
            "kind": "course_correction",
            "payload": {
                "failed_tool": "registry_query",
                "trigger_tool_call_id": "tc-999",  # never an executed tool_call
                "action": "narrow",
                "reason": "hive truncated",
            },
        }
    )
    run = _write_run(
        tmp_path / "bad_correction",
        records=records,
        findings=_clean_findings(),
    )
    violations = mod.audit_violations(run)
    assert violations, "course_correction citing a non-executed tool_call_id must be flagged"
    assert any("tc-999" in v for v in violations)


def test_shipped_rejected_finding_is_flagged(tmp_path: Path) -> None:
    mod = _load_checker()
    records = _clean_records()
    # Flip the verifier action to rejected while the finding still ships.
    for r in records:
        if r["kind"] == "verifier_action":
            r["payload"]["action"] = "rejected"
    run = _write_run(
        tmp_path / "shipped_rejected",
        records=records,
        findings=_clean_findings(),
    )
    violations = mod.audit_violations(run)
    assert violations, "a shipped finding with a rejected verifier_action must be flagged"
