"""Tests for scripts/self-score.py criterion 1 recovery/injection counters."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_SELF_SCORE = Path(__file__).resolve().parent.parent.parent.parent / "scripts" / "self-score.py"
_spec = importlib.util.spec_from_file_location("self_score", _SELF_SCORE)
assert _spec and _spec.loader
self_score = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(self_score)


def _write_audit(case_dir: Path, records: list[dict]) -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "audit.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
    )


def test_counts_course_correction_records(tmp_path: Path) -> None:
    _write_audit(
        tmp_path,
        [
            {"kind": "tool_call_start", "payload": {"tool_call_id": "tc-1", "tool": "vol_pslist"}},
            {
                "kind": "course_correction",
                "payload": {"failed_tool": "vol_pslist", "action": "defer"},
            },
            {
                "kind": "course_correction",
                "payload": {"failed_tool": "registry_query", "action": "narrow"},
            },
        ],
    )
    result = self_score.score(tmp_path)
    crit1 = next(r for r in result["rows"] if r["criterion"] == 1)
    assert "corrections=2" in crit1["answer"]


def test_counts_verdict_revision_records(tmp_path: Path) -> None:
    _write_audit(
        tmp_path,
        [
            {
                "kind": "tool_call_start",
                "payload": {"tool_call_id": "tc-1", "tool": "vol_pslist"},
            },
            {
                "kind": "verdict_revision",
                "payload": {
                    "finding_id": "f-1",
                    "from_verdict": "CONFIRMED",
                    "to_verdict": "INFERRED",
                    "mechanism": "verify_hash_drift",
                    "trigger_tool_call_id": "tc-1",
                },
            },
        ],
    )
    result = self_score.score(tmp_path)
    crit1 = next(r for r in result["rows"] if r["criterion"] == 1)
    assert "verdict_revisions=1" in crit1["answer"]
    # Backward compatible: the existing tokens are still present.
    assert "corrections=0" in crit1["answer"]


def test_zero_corrections_when_none(tmp_path: Path) -> None:
    _write_audit(
        tmp_path,
        [
            {
                "kind": "tool_call_start",
                "payload": {"tool_call_id": "tc-1", "tool": "evtx_query"},
            }
        ],
    )
    result = self_score.score(tmp_path)
    crit1 = next(r for r in result["rows"] if r["criterion"] == 1)
    assert "corrections=0" in crit1["answer"]


def test_distinguishes_injected_faults_from_natural_corrections(tmp_path: Path) -> None:
    # The Judge Pack discounts staged self-correction: a correction triggered by
    # FIND_EVIL_FAULT_INJECT (kind=fault_injection in the chain) must be reported
    # separately from one triggered by a natural tool failure.
    _write_audit(
        tmp_path,
        [
            {"kind": "fault_injection", "payload": {"mode": "verifier_reject_once"}},
            {
                "kind": "course_correction",
                "payload": {"failed_tool": "registry_query", "action": "narrow"},
            },
        ],
    )
    result = self_score.score(tmp_path)
    crit1 = next(r for r in result["rows"] if r["criterion"] == 1)
    assert "injected_faults=1" in crit1["answer"]


def test_zero_injected_faults_on_natural_run(tmp_path: Path) -> None:
    _write_audit(
        tmp_path,
        [
            {
                "kind": "course_correction",
                "payload": {"failed_tool": "registry_query", "action": "narrow"},
            },
        ],
    )
    result = self_score.score(tmp_path)
    crit1 = next(r for r in result["rows"] if r["criterion"] == 1)
    assert "injected_faults=0" in crit1["answer"]


def test_counts_clean_verifier_redispatch_separately_from_injection(
    tmp_path: Path,
) -> None:
    _write_audit(
        tmp_path,
        [
            {
                "kind": "verifier_redispatch",
                "payload": {
                    "finding_id": "f-1",
                    "attempt": 2,
                    "first_action": "rejected",
                    "trigger": "verifier_reject",
                },
            },
        ],
    )
    result = self_score.score(tmp_path)
    crit1 = next(r for r in result["rows"] if r["criterion"] == 1)
    assert "redispatches=1" in crit1["answer"]
    assert "injected_faults=0" in crit1["answer"]


def test_counts_injected_redispatch_without_calling_it_natural(
    tmp_path: Path,
) -> None:
    _write_audit(
        tmp_path,
        [
            {"kind": "fault_injection", "payload": {"mode": "verifier_reject_once"}},
            {
                "kind": "verifier_redispatch",
                "payload": {
                    "finding_id": "f-1",
                    "attempt": 2,
                    "first_action": "rejected",
                    "trigger": "verifier_reject",
                },
            },
        ],
    )
    result = self_score.score(tmp_path)
    crit1 = next(r for r in result["rows"] if r["criterion"] == 1)
    assert "redispatches=1" in crit1["answer"]
    assert "injected_faults=1" in crit1["answer"]


def test_no_correction_counters_are_zero(tmp_path: Path) -> None:
    _write_audit(
        tmp_path,
        [{"kind": "tool_call_start", "payload": {"tool_call_id": "tc-1", "tool": "evtx_query"}}],
    )
    result = self_score.score(tmp_path)
    crit1 = next(r for r in result["rows"] if r["criterion"] == 1)
    assert "corrections=0" in crit1["answer"]
    assert "redispatches=0" in crit1["answer"]
    assert "injected_faults=0" in crit1["answer"]


def test_traced_counts_findings_whose_tool_call_id_resolves(tmp_path: Path) -> None:
    # The judges' three-claim trace, run over every finding: a cited tool_call_id
    # must resolve to a tool_call_start in the same chain. A finding citing a
    # ghost id is cited-but-not-traced — the failure mode that fails judging.
    _write_audit(
        tmp_path,
        [
            {"kind": "tool_call_start", "payload": {"tool_call_id": "tc-1", "tool": "evtx_query"}},
            {
                "kind": "tool_call_output",
                "payload": {"tool_call_id": "tc-1", "output_hash": "abc"},
            },
            {"kind": "finding_approved", "payload": {"tool_call_id": "tc-1"}},
            {"kind": "finding_approved", "payload": {"tool_call_id": "tc-ghost"}},
        ],
    )
    result = self_score.score(tmp_path)
    crit5 = next(r for r in result["rows"] if r["criterion"] == 5)
    assert "cited=2/2" in crit5["answer"]
    assert "traced=1/2" in crit5["answer"]
