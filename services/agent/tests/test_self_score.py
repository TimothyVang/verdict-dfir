"""Tests for scripts/self-score.py — the course_correction metric (#4)."""

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


def test_zero_corrections_when_none(tmp_path: Path) -> None:
    _write_audit(
        tmp_path,
        [{"kind": "tool_call_start", "payload": {"tool_call_id": "tc-1", "tool": "evtx_query"}}],
    )
    result = self_score.score(tmp_path)
    crit1 = next(r for r in result["rows"] if r["criterion"] == 1)
    assert "corrections=0" in crit1["answer"]
