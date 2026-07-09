"""Tier A / Tier B accuracy-honesty enforcement.

VERDICT's anti-overclaim doctrine, applied to the accuracy report itself:

  * **Tier A** (``deterministic_grounding``) — internal-consistency the run can
    prove on its own (citation coverage, replay, custody): computable NOW, no
    answer key. "Provably consistent, not proven correct."
  * **Tier B** (``investigative_recall``) — recall / precision / F1: only valid
    against an EXTERNAL ground-truth answer key. When no golden resolves, the
    report must NOT fabricate a number — it emits ``{"value": null, "reason":
    "no_external_answer_key"}`` and ``pass: null``, while Tier A stays populated.

These tests pin that contract: a key-less case is disclosed (Tier A) without an
invented recall number, and a recall number never appears without a resolved key.
"""

from __future__ import annotations

import json
from pathlib import Path

from findevil_agent import accuracy

NO_KEY = {"value": None, "reason": "no_external_answer_key"}


def _write_verdict(
    case_dir: Path, verdict: str, findings: list[dict[str, object]], case_id: str = "c-1"
) -> Path:
    case_dir.mkdir(parents=True, exist_ok=True)
    doc = {"case_id": case_id, "verdict": verdict, "findings": findings}
    (case_dir / "verdict.json").write_text(json.dumps(doc), encoding="utf-8")
    return case_dir


def _write_golden(path: Path, **fields: object) -> Path:
    base: dict[str, object] = {"case_id": "c-1", "findings": [], "verdict": "SUSPICIOUS"}
    base.update(fields)
    path.write_text(json.dumps(base), encoding="utf-8")
    return path


class TestTierLabels:
    def test_golden_present_tags_both_axes(self, tmp_path: Path) -> None:
        golden = _write_golden(tmp_path / "g.json")
        case_dir = _write_verdict(tmp_path / "case", "SUSPICIOUS", [])
        grounding = {"available": True, "citation_coverage": 1.0, "custody_ok": True}
        report = accuracy.score_report(case_dir, golden, grounding=grounding)
        assert report["investigative_recall"]["tier"] == "B"
        assert report["deterministic_grounding"]["tier"] == "A"
        # corpus identity is named so a synthetic number is not read as field accuracy
        assert "corpus_identity" in report["investigative_recall"]

    def test_golden_present_recall_is_a_real_number(self, tmp_path: Path) -> None:
        golden = _write_golden(tmp_path / "g.json")  # empty golden -> 100% by definition
        case_dir = _write_verdict(tmp_path / "case", "SUSPICIOUS", [])
        report = accuracy.score_report(case_dir, golden)
        assert isinstance(report["investigative_recall"]["recall_percent"], int)
        assert report["investigative_recall"]["scored"] is True


class TestNoKeyNeverFabricates:
    def test_no_golden_emits_null_with_reason(self, tmp_path: Path) -> None:
        case_dir = _write_verdict(tmp_path / "case", "INDETERMINATE", [])
        grounding = {"available": True, "citation_coverage": 1.0, "custody_ok": True}
        report = accuracy.score_report(case_dir, None, grounding=grounding)
        ir = report["investigative_recall"]
        assert ir["tier"] == "B"
        assert ir["scored"] is False
        assert ir["recall_percent"] == NO_KEY
        assert ir["precision_percent"] == NO_KEY
        assert ir["f1"] == NO_KEY
        # pass cannot be asserted without a key
        assert report["pass"] is None

    def test_no_golden_keeps_tier_a_populated(self, tmp_path: Path) -> None:
        case_dir = _write_verdict(tmp_path / "case", "INDETERMINATE", [])
        grounding = {"available": True, "citation_coverage": 1.0, "custody_ok": True}
        report = accuracy.score_report(case_dir, None, grounding=grounding)
        # Tier A (grounding) is goldens-free, so it survives with no key.
        assert report["deterministic_grounding"]["tier"] == "A"
        assert report["deterministic_grounding"]["citation_coverage"] == 1.0

    def test_no_golden_no_planted_bait(self, tmp_path: Path) -> None:
        case_dir = _write_verdict(tmp_path / "case", "INDETERMINATE", [])
        report = accuracy.score_report(case_dir, None)
        ir = report["investigative_recall"]
        assert ir["fp_planted"] == 0
        assert ir["planted_bait_caught"] == []
        # grounding still recorded as unavailable, never a verified default
        assert report["deterministic_grounding"]["available"] is False
        assert report["deterministic_grounding"]["tier"] == "A"
