"""Tests for the two-axis accuracy report (P0-1 / P0-2).

``accuracy.score_report`` merges, WITHOUT blending into one number:
  * investigative_recall  — goldens-scored (recall / precision / F1 / planted bait),
  * deterministic_grounding — the goldens-free discipline view supplied by the caller
    (citation / replay / custody from score-overclaim); recorded as
    ``{"available": False}`` when no grounding metrics are available.

Each planted false-positive in ``planted_bait_caught`` carries a ``catch_reason``
naming the control that caught it (P0-1's "reasoned-away" requirement).
"""

from __future__ import annotations

import json
from pathlib import Path

from findevil_agent import accuracy


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


class TestScoreReportShape:
    def test_two_labeled_axes_no_blending(self, tmp_path: Path) -> None:
        golden = _write_golden(tmp_path / "g.json")
        case_dir = _write_verdict(tmp_path / "case", "SUSPICIOUS", [])
        report = accuracy.score_report(case_dir, golden)
        assert "investigative_recall" in report
        assert "deterministic_grounding" in report
        # No single blended top-level accuracy number.
        assert "accuracy" not in report
        assert "blended" not in report

    def test_grounding_absent_marked_unavailable(self, tmp_path: Path) -> None:
        golden = _write_golden(tmp_path / "g.json")
        case_dir = _write_verdict(tmp_path / "case", "SUSPICIOUS", [])
        report = accuracy.score_report(case_dir, golden)
        # No grounding supplied -> recorded as unavailable, NOT a verified default.
        assert report["deterministic_grounding"]["available"] is False

    def test_grounding_passed_through(self, tmp_path: Path) -> None:
        golden = _write_golden(tmp_path / "g.json")
        case_dir = _write_verdict(tmp_path / "case", "SUSPICIOUS", [])
        grounding = {"available": True, "citation_coverage": 1.0, "custody_ok": True}
        report = accuracy.score_report(case_dir, golden, grounding=grounding)
        assert report["deterministic_grounding"]["citation_coverage"] == 1.0
        assert report["deterministic_grounding"]["custody_ok"] is True


class TestCatchReason:
    def test_anti_fact_catch_reason(self, tmp_path: Path) -> None:
        # Eligibility is description token-overlap (>=3 shared distinctive tokens),
        # so the anti_fact and the run finding must share concrete vocabulary.
        golden = _write_golden(
            tmp_path / "g.json",
            anti_facts=[{"description": "attacker exfiltrated customer database records overseas"}],
        )
        case_dir = _write_verdict(
            tmp_path / "case",
            "SUSPICIOUS",
            [
                {
                    "finding_id": "f-1",
                    "description": "attacker exfiltrated customer database records to overseas server",
                }
            ],
        )
        report = accuracy.score_report(case_dir, golden)
        caught = report["investigative_recall"]["planted_bait_caught"]
        assert caught, "an anti_fact assertion must be caught"
        assert "anti_fact" in caught[0]["catch_reason"]

    def test_denylist_catch_reason_names_term(self, tmp_path: Path) -> None:
        golden = _write_golden(
            tmp_path / "g.json",
            named_claim_denylist=["mimikatz"],
        )
        case_dir = _write_verdict(
            tmp_path / "case",
            "SUSPICIOUS",
            [{"finding_id": "f-1", "description": "observed mimikatz credential theft"}],
        )
        report = accuracy.score_report(case_dir, golden)
        caught = report["investigative_recall"]["planted_bait_caught"]
        assert caught
        assert "mimikatz" in caught[0]["catch_reason"]
        assert "denylist" in caught[0]["catch_reason"]

    def test_clean_run_has_no_planted_bait_caught(self, tmp_path: Path) -> None:
        golden = _write_golden(tmp_path / "g.json", named_claim_denylist=["mimikatz"])
        case_dir = _write_verdict(tmp_path / "case", "NO_EVIL", [])
        report = accuracy.score_report(case_dir, golden)
        assert report["investigative_recall"]["planted_bait_caught"] == []


class TestPerTacticRecall:
    """Additive per-MITRE-tactic recall breakdown (custody-neutral): groups
    expected findings by ATT&CK family prefix and reports recall per bucket
    without touching any existing scoring key."""

    def test_tactic_of_strips_subtechnique(self) -> None:
        assert accuracy._tactic_of("T1059.001") == "T1059"
        assert accuracy._tactic_of("T1003") == "T1003"

    def test_tactic_of_unmapped_for_missing_or_malformed(self) -> None:
        assert accuracy._tactic_of(None) == "UNMAPPED"
        assert accuracy._tactic_of("") == "UNMAPPED"
        assert accuracy._tactic_of("not-an-attack-id") == "UNMAPPED"

    def test_per_tactic_recall_worked_example(self) -> None:
        expected = [
            {"mitre_technique": "T1059.001"},  # idx 0 — recalled
            {"mitre_technique": "T1059"},  # idx 1 — missed
            {"mitre_technique": "T1003.001"},  # idx 2 — recalled
            {"mitre_technique": None},  # idx 3 — missed, UNMAPPED
        ]
        assignment = {0: 10, 2: 11}  # expected idx 0 and 2 matched to run findings
        out = accuracy._per_tactic_recall(expected, assignment)
        assert out["T1059"] == {"expected_n": 2, "recalled_n": 1, "recall_percent": 50}
        assert out["T1003"] == {"expected_n": 1, "recalled_n": 1, "recall_percent": 100}
        assert out["UNMAPPED"] == {"expected_n": 1, "recalled_n": 0, "recall_percent": 0}

    def test_per_tactic_recall_buckets_sorted_and_deterministic(self) -> None:
        expected = [
            {"mitre_technique": "T1003"},
            {"mitre_technique": "T1059"},
        ]
        out = accuracy._per_tactic_recall(expected, {})
        assert list(out.keys()) == sorted(out.keys())
        assert accuracy._per_tactic_recall(expected, {}) == out

    def test_per_tactic_recall_sums_reconcile_with_totals(self) -> None:
        expected = [{"mitre_technique": "T1059"}, {"mitre_technique": "T1003"}]
        assignment = {0: 5}
        out = accuracy._per_tactic_recall(expected, assignment)
        assert sum(b["expected_n"] for b in out.values()) == len(expected)
        assert sum(b["recalled_n"] for b in out.values()) == len(assignment)
