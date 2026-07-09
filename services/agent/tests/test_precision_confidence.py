"""Confidence-aware precision: score FP only over asserted (CONFIRMED/HIGH) claims.

A run that already hedged a finding down to INFERRED / HYPOTHESIS / LOW has NOT
over-claimed it — penalising precision for it would punish the very scoping
discipline VERDICT rewards. So precision counts a false positive only for an
unmatched **asserted** (CONFIRMED/HIGH, or an unlabelled-and-therefore-asserted)
finding, and every unmatched asserted finding is surfaced as
``candidate_fp_for_human_review`` rather than silently folded into the count.

(``score`` lives in ``findevil_agent.accuracy`` and is re-exported by
``scripts/score-recall.py``; this pins the behaviour at the source.)
"""

from __future__ import annotations

import json
from pathlib import Path

from findevil_agent import accuracy

_E1 = "harassing email willselfdestruct anonymous remailer internal host"
_E2 = "gmail session cookie attributes host named individual suspect"
_EXTRA = "powershell execution encoded command download cradle stager unrelated"


def _case(tmp_path: Path, run_findings: list[dict]) -> Path:
    (tmp_path / "verdict.json").write_text(
        json.dumps({"case_id": "t", "verdict": "SUSPICIOUS", "findings": run_findings}),
        encoding="utf-8",
    )
    return tmp_path


def _golden(tmp_path: Path, findings: list[dict], **extra) -> Path:
    g = tmp_path / "expected-findings.json"
    g.write_text(
        json.dumps(
            {
                "case_id": "t",
                "verdict": "SUSPICIOUS",
                "min_recall_percent": 0,
                "findings": findings,
                **extra,
            }
        ),
        encoding="utf-8",
    )
    return g


def _f(fid: str, desc: str, confidence: str = "CONFIRMED") -> dict:
    return {"finding_id": fid, "description": desc, "confidence": confidence}


def test_hedged_extra_is_not_a_precision_false_positive(tmp_path: Path) -> None:
    # Closed world, but the unmatched finding is HYPOTHESIS -> the run already
    # scoped it down, so it must NOT be counted as a false positive.
    case = _case(tmp_path, [_f("r1", _E1), _f("r2", _E2), _f("x", _EXTRA, "HYPOTHESIS")])
    golden = _golden(tmp_path, [_f("e1", _E1), _f("e2", _E2)], exhaustive=True)
    r = accuracy.score(case, golden)
    assert r["extra_n"] == 1  # still reported for transparency
    assert r["false_positives_n"] == 0  # hedged -> not a precision FP
    assert r["precision_percent"] == 100
    assert r["candidate_fp_n"] == 0
    assert r["candidate_fp_for_human_review"] == []


def test_asserted_extra_is_a_precision_fp_and_listed_for_review(tmp_path: Path) -> None:
    # Same shape, but the unmatched finding is CONFIRMED -> a real over-claim.
    case = _case(tmp_path, [_f("r1", _E1), _f("r2", _E2), _f("x", _EXTRA, "CONFIRMED")])
    golden = _golden(tmp_path, [_f("e1", _E1), _f("e2", _E2)], exhaustive=True)
    r = accuracy.score(case, golden)
    assert r["false_positives_n"] == 1
    assert r["precision_percent"] == 67  # 2 / (2 + 1)
    assert r["candidate_fp_n"] == 1
    ids = [c["finding_id"] for c in r["candidate_fp_for_human_review"]]
    assert ids == ["x"]


def test_open_world_lists_asserted_extra_for_review_without_counting_it(
    tmp_path: Path,
) -> None:
    # Open world: an unmatched CONFIRMED finding is not a PROVABLE FP (key not
    # closed), but it must still be surfaced as a human-review candidate.
    case = _case(tmp_path, [_f("r1", _E1), _f("x", _EXTRA, "CONFIRMED")])
    golden = _golden(tmp_path, [_f("e1", _E1)])  # no exhaustive
    r = accuracy.score(case, golden)
    assert r["false_positives_n"] == 0  # open world -> not provably wrong
    assert r["precision_scored"] is False
    assert [c["finding_id"] for c in r["candidate_fp_for_human_review"]] == ["x"]


def test_score_report_surfaces_candidate_fp(tmp_path: Path) -> None:
    case = _case(tmp_path, [_f("r1", _E1), _f("x", _EXTRA, "CONFIRMED")])
    golden = _golden(tmp_path, [_f("e1", _E1)], exhaustive=True)
    report = accuracy.score_report(case, golden)
    ir = report["investigative_recall"]
    assert "candidate_fp_for_human_review" in ir
    assert ir["candidate_fp_n"] == 1
