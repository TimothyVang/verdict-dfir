"""Surface false negatives BY NAME — what a run MISSED, not just a recall percent.

Recall already knows which ground-truth claims went unrecalled (``unmatched``); this
pins that they are also disclosed as a first-class ``missed_by_name`` block (count +
named items) on both ``score`` and ``score_report``'s Tier B ``investigative_recall``,
so a reader sees *which* expected findings the run failed to surface — by finding_id
and description — instead of inferring a gap from a number. With no external answer
key there is no denominator, so ``missed_by_name`` is null-with-reason, never a
fabricated zero.
"""

from __future__ import annotations

import json
from pathlib import Path

from findevil_agent import accuracy

_A = "harassing email willselfdestruct anonymous remailer internal host"
_B = "gmail session cookie attributes host named individual suspect"
_C = "facebook authenticated login session distinct host correlation"


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


def _f(fid: str, desc: str, mitre: str = "T1071") -> dict:
    return {
        "finding_id": fid,
        "description": desc,
        "confidence": "CONFIRMED",
        "mitre_technique": mitre,
    }


def test_missed_by_name_lists_unrecalled_claims(tmp_path: Path) -> None:
    case = _case(tmp_path, [_f("r1", _A)])  # recalls only the first expected claim
    golden = _golden(tmp_path, [_f("e1", _A), _f("e2", _B), _f("e3", _C)])
    r = accuracy.score(case, golden)
    missed = r["missed_by_name"]
    assert missed["count"] == 2
    assert {m["finding_id"] for m in missed["items"]} == {"e2", "e3"}
    # each missed item is named, not just counted
    for m in missed["items"]:
        assert m["description"] and m["finding_id"]
    # count matches the recall gap
    assert missed["count"] == r["expected_n"] - r["recalled_n"]


def test_missed_by_name_empty_on_full_recall(tmp_path: Path) -> None:
    case = _case(tmp_path, [_f("r1", _A), _f("r2", _B)])
    golden = _golden(tmp_path, [_f("e1", _A), _f("e2", _B)])
    r = accuracy.score(case, golden)
    assert r["missed_by_name"]["count"] == 0
    assert r["missed_by_name"]["items"] == []


def test_score_report_surfaces_missed_by_name(tmp_path: Path) -> None:
    case = _case(tmp_path, [_f("r1", _A)])
    golden = _golden(tmp_path, [_f("e1", _A), _f("e2", _B)])
    report = accuracy.score_report(case, golden)
    ir = report["investigative_recall"]
    assert ir["missed_by_name"]["count"] == 1
    assert ir["missed_by_name"]["items"][0]["finding_id"] == "e2"


def test_no_key_missed_is_null_with_reason(tmp_path: Path) -> None:
    case = _case(tmp_path, [_f("r1", _A)])
    report = accuracy.score_report(case, None)
    missed = report["investigative_recall"]["missed_by_name"]
    assert missed["count"] is None
    assert missed["reason"] == "no_external_answer_key"
    assert missed["items"] == []
