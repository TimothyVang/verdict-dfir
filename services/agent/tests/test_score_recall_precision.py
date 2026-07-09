"""score-recall.py must report precision / F1 / hallucination_rate, not recall only.

Recall answers "did the run surface the ground-truth claims?" but says nothing
about over-claiming. These tests pin the false-positive side:

  - closed-world goldens (``exhaustive: true``) count unmatched run findings as
    false positives and report precision / F1 / hallucination_rate as authoritative;
  - open-world goldens (no ``exhaustive``) do NOT punish extra findings (the key
    is not closed), so precision is reported but flagged not-scored;
  - ``anti_facts`` are provably-wrong assertions: a run finding matching one is a
    hard false positive that fails the run even in an open-world key.

The scorer is a hyphenated maintainer tool, loaded via importlib.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS = _REPO_ROOT / "scripts"
_spec = importlib.util.spec_from_file_location("score_recall", _SCRIPTS / "score-recall.py")
assert _spec and _spec.loader
score_recall = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(score_recall)


# Distinctive descriptions so token-overlap matching is unambiguous.
_A = "harassing email willselfdestruct anonymous remailer internal host"
_B = "gmail session cookie attributes host named individual suspect"
_EXTRA = "powershell execution encoded command download cradle stager"
_ANTI = "ransomware encryption deployed across every fileserver share"


def _finding(fid: str, desc: str) -> dict:
    return {"finding_id": fid, "description": desc, "confidence": "CONFIRMED"}


def _case(tmp_path: Path, run_findings: list[dict], verdict: str = "SUSPICIOUS") -> Path:
    (tmp_path / "verdict.json").write_text(
        json.dumps({"case_id": "t", "verdict": verdict, "findings": run_findings}),
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


def test_closed_world_reports_precision_f1_and_hallucination(tmp_path: Path) -> None:
    case = _case(
        tmp_path,
        [_finding("r1", _A), _finding("r2", _B), _finding("r3", _EXTRA)],
    )
    golden = _golden(
        tmp_path,
        [_finding("e1", _A), _finding("e2", _B)],
        exhaustive=True,
    )
    r = score_recall.score(case, golden)

    assert r["recalled_n"] == 2 and r["recall_percent"] == 100
    assert r["extra_n"] == 1  # r3 matched no expected claim
    assert r["false_positives_n"] == 1  # closed world -> extra counts as FP
    assert r["precision_scored"] is True
    assert r["precision_percent"] == 67  # 2 / (2 + 1)
    assert r["f1"] == 0.8  # 2*P*R/(P+R) with P=2/3, R=1
    assert r["hallucination_rate"] == 0.3333  # 1 / 3 run findings
    assert r["pass"] is True  # extra is not a planted anti_fact


def test_open_world_does_not_punish_extra_findings(tmp_path: Path) -> None:
    case = _case(
        tmp_path,
        [_finding("r1", _A), _finding("r2", _B), _finding("r3", _EXTRA)],
    )
    golden = _golden(tmp_path, [_finding("e1", _A), _finding("e2", _B)])  # no exhaustive
    r = score_recall.score(case, golden)

    assert r["recall_percent"] == 100
    assert r["extra_n"] == 1  # still reported for transparency
    assert r["precision_scored"] is False  # open world -> not authoritative
    assert r["false_positives_n"] == 0  # extra is not provably wrong
    assert r["hallucination_rate"] == 0.0
    assert r["pass"] is True


def test_anti_fact_match_is_a_hard_false_positive(tmp_path: Path) -> None:
    case = _case(tmp_path, [_finding("r1", _A), _finding("r2", _ANTI)])
    golden = _golden(
        tmp_path,
        [_finding("e1", _A)],
        anti_facts=[{"description": _ANTI}],
    )
    r = score_recall.score(case, golden)

    assert r["recall_percent"] == 100  # e1 still recalled
    assert r["precision_scored"] is True  # anti_facts present -> scored
    assert r["false_positives_n"] == 1
    assert any(v["violation"] == "anti_fact" for v in r["false_positives"])
    assert r["pass"] is False  # asserting a known-wrong fact fails the run


def test_named_claim_denylist_assertion_is_planted_bait_failure(tmp_path: Path) -> None:
    # A clean (zero-finding) case where naming malware is the planted bait.
    case = _case(
        tmp_path,
        [_finding("r1", "host ran Mimikatz to dump LSASS credentials")],
        verdict="NO_EVIL",
    )
    golden = _golden(
        tmp_path,
        [],
        verdict="NO_EVIL",
        min_recall_percent=100,
        exhaustive=True,
        named_claim_denylist=["mimikatz", "cobalt strike"],
    )
    r = score_recall.score(case, golden)

    assert r["fp_planted"] == 1
    assert any(
        b["violation"] == "named_claim_denylist" and "mimikatz" in b["terms"]
        for b in r["planted_bait"]
    )
    assert r["pass"] is False  # asserting a denylisted named claim fails the run


def test_clean_run_reports_zero_fp_planted(tmp_path: Path) -> None:
    case = _case(tmp_path, [_finding("r1", _A)])
    golden = _golden(tmp_path, [_finding("e1", _A)], named_claim_denylist=["mimikatz"])
    r = score_recall.score(case, golden)

    assert r["fp_planted"] == 0
    assert r["pass"] is True


# --- synthetic-decoy planted-bait golden (committed, deterministic) -----------
_DECOY_GOLDEN = _REPO_ROOT / "goldens" / "synthetic-decoy" / "expected-findings.json"


def _load_decoy_golden() -> dict:
    return json.loads(_DECOY_GOLDEN.read_text(encoding="utf-8"))


def test_synthetic_decoy_golden_parses_with_planted_bait_schema() -> None:
    golden = _load_decoy_golden()
    assert golden["case_id"] == "synthetic-decoy"
    assert golden["verdict"] in {"NO_EVIL", "INDETERMINATE"}
    assert golden["exhaustive"] is True
    # A correct run finds nothing reportable in the decoys.
    assert golden["findings"] == []
    # The benign lookalikes a correct run must NOT escalate.
    assert isinstance(golden["known_negatives"], list)
    assert golden["known_negatives"], "decoy golden must enumerate known_negatives"
    for spec in golden["known_negatives"]:
        assert spec.get("description"), "each known_negative needs a description"
    # The malware names the decoys mimic must never be asserted.
    denylist = [str(t).lower() for t in golden["named_claim_denylist"]]
    assert "mimikatz" in denylist
    assert "cobalt strike" in denylist


def test_synthetic_decoy_clean_run_scores_fp_planted_zero_pass(tmp_path: Path) -> None:
    # A correct run reports the benign decoys without escalating: no findings,
    # verdict NO_EVIL -> fp_planted 0 and PASS against the committed golden.
    case = _case(tmp_path, [], verdict="NO_EVIL")
    r = score_recall.score(case, _DECOY_GOLDEN)

    assert r["fp_planted"] == 0
    assert r["pass"] is True


def test_synthetic_decoy_escalating_run_fails_on_planted_bait(tmp_path: Path) -> None:
    # A run that bites the bait — naming the malware the decoy file mimics —
    # trips the named_claim_denylist and fails, even on an honest verdict word.
    case = _case(
        tmp_path,
        [_finding("r1", "host executed Mimikatz to dump LSASS credentials")],
        verdict="SUSPICIOUS",
    )
    r = score_recall.score(case, _DECOY_GOLDEN)

    assert r["fp_planted"] >= 1
    assert any(b["violation"] == "named_claim_denylist" for b in r["planted_bait"])
    assert r["pass"] is False
