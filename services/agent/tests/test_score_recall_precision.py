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


def _ready_decoy_golden(tmp_path: Path) -> Path:
    golden = _load_decoy_golden()
    golden["scoring_status"] = "ready"
    golden.pop("not_ready_reason", None)
    path = tmp_path / "synthetic-decoy-ready.json"
    path.write_text(json.dumps(golden), encoding="utf-8")
    return path


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
    r = score_recall.score(case, _ready_decoy_golden(tmp_path))

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
    r = score_recall.score(case, _ready_decoy_golden(tmp_path))

    assert r["fp_planted"] >= 1
    assert any(b["violation"] == "named_claim_denylist" for b in r["planted_bait"])
    assert r["pass"] is False


# --- CLI exit codes: excluded-by-key is not an accuracy failure ---------------
#
# `scripts/score-recall.py` collapsed every refusal into exit 2, and
# `l3-run-goldens.sh` maps any non-zero to "FAIL ... (see recall-score.json)" —
# a file exit 2 never writes. So a key that says "do not score me" was reported
# as an accuracy FAIL with unknown metrics. These pin the four distinct codes:
#   0 PASS, 1 real FAIL (metrics exist), 2 scorer/lookup ERROR, 3 EXCLUDED by key.

_NOT_READY_GOLDEN_DIR = _REPO_ROOT / "goldens" / "synthetic-benign"


def _cli_case(tmp_path: Path, case_id: str, verdict: str, findings: list[dict]) -> Path:
    case_dir = tmp_path / f"{case_id}-case"
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "verdict.json").write_text(
        json.dumps(
            {
                "case_id": case_id,
                "verdict": verdict,
                "findings": findings,
                "tool_calls": [{"tool_call_id": "tc-1", "tool": "case_open"}],
            }
        ),
        encoding="utf-8",
    )
    return case_dir


def test_cli_exit_codes_are_named_constants() -> None:
    assert score_recall.EXIT_PASS == 0
    assert score_recall.EXIT_FAIL == 1
    assert score_recall.EXIT_ERROR == 2
    assert score_recall.EXIT_NOT_SCOREABLE == 3


def test_cli_returns_3_and_prints_the_keys_reason_for_a_not_ready_golden(
    tmp_path: Path, capsys
) -> None:
    case_dir = _cli_case(tmp_path, "synthetic-benign", "NO_EVIL", [])
    declared = json.loads(
        (_NOT_READY_GOLDEN_DIR / "expected-findings.json").read_text(encoding="utf-8")
    )

    rc = score_recall.main(
        ["score-recall.py", str(case_dir), "--golden", str(_NOT_READY_GOLDEN_DIR)]
    )

    assert rc == score_recall.EXIT_NOT_SCOREABLE
    out = capsys.readouterr()
    combined = out.out + out.err
    assert "EXCLUDED" in combined
    assert "synthetic-benign" in combined
    # The reader learns WHY from the key itself, not from a guess.
    assert declared["not_ready_reason"] in combined
    # Never presented as an accuracy result.
    assert "FAIL" not in combined


def test_cli_exclusion_writes_a_machine_readable_marker_not_a_score(tmp_path: Path) -> None:
    case_dir = _cli_case(tmp_path, "synthetic-benign", "NO_EVIL", [])

    rc = score_recall.main(
        ["score-recall.py", str(case_dir), "--golden", str(_NOT_READY_GOLDEN_DIR), "--quiet"]
    )

    assert rc == score_recall.EXIT_NOT_SCOREABLE
    # No score file: there is no score. A board that reads recall-score.json must
    # not find a document it can mistake for metrics.
    assert not (case_dir / "recall-score.json").exists()
    marker = case_dir / "recall-excluded.json"
    assert marker.is_file()
    payload = json.loads(marker.read_text(encoding="utf-8"))
    assert payload["excluded"] is True
    assert payload["case_id"] == "synthetic-benign"
    assert payload["scoring_status"] == "not_ready"
    assert payload["reason"]
    assert "pass" not in payload
    assert "recall_percent" not in payload


def test_cli_still_returns_2_for_an_unpopulated_stub_golden(tmp_path: Path) -> None:
    stub_dir = tmp_path / "stub-golden"
    stub_dir.mkdir(parents=True, exist_ok=True)
    (stub_dir / "expected-findings.json").write_text(
        json.dumps(
            {
                "case_id": "stub-key",
                "verdict": "UNKNOWN",
                "min_recall_percent": None,
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    case_dir = _cli_case(tmp_path, "stub-key", "UNKNOWN", [])

    rc = score_recall.main(["score-recall.py", str(case_dir), "--golden", str(stub_dir)])

    assert rc == score_recall.EXIT_ERROR
    assert not (case_dir / "recall-excluded.json").exists()


def test_cli_still_returns_1_for_a_real_accuracy_failure(tmp_path: Path) -> None:
    golden_dir = tmp_path / "real-golden"
    golden_dir.mkdir(parents=True, exist_ok=True)
    (golden_dir / "expected-findings.json").write_text(
        json.dumps(
            {
                "case_id": "real-key",
                "verdict": "SUSPICIOUS",
                "min_recall_percent": 100,
                "findings": [_finding("g1", _A)],
            }
        ),
        encoding="utf-8",
    )
    case_dir = _cli_case(tmp_path, "real-key", "SUSPICIOUS", [])

    rc = score_recall.main(
        ["score-recall.py", str(case_dir), "--golden", str(golden_dir), "--quiet"]
    )

    assert rc == score_recall.EXIT_FAIL
    # A real FAIL still leaves the metrics the runner's message points at.
    assert (case_dir / "recall-score.json").is_file()
