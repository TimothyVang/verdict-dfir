"""score-overclaim.py R3 fidelity must score the asserted subset off the run-level signal.

Regression for a judging-pass false negative: every finding carries an
``asserted_values`` key (often empty), and the per-finding ``entailment`` /
``entailment_ok`` fields are null. The old filter therefore matched ALL findings
and counted ``entailment_ok is True`` per-finding (always 0), printing
"0% of N findings" on a run the leaderboard reports as "100% on the asserted
subset". The real signal is RUN-LEVEL: ``manifest_verify.json`` ``entailment_ok``.

These tests pin:
  - the R3-scored subset is only findings with a NON-EMPTY ``asserted_values``;
  - fidelity is 100% of that subset when run-level ``entailment_ok`` is True;
  - a per-finding ``entailment_ok is False`` is honored as a miss;
  - when no finding asserts values, the n/a path is preserved (no regression).

The scorer is a hyphenated maintainer tool, loaded via importlib.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS = _REPO_ROOT / "scripts"
_spec = importlib.util.spec_from_file_location("score_overclaim", _SCRIPTS / "score-overclaim.py")
assert _spec and _spec.loader
score_overclaim = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(score_overclaim)


def _case(
    tmp_path: Path,
    findings: list[dict],
    manifest: dict | None = None,
) -> Path:
    (tmp_path / "verdict.json").write_text(
        json.dumps({"case_id": "t", "verdict": "SUSPICIOUS", "findings": findings}),
        encoding="utf-8",
    )
    if manifest is not None:
        (tmp_path / "manifest_verify.json").write_text(json.dumps(manifest), encoding="utf-8")
    return tmp_path


def _finding(fid: str, asserted: list | None) -> dict:
    # Mirror the real shape: the key is always present, often empty; the
    # per-finding entailment fields are null (signal is run-level).
    return {
        "finding_id": fid,
        "asserted_values": asserted if asserted is not None else [],
        "entailment": None,
        "entailment_ok": None,
    }


def test_r3_scores_only_nonempty_asserted_subset_off_run_level_signal(tmp_path):
    # Arrange: 3 findings, only 1 declares non-empty asserted_values; run-level OK.
    findings = [
        _finding("F1", [{"path": "run_count", "expected": "2", "match": "int"}]),
        _finding("F2", []),
        _finding("F3", None),
    ]
    case = _case(tmp_path, findings, manifest={"overall": True, "entailment_ok": True})

    # Act
    r3 = score_overclaim.score(case)["r3_fidelity"]

    # Assert: subset is the 1 non-empty finding, 100% via the run-level signal.
    assert r3["available"] is True
    assert r3["scored_n"] == 1
    assert r3["fidelity_pass_rate"] == 1.0
    assert r3["run_entailment_ok"] is True
    assert r3["signal"] == "manifest_verify.entailment_ok"


def test_r3_run_level_false_means_zero_fidelity(tmp_path):
    # Arrange: asserted subset exists but the run-level entailment signal is False.
    findings = [_finding("F1", [{"path": "x", "expected": "1", "match": "int"}])]
    case = _case(tmp_path, findings, manifest={"overall": True, "entailment_ok": False})

    # Act / Assert
    r3 = score_overclaim.score(case)["r3_fidelity"]
    assert r3["scored_n"] == 1
    assert r3["fidelity_pass_rate"] == 0.0


def test_r3_per_finding_false_is_honored_as_miss(tmp_path):
    # Arrange: run-level OK, but one asserted finding explicitly failed entailment.
    f = _finding("F1", [{"path": "x", "expected": "1", "match": "int"}])
    f["entailment_ok"] = False
    case = _case(tmp_path, [f], manifest={"overall": True, "entailment_ok": True})

    # Act / Assert: a per-finding False overrides the run-level pass.
    r3 = score_overclaim.score(case)["r3_fidelity"]
    assert r3["scored_n"] == 1
    assert r3["fidelity_pass_rate"] == 0.0


def test_r3_na_path_preserved_when_no_finding_asserts_values(tmp_path):
    # Arrange: keys present but all empty (older, pre-R3-emission runs).
    findings = [_finding("F1", []), _finding("F2", [])]
    case = _case(tmp_path, findings, manifest={"overall": True})

    # Act / Assert: n/a path with the original reason, no regression.
    r3 = score_overclaim.score(case)["r3_fidelity"]
    assert r3["available"] is False
    assert "no asserted_values to re-check" in r3["reason"]
