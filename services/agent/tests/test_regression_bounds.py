"""Tests for the accuracy regression-bounds check.

``scripts/score-regression-bounds.py`` is a post-run guard: after ``score-recall.py``
writes ``<case>/recall-score.json``, this asserts the metrics have not regressed below
a committed floor in ``goldens/<case>/regression-bounds.json`` (recall floor, precision
floor, hallucination ceiling, planted-bait ceiling, verdict-match). It catches a prompt
or tool edit that silently drops recall or lets a hallucination through.

The floor is the *reproducible* number, not the aspirational bar — e.g. NIST's
run-to-run recall is 5/14 (36%) on leaner runs, so the floor is 36, well below the 71%
golden target, so the guard fires only on a genuine regression below what we ship.

These tests exercise the pure ``check_bounds`` logic (CI-safe, no run dir needed).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

_SPEC = importlib.util.spec_from_file_location(
    "score_regression_bounds", _SCRIPTS / "score-regression-bounds.py"
)
assert _SPEC and _SPEC.loader
srb = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(srb)


_METRICS = {
    "recall_percent": 36,
    "precision_percent": 100,
    "hallucination_rate": 0.0,
    "fp_planted": 0,
    "verdict_match": True,
}


def test_metrics_at_floor_pass() -> None:
    bounds = {
        "min_recall_percent": 36,
        "min_precision_percent": 90,
        "max_hallucination_rate": 0.0,
        "max_fp_planted": 0,
        "require_verdict_match": True,
    }
    assert srb.check_bounds(_METRICS, bounds) == []


def test_recall_regression_below_floor_fails() -> None:
    bounds = {"min_recall_percent": 50}
    violations = srb.check_bounds(_METRICS, bounds)
    assert len(violations) == 1
    assert "recall" in violations[0].lower()


def test_hallucination_above_ceiling_fails() -> None:
    metrics = {**_METRICS, "hallucination_rate": 0.05}
    violations = srb.check_bounds(metrics, {"max_hallucination_rate": 0.0})
    assert len(violations) == 1
    assert "halluc" in violations[0].lower()


def test_planted_bait_asserted_fails() -> None:
    metrics = {**_METRICS, "fp_planted": 2}
    violations = srb.check_bounds(metrics, {"max_fp_planted": 0})
    assert len(violations) == 1
    assert "bait" in violations[0].lower() or "planted" in violations[0].lower()


def test_verdict_mismatch_fails_when_required() -> None:
    metrics = {**_METRICS, "verdict_match": False}
    violations = srb.check_bounds(metrics, {"require_verdict_match": True})
    assert len(violations) == 1
    assert "verdict" in violations[0].lower()


def test_unknown_bound_key_is_rejected() -> None:
    # A typo in a bounds file must fail loudly, not silently pass.
    try:
        srb.check_bounds(_METRICS, {"min_recal_percent": 36})
    except ValueError as exc:
        assert "min_recal_percent" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError on unknown bound key")


def test_comment_key_is_ignored() -> None:
    # "_comment" is a doc convention, not a typo — it must not raise.
    bounds = {"_comment": "the floor rationale", "min_recall_percent": 36}
    assert srb.check_bounds(_METRICS, bounds) == []
