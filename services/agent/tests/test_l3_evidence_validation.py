"""Regression tests for local L3 fallback evidence validation."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS = _ROOT / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


validate_l3_evidence = _load("validate-l3-evidence")


def _l3_fallback_evidence() -> dict:
    evidence_path = _ROOT / "docs" / "release-evidence" / "l3-local-sift.json"
    return json.loads(evidence_path.read_text(encoding="utf-8"))


def test_committed_l3_fallback_fails_when_recall_gate_fails() -> None:
    errors = validate_l3_evidence.validate_evidence(_l3_fallback_evidence())

    assert "recall.pass must be true" in errors


def test_l3_fallback_fails_when_recall_percent_is_below_minimum() -> None:
    evidence = _l3_fallback_evidence()
    evidence["recall"] = {
        **evidence["recall"],
        "pass": True,
        "recall_percent": 70,
        "min_recall_percent": 71,
    }

    errors = validate_l3_evidence.validate_evidence(evidence)

    assert "recall.recall_percent must be >= recall.min_recall_percent" in errors


def test_l3_fallback_fails_when_recall_percent_does_not_match_counts() -> None:
    evidence = _l3_fallback_evidence()
    evidence["recall"] = {
        **evidence["recall"],
        "pass": True,
        "recalled_n": 7,
        "expected_n": 14,
        "recall_percent": 71,
        "min_recall_percent": 71,
    }

    errors = validate_l3_evidence.validate_evidence(evidence)

    assert "recall.recall_percent must match recalled_n / expected_n" in errors


def test_l3_fallback_still_requires_a_real_product_commit() -> None:
    evidence = _l3_fallback_evidence()
    evidence["product_commit"] = "not-a-sha"

    errors = validate_l3_evidence.validate_evidence(evidence)

    assert "product_commit must be a 40-character lowercase hex SHA" in errors


def test_l3_fallback_fails_when_the_record_is_stale() -> None:
    """Staleness is the honest question; matching today's HEAD is not.

    The old check compared product_commit to $GITHUB_SHA, so it failed on every commit that was
    not the one the record happened to be generated on -- permanently, on every push, regardless
    of product quality. It fired for 14 consecutive nights while saying nothing about the
    product. Age is what distinguishes a usable record from an abandoned one.
    """
    evidence = _l3_fallback_evidence()
    evidence["generated_at_utc"] = "2020-01-01T00:00:00Z"

    errors = validate_l3_evidence.validate_evidence(evidence, max_age_days=30)

    assert any("evidence is stale" in error for error in errors)


def test_l3_fallback_accepts_a_recent_record_on_a_different_commit() -> None:
    evidence = _l3_fallback_evidence()
    evidence["generated_at_utc"] = "2999-01-01T00:00:00Z"

    errors = validate_l3_evidence.validate_evidence(evidence, max_age_days=30)

    assert not any("stale" in error for error in errors)
    assert not any("product_commit must match" in error for error in errors)


def test_recall_failure_stays_a_hard_error_named_as_product_signal() -> None:
    """A failing recall must remain a hard error and be classified as product signal.

    Downgrading it to a warning would turn L3 green while nist-hacking-case scores 50% against a
    71% bar -- the exact failure mode this gate exists to prevent.
    """
    errors = validate_l3_evidence.validate_evidence(_l3_fallback_evidence())

    assert "recall.pass must be true" in errors
    assert "recall.pass must be true" in validate_l3_evidence.PRODUCT_GATE_ERRORS


def test_l3_fallback_fails_without_itemized_recall_ids() -> None:
    evidence = _l3_fallback_evidence()
    evidence["recall"] = {
        **evidence["recall"],
        "pass": True,
        "recalled_n": 14,
        "expected_n": 14,
        "recall_percent": 100,
        "min_recall_percent": 71,
    }
    del evidence["recall"]["matched_ids"]
    del evidence["recall"]["unmatched_ids"]

    errors = validate_l3_evidence.validate_evidence(evidence)

    assert "recall.matched_ids must be a list" in errors
    assert "recall.unmatched_ids must be a list" in errors


def test_l3_fallback_accepts_synthesized_passing_packet() -> None:
    evidence = _l3_fallback_evidence()
    expected_commit = "a" * 40
    evidence["product_commit"] = expected_commit
    evidence["recall"] = {
        **evidence["recall"],
        "pass": True,
        "recalled_n": 14,
        "expected_n": 14,
        "recall_percent": 100,
        "min_recall_percent": 71,
        "matched_ids": [f"nhc-{index:03d}" for index in range(1, 15)],
        "unmatched_ids": [],
    }

    errors = validate_l3_evidence.validate_evidence(evidence, expected_commit=expected_commit)

    assert errors == []
