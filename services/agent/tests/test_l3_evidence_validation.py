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


def test_l3_fallback_fails_when_product_commit_is_not_expected_commit() -> None:
    evidence = _l3_fallback_evidence()

    errors = validate_l3_evidence.validate_evidence(evidence, expected_commit="a" * 40)

    assert "product_commit must match expected commit" in errors


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
