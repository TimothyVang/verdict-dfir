"""Tests for SOUL.md HYPOTHESIS-prefix enforcement on the Finding model."""

from __future__ import annotations

import sys
from pathlib import Path

from findevil_agent.events import Finding

_SCRIPTS = Path(__file__).resolve().parent.parent.parent.parent / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fa  # noqa: E402


def _f(confidence: str, description: str) -> Finding:
    return Finding(
        case_id="c",
        finding_id="f-1",
        tool_call_id="tc-1",
        artifact_path="mem.raw",
        confidence=confidence,
        description=description,
    )


class TestHypothesisPrefix:
    def test_missing_prefix_is_prepended(self) -> None:
        f = _f("HYPOTHESIS", "malfind found injected VAD regions")
        assert f.description == "hypothesis: malfind found injected VAD regions"

    def test_existing_prefix_preserved(self) -> None:
        f = _f("HYPOTHESIS", "hypothesis: code injection lead")
        assert f.description == "hypothesis: code injection lead"

    def test_existing_prefix_case_insensitive(self) -> None:
        f = _f("HYPOTHESIS", "Hypothesis: code injection lead")
        assert f.description == "Hypothesis: code injection lead"  # not double-prefixed

    def test_confirmed_unchanged(self) -> None:
        f = _f("CONFIRMED", "EID 1102 audit-log clear")
        assert f.description == "EID 1102 audit-log clear"

    def test_inferred_unchanged(self) -> None:
        f = _f("INFERRED", "pslist=0 but psscan=N — DKOM")
        assert f.description == "pslist=0 but psscan=N — DKOM"


class TestNormalizeHypothesisPrefixDictPath:
    """The dict-path normalizer catches post-validation downgrades."""

    def test_downgraded_hypothesis_gets_prefix(self) -> None:
        # A finding the verifier downgraded to HYPOTHESIS after validation.
        findings = [{"confidence": "HYPOTHESIS", "description": "Authenticated webmail session"}]
        out = fa.normalize_hypothesis_prefix(findings)
        assert out[0]["description"] == "hypothesis: Authenticated webmail session"

    def test_existing_prefix_not_doubled(self) -> None:
        findings = [{"confidence": "HYPOTHESIS", "description": "hypothesis: already labeled"}]
        out = fa.normalize_hypothesis_prefix(findings)
        assert out[0]["description"] == "hypothesis: already labeled"

    def test_non_hypothesis_unchanged(self) -> None:
        findings = [
            {"confidence": "CONFIRMED", "description": "EID 1102"},
            {"confidence": "INFERRED", "description": "DKOM", "derived_from": ["a", "b"]},
        ]
        out = fa.normalize_hypothesis_prefix(findings)
        assert out[0]["description"] == "EID 1102"
        assert out[1]["description"] == "DKOM"
