"""Tests for the SOUL.md ≥2-fact provenance gate.

Covers the ``derived_from`` field on the typed Finding model and the
``inference_provenance_warnings`` QA gate in ``scripts/find_evil_auto.py``,
which surfaces (never fabricates or drops) INFERRED findings that cite
fewer than two confirmed facts.
"""

from __future__ import annotations

import sys
from pathlib import Path

from findevil_agent.events import Finding

_SCRIPTS = Path(__file__).resolve().parent.parent.parent.parent / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fa  # noqa: E402


class TestFindingDerivedFrom:
    def test_inferred_finding_accepts_derived_from(self) -> None:
        f = Finding(
            case_id="c",
            finding_id="f-dkom",
            tool_call_id="tc-psxview",
            artifact_path="mem.raw",
            confidence="INFERRED",
            description="pslist=0 but psscan=N — selective DKOM",
            derived_from=["tc-pslist", "tc-psscan"],
        )
        assert f.derived_from == ["tc-pslist", "tc-psscan"]

    def test_derived_from_defaults_to_none(self) -> None:
        f = Finding(
            case_id="c",
            finding_id="f-confirmed",
            tool_call_id="tc-1",
            artifact_path="Security.evtx",
            confidence="CONFIRMED",
            description="EID 1102 audit-log clear",
        )
        assert f.derived_from is None


class TestInferenceProvenanceWarnings:
    def test_two_distinct_sources_no_warning(self) -> None:
        findings = [{"finding_id": "f1", "confidence": "INFERRED", "derived_from": ["a", "b"]}]
        assert fa.inference_provenance_warnings(findings) == []

    def test_single_source_warns(self) -> None:
        findings = [{"finding_id": "f2", "confidence": "INFERRED", "derived_from": ["a"]}]
        warnings = fa.inference_provenance_warnings(findings)
        assert len(warnings) == 1
        assert "f2" in warnings[0]
        assert "1 confirmed fact" in warnings[0]

    def test_missing_derived_from_warns(self) -> None:
        findings = [{"finding_id": "f3", "confidence": "INFERRED"}]
        warnings = fa.inference_provenance_warnings(findings)
        assert len(warnings) == 1
        assert "0 confirmed fact" in warnings[0]

    def test_duplicate_sources_count_once(self) -> None:
        findings = [{"finding_id": "f4", "confidence": "INFERRED", "derived_from": ["a", "a"]}]
        warnings = fa.inference_provenance_warnings(findings)
        assert len(warnings) == 1  # two cites, one distinct source → still under-corroborated

    def test_confirmed_and_hypothesis_ignored(self) -> None:
        findings = [
            {"finding_id": "f5", "confidence": "CONFIRMED"},
            {"finding_id": "f6", "confidence": "HYPOTHESIS"},
        ]
        assert fa.inference_provenance_warnings(findings) == []
