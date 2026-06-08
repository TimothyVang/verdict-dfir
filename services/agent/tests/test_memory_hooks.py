"""Tests for ``findevil_agent.memory.hooks`` — pure recall/remember glue.

These helpers are the testable seam between the orchestrator and the Hermes
memory tools. They are pure dict->dict (no I/O), and they enforce the "memory
is never evidence" invariant at the data-shape layer:

- G1: ``attach_prior_observations`` never touches a finding's ``tool_call_id``.
- G2: ``hits_to_prior_observations`` emits only ``{case_id, ts, confidence}``.
- G5: ``confirmed_findings_for_remember`` keeps only CONFIRMED findings.
"""

from __future__ import annotations

import re

from findevil_agent.memory.hooks import (
    attach_prior_observations,
    confirmed_findings_for_remember,
    hits_to_prior_observations,
    recall_terms_for_finding,
    remember_payload_for_finding,
)

_HIT = {
    "case_id": "case-prev",
    "kind": "ioc",
    "key": "evil.example",
    "value": "evil.example c2 domain",
    "sha256": "sha256:" + "a" * 64,
    "ts": "2026-01-01T00:00:00Z",
    "confidence": 0.8,
}


def _finding(**overrides: object) -> dict:
    base: dict = {
        "case_id": "c-1",
        "finding_id": "f-1",
        "tool_call_id": "tc-1",
        "artifact_path": "x",
        "confidence": "CONFIRMED",
        "description": "benign description",
        "mitre_technique": None,
    }
    base.update(overrides)
    return base


class TestRecallTerms:
    def test_extracts_technique_and_iocs(self) -> None:
        f = _finding(
            mitre_technique="T1014",
            description="dropped evil.exe and beaconed to 10.0.0.5",
        )
        terms = recall_terms_for_finding(f)
        assert "T1014" in terms
        assert "evil.exe" in terms
        assert "10.0.0.5" in terms

    def test_no_signals_yields_empty(self) -> None:
        f = _finding(mitre_technique=None, description="nothing notable here")
        assert recall_terms_for_finding(f) == []

    def test_terms_are_deduped_in_order(self) -> None:
        f = _finding(
            mitre_technique="T1059",
            description="T1059 seen; 1.1.1.1 then 1.1.1.1 again",
        )
        terms = recall_terms_for_finding(f)
        assert terms.count("1.1.1.1") == 1
        assert terms[0] == "T1059"


class TestPriorObservations:
    def test_hits_map_to_context_keys_only(self) -> None:
        # G2: only the three context keys survive — no evidence handles.
        out = hits_to_prior_observations([_HIT])
        assert out == [{"case_id": "case-prev", "ts": "2026-01-01T00:00:00Z", "confidence": 0.8}]
        for forbidden in ("tool_call_id", "value", "sha256", "key", "kind"):
            assert forbidden not in out[0]

    def test_attach_preserves_tool_call_id(self) -> None:
        # G1: memory context never substitutes for the evidence citation.
        f = _finding(tool_call_id="tc-evidence")
        attached = attach_prior_observations(f, [_HIT])
        assert attached["tool_call_id"] == "tc-evidence"
        assert len(attached["prior_observations"]) == 1
        assert attached["prior_observations"][0]["case_id"] == "case-prev"

    def test_attach_does_not_mutate_input(self) -> None:
        f = _finding()
        attach_prior_observations(f, [_HIT])
        assert "prior_observations" not in f  # input untouched (immutability)

    def test_empty_hits_yield_empty_list(self) -> None:
        attached = attach_prior_observations(_finding(), [])
        assert attached["prior_observations"] == []


class TestRememberHelpers:
    def test_confirmed_only(self) -> None:
        # G5: only CONFIRMED findings are eligible to be remembered.
        merged = [
            _finding(finding_id="f-c", confidence="CONFIRMED"),
            _finding(finding_id="f-i", confidence="INFERRED"),
            _finding(finding_id="f-h", confidence="HYPOTHESIS"),
        ]
        kept = confirmed_findings_for_remember(merged)
        assert [f["finding_id"] for f in kept] == ["f-c"]

    def test_remember_payload_for_confirmed(self) -> None:
        f = _finding(
            confidence="CONFIRMED",
            mitre_technique="T1053.005",
            description="scheduled task persistence",
        )
        payload = remember_payload_for_finding(f)
        assert payload is not None
        assert payload["kind"] == "finding_summary"
        assert payload["key"] == "T1053.005"
        assert payload["value"] == "scheduled task persistence"
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", payload["sha256"])

    def test_remember_payload_none_for_non_confirmed(self) -> None:
        assert remember_payload_for_finding(_finding(confidence="INFERRED")) is None
        assert remember_payload_for_finding(_finding(confidence="HYPOTHESIS")) is None

    def test_remember_payload_falls_back_to_finding_id_key(self) -> None:
        f = _finding(confidence="CONFIRMED", mitre_technique=None, finding_id="f-xyz")
        payload = remember_payload_for_finding(f)
        assert payload is not None
        assert payload["key"] == "f-xyz"
