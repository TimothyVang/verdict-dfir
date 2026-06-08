"""Tests for the inline Hermes memory glue in ``scripts/find_evil_auto.py``.

The host engine runs under bare ``python3`` (3.10) and cannot import the 3.11+
``findevil_agent`` package, so the recall/remember helpers are inlined in
``find_evil_auto.py``. These tests import that module (under the 3.11+ agent
venv, where its guarded findevil_agent import succeeds) and exercise the ACTUAL
engine functions, pinning the "memory is never evidence" invariant at the data
layer:

- G1: ``mem_attach_prior_observations`` never touches a finding's ``tool_call_id``.
- G2: ``mem_hits_to_prior_observations`` emits only ``{case_id, ts, confidence}``.
- G5: ``mem_confirmed_for_remember`` keeps only CONFIRMED findings.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

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
        terms = fea.mem_recall_terms(f)
        assert "T1014" in terms
        assert "evil.exe" in terms
        assert "10.0.0.5" in terms

    def test_no_signals_yields_empty(self) -> None:
        assert fea.mem_recall_terms(_finding(description="nothing notable here")) == []

    def test_terms_are_deduped_in_order(self) -> None:
        f = _finding(
            mitre_technique="T1059",
            description="T1059 seen; 1.1.1.1 then 1.1.1.1 again",
        )
        terms = fea.mem_recall_terms(f)
        assert terms.count("1.1.1.1") == 1
        assert terms[0] == "T1059"


class TestPriorObservations:
    def test_hits_map_to_context_keys_only(self) -> None:
        # G2: only the three context keys survive — no evidence handles.
        out = fea.mem_hits_to_prior_observations([_HIT])
        assert out == [{"case_id": "case-prev", "ts": "2026-01-01T00:00:00Z", "confidence": 0.8}]
        for forbidden in ("tool_call_id", "value", "sha256", "key", "kind"):
            assert forbidden not in out[0]

    def test_attach_preserves_tool_call_id(self) -> None:
        # G1: memory context never substitutes for the evidence citation.
        f = _finding(tool_call_id="tc-evidence")
        attached = fea.mem_attach_prior_observations(f, [_HIT])
        assert attached["tool_call_id"] == "tc-evidence"
        assert attached["prior_observations"][0]["case_id"] == "case-prev"

    def test_attach_does_not_mutate_input(self) -> None:
        f = _finding()
        fea.mem_attach_prior_observations(f, [_HIT])
        assert "prior_observations" not in f  # input untouched (immutability)

    def test_empty_hits_yield_empty_list(self) -> None:
        assert fea.mem_attach_prior_observations(_finding(), [])["prior_observations"] == []


class TestRememberHelpers:
    def test_confirmed_only(self) -> None:
        # G5: only CONFIRMED findings are eligible to be remembered.
        merged = [
            _finding(finding_id="f-c", confidence="CONFIRMED"),
            _finding(finding_id="f-i", confidence="INFERRED"),
            _finding(finding_id="f-h", confidence="HYPOTHESIS"),
        ]
        assert [f["finding_id"] for f in fea.mem_confirmed_for_remember(merged)] == ["f-c"]

    def test_remember_payload_for_confirmed(self) -> None:
        f = _finding(
            confidence="CONFIRMED",
            mitre_technique="T1053.005",
            description="scheduled task persistence",
        )
        payload = fea.mem_remember_payload(f)
        assert payload is not None
        assert payload["kind"] == "finding_summary"
        assert payload["key"] == "T1053.005"
        assert payload["value"] == "scheduled task persistence"
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", payload["sha256"])

    def test_remember_payload_none_for_non_confirmed(self) -> None:
        assert fea.mem_remember_payload(_finding(confidence="INFERRED")) is None
        assert fea.mem_remember_payload(_finding(confidence="HYPOTHESIS")) is None

    def test_remember_payload_falls_back_to_finding_id_key(self) -> None:
        f = _finding(confidence="CONFIRMED", mitre_technique=None, finding_id="f-xyz")
        assert fea.mem_remember_payload(f)["key"] == "f-xyz"


class TestStorePath:
    def test_explicit_override_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FINDEVIL_MEMORY_STORE", "/tmp/custom/memory.sqlite")
        assert fea.mem_store_path() == "/tmp/custom/memory.sqlite"

    def test_findevil_home_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("FINDEVIL_MEMORY_STORE", raising=False)
        monkeypatch.setenv("FINDEVIL_HOME", "/tmp/case-home")
        assert fea.mem_store_path() == "/tmp/case-home/memory/memory.sqlite"
