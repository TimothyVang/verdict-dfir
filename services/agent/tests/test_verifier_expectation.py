"""Tests for the falsifiable-expectation refutation gate (verifier).

Provenance pattern: when a pool proposes a finding it may commit to a PREDICTED,
refutable observation (``Finding.expectation``) the verifier can later check. If
the cited tool output CONTRADICTS the stated expectation, the finding is refuted
— rejected on the strongest tier, downgraded on lower tiers. Consistent or
silent (path absent) expectations pass.

This is the *inverse polarity* of the entailment check: entailment refutes when
an asserted value is ABSENT; the expectation refutes when the prediction is
actively CONTRADICTED by a present leaf. The gate is opt-in via
``FIND_EVIL_REQUIRE_EXPECTATION=1`` so default verdicts never change.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from findevil_agent.events import AssertedValue, Finding
from findevil_agent.mcp_client import MockMcpClient
from findevil_agent.verifier import reverify_finding


def _index_for(
    payload: dict[str, Any], tool_name: str = "prefetch_parse"
) -> dict[str, dict[str, Any]]:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {
        "tc-1": {
            "tool_name": tool_name,
            "arguments": {"case_id": "c-1"},
            "output_sha256": sha,
        }
    }


def _finding(
    confidence: str,
    expectation: AssertedValue | None,
    *,
    asserted: list[AssertedValue] | None = None,
) -> Finding:
    return Finding(
        case_id="c-1",
        finding_id="f-1",
        tool_call_id="tc-1",
        artifact_path="EVIL.EXE-1234.pf",
        confidence=confidence,
        description="ran 8 times",
        expectation=expectation,
        asserted_values=asserted or [],
    )


@pytest.fixture(autouse=True)
def _enable_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIND_EVIL_REQUIRE_EXPECTATION", "1")


class TestExpectationRefutes:
    """A CONFIRMED finding whose cited output contradicts its stated expectation
    is refuted (rejected). A lower tier is downgraded."""

    def test_contradicted_expectation_rejects_confirmed(self) -> None:
        # The finding predicts run_count 8; the cited output actually says 3.
        # The expectation is CONTRADICTED -> the CONFIRMED finding is refuted.
        payload = {"run_count": 3, "executable_name": "EVIL.EXE"}
        mcp = MockMcpClient()
        mcp.register("prefetch_parse", payload)
        f = _finding("CONFIRMED", AssertedValue(path="run_count", expected="8", match="int"))
        action, replay = reverify_finding(f, mcp=mcp, tool_call_index=_index_for(payload))
        assert action.action == "rejected"
        assert "expectation" in action.reason
        assert replay is not None
        # SHA still matched: the citation reproduces; the finding's PREDICTION is
        # what failed. Refutation is not drift.
        assert replay.artifact.drift_class == "exact_match"

    def test_contradicted_expectation_downgrades_inferred(self) -> None:
        payload = {"run_count": 3}
        mcp = MockMcpClient()
        mcp.register("prefetch_parse", payload)
        f = _finding("INFERRED", AssertedValue(path="run_count", expected="8", match="int"))
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=_index_for(payload))
        assert action.action == "downgraded"
        assert "expectation" in action.reason

    def test_contradicted_string_expectation_rejects(self) -> None:
        # Predicts the executable is EVIL.EXE; the evidence names BENIGN.EXE.
        payload = {"executable_name": "BENIGN.EXE"}
        mcp = MockMcpClient()
        mcp.register("prefetch_parse", payload)
        f = _finding("CONFIRMED", AssertedValue(path="executable_name", expected="EVIL.EXE"))
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=_index_for(payload))
        assert action.action == "rejected"
        assert "expectation" in action.reason


class TestExpectationConsistent:
    """A finding whose cited output AGREES with its stated expectation passes."""

    def test_consistent_expectation_approves(self) -> None:
        payload = {"run_count": 8}
        mcp = MockMcpClient()
        mcp.register("prefetch_parse", payload)
        f = _finding("CONFIRMED", AssertedValue(path="run_count", expected="8", match="int"))
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=_index_for(payload))
        assert action.action == "approved"

    def test_absent_path_does_not_refute(self) -> None:
        # The expectation's path reaches NOTHING in the cited output -> there is
        # no contradicting evidence, so the finding is not refuted (silent pass).
        # Refutation requires a present-but-conflicting leaf, never absence.
        payload = {"executable_name": "EVIL.EXE"}
        mcp = MockMcpClient()
        mcp.register("prefetch_parse", payload)
        f = _finding("CONFIRMED", AssertedValue(path="run_count", expected="8", match="int"))
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=_index_for(payload))
        assert action.action == "approved"


class TestExpectationGateDefaultOff:
    """Default-off: with the gate disabled, a contradicted expectation does NOT
    change the verdict (backward compatible)."""

    def test_gate_off_ignores_contradiction(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("FIND_EVIL_REQUIRE_EXPECTATION", raising=False)
        payload = {"run_count": 3}
        mcp = MockMcpClient()
        mcp.register("prefetch_parse", payload)
        f = _finding("CONFIRMED", AssertedValue(path="run_count", expected="8", match="int"))
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=_index_for(payload))
        assert action.action == "approved"


class TestExpectationOptional:
    """No expectation declared -> the gate is a no-op even when enabled."""

    def test_no_expectation_approves(self) -> None:
        payload = {"run_count": 3}
        mcp = MockMcpClient()
        mcp.register("prefetch_parse", payload)
        f = _finding("CONFIRMED", None)
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=_index_for(payload))
        assert action.action == "approved"
