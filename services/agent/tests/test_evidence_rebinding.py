"""Two verifier-discipline gates in ``findevil_agent.verifier.reverify_finding``.

Gate 1 — EVIDENCE RE-BINDING (FIND_EVIL_REQUIRE_ARTIFACT_REBIND=1, default-off):
    The model PROPOSES ``finding.artifact_path``, but the server RE-DERIVES the
    artifact from the cited tool_call's recorded ``arguments`` (the ``*_path``
    the tool was actually given) and REJECTS the finding when the model's claimed
    artifact does not match any path the cited call read. This hardens a finding
    that glues a REAL ``tool_call_id`` to a FABRICATED artifact: the citation
    reproduces (SHA matches) yet points at evidence the model never actually
    cited. drift_class on rejection is ``artifact_rebind_mismatch``.

Gate 2 — ANTI-COHERENCE "TOO CLEAN" PREFLIGHT
    (FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING=1, default-off):
    A CONFIRMED finding lacking a populated ``counter_hypothesis`` fails a hard
    preflight in ``reverify_finding`` before any replay — a confident claim that
    considered no benign alternative is the "too clean" tell. drift_class on
    rejection is ``counter_hypothesis_missing``.

Both default-OFF so existing emitters/findings stay valid until rollout flips
the flag, mirroring the ``FIND_EVIL_REQUIRE_ASSERTED_VALUES`` pattern.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from findevil_agent.events import Finding
from findevil_agent.mcp_client import MockMcpClient
from findevil_agent.verifier import reverify_finding


def _sha(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _index(
    *,
    tool_name: str,
    arguments: dict[str, Any],
    output_sha256: str,
) -> dict[str, dict[str, Any]]:
    return {
        "tc-1": {
            "tool_name": tool_name,
            "arguments": arguments,
            "output_sha256": output_sha256,
        }
    }


def _finding(
    *,
    artifact_path: str,
    confidence: str = "CONFIRMED",
    counter_hypothesis: str | None = None,
) -> Finding:
    return Finding(
        case_id="c-1",
        finding_id="f-1",
        tool_call_id="tc-1",
        artifact_path=artifact_path,
        confidence=confidence,
        description="logon from 192.168.1.5",
        counter_hypothesis=counter_hypothesis,
    )


# ---------------------------------------------------------------------------
# Gate 1 — evidence re-binding.
# ---------------------------------------------------------------------------


class TestEvidenceRebinding:
    _GATE = "FIND_EVIL_REQUIRE_ARTIFACT_REBIND"

    def _setup(self, *, evtx_path: str, payload: dict[str, Any]) -> tuple[MockMcpClient, dict]:
        mcp = MockMcpClient()
        mcp.register("evtx_query", payload)
        index = _index(
            tool_name="evtx_query",
            arguments={"case_id": "c-1", "evtx_path": evtx_path},
            output_sha256=_sha(payload),
        )
        return mcp, index

    def test_mismatched_artifact_rejected_when_flag_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Real tool_call_id, SHA reproduces, but the cited call read
        # Security.evtx while the model claims System.evtx — a real token glued
        # to a fabricated artifact. Re-binding rejects it.
        monkeypatch.setenv(self._GATE, "1")
        payload = {"row_count": 7}
        mcp, index = self._setup(evtx_path="/case/Security.evtx", payload=payload)
        f = _finding(artifact_path="System.evtx")
        action, replay = reverify_finding(f, mcp=mcp, tool_call_index=index)
        assert action.action == "rejected"
        assert "rebind" in action.reason.lower() or "artifact" in action.reason.lower()
        assert replay is not None
        assert replay.artifact.drift_class == "artifact_rebind_mismatch"

    def test_matching_artifact_basename_approves_when_flag_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The finding cites the same artifact the tool read (by basename), so the
        # re-binding passes and the normal SHA path approves.
        monkeypatch.setenv(self._GATE, "1")
        payload = {"row_count": 7}
        mcp, index = self._setup(evtx_path="/case/Security.evtx", payload=payload)
        f = _finding(artifact_path="Security.evtx")
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=index)
        assert action.action == "approved"

    def test_matching_full_path_approves_when_flag_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(self._GATE, "1")
        payload = {"row_count": 7}
        mcp, index = self._setup(evtx_path="/case/Security.evtx", payload=payload)
        f = _finding(artifact_path="/case/Security.evtx")
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=index)
        assert action.action == "approved"

    def test_mismatch_ignored_when_flag_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Default-off: a mismatched artifact is NOT gated (backward compatible),
        # so the finding still approves on the SHA path.
        monkeypatch.delenv(self._GATE, raising=False)
        payload = {"row_count": 7}
        mcp, index = self._setup(evtx_path="/case/Security.evtx", payload=payload)
        f = _finding(artifact_path="System.evtx")
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=index)
        assert action.action == "approved"

    def test_rebind_runs_before_replay(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The rebind veto is a preflight: it fires even when the tool re-run would
        # itself fail (no handler registered), so a fabricated artifact is caught
        # without spending a replay.
        monkeypatch.setenv(self._GATE, "1")
        mcp = MockMcpClient()  # no handler -> replay would error
        index = _index(
            tool_name="evtx_query",
            arguments={"case_id": "c-1", "evtx_path": "/case/Security.evtx"},
            output_sha256=_sha({"row_count": 7}),
        )
        f = _finding(artifact_path="System.evtx")
        action, replay = reverify_finding(f, mcp=mcp, tool_call_index=index)
        assert action.action == "rejected"
        assert replay is not None
        assert replay.artifact.drift_class == "artifact_rebind_mismatch"
        assert mcp.calls == []  # no replay was attempted

    def test_no_path_argument_does_not_gate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # When the cited call carries no ``*_path`` argument (nothing to
        # re-derive against), the gate cannot bind and must not fabricate a
        # rejection — it falls through to the normal SHA path.
        monkeypatch.setenv(self._GATE, "1")
        payload = {"row_count": 7}
        mcp = MockMcpClient()
        mcp.register("evtx_query", payload)
        index = _index(
            tool_name="evtx_query",
            arguments={"case_id": "c-1"},
            output_sha256=_sha(payload),
        )
        f = _finding(artifact_path="Security.evtx")
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=index)
        assert action.action == "approved"


# ---------------------------------------------------------------------------
# Gate 2 — anti-coherence "too clean" preflight.
# ---------------------------------------------------------------------------


class TestCounterHypothesisPreflight:
    _GATE = "FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING"

    def _approving_setup(self) -> tuple[MockMcpClient, dict]:
        payload = {"row_count": 7}
        mcp = MockMcpClient()
        mcp.register("evtx_query", payload)
        index = _index(
            tool_name="evtx_query",
            arguments={"case_id": "c-1", "evtx_path": "/case/Security.evtx"},
            output_sha256=_sha(payload),
        )
        return mcp, index

    def test_confirmed_without_counter_hypothesis_rejected_when_flag_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The verifier preflight is the enforcement point for a finding that
        # reaches reverify WITHOUT the schema validator firing — e.g.
        # reconstructed from an audit record, or drafted before the flag flipped.
        # Build the finding flag-OFF, then turn the flag ON for the reverify call.
        mcp, index = self._approving_setup()
        f = _finding(artifact_path="/case/Security.evtx", counter_hypothesis=None)
        monkeypatch.setenv(self._GATE, "1")
        action, replay = reverify_finding(f, mcp=mcp, tool_call_index=index)
        assert action.action == "rejected"
        assert "counter" in action.reason.lower()
        assert replay is not None
        assert replay.artifact.drift_class == "counter_hypothesis_missing"
        assert mcp.calls == []  # preflight fires before replay

    def test_confirmed_with_blank_counter_hypothesis_rejected_when_flag_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mcp, index = self._approving_setup()
        f = _finding(artifact_path="/case/Security.evtx", counter_hypothesis="   ")
        monkeypatch.setenv(self._GATE, "1")
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=index)
        assert action.action == "rejected"

    def test_confirmed_with_populated_counter_hypothesis_approves_when_flag_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(self._GATE, "1")
        mcp, index = self._approving_setup()
        f = _finding(
            artifact_path="/case/Security.evtx",
            counter_hypothesis="benign: interactive admin logon during a maintenance window",
        )
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=index)
        assert action.action == "approved"

    def test_inferred_without_counter_hypothesis_unaffected_when_flag_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The preflight binds only CONFIRMED; lower tiers are exempt and approve.
        monkeypatch.setenv(self._GATE, "1")
        mcp, index = self._approving_setup()
        f = _finding(
            artifact_path="/case/Security.evtx",
            confidence="INFERRED",
            counter_hypothesis=None,
        )
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=index)
        assert action.action == "approved"

    def test_confirmed_without_counter_hypothesis_unaffected_when_flag_off(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Default-off: backward compatible — the missing counter_hypothesis is
        # not gated and the finding approves on the SHA path.
        monkeypatch.delenv(self._GATE, raising=False)
        mcp, index = self._approving_setup()
        f = _finding(artifact_path="/case/Security.evtx", counter_hypothesis=None)
        action, _ = reverify_finding(f, mcp=mcp, tool_call_index=index)
        assert action.action == "approved"
