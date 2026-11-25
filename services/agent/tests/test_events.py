"""Tests for ``findevil_agent.events``.

Spec #2 §5 — the AgentEvent union is the wire format between
supervisor / workers / SSE / Next.js UI. Schema drift between the
11 variants breaks every downstream consumer, so these tests are
strict about discriminator behavior + forbid-extras semantics.
"""

from __future__ import annotations

import json

import pytest
from pydantic import TypeAdapter, ValidationError

from findevil_agent.events import (
    AgentEvent,
    AgentMessage,
    ContradictionFound,
    Finding,
    HypothesisUpdate,
    PlanApproved,
    PriorObservation,
    ToolCallStart,
)

AE = TypeAdapter(AgentEvent)


class TestDiscriminator:
    def test_all_eleven_variants_roundtrip_via_union(self) -> None:
        samples: list[dict] = [
            {
                "event_type": "ToolCallStart",
                "case_id": "c-1",
                "tool_name": "evtx_query",
                "tool_call_id": "tc-1",
                "input_hash": "abc",
            },
            {
                "event_type": "ToolCallOutput",
                "case_id": "c-1",
                "tool_call_id": "tc-1",
                "output_hash": "def",
                "row_count": 42,
            },
            {
                "event_type": "AgentMessage",
                "case_id": "c-1",
                "role": "supervisor",
                "content": "plan phase",
            },
            {
                "event_type": "Finding",
                "case_id": "c-1",
                "finding_id": "f-1",
                "tool_call_id": "tc-1",
                "artifact_path": "Security.evtx",
                "confidence": "CONFIRMED",
                "description": "logon from 192.168.1.5",
            },
            {
                "event_type": "VerifierAction",
                "case_id": "c-1",
                "action": "approved",
                "finding_id": "f-1",
                "reason": "tool_call_id present, evidence cited",
            },
            {
                "event_type": "ChainUpdate",
                "case_id": "c-1",
                "merkle_root": "deadbeef",
                "leaf_count": 3,
                "signature_pending": True,
            },
            {
                "event_type": "RunVerdict",
                "case_id": "c-1",
                "verdict": "CONFIRMED_EVIL",
                "confidence_score": 0.92,
                "finding_count": 14,
                "manifest_path": "/tmp/run.manifest.json",
                "manifest_verify_path": "/tmp/manifest_verify.json",
            },
            {
                "event_type": "PlanProposed",
                "case_id": "c-1",
                "plan_steps": ["open case", "hayabusa scan", "correlate"],
                "estimated_tool_calls": 12,
            },
            {
                "event_type": "PlanApproved",
                "case_id": "c-1",
                "approved_by": "human",
            },
            {
                "event_type": "HypothesisUpdate",
                "case_id": "c-1",
                "hypothesis": "persistence",
                "pool": "A",
                "confidence_delta": 0.12,
                "supporting_finding_ids": ["f-1", "f-2"],
            },
            {
                "event_type": "ContradictionFound",
                "case_id": "c-1",
                "contradiction_id": "ctr-1",
                "pool_a_claim": "scheduled task T1053.005",
                "pool_b_claim": "no MFT evidence",
                "conflicting_tool_call_ids": ["tc-1", "tc-2"],
                "resolution_required": True,
            },
        ]
        for s in samples:
            event = AE.validate_python(s)
            # Roundtrip via JSON so we catch encoder drift.
            blob = AE.dump_json(event)
            again = AE.validate_python(json.loads(blob))
            # Discriminator must round-trip cleanly.
            assert type(again).__name__ == s["event_type"]

    def test_unknown_event_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AE.validate_python({"event_type": "Bogus", "case_id": "c-1"})

    def test_forbid_extras(self) -> None:
        with pytest.raises(ValidationError):
            ToolCallStart(
                case_id="c-1",
                tool_name="evtx_query",
                tool_call_id="tc-1",
                input_hash="abc",
                rogue_field="nope",  # type: ignore[call-arg]
            )


class TestAutoFields:
    def test_event_id_autofills_as_uuid(self) -> None:
        e = AgentMessage(case_id="c-1", role="supervisor", content="x")
        assert len(e.event_id) == 36
        assert e.event_id.count("-") == 4  # canonical UUID4 dashes

    def test_ts_autofills_utc_with_z_suffix(self) -> None:
        e = AgentMessage(case_id="c-1", role="supervisor", content="x")
        assert e.ts.endswith("Z")
        assert "T" in e.ts

    def test_frozen(self) -> None:
        e = AgentMessage(case_id="c-1", role="supervisor", content="x")
        with pytest.raises(ValidationError):
            e.content = "mutated"  # type: ignore[misc]


class TestFindingInvariants:
    def test_finding_requires_tool_call_id(self) -> None:
        # Spec #2 §"Non-negotiable invariants": every Finding cites a
        # tool_call_id. Pydantic enforces by making the field
        # required (no default).
        with pytest.raises(ValidationError) as exc:
            Finding(  # type: ignore[call-arg]
                case_id="c-1",
                finding_id="f-1",
                artifact_path="x",
                confidence="CONFIRMED",
                description="y",
            )
        assert "tool_call_id" in str(exc.value)

    def test_finding_confidence_enum(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                case_id="c-1",
                finding_id="f-1",
                tool_call_id="tc-1",
                artifact_path="x",
                confidence="MAYBE",  # type: ignore[arg-type]
                description="y",
            )

    def test_plan_approved_by_human_or_auto(self) -> None:
        PlanApproved(case_id="c-1", approved_by="human")
        PlanApproved(case_id="c-1", approved_by="auto")
        with pytest.raises(ValidationError):
            PlanApproved(case_id="c-1", approved_by="computer")  # type: ignore[arg-type]


class TestContradictionEmission:
    def test_resolution_required_flag(self) -> None:
        # --unattended mode sets resolution_required=False, passing
        # all contradictions to the judge without waiting on the UI.
        # Both shapes must be constructible.
        interactive = ContradictionFound(
            case_id="c-1",
            contradiction_id="ctr-1",
            pool_a_claim="x",
            pool_b_claim="y",
            conflicting_tool_call_ids=["t1"],
            resolution_required=True,
        )
        unattended = ContradictionFound(
            case_id="c-1",
            contradiction_id="ctr-2",
            pool_a_claim="x",
            pool_b_claim="y",
            conflicting_tool_call_ids=["t1"],
            resolution_required=False,
        )
        assert interactive.resolution_required is True
        assert unattended.resolution_required is False


class TestFindingPriorObservations:
    """Hermes recall hits ride on a Finding as NON-evidentiary context.

    Guards the "memory is never evidence" invariant at the type layer:
    - G1: prior_observations never substitutes for the required tool_call_id.
    - G2: a prior observation carries only {case_id, ts, confidence} — no
      tool_call_id / value / sha256 that could masquerade as current-case
      evidence.
    """

    def _finding(self, **overrides: object) -> Finding:
        base: dict[str, object] = {
            "case_id": "c-1",
            "finding_id": "f-1",
            "tool_call_id": "tc-1",
            "artifact_path": "x",
            "confidence": "CONFIRMED",
            "description": "y",
        }
        base.update(overrides)
        return Finding(**base)  # type: ignore[arg-type]

    def test_prior_observations_defaults_empty(self) -> None:
        # Backward-compatible: findings built without recall context have [].
        assert self._finding().prior_observations == []

    def test_accepts_context_entries_and_round_trips(self) -> None:
        f = self._finding(
            prior_observations=[
                {"case_id": "c-prev", "ts": "2026-01-01T00:00:00Z", "confidence": 0.8}
            ]
        )
        assert len(f.prior_observations) == 1
        assert isinstance(f.prior_observations[0], PriorObservation)
        # Survives a model_dump round-trip through the discriminated union…
        again = AE.validate_python(f.model_dump())
        assert again.prior_observations[0].case_id == "c-prev"  # type: ignore[union-attr]
        # …and JSON serialization.
        assert "c-prev" in f.model_dump_json()

    def test_prior_observation_forbids_tool_call_id(self) -> None:
        # G2: a prior observation must not smuggle a current-case evidence
        # handle. extra="forbid" rejects tool_call_id / value / sha256.
        with pytest.raises(ValidationError):
            PriorObservation(
                case_id="c-prev",
                ts="2026-01-01T00:00:00Z",
                confidence=0.8,
                tool_call_id="tc-prev",  # type: ignore[call-arg]
            )

    def test_prior_observations_do_not_replace_tool_call_id(self) -> None:
        # G1: memory context never satisfies the required evidence citation.
        with pytest.raises(ValidationError) as exc:
            Finding(  # type: ignore[call-arg]
                case_id="c-1",
                finding_id="f-1",
                artifact_path="x",
                confidence="CONFIRMED",
                description="y",
                prior_observations=[
                    {"case_id": "c-prev", "ts": "2026-01-01T00:00:00Z", "confidence": 0.8}
                ],
            )
        assert "tool_call_id" in str(exc.value)

    def test_prior_observation_frozen(self) -> None:
        po = PriorObservation(case_id="c-prev", ts="2026-01-01T00:00:00Z", confidence=0.8)
        with pytest.raises(ValidationError):
            po.confidence = 0.1  # type: ignore[misc]


class TestAssertedValuesGate:
    """Phase 2a schema gate: under FIND_EVIL_REQUIRE_ASSERTED_VALUES=1, a
    fact-bearing (CONFIRMED/INFERRED) Finding must declare the structured
    value(s) it asserts, so nothing reaches the verifier without facts the
    entailment check can re-extract. Default ON (Stage A, 2026-06-22); opt out
    with ``FIND_EVIL_REQUIRE_ASSERTED_VALUES=0``.
    """

    _GATE = "FIND_EVIL_REQUIRE_ASSERTED_VALUES"

    def _finding(self, confidence: str, **overrides: object) -> Finding:
        base: dict[str, object] = {
            "case_id": "c-1",
            "finding_id": "f-1",
            "tool_call_id": "tc-1",
            "artifact_path": "x",
            "confidence": confidence,
            "description": "y",
        }
        base.update(overrides)
        return Finding(**base)  # type: ignore[arg-type]

    def test_confirmed_without_asserted_values_allowed_when_flag_zero(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Explicit opt-out: =0 disables the gate (debugging / legacy escape hatch).
        monkeypatch.setenv(self._GATE, "0")
        f = self._finding("CONFIRMED")
        assert f.asserted_values == []

    def test_confirmed_without_asserted_values_rejected_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Stage A: the gate is ON by default — a CONFIRMED finding declaring no
        # asserted_values cannot be built unless the flag is explicitly =0.
        monkeypatch.delenv(self._GATE, raising=False)
        with pytest.raises(ValidationError) as exc:
            self._finding("CONFIRMED")
        assert "asserted_values" in str(exc.value)

    def test_confirmed_without_asserted_values_rejected_when_flag_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(self._GATE, "1")
        with pytest.raises(ValidationError) as exc:
            self._finding("CONFIRMED")
        assert "asserted_values" in str(exc.value)

    def test_inferred_with_derived_from_allowed_when_flag_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # An INFERRED finding is a cross-fact inference (e.g. DKOM = pslist 0 AND
        # psscan N>0). It has no single re-extractable value; its fidelity is the
        # CONFIRMED facts it derives from, so citing derived_from satisfies the
        # gate without forcing a dishonest single-value assertion.
        monkeypatch.setenv(self._GATE, "1")
        f = self._finding("INFERRED", derived_from=["tc-1", "tc-2"])
        assert f.derived_from == ["tc-1", "tc-2"]

    def test_inferred_with_neither_asserted_nor_derived_rejected_when_flag_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(self._GATE, "1")
        with pytest.raises(ValidationError):
            self._finding("INFERRED")

    def test_hypothesis_without_asserted_values_allowed_when_flag_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # HYPOTHESIS is a lead, not an asserted fact — exempt from the gate.
        monkeypatch.setenv(self._GATE, "1")
        f = self._finding("HYPOTHESIS")
        assert f.asserted_values == []

    def test_confirmed_with_asserted_values_allowed_when_flag_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(self._GATE, "1")
        f = self._finding(
            "CONFIRMED",
            asserted_values=[{"path": "entries[*].values[*].name", "expected": "Updater"}],
        )
        assert len(f.asserted_values) == 1


class TestCounterHypothesisGate:
    """Anti-coherence "too clean" schema gate: under
    FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING=1, a CONFIRMED Finding must
    carry a populated ``counter_hypothesis`` (the benign explanation it ruled
    out). A confident finding that lists no alternative it considered is the
    "too clean" tell. Default OFF — backward compatible. Complements the
    judge.py counter-hypothesis discipline (FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS).
    """

    _GATE = "FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING"

    def _finding(self, confidence: str, **overrides: object) -> Finding:
        base: dict[str, object] = {
            "case_id": "c-1",
            "finding_id": "f-1",
            "tool_call_id": "tc-1",
            "artifact_path": "x",
            "confidence": confidence,
            "description": "y",
        }
        base.update(overrides)
        return Finding(**base)  # type: ignore[arg-type]

    def test_counter_hypothesis_defaults_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(self._GATE, raising=False)
        f = self._finding("CONFIRMED")
        assert f.counter_hypothesis is None

    def test_confirmed_without_counter_hypothesis_allowed_when_flag_off(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Default behavior (no flag): the not-yet-wired emitters still build
        # CONFIRMED findings without a counter_hypothesis, so the gate is opt-in.
        monkeypatch.delenv(self._GATE, raising=False)
        f = self._finding("CONFIRMED")
        assert f.counter_hypothesis is None

    def test_confirmed_without_counter_hypothesis_rejected_when_flag_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(self._GATE, "1")
        with pytest.raises(ValidationError) as exc:
            self._finding("CONFIRMED")
        assert "counter_hypothesis" in str(exc.value)

    def test_confirmed_with_blank_counter_hypothesis_rejected_when_flag_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A whitespace-only string is not a real alternative considered.
        monkeypatch.setenv(self._GATE, "1")
        with pytest.raises(ValidationError):
            self._finding("CONFIRMED", counter_hypothesis="   ")

    def test_confirmed_with_populated_counter_hypothesis_allowed_when_flag_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(self._GATE, "1")
        f = self._finding(
            "CONFIRMED",
            counter_hypothesis="benign admin task: scheduled task is a vendor updater",
        )
        assert f.counter_hypothesis is not None

    def test_inferred_without_counter_hypothesis_allowed_when_flag_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The gate only binds CONFIRMED — the strongest tier, where a missing
        # alternative is most suspicious. INFERRED/HYPOTHESIS stay exempt.
        monkeypatch.setenv(self._GATE, "1")
        f = self._finding("INFERRED", derived_from=["tc-1", "tc-2"])
        assert f.counter_hypothesis is None

    def test_hypothesis_without_counter_hypothesis_allowed_when_flag_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(self._GATE, "1")
        f = self._finding("HYPOTHESIS")
        assert f.counter_hypothesis is None


class TestHypothesisUpdate:
    def test_pool_must_be_a_or_b(self) -> None:
        HypothesisUpdate(
            case_id="c-1",
            hypothesis="persistence",
            pool="A",
            confidence_delta=0.0,
            supporting_finding_ids=[],
        )
        HypothesisUpdate(
            case_id="c-1",
            hypothesis="exfiltration",
            pool="B",
            confidence_delta=-0.1,
            supporting_finding_ids=[],
        )
        with pytest.raises(ValidationError):
            HypothesisUpdate(
                case_id="c-1",
                hypothesis="persistence",
                pool="C",  # type: ignore[arg-type]
                confidence_delta=0.0,
                supporting_finding_ids=[],
            )
