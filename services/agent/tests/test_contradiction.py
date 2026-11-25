"""Tests for findevil_agent.contradiction."""

from __future__ import annotations

from findevil_agent.contradiction import (
    _is_confidence_extreme,
    _token_overlap,
    detect_contradictions,
    to_events,
)
from findevil_agent.events import ContradictionFound, Finding


def _f(
    finding_id: str,
    confidence: str = "CONFIRMED",
    *,
    tool_call_id: str = "tc-1",
    artifact_path: str = "Security.evtx",
    mitre: str | None = None,
    description: str = "logon evt",
    pool: str = "A",
) -> Finding:
    return Finding(
        case_id="c",
        finding_id=finding_id,
        tool_call_id=tool_call_id,
        artifact_path=artifact_path,
        confidence=confidence,
        mitre_technique=mitre,
        description=description,
        pool_origin=pool,
    )


class TestExtremeConfidence:
    def test_confirmed_vs_hypothesis_is_extreme(self) -> None:
        assert _is_confidence_extreme("CONFIRMED", "HYPOTHESIS") is True
        assert _is_confidence_extreme("HYPOTHESIS", "CONFIRMED") is True

    def test_one_tier_apart_is_not_extreme(self) -> None:
        assert _is_confidence_extreme("CONFIRMED", "INFERRED") is False
        assert _is_confidence_extreme("INFERRED", "HYPOTHESIS") is False

    def test_same_label_not_extreme(self) -> None:
        assert _is_confidence_extreme("CONFIRMED", "CONFIRMED") is False


class TestTokenOverlap:
    def test_identical_strings(self) -> None:
        assert _token_overlap("foo bar", "foo bar") == 1.0

    def test_disjoint_strings(self) -> None:
        assert _token_overlap("foo bar", "baz quux") == 0.0

    def test_partial_overlap(self) -> None:
        # 1 shared / 3 unique = 1/3 ≈ 0.333
        assert abs(_token_overlap("foo bar", "foo baz") - (1.0 / 3.0)) < 0.01

    def test_empty_both(self) -> None:
        assert _token_overlap("", "") == 1.0

    def test_empty_one(self) -> None:
        assert _token_overlap("foo", "") == 0.0


class TestDetectContradictions:
    def test_extreme_confidence_same_tool_call(self) -> None:
        a = _f("f-1", confidence="CONFIRMED", pool="A")
        b = _f("f-2", confidence="HYPOTHESIS", pool="B")
        contradictions = detect_contradictions([a], [b])
        assert len(contradictions) == 1
        assert "CONFIRMED" in contradictions[0].reason
        assert "HYPOTHESIS" in contradictions[0].reason

    def test_one_tier_apart_does_not_contradict(self) -> None:
        a = _f("f-1", confidence="CONFIRMED", pool="A")
        b = _f("f-2", confidence="INFERRED", pool="B")
        contradictions = detect_contradictions([a], [b])
        # No tool_call_id contradiction (one tier apart isn't extreme)
        # AND descriptions are identical so no token-overlap rule
        # fires either.
        assert contradictions == []

    def test_different_mitre_technique_same_artifact(self) -> None:
        a = _f("f-1", mitre="T1053.005", pool="A", description="scheduled task")
        b = _f("f-2", mitre="T1547.001", pool="B", description="run key")
        contradictions = detect_contradictions([a], [b])
        # Same tool_call_id + same artifact + different MITRE → contradicts.
        assert len(contradictions) >= 1
        assert any("MITRE" in p.reason for p in contradictions)

    def test_low_token_overlap_same_artifact(self) -> None:
        # Same artifact_path, same tool_call_id, similar confidence,
        # but very different descriptions.
        a = _f(
            "f-1",
            description="alpha bravo charlie delta",
            pool="A",
            mitre=None,
        )
        b = _f(
            "f-2",
            description="echo foxtrot golf hotel",
            pool="B",
            mitre=None,
        )
        contradictions = detect_contradictions([a], [b])
        assert any("token-overlap" in p.reason for p in contradictions)

    def test_no_contradiction_when_descriptions_match(self) -> None:
        a = _f("f-1", pool="A", mitre=None)
        b = _f("f-2", pool="B", mitre=None)
        # Same description text → token overlap = 1.0 → no rule fires.
        contradictions = detect_contradictions([a], [b])
        assert contradictions == []


class TestToEvents:
    def test_emits_one_event_per_pair(self) -> None:
        a = _f("f-1", confidence="CONFIRMED", pool="A")
        b = _f("f-2", confidence="HYPOTHESIS", pool="B")
        contradictions = detect_contradictions([a], [b])
        events = to_events(contradictions, case_id="c-1", resolution_required=True)
        assert len(events) == 1
        ev = events[0]
        assert isinstance(ev, ContradictionFound)
        assert ev.contradiction_id == "ctr-0001"
        assert ev.resolution_required is True
        assert "CONFIRMED" in ev.pool_a_claim
        assert "HYPOTHESIS" in ev.pool_b_claim

    def test_unattended_sets_resolution_required_false(self) -> None:
        a = _f("f-1", confidence="CONFIRMED", pool="A")
        b = _f("f-2", confidence="HYPOTHESIS", pool="B")
        contradictions = detect_contradictions([a], [b])
        events = to_events(contradictions, case_id="c-1", resolution_required=False)
        assert events[0].resolution_required is False

    def test_conflicting_tool_call_ids_deduped(self) -> None:
        a = _f("f-1", confidence="CONFIRMED", tool_call_id="tc-1", pool="A")
        b = _f("f-2", confidence="HYPOTHESIS", tool_call_id="tc-1", pool="B")
        contradictions = detect_contradictions([a], [b])
        events = to_events(contradictions, case_id="c-1", resolution_required=True)
        # Both findings cite the same tc-1 — should appear ONCE.
        assert events[0].conflicting_tool_call_ids == ["tc-1"]
