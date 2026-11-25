"""Tests for the M4 ACH wrappers — detect_contradictions, judge_findings, correlate_findings."""

from __future__ import annotations

from typing import Any

import pytest

from findevil_agent_mcp.tools.correlate_findings import (
    SPEC as CORRELATE_SPEC,
)
from findevil_agent_mcp.tools.correlate_findings import (
    CorrelateFindingsInput,
    CorrelateFindingsOutput,
)
from findevil_agent_mcp.tools.detect_contradictions import (
    SPEC as DETECT_SPEC,
)
from findevil_agent_mcp.tools.detect_contradictions import (
    DetectContradictionsInput,
    DetectContradictionsOutput,
)
from findevil_agent_mcp.tools.judge_findings import (
    SPEC as JUDGE_SPEC,
)
from findevil_agent_mcp.tools.judge_findings import (
    JudgeFindingsInput,
    JudgeFindingsOutput,
)


def _finding(**overrides: Any) -> dict[str, Any]:
    """Build a Finding dict with overridable fields."""
    base = {
        "case_id": "case-001",
        "finding_id": "f-1",
        "tool_call_id": "tc-1",
        "artifact_path": "C:\\Windows\\Temp\\evil.exe",
        "confidence": "INFERRED",
        "mitre_technique": "T1059.001",
        "description": "Process invoked from a writable temp directory",
        "pool_origin": "A",
    }
    base.update(overrides)
    return base


def _verifier_action(finding_id: str = "f-1", action: str = "approved") -> dict[str, Any]:
    return {
        "case_id": "case-001",
        "finding_id": finding_id,
        "action": action,
        "reason": "tool re-run output_sha256 matches audit log",
    }


class TestDetectContradictions:
    async def test_no_contradictions_returns_empty_list(self) -> None:
        result = await DETECT_SPEC.handler(
            DetectContradictionsInput(
                case_id="case-001",
                pool_a=[_finding(pool_origin="A")],
                pool_b=[
                    _finding(
                        finding_id="f-2",
                        tool_call_id="tc-2",
                        artifact_path="other",
                        pool_origin="B",
                    )
                ],
            )
        )
        assert isinstance(result, DetectContradictionsOutput)
        assert result.contradictions == []
        assert result.pool_a_count == 1
        assert result.pool_b_count == 1

    async def test_extreme_confidence_pair_flagged(self) -> None:
        a = _finding(pool_origin="A", confidence="CONFIRMED")
        b = _finding(
            finding_id="f-B-1",
            pool_origin="B",
            confidence="HYPOTHESIS",
        )
        result = await DETECT_SPEC.handler(
            DetectContradictionsInput(case_id="case-001", pool_a=[a], pool_b=[b])
        )
        assert isinstance(result, DetectContradictionsOutput)
        assert len(result.contradictions) == 1
        ctr = result.contradictions[0]
        assert "tc-1" in ctr.conflicting_tool_call_ids
        assert ctr.resolution_required is True


class TestJudgeFindings:
    async def test_rejects_findings_without_verifier_actions(self) -> None:
        with pytest.raises(ValueError, match="verifier_actions"):
            JudgeFindingsInput(
                pool_a_findings=[_finding(pool_origin="A")],
                pool_b_findings=[],
            )

    async def test_rejects_findings_without_matching_verifier_actions(self) -> None:
        with pytest.raises(ValueError, match="missing verifier action"):
            JudgeFindingsInput(
                pool_a_findings=[_finding(pool_origin="A")],
                pool_a_verifier_actions=[_verifier_action("f-other")],
                pool_b_findings=[],
            )

    async def test_applies_downgraded_verifier_action_before_judging(self) -> None:
        result = await JUDGE_SPEC.handler(
            JudgeFindingsInput(
                pool_a_findings=[_finding(pool_origin="A", confidence="CONFIRMED")],
                pool_a_verifier_actions=[_verifier_action("f-1", "downgraded")],
                pool_b_findings=[],
            )
        )

        assert result.merged[0].finding["confidence"] == "INFERRED"

    async def test_rejects_duplicate_verifier_actions(self) -> None:
        with pytest.raises(ValueError, match="duplicate verifier action"):
            JudgeFindingsInput(
                pool_a_findings=[_finding(pool_origin="A", confidence="CONFIRMED")],
                pool_a_verifier_actions=[
                    _verifier_action("f-1", "rejected"),
                    _verifier_action("f-1", "approved"),
                ],
                pool_b_findings=[],
            )

    async def test_rejects_extra_verifier_actions(self) -> None:
        with pytest.raises(ValueError, match="without matching finding"):
            JudgeFindingsInput(
                pool_a_findings=[_finding(pool_origin="A")],
                pool_a_verifier_actions=[
                    _verifier_action("f-1"),
                    _verifier_action("f-other"),
                ],
                pool_b_findings=[],
            )

    async def test_rejects_extra_rejected_verifier_actions(self) -> None:
        with pytest.raises(ValueError, match="without matching finding"):
            JudgeFindingsInput(
                pool_a_findings=[_finding(pool_origin="A", confidence="CONFIRMED")],
                pool_a_verifier_actions=[
                    _verifier_action("f-1", "approved"),
                    _verifier_action("f-rejected", "rejected"),
                ],
                pool_b_findings=[],
            )

    async def test_rejects_orphan_verifier_actions_when_pool_empty(self) -> None:
        with pytest.raises(ValueError, match="without matching finding"):
            JudgeFindingsInput(
                pool_a_findings=[],
                pool_a_verifier_actions=[_verifier_action("f-orphan", "approved")],
                pool_b_findings=[],
            )

    async def test_rejects_orphan_rejected_verifier_actions_when_pool_empty(self) -> None:
        with pytest.raises(ValueError, match="without matching finding"):
            JudgeFindingsInput(
                pool_a_findings=[],
                pool_a_verifier_actions=[_verifier_action("f-orphan", "rejected")],
                pool_b_findings=[],
            )

    async def test_rejected_verifier_action_filters_finding_before_judging(self) -> None:
        result = await JUDGE_SPEC.handler(
            JudgeFindingsInput(
                pool_a_findings=[_finding(pool_origin="A", confidence="CONFIRMED")],
                pool_a_verifier_actions=[_verifier_action("f-1", "rejected")],
                pool_b_findings=[],
            )
        )

        assert result.merged == []

    async def test_pure_pool_a_yields_pool_a_only_results(self) -> None:
        result = await JUDGE_SPEC.handler(
            JudgeFindingsInput(
                pool_a_findings=[_finding(pool_origin="A")],
                pool_a_verifier_actions=[_verifier_action("f-1")],
                pool_b_findings=[],
            )
        )
        assert isinstance(result, JudgeFindingsOutput)
        assert len(result.merged) == 1
        assert result.merged[0].chosen_pool == "A"
        assert result.budget_exceeded is False

    async def test_corroborated_finding_gets_bonus(self) -> None:
        # Both pools cite same tool_call_id + artifact_path AND
        # at least one pool also has a different artifact-class
        # finding to trigger the cross-class corroboration.
        a_main = _finding(
            finding_id="f-A-1",
            description="Service binary executed from temp directory",
            pool_origin="A",
            confidence="INFERRED",
        )
        a_other = _finding(
            finding_id="f-A-2",
            tool_call_id="tc-2",
            artifact_path="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
            description="EVTX security log shows logon",
            pool_origin="A",
            confidence="INFERRED",
        )
        b_main = _finding(
            finding_id="f-B-1",
            description="Same tool output observed from exfil-pool",
            pool_origin="B",
            confidence="INFERRED",
        )

        result = await JUDGE_SPEC.handler(
            JudgeFindingsInput(
                pool_a_findings=[a_main, a_other],
                pool_a_verifier_actions=[
                    _verifier_action("f-A-1"),
                    _verifier_action("f-A-2"),
                ],
                pool_b_findings=[b_main],
                pool_b_verifier_actions=[_verifier_action("f-B-1")],
            )
        )
        assert isinstance(result, JudgeFindingsOutput)
        # The main finding (tc-1, artifact_path) has both pools.
        merged_main = [
            m
            for m in result.merged
            if m.finding["tool_call_id"] == "tc-1"
            and m.finding["artifact_path"] == _finding()["artifact_path"]
        ]
        assert len(merged_main) == 1
        assert merged_main[0].corroborated is True


class TestCorrelateFindings:
    async def test_non_execution_claim_kept(self) -> None:
        # T1071 = application-layer protocol; not an execution technique
        # per the correlator's whitelist, so this finding stays as-is.
        result = await CORRELATE_SPEC.handler(
            CorrelateFindingsInput(
                findings=[
                    _finding(
                        description="Network connection observed",
                        mitre_technique="T1071.001",
                        confidence="CONFIRMED",
                    )
                ]
            )
        )
        assert isinstance(result, CorrelateFindingsOutput)
        assert len(result.outcomes) == 1
        assert result.outcomes[0].action == "kept"
        assert result.refined[0]["confidence"] == "CONFIRMED"

    async def test_amcache_only_execution_downgraded(self) -> None:
        # T1059 (command interpreter) makes this an execution claim; the
        # description cites only Amcache, so the SOUL.md rule downgrades.
        result = await CORRELATE_SPEC.handler(
            CorrelateFindingsInput(
                findings=[
                    _finding(
                        description="Amcache shows the binary executed at 10:42",
                        mitre_technique="T1059.001",
                        confidence="CONFIRMED",
                    )
                ]
            )
        )
        assert isinstance(result, CorrelateFindingsOutput)
        assert result.outcomes[0].action == "downgraded"
        assert "Amcache" in result.outcomes[0].reason
        assert result.refined[0]["confidence"] == "INFERRED"
