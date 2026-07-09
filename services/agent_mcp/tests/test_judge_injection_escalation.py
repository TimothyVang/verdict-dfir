"""Tests for the judge_findings injection-escalation hook.

A merged finding whose cited -- or derived_from -- tool call had its output
injection-neutralized at the MCP-output boundary is routed to human review. The
hook is a safety flag only: it never changes the merge math or the finding's
confidence. Kept in a dedicated file so the shared M4 test module is untouched.
"""

from __future__ import annotations

from typing import Any

from findevil_agent_mcp.tools.judge_findings import (
    SPEC as JUDGE_SPEC,
)
from findevil_agent_mcp.tools.judge_findings import (
    JudgeFindingsInput,
)


def _finding(**overrides: Any) -> dict[str, Any]:
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


async def test_no_injection_set_leaves_review_neutral() -> None:
    result = await JUDGE_SPEC.handler(
        JudgeFindingsInput(
            pool_a_findings=[_finding(pool_origin="A")],
            pool_a_verifier_actions=[_verifier_action("f-1")],
            pool_b_findings=[],
        )
    )
    assert result.human_review_finding_ids == []
    assert result.merged[0].needs_human_review is False


async def test_cited_tool_call_routes_to_human_review() -> None:
    result = await JUDGE_SPEC.handler(
        JudgeFindingsInput(
            pool_a_findings=[_finding(pool_origin="A", tool_call_id="tc-evil")],
            pool_a_verifier_actions=[_verifier_action("f-1")],
            pool_b_findings=[],
            injection_affected_tool_call_ids=["tc-evil"],
        )
    )
    assert result.merged[0].needs_human_review is True
    assert result.human_review_finding_ids == ["f-1"]
    # The escalation is a flag, not a confidence change.
    assert result.merged[0].finding["confidence"] == "INFERRED"


async def test_unaffected_finding_is_not_flagged() -> None:
    result = await JUDGE_SPEC.handler(
        JudgeFindingsInput(
            pool_a_findings=[_finding(pool_origin="A", tool_call_id="tc-clean")],
            pool_a_verifier_actions=[_verifier_action("f-1")],
            pool_b_findings=[],
            injection_affected_tool_call_ids=["tc-evil"],
        )
    )
    assert result.merged[0].needs_human_review is False
    assert result.human_review_finding_ids == []


async def test_derived_from_injection_affected_routes_to_review() -> None:
    # An inference whose cited tool_call is clean but whose derived_from rests on
    # an injection-affected fact is still escalated.
    result = await JUDGE_SPEC.handler(
        JudgeFindingsInput(
            pool_a_findings=[
                _finding(
                    pool_origin="A",
                    tool_call_id="tc-clean",
                    derived_from=["tc-evil", "tc-other"],
                )
            ],
            pool_a_verifier_actions=[_verifier_action("f-1")],
            pool_b_findings=[],
            injection_affected_tool_call_ids=["tc-evil"],
        )
    )
    assert result.merged[0].needs_human_review is True
    assert result.human_review_finding_ids == ["f-1"]


async def test_review_flag_serializes_into_output_dict() -> None:
    # The fields must survive JSON serialization (the verdict.json path).
    result = await JUDGE_SPEC.handler(
        JudgeFindingsInput(
            pool_a_findings=[_finding(pool_origin="A", tool_call_id="tc-evil")],
            pool_a_verifier_actions=[_verifier_action("f-1")],
            pool_b_findings=[],
            injection_affected_tool_call_ids=["tc-evil"],
        )
    )
    dumped = result.model_dump()
    assert dumped["human_review_finding_ids"] == ["f-1"]
    assert dumped["merged"][0]["needs_human_review"] is True
