"""``detect_contradictions`` tool — Pool A vs Pool B disagreement scan.

Wraps :func:`findevil_agent.contradiction.detect_contradictions`.
Pure Python, deterministic, no I/O. Output is a list of
contradictions with reason strings the agent surfaces to the
analyst before the judge merges.
"""

from __future__ import annotations

from typing import Any

from findevil_agent.contradiction import detect_contradictions, to_events
from findevil_agent.events import Finding
from pydantic import BaseModel, ConfigDict, Field

from findevil_agent_mcp.tools._base import ToolSpec


class DetectContradictionsInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(..., description="UUID4 of the case.", min_length=1)
    pool_a: list[dict[str, Any]] = Field(
        ...,
        description="Pool A findings as Finding-event dicts (pool_origin='A').",
    )
    pool_b: list[dict[str, Any]] = Field(
        ...,
        description="Pool B findings as Finding-event dicts (pool_origin='B').",
    )
    resolution_required: bool = Field(
        default=True,
        description=(
            "True for interactive runs (analyst must Trust A / Trust B / Flag "
            "before the judge fires); False for --unattended."
        ),
    )


class ContradictionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contradiction_id: str
    pool_a_claim: str
    pool_b_claim: str
    conflicting_tool_call_ids: list[str]
    resolution_required: bool


class DetectContradictionsOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contradictions: list[ContradictionRecord]
    pool_a_count: int
    pool_b_count: int


async def _handle(inp: BaseModel) -> DetectContradictionsOutput:
    assert isinstance(inp, DetectContradictionsInput)
    pool_a = [Finding.model_validate(f) for f in inp.pool_a]
    pool_b = [Finding.model_validate(f) for f in inp.pool_b]
    pairs = detect_contradictions(pool_a, pool_b)
    events = to_events(
        pairs,
        case_id=inp.case_id,
        resolution_required=inp.resolution_required,
    )
    records = [
        ContradictionRecord(
            contradiction_id=ev.contradiction_id,
            pool_a_claim=ev.pool_a_claim,
            pool_b_claim=ev.pool_b_claim,
            conflicting_tool_call_ids=list(ev.conflicting_tool_call_ids),
            resolution_required=ev.resolution_required,
        )
        for ev in events
    ]
    return DetectContradictionsOutput(
        contradictions=records,
        pool_a_count=len(pool_a),
        pool_b_count=len(pool_b),
    )


SPEC = ToolSpec(
    name="detect_contradictions",
    description=(
        "M4 contradiction stage — surface Pool A vs Pool B disagreements BEFORE "
        "judge_findings reconciles them. This is the FIRST-CLASS OUTPUT of the ACH "
        "moat: most submissions hide contradictions inside a consensus answer; we "
        "show them to the analyst as their own event class. Run this AFTER both "
        "pools have emitted findings and AFTER verify_finding has triaged them. "
        "Three detection rules (in severity order): (1) same tool_call_id cited by "
        "both pools at opposite confidence ends (CONFIRMED vs HYPOTHESIS); "
        "(2) same artifact + same tool_call_id but different MITRE techniques; "
        "(3) same artifact_path with description token-overlap < 30%. "
        "resolution_required=True for interactive runs (analyst must Trust A / "
        "Trust B / Flag before judge fires); =False for --unattended (auto-passes "
        "with the contradiction logged in the audit chain). "
        "Returns one ContradictionFound per pair plus the input pool counts for "
        "sanity checks. Empty contradictions list = no disagreements detected."
    ),
    input_model=DetectContradictionsInput,
    output_model=DetectContradictionsOutput,
    handler=_handle,
)

__all__ = [
    "SPEC",
    "ContradictionRecord",
    "DetectContradictionsInput",
    "DetectContradictionsOutput",
]
