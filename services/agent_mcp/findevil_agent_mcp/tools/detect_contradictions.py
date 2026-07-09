"""``detect_contradictions`` tool — Pool A vs Pool B disagreement scan.

Wraps :func:`findevil_agent.contradiction.detect_contradictions`.
Pure Python, deterministic, no I/O. Output is a list of
contradictions with reason strings the agent surfaces to the
analyst before the judge merges.
"""

from __future__ import annotations

from typing import Any

from findevil_agent.contradiction import (
    antiforensics_to_events,
    detect_antiforensics,
    detect_contradictions,
    to_events,
)
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
    # How many of the records above are cross-source anti-forensics LEADS
    # (contradiction_id prefix 'afl-') vs Pool A/B contradictions ('ctr-').
    # Additive, informational — the engine still consumes the combined list.
    antiforensics_count: int = 0


def _to_record(ev: Any) -> ContradictionRecord:
    return ContradictionRecord(
        contradiction_id=ev.contradiction_id,
        pool_a_claim=ev.pool_a_claim,
        pool_b_claim=ev.pool_b_claim,
        conflicting_tool_call_ids=list(ev.conflicting_tool_call_ids),
        resolution_required=ev.resolution_required,
    )


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

    # Cross-source anti-forensics 'something is missing' leads, scanned over the
    # COMBINED finding set and surfaced through the same resolution path so the
    # engine's existing contradiction consumer picks them up unchanged.
    leads = detect_antiforensics(pool_a + pool_b)
    af_events = antiforensics_to_events(
        leads,
        case_id=inp.case_id,
        resolution_required=inp.resolution_required,
    )

    records = [_to_record(ev) for ev in events] + [_to_record(ev) for ev in af_events]
    return DetectContradictionsOutput(
        contradictions=records,
        pool_a_count=len(pool_a),
        pool_b_count=len(pool_b),
        antiforensics_count=len(af_events),
    )


SPEC = ToolSpec(
    name="detect_contradictions",
    description=(
        "M4 contradiction stage — surface Pool A vs Pool B disagreements BEFORE "
        "judge_findings reconciles them. This is the FIRST-CLASS OUTPUT of the ACH "
        "moat: most submissions hide contradictions inside a consensus answer; we "
        "show them to the analyst as their own event class. Run this AFTER both "
        "pools have emitted findings and AFTER verify_finding has triaged them. "
        "Four Pool-A-vs-Pool-B contradiction rules (in severity order): (1) same "
        "tool_call_id cited by both pools at opposite confidence ends (CONFIRMED vs "
        "HYPOTHESIS); (2) same artifact + same tool_call_id but different MITRE "
        "techniques; (3) same artifact_path with description token-overlap < 30%; "
        "(4) same named entity (binary/hash) asserted present-vs-absent or at "
        "mutually exclusive timestamps across disjoint citations. PLUS a "
        "cross-source ANTI-FORENSICS 'something is missing' family (scanned over "
        "the combined finding set, each a HYPOTHESIS-tier LEAD, never a conclusion): "
        "HIDDEN_SERVICE (service with no matching process), NETWORK_WITHOUT_PROCESS "
        "(connection with no owning process), INVISIBLE_CONNECTION (connection whose "
        "prose has no owner), LOG_WIPE (EID 1102 / explicit clear, optionally + a "
        "timeline gap), PREFETCH_WITHOUT (execution artifact with no corroborating "
        "trace). These ride the same resolution path with 'afl-' IDs. "
        "resolution_required=True for interactive runs (analyst must Trust A / "
        "Trust B / Flag before judge fires); =False for --unattended (auto-passes "
        "with the contradiction logged in the audit chain). "
        "Returns one record per contradiction/lead, the input pool counts, and "
        "antiforensics_count (how many records are 'afl-' leads). Empty "
        "contradictions list = no disagreements or missing-corroboration leads."
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
