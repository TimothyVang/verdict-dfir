"""``correlate_findings`` tool — SOUL.md cross-artifact rule check.

Wraps :func:`findevil_agent.correlator.correlate`. Last gate before
verdict assembly: walks the merged finding list and downgrades any
"execution"-flavored claim that doesn't have corroboration from at
least two distinct artifact classes (disk + log + memory).
"""

from __future__ import annotations

from typing import Any

from findevil_agent.correlator import correlate
from findevil_agent.events import Finding
from pydantic import BaseModel, ConfigDict, Field

from findevil_agent_mcp.tools._base import ToolSpec


class CorrelateFindingsInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    findings: list[dict[str, Any]] = Field(
        ...,
        description="Findings to correlate (typically the judge's merged output).",
    )


class CorrelationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str
    action: str = Field(..., description="'kept' | 'downgraded' | 'rejected'.")
    reason: str
    # Structured per-technique corroboration-gate record. Populated when a gate
    # fired (EXECUTION / LATERAL_MOVEMENT / PRIVILEGE_ESCALATION / PERSISTENCE);
    # left at the neutral defaults for findings no gate matched. Additive output
    # fields — old consumers that read only finding_id/action/reason are unaffected.
    gate: str | None = Field(
        default=None,
        description="Corroboration gate that fired, e.g. 'EXECUTION' | 'LATERAL_MOVEMENT'.",
    )
    severity: str | None = Field(
        default=None,
        description="Gate severity tag, e.g. 'high' | 'medium'.",
    )
    required_pairs: list[str] = Field(
        default_factory=list,
        description=(
            "Independent artifact-class pairs the gate accepts (any ONE satisfies "
            "it), e.g. ['network+process', 'logon']."
        ),
    )
    missing_classes: list[str] = Field(
        default_factory=list,
        description=(
            "Artifact classes that, if added, would satisfy the closest pair. "
            "Empty when the gate held (or no gate fired)."
        ),
    )


class CorrelateFindingsOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    refined: list[dict[str, Any]] = Field(
        ...,
        description=(
            "Findings after correlator pass. Same length as input; "
            "confidence may be downgraded by SOUL.md rules."
        ),
    )
    outcomes: list[CorrelationRecord]


async def _handle(inp: BaseModel) -> CorrelateFindingsOutput:
    assert isinstance(inp, CorrelateFindingsInput)
    findings = [Finding.model_validate(f) for f in inp.findings]
    refined, outcomes = correlate(findings)
    return CorrelateFindingsOutput(
        refined=[f.model_dump() for f in refined],
        outcomes=[
            CorrelationRecord(
                finding_id=o.finding_id,
                action=o.action,
                reason=o.reason,
                gate=o.gate,
                severity=o.severity,
                required_pairs=list(o.required_pairs),
                missing_classes=list(o.missing_classes),
            )
            for o in outcomes
        ],
    )


SPEC = ToolSpec(
    name="correlate_findings",
    description=(
        "FINAL ACH gate before manifest_finalize. Applies the agent-config/SOUL.md "
        "cross-artifact rule: an execution claim must be supported by ≥2 distinct "
        "artifact classes (disk + log + memory). Findings that cite execution "
        "(description tokens like 'executed', 'ran', 'launched', or MITRE prefixes "
        "T1059/T1106/T1129/T1203/T1543/T1547/T1053) are checked against the rule and "
        "DOWNGRADED one tier when corroboration is missing. The hard-coded special "
        "case from agent-config/MEMORY.md: Amcache-ONLY execution claims always "
        "downgrade because Amcache LastModified is catalog-registration time, NOT "
        "execution time. Strong corroboration (Prefetch + Amcache/Shimcache pair, OR "
        "Sysmon/Carbon Black/CrowdStrike telemetry mentioned in the description) keeps "
        "the original confidence. Pass the judge's merged output here (ideally; the "
        "tool also handles raw pool findings). Returns refined[] (same length as "
        "input; confidence may be lower) plus outcomes[] (one CorrelationOutcome per "
        "finding describing the action taken and why, including the structured "
        "gate/severity/required_pairs/missing_classes record when a per-technique "
        "corroboration gate fired)."
    ),
    input_model=CorrelateFindingsInput,
    output_model=CorrelateFindingsOutput,
    handler=_handle,
)

__all__ = [
    "SPEC",
    "CorrelateFindingsInput",
    "CorrelateFindingsOutput",
    "CorrelationRecord",
]
