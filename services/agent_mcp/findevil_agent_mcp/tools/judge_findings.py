"""``judge_findings`` tool — credibility-weighted Pool A + Pool B merge.

Wraps :func:`findevil_agent.judge.judge_findings` (Estornell ICML
2025 formula). Each pool contributes findings + the verifier's
actions on them; the judge weights each pool's claims by the
fraction of its findings the verifier approved, then thresholds
the weighted score back to a confidence label.
"""

from __future__ import annotations

from typing import Any

from findevil_agent.events import Finding, VerifierAction
from findevil_agent.judge import JudgeBudgetExceeded, PoolStats, judge_findings
from pydantic import BaseModel, ConfigDict, Field, model_validator

from findevil_agent_mcp.tools._base import ToolSpec

DOWNGRADED_CONFIDENCE = {
    "CONFIRMED": "INFERRED",
    "INFERRED": "HYPOTHESIS",
    "HYPOTHESIS": "HYPOTHESIS",
}


class JudgeFindingsInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    pool_a_findings: list[dict[str, Any]] = Field(
        ..., description="Pool A findings as Finding-event dicts."
    )
    pool_a_verifier_actions: list[dict[str, Any]] = Field(
        default_factory=list,
        description="VerifierAction-event dicts for Pool A findings.",
    )
    pool_b_findings: list[dict[str, Any]] = Field(
        ..., description="Pool B findings as Finding-event dicts."
    )
    pool_b_verifier_actions: list[dict[str, Any]] = Field(
        default_factory=list,
        description="VerifierAction-event dicts for Pool B findings.",
    )
    budget_seconds: float = Field(
        default=120.0,
        gt=0.0,
        description="Wall-clock budget for the merge (Spec #2 §8.1 default 120s).",
    )

    @model_validator(mode="after")
    def _require_verifier_actions(self) -> JudgeFindingsInput:
        _validate_pool_verifier_actions(
            "pool_a", self.pool_a_findings, self.pool_a_verifier_actions
        )
        _validate_pool_verifier_actions(
            "pool_b", self.pool_b_findings, self.pool_b_verifier_actions
        )
        return self


def _validate_pool_verifier_actions(
    pool: str, findings: list[dict[str, Any]], actions: list[dict[str, Any]]
) -> None:
    if not findings:
        if actions:
            raise ValueError(f"{pool}_verifier_actions has action(s) without matching finding")
        return
    if not actions:
        raise ValueError(f"{pool}_verifier_actions required when {pool}_findings is non-empty")
    finding_ids = {str(finding.get("finding_id") or "") for finding in findings}
    action_by_finding: dict[str, dict[str, Any]] = {}
    for action in actions:
        finding_id = action.get("finding_id")
        if not isinstance(finding_id, str):
            continue
        if finding_id in action_by_finding:
            raise ValueError(
                f"{pool}_verifier_actions duplicate verifier action for "
                f"finding_id={finding_id!r}"
            )
        action_by_finding[finding_id] = action
    for finding in findings:
        finding_id = str(finding.get("finding_id") or "")
        action = action_by_finding.get(finding_id)
        if action is None:
            raise ValueError(
                f"{pool}_verifier_actions missing verifier action for " f"finding_id={finding_id!r}"
            )
    extras = sorted(set(action_by_finding) - finding_ids)
    if extras:
        raise ValueError(
            f"{pool}_verifier_actions has action(s) without matching finding: " + ", ".join(extras)
        )


def _apply_verifier_actions(
    findings: list[dict[str, Any]], actions: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    action_by_finding = {str(action.get("finding_id")): action for action in actions}
    verified: list[dict[str, Any]] = []
    for finding in findings:
        finding_id = str(finding.get("finding_id") or "")
        action = action_by_finding[finding_id]
        if action.get("action") == "rejected":
            continue
        next_finding = dict(finding)
        if action.get("action") == "downgraded":
            next_finding["confidence"] = DOWNGRADED_CONFIDENCE.get(
                str(next_finding.get("confidence")),
                next_finding.get("confidence"),
            )
        verified.append(next_finding)
    return verified


class MergedFindingRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding: dict[str, Any] = Field(..., description="The merged Finding (event dict).")
    merged_confidence: float
    chosen_pool: str
    pool_a_score: float
    pool_b_score: float
    credibility_a: float
    credibility_b: float
    corroborated: bool


class JudgeFindingsOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    merged: list[MergedFindingRecord]
    budget_exceeded: bool
    budget_detail: str | None


async def _handle(inp: BaseModel) -> JudgeFindingsOutput:
    assert isinstance(inp, JudgeFindingsInput)
    pool_a = PoolStats(
        pool="A",
        findings=[
            Finding.model_validate(f)
            for f in _apply_verifier_actions(inp.pool_a_findings, inp.pool_a_verifier_actions)
        ],
        verified_actions=[VerifierAction.model_validate(a) for a in inp.pool_a_verifier_actions],
    )
    pool_b = PoolStats(
        pool="B",
        findings=[
            Finding.model_validate(f)
            for f in _apply_verifier_actions(inp.pool_b_findings, inp.pool_b_verifier_actions)
        ],
        verified_actions=[VerifierAction.model_validate(a) for a in inp.pool_b_verifier_actions],
    )
    try:
        merged = judge_findings(pool_a, pool_b, budget_seconds=inp.budget_seconds)
    except JudgeBudgetExceeded as exc:
        return JudgeFindingsOutput(
            merged=[],
            budget_exceeded=True,
            budget_detail=str(exc),
        )

    records = [
        MergedFindingRecord(
            finding=m.finding.model_dump(),
            merged_confidence=m.merged_confidence,
            chosen_pool=m.chosen_pool,
            pool_a_score=m.pool_a_score,
            pool_b_score=m.pool_b_score,
            credibility_a=m.credibility_a,
            credibility_b=m.credibility_b,
            corroborated=m.corroborated,
        )
        for m in merged
    ]
    return JudgeFindingsOutput(
        merged=records,
        budget_exceeded=False,
        budget_detail=None,
    )


SPEC = ToolSpec(
    name="judge_findings",
    description=(
        "M4 judge stage — credibility-weighted merge of Pool A + Pool B findings into "
        "a single approved set. Run this AFTER verify_finding (so the verifier_actions "
        "are populated for prior_accuracy) and AFTER detect_contradictions (so the "
        "analyst's resolution decisions are baked in). Implements the Estornell ICML "
        "2025 formula: each pool's score is its raw confidence *credibility, where "
        "credibility = prior_accuracy *(1 + corroboration_bonus). Findings sharing "
        "(tool_call_id, artifact_path) merge into one MergedFinding with chosen_pool="
        "'merged'; solo findings keep their pool letter. The merged_confidence then "
        "thresholds to a label: ≥0.80 → CONFIRMED, ≥0.50 → INFERRED, < 0.50 → "
        "HYPOTHESIS (HYPOTHESIS findings are still emitted — the epistemic hierarchy "
        "permits them). budget_seconds defaults to 120s (Spec #2 §8.1); a 0-second "
        "budget force-fails on the first iteration for tests. "
        "Returns merged[] (each entry has the full math: pool_a_score, pool_b_score, "
        "credibility_a, credibility_b, corroborated) plus budget_exceeded flag."
    ),
    input_model=JudgeFindingsInput,
    output_model=JudgeFindingsOutput,
    handler=_handle,
)

__all__ = [
    "SPEC",
    "JudgeFindingsInput",
    "JudgeFindingsOutput",
    "MergedFindingRecord",
]
