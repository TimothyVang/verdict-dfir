"""Typed AgentEvent union streamed over SSE.

Spec #2 §5. Every event is a Pydantic v2 model; the 11-variant
discriminated union serializes cleanly to JSON for the SSE bus and
deserializes cleanly on the Next.js frontend. TypeScript types are
generated via ``pydantic-to-typescript`` to ``apps/web/lib/events.ts``.

Standard fields on every event: ``case_id`` (UUID4), ``event_id``
(UUID4), ``ts`` (UTC ISO-8601 with trailing ``Z``).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# ---------------------------------------------------------------------------
# Shared base.
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    """UTC ISO-8601 with trailing Z (Spec #2 §"Non-negotiable invariants")."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _uuid4() -> str:
    return str(uuid.uuid4())


class _BaseEvent(BaseModel):
    """Shared envelope. Subclasses add an ``event_type`` Literal."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(..., description="UUID4 of the case this event belongs to")
    event_id: str = Field(default_factory=_uuid4)
    ts: str = Field(default_factory=_now_iso)


# ---------------------------------------------------------------------------
# Tool-call lifecycle.
# ---------------------------------------------------------------------------


class ToolCallStart(_BaseEvent):
    event_type: Literal["ToolCallStart"] = "ToolCallStart"
    tool_name: str
    tool_call_id: str
    input_hash: str  # SHA-256 hex of JCS-canonicalized input
    pool: Literal["A", "B", "shared"] | None = None


class ToolCallOutput(_BaseEvent):
    event_type: Literal["ToolCallOutput"] = "ToolCallOutput"
    tool_call_id: str
    output_hash: str  # SHA-256 hex of raw output bytes
    row_count: int | None = None
    signature_bundle: str | None = None  # base64 signer bundle when emitted
    merkle_leaf_index: int | None = None


# ---------------------------------------------------------------------------
# Agent reasoning.
# ---------------------------------------------------------------------------


class AgentMessage(_BaseEvent):
    event_type: Literal["AgentMessage"] = "AgentMessage"
    role: Literal["supervisor", "pool_a", "pool_b", "judge", "verifier", "correlator"]
    content: str


# ---------------------------------------------------------------------------
# Findings + verifier actions.
# ---------------------------------------------------------------------------


class PriorObservation(BaseModel):
    """A NON-evidentiary cross-case recall hit (Hermes ``memory_recall``).

    Rides on a :class:`Finding` as background context only. It deliberately
    carries no ``tool_call_id``, ``value``, or ``sha256``: prior-case memory is
    never current-case evidence (SOUL.md / PLAYBOOK.md §34), never satisfies the
    >=2-artifact-class rule, and never becomes a Merkle leaf. ``extra="forbid"``
    keeps an evidence handle from being smuggled in.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(..., description="UUID4 of the PRIOR case this hit came from")
    ts: str = Field(..., description="UTC ISO-8601 (trailing Z) of the prior observation")
    confidence: float = Field(..., description="BM25 x recency-decayed recall confidence, 0.0-1.0")


class Finding(_BaseEvent):
    event_type: Literal["Finding"] = "Finding"
    finding_id: str
    tool_call_id: str  # REQUIRED — verifier vetos if absent
    artifact_path: str
    artifact_offset: str | None = None
    confidence: Literal["CONFIRMED", "INFERRED", "HYPOTHESIS"]
    mitre_technique: str | None = None  # e.g. "T1053.005"
    description: str
    pool_origin: Literal["A", "B", "merged"] | None = None
    # SOUL.md / JUDGING.md §"IR Accuracy": an INFERRED finding must cite the
    # confirmed facts it rests on (≥2). Carries the tool_call_ids (or
    # finding_ids) of those facts. Optional so CONFIRMED/HYPOTHESIS findings,
    # which don't derive from other facts, can omit it.
    derived_from: list[str] | None = None
    # Hermes cross-case recall hits attached as NON-evidentiary context
    # (memory_recall). Never a tool_call_id, never counts toward the >=2
    # artifact-class rule, never a Merkle leaf. Default empty so findings
    # drafted without recall stay backward-compatible.
    prior_observations: list[PriorObservation] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _enforce_hypothesis_prefix(cls, data: object) -> object:
        """SOUL.md: HYPOTHESIS findings carry a ``hypothesis:`` prefix.

        Normalize rather than reject — a missing prefix is a labeling slip,
        not grounds for dropping a lead. Prepends the prefix when absent so
        the epistemic level is unambiguous in the report and the audit chain.
        """
        if isinstance(data, dict) and data.get("confidence") == "HYPOTHESIS":
            desc = data.get("description")
            if isinstance(desc, str) and not desc.lstrip().lower().startswith("hypothesis:"):
                data = {**data, "description": f"hypothesis: {desc.lstrip()}"}
        return data


class VerifierAction(_BaseEvent):
    event_type: Literal["VerifierAction"] = "VerifierAction"
    action: Literal["approved", "rejected", "downgraded"]
    finding_id: str
    reason: str  # shown in the fade-out tooltip on the UI


# ---------------------------------------------------------------------------
# Crypto chain-of-custody.
# ---------------------------------------------------------------------------


class ChainUpdate(_BaseEvent):
    event_type: Literal["ChainUpdate"] = "ChainUpdate"
    merkle_root: str  # hex SHA-256
    leaf_count: int
    signature_pending: bool  # True until manifest_finalize writes a signature bundle


# ---------------------------------------------------------------------------
# Verdict.
# ---------------------------------------------------------------------------


class RunVerdict(_BaseEvent):
    event_type: Literal["RunVerdict"] = "RunVerdict"
    verdict: Literal["CONFIRMED_EVIL", "SUSPICIOUS", "BENIGN", "INCONCLUSIVE"]
    confidence_score: float  # 0.0 to 1.0
    finding_count: int
    manifest_path: str
    manifest_verify_path: str | None = None


# ---------------------------------------------------------------------------
# Plan mode + hypothesis board + contradiction.
# ---------------------------------------------------------------------------


class PlanProposed(_BaseEvent):
    event_type: Literal["PlanProposed"] = "PlanProposed"
    plan_steps: list[str]
    estimated_tool_calls: int


class PlanApproved(_BaseEvent):
    event_type: Literal["PlanApproved"] = "PlanApproved"
    approved_by: Literal["human", "auto"]  # "auto" only in --unattended


class HypothesisUpdate(_BaseEvent):
    event_type: Literal["HypothesisUpdate"] = "HypothesisUpdate"
    hypothesis: Literal["persistence", "exfiltration", "both", "neither"]
    pool: Literal["A", "B"]
    confidence_delta: float
    supporting_finding_ids: list[str]


class ContradictionFound(_BaseEvent):
    event_type: Literal["ContradictionFound"] = "ContradictionFound"
    contradiction_id: str
    pool_a_claim: str
    pool_b_claim: str
    conflicting_tool_call_ids: list[str]
    resolution_required: bool  # True = analyst must decide before judge


# ---------------------------------------------------------------------------
# Union — the thing the SSE bus actually emits.
# ---------------------------------------------------------------------------


AgentEvent = Annotated[
    ToolCallStart
    | ToolCallOutput
    | AgentMessage
    | Finding
    | VerifierAction
    | ChainUpdate
    | RunVerdict
    | PlanProposed
    | PlanApproved
    | HypothesisUpdate
    | ContradictionFound,
    Field(discriminator="event_type"),
]
"""Discriminated union of all 11 AgentEvent variants.

Use ``pydantic.TypeAdapter(AgentEvent).validate_python(...)`` on the
SSE consumer side. The Next.js frontend imports the generated
TypeScript union from ``apps/web/lib/events.ts`` for symmetry.
"""


__all__ = [
    "AgentEvent",
    "AgentMessage",
    "ChainUpdate",
    "ContradictionFound",
    "Finding",
    "HypothesisUpdate",
    "PlanApproved",
    "PlanProposed",
    "PriorObservation",
    "RunVerdict",
    "ToolCallOutput",
    "ToolCallStart",
    "VerifierAction",
]
