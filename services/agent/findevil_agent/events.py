"""Typed AgentEvent union streamed over SSE.

Spec #2 §5. Every event is a Pydantic v2 model; the 11-variant
discriminated union serializes cleanly to JSON for the SSE bus and
deserializes cleanly on the Next.js frontend. TypeScript types are
generated via ``pydantic-to-typescript`` to ``apps/web/lib/events.ts``.

Standard fields on every event: ``case_id`` (UUID4), ``event_id``
(UUID4), ``ts`` (UTC ISO-8601 with trailing ``Z``).
"""

from __future__ import annotations

import os
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


class AssertedValue(BaseModel):
    """A structured value a :class:`Finding` claims is present in its cited output.

    The verifier's entailment check re-extracts ``path`` from the re-run tool
    output and confirms ``expected`` is actually there. This is what stops a
    model from misreading real evidence and laundering it through a valid
    ``tool_call_id``: a non-LLM check confirms the specific value, not the
    model. ``path`` is a dotted/wildcard path into the tool's output JSON, e.g.
    ``entries[*].values[*].data_str``, ``run_count``, ``rows[0].FILENAME``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(..., description="Dotted/wildcard path into the cited tool's output JSON")
    expected: str = Field(
        ...,
        description=(
            "The value the finding claims is present at path. For match='record' "
            "this is a JSON object of {field: substring} constraints that must all "
            "hold within ONE record reached by path (co-location)."
        ),
    )
    match: Literal["exact", "contains", "iso_ts", "int", "record"] = "exact"
    # Multiplicity guard: a count claim ("two variants", "N entries", "3
    # sessions") must be backed by at least this many ENTAILED leaves under a
    # wildcard path. When set >1 and fewer leaves actually entail, the verifier
    # demotes the finding below CONFIRMED — the one real line is genuine, the
    # over-count is not. Default None means "singular claim, no count gate".
    count: int | None = Field(
        default=None,
        ge=1,
        description="Minimum entailed leaves a multiplicity claim must back (>=1)",
    )


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
    # Structured values this finding claims are present in the cited tool
    # output. The verifier re-extracts each (entailment check) and rejects /
    # downgrades the finding if the value is not actually there — closing the
    # "model misread real evidence behind a valid citation" gap. Default empty
    # keeps existing findings backward-compatible (the check is a no-op when
    # absent); the opt-in gate below makes it required for CONFIRMED/INFERRED.
    asserted_values: list[AssertedValue] = Field(default_factory=list)
    # The benign/alternative explanation this finding ruled out — the
    # devil's-advocate stance recorded ON the finding (JUDGING.md §"counter
    # hypothesis"; complements the judge.py counter-hypothesis discipline). A
    # CONFIRMED claim that considered NO alternative is the anti-coherence "too
    # clean" tell. Optional + default None so findings drafted before this field
    # stay backward-compatible; the opt-in gate below makes it required for
    # CONFIRMED, and the verifier preflight rejects a CONFIRMED finding that
    # arrives without it.
    counter_hypothesis: str | None = None
    # A falsifiable PREDICTION the pool commits to when proposing this finding: a
    # single refutable observation the verifier can later check against the cited
    # output. Inverse polarity of asserted_values — an AssertedValue is REFUTED
    # when its value is ABSENT; an expectation is REFUTED only when the cited
    # output reaches its path and holds a leaf that CONTRADICTS the prediction
    # (a present-but-conflicting value). Path-absent = no contradicting evidence
    # = not refuted. Reuses the AssertedValue shape (path/expected/match) rather
    # than a new model. Optional + default-None so existing findings stay valid;
    # the refutation gate is opt-in via FIND_EVIL_REQUIRE_EXPECTATION=1.
    expectation: AssertedValue | None = None

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

    @model_validator(mode="after")
    def _require_asserted_values(self) -> Finding:
        """Fact-fidelity gate, **default-on**; opt out via ``FIND_EVIL_REQUIRE_ASSERTED_VALUES=0``.

        * CONFIRMED asserts a specific tool-backed value, so it MUST declare the
          structured value(s) it claims — the verifier re-extracts each from the
          cited output (entailment check) and kills a misread behind a valid
          ``tool_call_id``.
        * INFERRED is a cross-fact inference (e.g. DKOM = pslist 0 AND psscan
          N>0): it has no single re-extractable value, so it may EITHER declare
          asserted_values OR cite the CONFIRMED facts it rests on
          (``derived_from``), whose own fidelity is checked. Forcing a single
          value on an inference would be dishonest.
        * HYPOTHESIS is a lead, not an asserted fact — exempt.

        Default-ON (Stage A, 2026-06-22): the gate is active unless explicitly
        disabled with ``FIND_EVIL_REQUIRE_ASSERTED_VALUES=0``. Validated by a live
        full-coverage run on real evidence — recall held, 0 gate rejections,
        manifest_verify overall true (receipt in docs/fact-fidelity.md).
        """
        if os.environ.get("FIND_EVIL_REQUIRE_ASSERTED_VALUES") == "0":
            return self
        if self.confidence == "CONFIRMED" and not self.asserted_values:
            raise ValueError(
                f"CONFIRMED finding {self.finding_id} declares no asserted_values; "
                "a CONFIRMED fact must declare the structured value(s) it asserts "
                "so the entailment check can re-extract them from the cited output"
            )
        if self.confidence == "INFERRED" and not self.asserted_values and not self.derived_from:
            raise ValueError(
                f"INFERRED finding {self.finding_id} declares neither asserted_values "
                "nor derived_from; an inference must either declare its re-extractable "
                "value or cite the confirmed facts it rests on"
            )
        return self

    @model_validator(mode="after")
    def _require_counter_hypothesis(self) -> Finding:
        """Anti-coherence "too clean" gate, opt-in via
        ``FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING=1``.

        A CONFIRMED finding is the strongest claim VERDICT makes; a confident
        claim that ruled out NO benign alternative is the coherence tell that
        the model talked itself into a clean story. When the flag is on, a
        CONFIRMED finding MUST carry a non-blank ``counter_hypothesis`` (the
        alternative it considered and discarded). INFERRED/HYPOTHESIS are leads
        or cross-fact inferences and stay exempt.

        Default-OFF: emitters not yet wired, and findings built before this
        field existed, stay valid until the rollout flips the flag on. Mirrors
        :meth:`_require_asserted_values`. The verifier preflight enforces the
        same rule at re-verify time for findings that reach it from elsewhere.
        """
        if os.environ.get("FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING") != "1":
            return self
        if self.confidence == "CONFIRMED" and not (self.counter_hypothesis or "").strip():
            raise ValueError(
                f"CONFIRMED finding {self.finding_id} declares no counter_hypothesis; "
                "a CONFIRMED claim must record the benign/alternative explanation it "
                "ruled out (anti-coherence 'too clean' gate)"
            )
        return self


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
