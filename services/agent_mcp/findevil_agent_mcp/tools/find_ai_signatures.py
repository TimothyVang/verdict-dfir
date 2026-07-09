"""``find_ai_signatures`` tool — scan text/artifacts for AI/agent tradecraft.

Typed, read-only MCP tool (same shape as ``yara_scan``: a typed schema with
``extra='forbid'`` unknown-field denial, safe error mapping at the server
boundary, server registration, tests). It is a SIGNATURE SCANNER, not a broad
filesystem/shell surface — it only reads the inline text and the explicit file
paths the caller passes, and it never writes or mutates evidence.

Domain logic lives in :mod:`findevil_agent.ai_signatures` (the curated general
signature list + the pure scan). This module is the protocol shim: validate the
typed input, call the domain scan, shape the typed output.

Epistemic scope (enforced in the output shape): every match is a
``HYPOTHESIS``-tier LEAD. The output pins ``confidence_tier="HYPOTHESIS"`` and
``lead_only=True`` and carries the lead disclaimer so a match can never be read
as a conclusion or as execution proof. A lead never satisfies the
>=2-artifact-class corroboration gate on its own.
"""

from __future__ import annotations

from findevil_agent.ai_signatures import (
    CONFIDENCE_TIER,
    DEFAULT_LIMIT,
    DEFAULT_PREVIEW_CHARS,
    LEAD_DISCLAIMER,
    MAX_PREVIEW_CHARS,
    known_categories,
    scan_sources,
)
from pydantic import BaseModel, ConfigDict, Field, model_validator

from findevil_agent_mcp.tools._base import ToolSpec


class FindAiSignaturesInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(
        ...,
        min_length=1,
        description="Case ID from a prior case_open call, for audit correlation.",
    )
    text: str | None = Field(
        default=None,
        description=(
            "Inline text to scan (e.g. a recovered script, log slice, or note "
            "body). Scanned under the source label '<inline>'. At least one of "
            "'text' or 'paths' must be provided."
        ),
    )
    paths: list[str] = Field(
        default_factory=list,
        description=(
            "Absolute paths to text artifacts to read (open-for-read only) and "
            "scan. A path that cannot be read is reported in 'read_errors' and "
            "skipped; the scan still completes."
        ),
    )
    categories: list[str] | None = Field(
        default=None,
        description=(
            "Optional filter restricting which signature categories are "
            "evaluated. Omit to evaluate every category. Unknown categories are "
            "rejected at validation."
        ),
    )
    limit: int = Field(
        default=DEFAULT_LIMIT,
        ge=1,
        le=10_000,
        description="Hard cap on total matches emitted across all sources.",
    )
    preview_chars: int = Field(
        default=DEFAULT_PREVIEW_CHARS,
        ge=0,
        le=MAX_PREVIEW_CHARS,
        description="Approximate width of the whitespace-collapsed match preview.",
    )

    @model_validator(mode="after")
    def _require_a_source(self) -> FindAiSignaturesInput:
        if self.text is None and not self.paths:
            raise ValueError("provide at least one of 'text' or 'paths' to scan")
        return self

    @model_validator(mode="after")
    def _validate_categories(self) -> FindAiSignaturesInput:
        if self.categories is not None:
            allowed = set(known_categories())
            unknown = sorted(set(self.categories) - allowed)
            if unknown:
                raise ValueError(
                    f"unknown signature categories {unknown}; " f"known: {sorted(allowed)}"
                )
        return self


class AiSignatureMatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    signature_id: str
    category: str
    description: str
    source: str
    occurrences: int
    first_offset: int
    preview: str


class FindAiSignaturesOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    confidence_tier: str = Field(
        default=CONFIDENCE_TIER,
        description="Always HYPOTHESIS — every match is a lead, never a conclusion.",
    )
    lead_only: bool = Field(
        default=True,
        description="Always True — a signature alone never proves execution.",
    )
    disclaimer: str = Field(default=LEAD_DISCLAIMER)
    matches: list[AiSignatureMatch]
    sources_scanned: int
    chars_scanned: int
    signatures_evaluated: int
    read_errors: list[str]
    truncated: bool


async def _handle(inp: BaseModel) -> FindAiSignaturesOutput:
    assert isinstance(inp, FindAiSignaturesInput)
    scan = scan_sources(
        text=inp.text,
        paths=tuple(inp.paths),
        categories=(frozenset(inp.categories) if inp.categories is not None else None),
        limit=inp.limit,
        preview_chars=inp.preview_chars,
    )
    matches = [
        AiSignatureMatch(
            signature_id=hit.signature_id,
            category=hit.category,
            description=hit.description,
            source=hit.source,
            occurrences=hit.occurrences,
            first_offset=hit.first_offset,
            preview=hit.preview,
        )
        for hit in scan.hits
    ]
    return FindAiSignaturesOutput(
        case_id=inp.case_id,
        matches=matches,
        sources_scanned=scan.sources_scanned,
        chars_scanned=scan.chars_scanned,
        signatures_evaluated=scan.signatures_evaluated,
        read_errors=list(scan.read_errors),
        truncated=scan.truncated,
    )


SPEC = ToolSpec(
    name="find_ai_signatures",
    description=(
        "Scan supplied text and/or named text artifacts for AI / agent tradecraft "
        "signatures and return matches as HYPOTHESIS-tier LEADS. Read-only typed "
        "scanner (NOT a filesystem/shell surface): it touches only the inline "
        "'text' and the explicit 'paths' you pass, opens files for read only, and "
        "never mutates evidence. The curated GENERAL signature list keys on "
        "LLM-assisted tooling and agent-framework fingerprints — LLM output "
        "boilerplate (refusals, 'as an AI language model'), agent-framework module "
        "names (LangChain/LangGraph, LlamaIndex, Auto-GPT/BabyAGI, CrewAI, AutoGen, "
        "Semantic Kernel), the ReAct scratchpad shape, LLM API-client fingerprints "
        "(api.openai.com, api.anthropic.com, SDK imports, system_fingerprint), "
        "prompt scaffolding, and general model-family identifiers (gpt-/claude-/"
        "llama-/mistral-/gemini-). Evidence-agnostic: no image-specific values. "
        "EPISTEMIC SCOPE: every match is a LEAD at the HYPOTHESIS tier "
        "(confidence_tier='HYPOTHESIS', lead_only=True) — it suggests AI/agent "
        "involvement, NEVER that anything executed and NEVER an attribution. A "
        "signature alone never satisfies the >=2-artifact-class execution gate; "
        "corroborate with an independent artifact class before raising confidence. "
        "Pass 'categories' to scope the scan; a file that cannot be read is "
        "reported in 'read_errors' and skipped."
    ),
    input_model=FindAiSignaturesInput,
    output_model=FindAiSignaturesOutput,
    handler=_handle,
)

__all__ = [
    "SPEC",
    "AiSignatureMatch",
    "FindAiSignaturesInput",
    "FindAiSignaturesOutput",
]
