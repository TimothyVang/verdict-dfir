"""``memory_recall`` tool — Hermes-pattern cross-case memory query (A3 §2.2)."""

from __future__ import annotations

from pathlib import Path

from findevil_agent.memory.store import MemoryStore
from pydantic import BaseModel, ConfigDict, Field

from findevil_agent_mcp.tools._base import ToolSpec


class MemoryRecallInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    store_path: str = Field(..., description="Absolute path to memory.sqlite.")
    query: str = Field(..., min_length=1, description="FTS5 query string.")
    kind: str | None = Field(
        default=None,
        description="Optional filter: 'ioc'|'hash'|'ttp'|'hostname'|'finding_summary'.",
    )
    limit: int = Field(default=10, ge=1, le=100)


class RecallHitOut(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    kind: str
    key: str
    value: str
    sha256: str
    ts: str
    confidence: float


class MemoryRecallOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hits: list[RecallHitOut]


async def _handle(inp: BaseModel) -> MemoryRecallOutput:
    assert isinstance(inp, MemoryRecallInput)
    with MemoryStore(Path(inp.store_path)) as store:
        rows = store.recall(inp.query, kind=inp.kind, limit=inp.limit)
    return MemoryRecallOutput(
        hits=[
            RecallHitOut(
                case_id=r.case_id,
                kind=r.kind,
                key=r.key,
                value=r.value,
                sha256=r.sha256,
                ts=r.ts,
                confidence=r.confidence,
            )
            for r in rows
        ]
    )


SPEC = ToolSpec(
    name="memory_recall",
    description=(
        "Query the cross-case FTS5 memory store for prior-case observations matching a search. "
        "Use this BEFORE proposing a finding to check whether you've seen this IOC/hash/TTP "
        "in a previous investigation — reduces re-investigation hallucination on patterns you "
        "already know. Hermes-pattern (A3 §2.2). "
        "**Query semantics: exact phrase match.** The query string is phrase-quoted before "
        "being passed to FTS5 MATCH (so 'evil.com' or 'T1059.001' match safely without "
        "tripping on the dot). Multi-word queries become exact-phrase searches: pass "
        "'powershell' alone, NOT 'powershell encoded' (which would only hit rows containing "
        "that literal two-word phrase). Hits are returned ordered by BM25 relevance * "
        "90-day exponential decay. The kind argument optionally filters to one of: 'ioc', "
        "'hash', 'ttp', 'hostname', 'finding_summary'. Empty hits list means no prior cases "
        "matched — that's a useful signal too."
    ),
    input_model=MemoryRecallInput,
    output_model=MemoryRecallOutput,
    handler=_handle,
)

__all__ = ["SPEC", "MemoryRecallInput", "MemoryRecallOutput", "RecallHitOut"]
