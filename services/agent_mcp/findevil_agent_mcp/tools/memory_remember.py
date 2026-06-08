"""``memory_remember`` tool — Hermes-pattern cross-case memory write (A3 §2.2)."""

from __future__ import annotations

from pathlib import Path

from findevil_agent.memory.store import MemoryStore
from pydantic import BaseModel, ConfigDict, Field

from findevil_agent_mcp.tools._base import ToolSpec


class MemoryRememberInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    store_path: str = Field(..., description="Absolute path to memory.sqlite. Created if missing.")
    case_id: str = Field(..., min_length=1)
    kind: str = Field(
        ..., description="One of: 'ioc', 'hash', 'ttp', 'hostname', 'finding_summary'."
    )
    key: str = Field(..., min_length=1)
    value: str = Field(..., min_length=1)
    sha256: str = Field(
        ...,
        pattern=r"^sha256:[0-9a-f]{64}$",
        description="Lowercase hex SHA-256 with 'sha256:' prefix, e.g. 'sha256:ab12...'.",
    )
    ts: str | None = Field(default=None, description="UTC ISO-8601Z; defaults to now().")
    case_path: str | None = Field(default=None)


class MemoryRememberOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    kind: str
    key: str
    sha256: str


async def _handle(inp: BaseModel) -> MemoryRememberOutput:
    assert isinstance(inp, MemoryRememberInput)
    with MemoryStore(Path(inp.store_path)) as store:
        store.remember(
            case_id=inp.case_id,
            kind=inp.kind,
            key=inp.key,
            value=inp.value,
            sha256=inp.sha256,
            ts=inp.ts,
            case_path=inp.case_path,
        )
    return MemoryRememberOutput(case_id=inp.case_id, kind=inp.kind, key=inp.key, sha256=inp.sha256)


SPEC = ToolSpec(
    name="memory_remember",
    description=(
        "Write a (case_id, kind, key, value, sha256) row to the cross-case FTS5 memory store "
        "so that future investigations can recall this observation. Call when you encounter a "
        "noteworthy IOC, hash, TTP, hostname, or finding summary you'd want a future case to "
        "see. Hermes-pattern (A3 §2.2). The store_path argument is the absolute path to "
        "memory.sqlite — typically ~/.local/state/findevil/memory.sqlite or "
        "%LOCALAPPDATA%\\findevil\\memory.sqlite on Windows. Returns an echo of the key fields. "
        "On error: check the store_path parent directory is writable."
    ),
    input_model=MemoryRememberInput,
    output_model=MemoryRememberOutput,
    handler=_handle,
)

__all__ = ["SPEC", "MemoryRememberInput", "MemoryRememberOutput"]
