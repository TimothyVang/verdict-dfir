"""``pool_handoff`` tool — IBM-ACP agent-to-agent handoff (A3 §2.3)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from findevil_agent.acp.handoff import handoff
from findevil_agent.crypto.audit_log import AuditLog
from pydantic import BaseModel, ConfigDict, Field

from findevil_agent_mcp.tools._base import ToolSpec

Role = Literal["pool_a", "pool_b", "verifier", "judge", "correlator", "supervisor"]


class PoolHandoffInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    audit_path: str = Field(..., description="Absolute path to the case's audit.jsonl.")
    from_role: Role
    to_role: Role
    payload: dict[str, Any]
    correlation_id: str | None = Field(default=None)


class PoolHandoffOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    acp_version: str
    from_role: Role
    to_role: Role
    correlation_id: str
    ts: str


async def _handle(inp: BaseModel) -> PoolHandoffOutput:
    assert isinstance(inp, PoolHandoffInput)
    log = AuditLog(Path(inp.audit_path))
    msg = handoff(
        log=log,
        from_role=inp.from_role,
        to_role=inp.to_role,
        payload=inp.payload,
        correlation_id=inp.correlation_id,
    )
    return PoolHandoffOutput(
        acp_version=msg.acp_version,
        from_role=msg.from_role,
        to_role=msg.to_role,
        correlation_id=msg.correlation_id,
        ts=msg.ts,
    )


SPEC = ToolSpec(
    name="pool_handoff",
    description=(
        "Send an IBM-ACP-shaped agent-to-agent message between roles "
        "(pool_a → pool_b, verifier → judge, etc.) and record it as a kind='acp_handoff' "
        "line in the case audit JSONL. Use when one pool/role needs to formally hand "
        "structured findings or context to another, distinct from natural-language "
        "supervisor messaging. The correlation_id lets downstream roles thread replies. "
        "Returns the envelope echo so the caller can record the correlation_id for "
        "later replies. "
        "On error: verify audit_path's parent directory exists and is writable, and "
        "that no concurrent process is appending to the same file."
    ),
    input_model=PoolHandoffInput,
    output_model=PoolHandoffOutput,
    handler=_handle,
)

__all__ = ["SPEC", "PoolHandoffInput", "PoolHandoffOutput"]
