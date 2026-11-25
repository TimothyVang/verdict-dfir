"""``audit_append`` tool — append one record to a hash-chained audit log.

Wraps :meth:`findevil_agent.crypto.audit_log.AuditLog.append`. The
log is identified by an absolute filesystem path; the wrapper
opens (or re-opens) the log for each call so concurrent agents
share the chain through the file system, not in-process state.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from findevil_agent.crypto.audit_log import AuditLog
from pydantic import BaseModel, ConfigDict, Field

from findevil_agent_mcp.tools._base import ToolSpec


class AuditAppendInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(
        ...,
        description="Absolute path to audit.jsonl. Created if missing.",
    )
    kind: str = Field(
        ...,
        description="Event kind, e.g. 'tool_call_start', 'tool_call_output', 'finding_approved'.",
        min_length=1,
    )
    payload: dict[str, Any] = Field(
        ...,
        description="Event body. Will be RFC-8785 canonicalized before hashing.",
    )
    ts: str | None = Field(
        default=None,
        description="Optional UTC ISO-8601Z timestamp; defaults to now().",
    )


class AuditAppendOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    seq: int
    ts: str
    kind: str
    prev_hash: str
    line_hash: str = Field(..., description="SHA-256 of the canonicalized line just written.")


async def _handle(inp: BaseModel) -> AuditAppendOutput:
    args = inp  # already validated AuditAppendInput
    assert isinstance(args, AuditAppendInput)
    log = AuditLog(Path(args.path))
    record = log.append(args.kind, args.payload, ts=args.ts)
    return AuditAppendOutput(
        seq=record.seq,
        ts=record.ts,
        kind=record.kind,
        prev_hash=record.prev_hash,
        line_hash=log.last_hash,
    )


SPEC = ToolSpec(
    name="audit_append",
    description=(
        "Append one event to the case's hash-chained JSONL audit log. Call this after "
        "EVERY tool invocation, finding emission, contradiction, plan change, and analyst "
        "decision — the chain is the M2 chain-of-custody backbone. Each line embeds "
        "prev_hash linking to SHA-256 of the previous line; rewriting history breaks the "
        "chain on verify and the manifest will fail FRE 902(14) authentication. "
        "Common kinds: 'tool_call_start', 'tool_call_output', 'finding_approved', "
        "'agent_message', 'plan_proposed', 'contradiction'. The path argument is the "
        "absolute path to the case's audit.jsonl (created if missing). "
        "Returns the seq, ts, prev_hash, and line_hash so the caller can assert the "
        "chain link landed cleanly. "
        "On error: check the path is writable and that no concurrent process is appending."
    ),
    input_model=AuditAppendInput,
    output_model=AuditAppendOutput,
    handler=_handle,
)

__all__ = ["SPEC", "AuditAppendInput", "AuditAppendOutput"]
