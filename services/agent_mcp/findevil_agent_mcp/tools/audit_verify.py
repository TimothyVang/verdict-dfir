"""``audit_verify`` tool — replay the hash-chained audit log offline.

Wraps :meth:`findevil_agent.crypto.audit_log.AuditLog.verify`. Returns
``ok: True`` plus the record count on a clean replay; ``ok: False``
plus the first chain-break message on failure.
"""

from __future__ import annotations

from pathlib import Path

from findevil_agent.crypto.audit_log import AuditLog, AuditLogError
from pydantic import BaseModel, ConfigDict, Field

from findevil_agent_mcp.tools._base import ToolSpec


class AuditVerifyInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(..., description="Absolute path to audit.jsonl.")


class AuditVerifyOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    record_count: int
    error: str | None = Field(
        default=None,
        description="Chain-break reason on failure; null on success.",
    )


async def _handle(inp: BaseModel) -> AuditVerifyOutput:
    assert isinstance(inp, AuditVerifyInput)
    log = AuditLog(Path(inp.path))
    try:
        count = log.verify()
    except AuditLogError as exc:
        return AuditVerifyOutput(ok=False, record_count=0, error=str(exc))
    return AuditVerifyOutput(ok=True, record_count=count, error=None)


SPEC = ToolSpec(
    name="audit_verify",
    description=(
        "Replay an audit-log hash chain and report whether it verifies cleanly. Use this "
        "before manifest_finalize (sanity check) and during offline replay by a third "
        "party validating the FRE 902(14) self-authenticating evidence chain. Detects: "
        "(1) prev_hash mismatch (tampering), (2) seq gaps (torn writes / append race), "
        "(3) non-canonical lines (a writer that didn't use canonicalize_json). "
        "Returns ok=True + record_count on success; ok=False + error string on the first "
        "break (the rest is unverified — the chain breaks at the first bad link). "
        "Missing-file is treated as an empty (valid) log and returns ok=True, count=0; "
        "use this to distinguish 'no events yet' from 'chain broken'."
    ),
    input_model=AuditVerifyInput,
    output_model=AuditVerifyOutput,
    handler=_handle,
)

__all__ = ["SPEC", "AuditVerifyInput", "AuditVerifyOutput"]
