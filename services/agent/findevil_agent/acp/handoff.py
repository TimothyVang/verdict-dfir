"""IBM-ACP envelope + audit-log-backed handoff (A3 §2.3).

Records agent-to-agent messages as kind="acp_handoff" lines in the
case's hash-chained audit JSONL. Network transport is deliberately
out of scope; future networked-ACP can add an HTTP transport behind
the same `handoff()` signature.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from findevil_agent.crypto.audit_log import AuditLog

Role = Literal["pool_a", "pool_b", "verifier", "judge", "correlator", "supervisor"]


class ACPMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    acp_version: str = Field(default="1.0")
    from_role: Role
    to_role: Role
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    payload: dict[str, Any]
    ts: str = Field(default_factory=lambda: datetime.now(tz=UTC).isoformat().replace("+00:00", "Z"))


def handoff(
    *,
    log: AuditLog,
    from_role: Role,
    to_role: Role,
    payload: dict[str, Any],
    correlation_id: str | None = None,
) -> ACPMessage:
    msg = ACPMessage(
        from_role=from_role,
        to_role=to_role,
        payload=payload,
        **({"correlation_id": correlation_id} if correlation_id else {}),
    )
    log.append("acp_handoff", msg.model_dump(), ts=msg.ts)
    return msg
