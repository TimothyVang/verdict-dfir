"""IBM-ACP envelope + audit-log writer tests (A3 §2.3)."""

import json
from pathlib import Path

from findevil_agent.acp.handoff import ACPMessage, handoff
from findevil_agent.crypto.audit_log import AuditLog


def test_handoff_writes_acp_handoff_kind_to_audit_log(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    log = AuditLog(audit)

    msg = handoff(
        log=log,
        from_role="pool_a",
        to_role="pool_b",
        payload={"finding_id": "f-001", "summary": "persistence via Run key"},
    )

    assert msg.acp_version == "1.0"
    assert msg.from_role == "pool_a"
    assert msg.to_role == "pool_b"
    assert msg.correlation_id  # non-empty UUID

    # The audit log got one entry, kind=acp_handoff.
    lines = audit.read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["kind"] == "acp_handoff"
    assert record["payload"]["from_role"] == "pool_a"
    assert record["payload"]["to_role"] == "pool_b"


def test_acp_message_envelope_shape() -> None:
    msg = ACPMessage(
        from_role="pool_a",
        to_role="judge",
        payload={"x": 1},
    )
    dumped = msg.model_dump()
    assert set(dumped.keys()) == {
        "acp_version",
        "from_role",
        "to_role",
        "correlation_id",
        "payload",
        "ts",
    }
    assert dumped["acp_version"] == "1.0"
