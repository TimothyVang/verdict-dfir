"""Tests for pool_handoff MCP tool (A3 §2.3)."""

import json
from pathlib import Path

import pytest

from findevil_agent_mcp.tools.pool_handoff import SPEC, PoolHandoffInput


@pytest.mark.asyncio
async def test_pool_handoff_appends_acp_line(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    out = await SPEC.handler(
        PoolHandoffInput(
            audit_path=str(audit),
            from_role="pool_a",
            to_role="judge",
            payload={"finding_id": "f-42"},
        )
    )
    assert out.acp_version == "1.0"
    assert out.from_role == "pool_a"
    assert out.to_role == "judge"

    record = json.loads(audit.read_text().splitlines()[0])
    assert record["kind"] == "acp_handoff"
