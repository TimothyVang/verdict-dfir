from __future__ import annotations

import json
from pathlib import Path

import pytest
from findevil_agent.crypto.audit_log import AuditLog

from findevil_agent_mcp.tools.expert_miss_capture import (
    ExpertMissCaptureInput,
    _handle,
)


@pytest.mark.asyncio
async def test_expert_miss_capture_appends_hash_chained_record(tmp_path: Path) -> None:
    ledger = tmp_path / "expert_misses.jsonl"

    first = await _handle(
        ExpertMissCaptureInput(
            case_id="case-001",
            finding_id="finding-001",
            edit_type="qa",
            edit_text="Report needed a stronger replay caveat.",
            expert_name="Analyst One",
            ledger_path=str(ledger),
        )
    )
    second = await _handle(
        ExpertMissCaptureInput(
            case_id="case-001",
            finding_id=None,
            edit_type="connector",
            edit_text="Need a network connector for proxy logs.",
            expert_name=None,
            ledger_path=str(ledger),
        )
    )

    assert first.seq == 0
    assert first.prev_hash == ""
    assert first.github_issue_url is None
    assert second.seq == 1
    assert second.prev_hash == first.line_hash
    assert AuditLog(ledger).verify() == 2

    lines = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["kind"] == "expert_miss"
    assert lines[0]["payload"] == {
        "case_id": "case-001",
        "finding_id": "finding-001",
        "edit_type": "qa",
        "edit_text": "Report needed a stronger replay caveat.",
        "expert_name": "Analyst One",
    }
    assert lines[1]["payload"]["edit_type"] == "connector"


def test_expert_miss_capture_requires_absolute_ledger_path() -> None:
    with pytest.raises(ValueError, match="ledger_path must be absolute"):
        ExpertMissCaptureInput(
            case_id="case-001",
            finding_id=None,
            edit_type="language",
            edit_text="Remove unqualified wording.",
            expert_name=None,
            ledger_path="relative/expert_misses.jsonl",
        )
