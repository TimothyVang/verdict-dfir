"""Shared fixtures for findevil-agent-mcp tests.

The tests exercise the MCP-layer wrappers — input validation, output
shape, error mapping. The wrapped logic is already covered by
``services/agent/tests``; here we focus on the boundary.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from findevil_agent.crypto.audit_log import AuditLog


@pytest.fixture(autouse=True)
def _fact_fidelity_gate_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    # The fact-fidelity gate is production-default-ON (Stage A). These MCP-boundary
    # tests build findings as fixtures (finding_a / finding_b) to exercise the
    # wrappers, not the gate, so default it off here; gate behavior is covered in
    # services/agent/tests. See services/agent/tests/conftest.py.
    monkeypatch.setenv("FIND_EVIL_REQUIRE_ASSERTED_VALUES", "0")


@pytest.fixture
def seeded_audit_log(tmp_path: Path) -> Path:
    """Audit log with the seven-record fixture used by manifest tests."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("tool_call_start", {"tool_call_id": "tc-1", "tool": "evtx_query"})
    log.append(
        "tool_call_output",
        {"tool_call_id": "tc-1", "output_hash": "a" * 64, "row_count": 42},
    )
    log.append("agent_message", {"role": "supervisor", "content": "investigating"})
    log.append("tool_call_start", {"tool_call_id": "tc-2", "tool": "mft_timeline"})
    log.append(
        "tool_call_output",
        {"tool_call_id": "tc-2", "output_hash": "b" * 64, "row_count": 12},
    )
    log.append(
        "finding_approved",
        {"finding_id": "f-1", "tool_call_id": "tc-1", "confidence": "CONFIRMED"},
    )
    log.append(
        "finding_approved",
        {"finding_id": "f-2", "tool_call_id": "tc-2", "confidence": "INFERRED"},
    )
    return path


@pytest.fixture
def finding_a() -> dict[str, Any]:
    """A canonical Pool A finding (persistence-flavored)."""
    return {
        "case_id": "case-001",
        "finding_id": "f-A-1",
        "tool_call_id": "tc-1",
        "artifact_path": "C:\\Windows\\System32\\Tasks\\Microsoft\\evil.xml",
        "confidence": "CONFIRMED",
        "mitre_technique": "T1053.005",
        "description": "Scheduled task pointing at user-writable binary",
        "pool_origin": "A",
    }


@pytest.fixture
def finding_b() -> dict[str, Any]:
    """A canonical Pool B finding (exfil-flavored) on a different artifact."""
    return {
        "case_id": "case-001",
        "finding_id": "f-B-1",
        "tool_call_id": "tc-2",
        "artifact_path": "C:\\Users\\Public\\out\\stage.zip",
        "confidence": "INFERRED",
        "mitre_technique": "T1560.001",
        "description": "Compressed staging archive in user-writable directory",
        "pool_origin": "B",
    }
