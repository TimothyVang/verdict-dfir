"""MCP-surface tests for the anti-forensics 'something is missing' family.

The cross-source anti-forensics leads ride the SAME ``detect_contradictions`` tool
output (with ``afl-`` IDs) so the engine's existing contradiction-resolution path
consumes them with no engine change. These tests assert that surfacing.
"""

from __future__ import annotations

from typing import Any

from findevil_agent_mcp.tools.detect_contradictions import (
    SPEC as DETECT_SPEC,
)
from findevil_agent_mcp.tools.detect_contradictions import (
    DetectContradictionsInput,
    DetectContradictionsOutput,
)


def _finding(**overrides: Any) -> dict[str, Any]:
    base = {
        "case_id": "case-001",
        "finding_id": "f-1",
        "tool_call_id": "tc-1",
        "artifact_path": "SYSTEM",
        "confidence": "HYPOTHESIS",
        "mitre_technique": None,
        "description": "a logon event was recorded",
        "pool_origin": "A",
    }
    base.update(overrides)
    return base


async def test_log_wipe_lead_surfaces_via_tool() -> None:
    wipe = _finding(
        finding_id="f-wipe",
        artifact_path="Security.evtx",
        description="EID 1102: the security audit log was cleared",
        pool_origin="A",
    )
    result = await DETECT_SPEC.handler(
        DetectContradictionsInput(
            case_id="case-001",
            pool_a=[wipe],
            pool_b=[],
            resolution_required=False,
        )
    )
    assert isinstance(result, DetectContradictionsOutput)
    assert result.antiforensics_count == 1
    afl = [c for c in result.contradictions if c.contradiction_id.startswith("afl-")]
    assert len(afl) == 1
    assert "LOG_WIPE" in afl[0].pool_b_claim
    assert "HYPOTHESIS" in afl[0].pool_b_claim


async def test_hidden_service_lead_surfaces_via_tool() -> None:
    svc = _finding(
        finding_id="f-svc",
        description="EID 7045: a new service was installed with ImagePath C:\\Windows\\evil.sys",
        pool_origin="A",
    )
    proc = _finding(
        finding_id="f-proc",
        tool_call_id="tc-2",
        artifact_path="memdump",
        description="pslist shows running process explorer.exe (pid 1234)",
        pool_origin="B",
    )
    result = await DETECT_SPEC.handler(
        DetectContradictionsInput(
            case_id="case-001",
            pool_a=[svc],
            pool_b=[proc],
            resolution_required=True,
        )
    )
    assert result.antiforensics_count >= 1
    assert any("HIDDEN_SERVICE" in c.pool_b_claim for c in result.contradictions)


async def test_benign_findings_surface_no_antiforensics() -> None:
    a = _finding(finding_id="f-a", description="a logon event was recorded", pool_origin="A")
    b = _finding(
        finding_id="f-b",
        tool_call_id="tc-2",
        artifact_path="other",
        description="another logon event was recorded",
        pool_origin="B",
    )
    result = await DETECT_SPEC.handler(
        DetectContradictionsInput(case_id="case-001", pool_a=[a], pool_b=[b])
    )
    assert result.antiforensics_count == 0
    assert all(not c.contradiction_id.startswith("afl-") for c in result.contradictions)
