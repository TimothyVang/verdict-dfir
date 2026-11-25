from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from findevil_agent.agentloop.loop import LoopResult, ToolInvocation

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def _evtx_output(event_id: int, channel: str = "Security") -> dict:
    return {
        "rows": [
            {
                "event_id": event_id,
                "channel": channel,
                "record_id": 42,
                "ts": "2019-03-19T23:35:07Z",
                "data": {},
            }
        ],
        "row_count": 1,
        "records_seen": 1,
        "parse_errors": 0,
    }


def test_recovers_confirmed_1102_from_current_agent_query() -> None:
    findings = fea.recover_agent_high_signal_findings(
        [("tc-agent-1", _evtx_output(1102))],
        existing_findings=[],
        case_id="case-agent",
        artifact_path="/evidence/Security.evtx",
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["tool_call_id"] == "tc-agent-1"
    assert finding["confidence"] == "CONFIRMED"
    assert finding["mitre_technique"] == "T1070.001"
    assert finding["asserted_values"] == [
        {
            "path": "rows[*]",
            "expected": '{"event_id": "1102", "channel": "Security"}',
            "match": "record",
        }
    ]


def test_benign_agent_query_recovers_nothing() -> None:
    assert (
        fea.recover_agent_high_signal_findings(
            [("tc-agent-1", _evtx_output(4624))],
            existing_findings=[],
            case_id="case-agent",
            artifact_path="/evidence/Security.evtx",
        )
        == []
    )


def test_existing_1102_assertion_suppresses_duplicate() -> None:
    existing = [
        {
            "mitre_technique": "T1070.001",
            "asserted_values": [
                {"path": "rows[0].event_id", "expected": "1102", "match": "exact"}
            ],
        }
    ]
    assert (
        fea.recover_agent_high_signal_findings(
            [("tc-agent-1", _evtx_output(1102))],
            existing_findings=existing,
            case_id="case-agent",
            artifact_path="/evidence/Security.evtx",
        )
        == []
    )


def test_unrelated_1102_substring_does_not_suppress_recovery() -> None:
    existing = [
        {
            "mitre_technique": "T1070.001",
            "asserted_values": [
                {"path": "rows[0].record_id", "expected": "1102", "match": "exact"}
            ],
        }
    ]

    findings = fea.recover_agent_high_signal_findings(
        [("tc-agent-1", _evtx_output(1102))],
        existing_findings=existing,
        case_id="case-agent",
        artifact_path="/evidence/Security.evtx",
    )

    assert len(findings) == 1


def test_invalid_event_id_matcher_does_not_suppress_recovery() -> None:
    existing = [
        {
            "mitre_technique": "T1070.001",
            "asserted_values": [
                {"path": "rows[0].event_id", "expected": "1102", "match": "iso_ts"}
            ],
        }
    ]

    findings = fea.recover_agent_high_signal_findings(
        [("tc-agent-1", _evtx_output(1102))],
        existing_findings=existing,
        case_id="case-agent",
        artifact_path="/evidence/Security.evtx",
    )

    assert len(findings) == 1


def test_nested_record_assertion_does_not_suppress_recovery() -> None:
    existing = [
        {
            "mitre_technique": "T1070.001",
            "asserted_values": [
                {
                    "path": "rows[*].data",
                    "expected": '{"event_id": "1102", "channel": "Security"}',
                    "match": "record",
                }
            ],
        }
    ]

    findings = fea.recover_agent_high_signal_findings(
        [("tc-agent-1", _evtx_output(1102))],
        existing_findings=existing,
        case_id="case-agent",
        artifact_path="/evidence/Security.evtx",
    )

    assert len(findings) == 1


def test_non_security_eid_1102_recovers_nothing() -> None:
    findings = fea.recover_agent_high_signal_findings(
        [("tc-agent-1", _evtx_output(1102, channel="Application"))],
        existing_findings=[],
        case_id="case-agent",
        artifact_path="/evidence/Application.evtx",
    )

    assert findings == []


def test_error_shaped_agent_output_recovers_nothing() -> None:
    findings = fea.recover_agent_high_signal_findings(
        [("tc-agent-1", {"_error": {"message": "parse failed"}})],
        existing_findings=[],
        case_id="case-agent",
        artifact_path="/evidence/Security.evtx",
    )

    assert findings == []


class _Rust:
    def call(self, method: str, _params: dict) -> dict:
        assert method == "tools/list"
        return {"tools": [{"name": "evtx_query"}]}

    def call_tool(self, name: str, _args: dict) -> dict:
        assert name == "evtx_query"
        return {**_evtx_output(1102), "_mcp_output_sha256": "a" * 64}


def test_agent_pools_recover_1102_when_model_does_not_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import findevil_agent.agentloop.factory as factory
    import findevil_agent.agentloop.loop as loop
    import findevil_agent.agentloop.mcp_tools as mcp_tools

    investigation = object.__new__(fea.Investigation)
    investigation.agent_provider = "stub"
    investigation.agent_model = "stub"
    investigation.agent_acknowledge_evidence_egress = False
    investigation.agent_max_steps = 2
    investigation.handle = {"id": "case-agent"}
    investigation.evidence = "/evidence/Security.evtx"
    investigation.tool_calls = []
    investigation.findings_pool_a = []
    investigation.findings_pool_b = []
    investigation._heartbeat = lambda *_args, **_kwargs: None
    tcids = iter(("tc-agent-1", "tc-agent-2"))

    def record_tool(_py, name: str, output_hash: str, **kwargs) -> str:
        tcid = next(tcids)
        investigation.tool_calls.append(
            {
                "tool_call_id": tcid,
                "tool": name,
                "output_hash": output_hash,
                "arguments": kwargs.get("arguments", {}),
            }
        )
        return tcid

    investigation._record_tool = record_tool
    audited: list[tuple[str, dict]] = []
    investigation._audit = lambda _py, kind, payload: audited.append((kind, payload))
    disciplined_nonempty: list[list[dict]] = []
    real_discipline = fea.discipline_agent_findings

    def track_discipline(findings: list[dict], tool_calls: list[dict]):
        if findings:
            disciplined_nonempty.append(findings)
        return real_discipline(findings, tool_calls)

    monkeypatch.setattr(fea, "discipline_agent_findings", track_discipline)

    def run_agent_loop(*_args, **kwargs) -> LoopResult:
        result = kwargs["dispatch"]("evtx_query", {})
        return LoopResult(
            final_text="done without recording",
            stop="end_turn",
            steps=1,
            messages=[],
            tool_invocations=[
                ToolInvocation(id="query", name="evtx_query", arguments={}, result=result)
            ],
        )

    monkeypatch.setattr(factory, "build_provider", lambda **_kwargs: object())
    monkeypatch.setattr(loop, "run_agent_loop", run_agent_loop)
    monkeypatch.setattr(
        mcp_tools,
        "mcp_tools_to_openai",
        lambda _tools: [{"type": "function", "function": {"name": "evtx_query"}}],
    )

    investigation._run_agent_pools(_Rust(), SimpleNamespace(), "evtx")

    assert [f["mitre_technique"] for f in investigation.findings_pool_a] == ["T1070.001"]
    assert investigation.findings_pool_a[0]["tool_call_id"] in {"tc-agent-1", "tc-agent-2"}
    assert any(kind == "agent_high_signal_candidate" for kind, _payload in audited)
    assert [[f["mitre_technique"] for f in findings] for findings in disciplined_nonempty] == [
        ["T1070.001"]
    ]
