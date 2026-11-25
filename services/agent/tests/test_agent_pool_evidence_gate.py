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


class _Rust:
    def call(self, method: str, _params: dict) -> dict:
        assert method == "tools/list"
        return {"tools": [{"name": "evtx_query"}]}


class _Bridge:
    def __init__(self, **_kwargs: object) -> None:
        self.findings: list[dict] = []

    def dispatch(self, _name: str, _args: dict) -> str:
        raise AssertionError("the stubbed loop must not dispatch")


def _investigation() -> fea.Investigation:
    investigation = object.__new__(fea.Investigation)
    investigation.agent_provider = "stub"
    investigation.agent_model = "stub"
    investigation.agent_acknowledge_evidence_egress = False
    investigation.agent_max_steps = 1
    investigation.handle = {"id": "case-agent-gate"}
    investigation.evidence = "/evidence/sample.evtx"
    investigation.tool_calls = []
    investigation.findings_pool_a = []
    investigation.findings_pool_b = []
    investigation._heartbeat = lambda *_args, **_kwargs: None
    return investigation


def _patch_agent_runtime(monkeypatch: pytest.MonkeyPatch, results: list[LoopResult]) -> list[dict]:
    import findevil_agent.agentloop.factory as factory
    import findevil_agent.agentloop.integration as integration
    import findevil_agent.agentloop.loop as loop
    import findevil_agent.agentloop.mcp_tools as mcp_tools

    calls: list[dict] = []
    queued = iter(results)

    def run_agent_loop(*_args: object, **kwargs: object) -> LoopResult:
        calls.append(kwargs)
        return next(queued)

    monkeypatch.setattr(factory, "build_provider", lambda **_kwargs: object())
    monkeypatch.setattr(integration, "AgentToolBridge", _Bridge)
    monkeypatch.setattr(loop, "run_agent_loop", run_agent_loop)
    monkeypatch.setattr(
        mcp_tools,
        "mcp_tools_to_openai",
        lambda _tools: [{"type": "function", "function": {"name": "evtx_query"}}],
    )
    return calls


def test_agent_pools_fail_closed_when_loop_has_no_successful_evidence_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failed = LoopResult(
        final_text="",
        stop="max_steps",
        steps=1,
        messages=[],
        tool_invocations=[
            ToolInvocation(id="bad", name="evtx_query", arguments={}, result="ERROR invalid args"),
            ToolInvocation(id="finding", name="record_finding", arguments={}, result="recorded"),
        ],
    )
    calls = _patch_agent_runtime(monkeypatch, [failed])

    with pytest.raises(RuntimeError, match=r"Pool A.*no successful evidence invocation"):
        _investigation()._run_agent_pools(_Rust(), SimpleNamespace(), "evtx")

    assert len(calls) == 1


def test_agent_pools_continue_when_each_loop_has_successful_evidence_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    successful = LoopResult(
        final_text="done",
        stop="end_turn",
        steps=1,
        messages=[],
        tool_invocations=[
            ToolInvocation(id="good", name="evtx_query", arguments={}, result="3 rows")
        ],
    )
    calls = _patch_agent_runtime(monkeypatch, [successful, successful])

    _investigation()._run_agent_pools(_Rust(), SimpleNamespace(), "evtx")

    assert len(calls) == 2
