"""Increment 4: the agent loop — provider <-> MCP tool dispatch until end_turn.

A scripted fake provider returns a queue of ProviderResponses; a fake dispatch
records (name, arguments) and returns a canned tool result. No network, no real
MCP. The loop must: feed tool results back as ``tool`` messages, stop on end_turn,
and enforce a max-step guard so a model that never stops is bounded.
"""

from __future__ import annotations

from typing import Any

from findevil_agent.agentloop.loop import run_agent_loop
from findevil_agent.agentloop.types import ProviderResponse, ToolCall


class ScriptedProvider:
    """Returns queued responses in order; records the messages it was given."""

    def __init__(self, responses: list[ProviderResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[list[dict[str, Any]]] = []

    def complete(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], **kwargs: Any
    ) -> ProviderResponse:
        self.calls.append([dict(m) for m in messages])
        return self._responses.pop(0)


def _dispatch_recorder(result: str = "ok-result"):
    seen: list[tuple[str, dict[str, Any]]] = []

    def dispatch(name: str, arguments: dict[str, Any]) -> str:
        seen.append((name, arguments))
        return result

    return seen, dispatch


def test_loop_stops_immediately_on_end_turn() -> None:
    provider = ScriptedProvider([ProviderResponse(text="nothing to do", stop_reason="end_turn")])
    seen, dispatch = _dispatch_recorder()
    result = run_agent_loop(provider, tools=[], dispatch=dispatch, system="s", user_task="go")
    assert result.stop == "end_turn"
    assert result.final_text == "nothing to do"
    assert result.tool_invocations == []
    assert seen == []


def test_loop_dispatches_tool_then_finishes() -> None:
    provider = ScriptedProvider(
        [
            ProviderResponse(
                text="checking",
                tool_calls=[ToolCall(id="t1", name="evtx_query", arguments={"path": "/x"})],
                stop_reason="tool_use",
            ),
            ProviderResponse(text="done analyzing", stop_reason="end_turn"),
        ]
    )
    seen, dispatch = _dispatch_recorder(result="5 rows")
    result = run_agent_loop(provider, tools=[], dispatch=dispatch, system="s", user_task="go")

    assert result.stop == "end_turn"
    assert result.final_text == "done analyzing"
    assert seen == [("evtx_query", {"path": "/x"})]
    # the tool result was fed back to the model on its second turn
    second_turn_msgs = provider.calls[1]
    tool_msgs = [m for m in second_turn_msgs if m["role"] == "tool"]
    assert tool_msgs == [{"role": "tool", "tool_call_id": "t1", "content": "5 rows"}]
    # and the loop recorded the invocation for audit
    assert result.tool_invocations[0].name == "evtx_query"
    assert result.tool_invocations[0].result == "5 rows"


def test_loop_enforces_max_steps_guard() -> None:
    never_stops = [
        ProviderResponse(
            text="again",
            tool_calls=[ToolCall(id=f"t{i}", name="vol_pslist", arguments={})],
            stop_reason="tool_use",
        )
        for i in range(10)
    ]
    provider = ScriptedProvider(never_stops)
    seen, dispatch = _dispatch_recorder()
    result = run_agent_loop(
        provider, tools=[], dispatch=dispatch, system="s", user_task="go", max_steps=3
    )
    assert result.stop == "max_steps"
    assert len(seen) == 3


def test_loop_handles_multiple_tool_calls_in_one_turn() -> None:
    provider = ScriptedProvider(
        [
            ProviderResponse(
                text="",
                tool_calls=[
                    ToolCall(id="a", name="case_open", arguments={"path": "/e"}),
                    ToolCall(id="b", name="evtx_query", arguments={"path": "/e/x"}),
                ],
                stop_reason="tool_use",
            ),
            ProviderResponse(text="fin", stop_reason="end_turn"),
        ]
    )
    seen, dispatch = _dispatch_recorder()
    result = run_agent_loop(provider, tools=[], dispatch=dispatch, system="s", user_task="go")
    assert [n for n, _ in seen] == ["case_open", "evtx_query"]
    assert len(result.tool_invocations) == 2
