"""Increment 3: AnthropicProvider — canonical messages+tools <-> Claude Messages API.

Uses an injected transport (request dict -> response dict) so the mapping and
response normalization are tested with no network. The real HTTP transport is a
thin default exercised only by the live acceptance run.
"""

from __future__ import annotations

from typing import Any

from findevil_agent.agentloop.anthropic_provider import AnthropicProvider
from findevil_agent.agentloop.types import ProviderResponse

_OPENAI_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "evtx_query",
            "description": "Parse EVTX.",
            "parameters": {"type": "object", "properties": {"path": {"type": "string"}}},
        },
    }
]


def _recorder() -> tuple[list[dict[str, Any]], Any]:
    seen: list[dict[str, Any]] = []

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        seen.append(request)
        return {"content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"}

    return seen, transport


def test_openai_tools_become_anthropic_input_schema() -> None:
    seen, transport = _recorder()
    p = AnthropicProvider(model="claude-x", transport=transport)
    p.complete([{"role": "user", "content": "hi"}], _OPENAI_TOOLS)
    sent_tools = seen[0]["tools"]
    assert sent_tools == [
        {
            "name": "evtx_query",
            "description": "Parse EVTX.",
            "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}},
        }
    ]


def test_tool_use_response_normalizes_to_toolcalls() -> None:
    def transport(_req: dict[str, Any]) -> dict[str, Any]:
        return {
            "content": [
                {"type": "text", "text": "let me look"},
                {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "evtx_query",
                    "input": {"path": "/x.evtx"},
                },
            ],
            "stop_reason": "tool_use",
        }

    p = AnthropicProvider(model="claude-x", transport=transport)
    resp: ProviderResponse = p.complete([{"role": "user", "content": "go"}], _OPENAI_TOOLS)
    assert resp.stop_reason == "tool_use"
    assert resp.text == "let me look"
    assert len(resp.tool_calls) == 1
    assert resp.tool_calls[0].id == "toolu_1"
    assert resp.tool_calls[0].name == "evtx_query"
    assert resp.tool_calls[0].arguments == {"path": "/x.evtx"}


def test_text_only_response_is_end_turn() -> None:
    seen, transport = _recorder()
    p = AnthropicProvider(model="claude-x", transport=transport)
    resp = p.complete([{"role": "user", "content": "hi"}], [])
    assert resp.stop_reason == "end_turn"
    assert resp.text == "ok"
    assert resp.tool_calls == []


def test_tool_result_message_becomes_anthropic_tool_result_block() -> None:
    seen, transport = _recorder()
    p = AnthropicProvider(model="claude-x", transport=transport)
    messages = [
        {"role": "user", "content": "go"},
        {
            "role": "assistant",
            "tool_calls": [{"id": "toolu_1", "name": "evtx_query", "arguments": {"path": "/x"}}],
        },
        {"role": "tool", "tool_call_id": "toolu_1", "content": "5 rows"},
    ]
    p.complete(messages, _OPENAI_TOOLS)
    sent = seen[0]["messages"]
    # assistant turn carries a tool_use block; the tool result becomes a user tool_result block
    assert sent[1]["role"] == "assistant"
    assert sent[1]["content"][0]["type"] == "tool_use"
    assert sent[2]["role"] == "user"
    assert sent[2]["content"][0] == {
        "type": "tool_result",
        "tool_use_id": "toolu_1",
        "content": "5 rows",
    }


def test_system_prompt_is_separated() -> None:
    seen, transport = _recorder()
    p = AnthropicProvider(model="claude-x", transport=transport)
    p.complete([{"role": "user", "content": "hi"}], [], system="you are pool A")
    assert seen[0]["system"] == "you are pool A"
    assert all(m["role"] != "system" for m in seen[0]["messages"])
