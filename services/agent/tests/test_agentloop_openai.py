"""OpenAIProvider — the provider-agnostic backend (OpenAI / OpenRouter / local / DGX).

The OpenAI Chat Completions shape is the universal contract: native tool-calling
(structured tool_calls, no JSON-in-prose), automatic prefix caching, and a clean
inference endpoint (no per-call agent boot like claude -p). One adapter serves
OpenAI, OpenRouter, a local vLLM/Ollama server, and a DGX Spark — only base_url +
key + model change. The HTTP call is an injected transport so mapping and parsing
are tested with no network.
"""

from __future__ import annotations

from typing import Any

import pytest

from findevil_agent.agentloop.openai_provider import OpenAIProvider


def test_rejects_non_http_base_url() -> None:
    # SSRF guard: a non-http(s) base_url is refused before any evidence is POSTed.
    with pytest.raises(ValueError, match="http"):
        OpenAIProvider(model="m", base_url="file:///etc/passwd")


_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "evtx_query",
            "description": "Parse EVTX.",
            "parameters": {"type": "object", "properties": {"path": {"type": "string"}}},
        },
    }
]


def _recorder(response: dict[str, Any]):
    seen: list[dict[str, Any]] = []

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        seen.append(request)
        return response

    return seen, transport


def test_request_carries_model_tools_and_tool_choice() -> None:
    seen, transport = _recorder(
        {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}
    )
    p = OpenAIProvider(model="gpt-x", transport=transport)
    p.complete([{"role": "user", "content": "hi"}], _TOOLS, system="you are pool A")
    req = seen[0]
    assert req["model"] == "gpt-x"
    assert req["tools"] == _TOOLS  # already OpenAI-shape, passed through
    assert req["tool_choice"] == "auto"
    # system becomes a leading system message
    assert req["messages"][0] == {"role": "system", "content": "you are pool A"}
    assert req["messages"][1] == {"role": "user", "content": "hi"}


def test_tool_call_response_normalizes_to_toolcalls() -> None:
    response = {
        "choices": [
            {
                "message": {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "evtx_query", "arguments": '{"path": "/x.evtx"}'},
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ]
    }
    _seen, transport = _recorder(response)
    p = OpenAIProvider(model="gpt-x", transport=transport)
    resp = p.complete([{"role": "user", "content": "go"}], _TOOLS)
    assert resp.stop_reason == "tool_use"
    assert len(resp.tool_calls) == 1
    assert resp.tool_calls[0].id == "call_1"
    assert resp.tool_calls[0].name == "evtx_query"
    assert resp.tool_calls[0].arguments == {"path": "/x.evtx"}  # JSON-string args parsed


def test_text_response_is_end_turn() -> None:
    _seen, transport = _recorder(
        {"choices": [{"message": {"content": "no leads"}, "finish_reason": "stop"}]}
    )
    p = OpenAIProvider(model="gpt-x", transport=transport)
    resp = p.complete([{"role": "user", "content": "hi"}], [])
    assert resp.stop_reason == "end_turn"
    assert resp.text == "no leads"
    assert resp.tool_calls == []


def test_assistant_tool_calls_and_tool_result_round_trip() -> None:
    seen, transport = _recorder(
        {"choices": [{"message": {"content": "done"}, "finish_reason": "stop"}]}
    )
    p = OpenAIProvider(model="gpt-x", transport=transport)
    messages = [
        {"role": "user", "content": "go"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [{"id": "c1", "name": "evtx_query", "arguments": {"path": "/x"}}],
        },
        {"role": "tool", "tool_call_id": "c1", "content": "5 rows"},
    ]
    p.complete(messages, _TOOLS)
    sent = seen[0]["messages"]
    # assistant tool_calls rendered in OpenAI shape (arguments JSON-stringified)
    assistant = next(m for m in sent if m["role"] == "assistant")
    assert assistant["tool_calls"][0]["type"] == "function"
    assert assistant["tool_calls"][0]["function"]["name"] == "evtx_query"
    assert assistant["tool_calls"][0]["function"]["arguments"] == '{"path": "/x"}'
    # tool result carries the tool_call_id
    tool_msg = next(m for m in sent if m["role"] == "tool")
    assert tool_msg == {"role": "tool", "tool_call_id": "c1", "content": "5 rows"}


def test_default_transport_targets_base_url_with_bearer() -> None:
    # Without a transport, the provider builds a urllib transport; we only assert it
    # constructs (no network call made) and exposes its config.
    p = OpenAIProvider(model="m", base_url="http://localhost:11434/v1", api_key="sk-local")
    assert p.base_url == "http://localhost:11434/v1"
    assert p.model == "m"
