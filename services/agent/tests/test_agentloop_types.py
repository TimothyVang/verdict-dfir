"""Increment 2: canonical provider types + the ChatProvider contract.

The loop speaks one shape regardless of backend: messages + tool specs in, a
ProviderResponse (text + normalized ToolCalls + stop reason) out. OpenAI returns
tool-call arguments as a JSON *string*; the canonical ToolCall exposes a parsed dict
so the loop never re-parses per provider.
"""

from __future__ import annotations

from findevil_agent.agentloop.types import (
    ChatProvider,
    ProviderResponse,
    ToolCall,
)


def test_toolcall_from_openai_parses_json_string_arguments() -> None:
    raw = {
        "id": "call_1",
        "function": {"name": "evtx_query", "arguments": '{"path": "/x.evtx", "limit": 5}'},
    }
    tc = ToolCall.from_openai(raw)
    assert tc.id == "call_1"
    assert tc.name == "evtx_query"
    assert tc.arguments == {"path": "/x.evtx", "limit": 5}


def test_toolcall_from_openai_empty_arguments_is_empty_dict() -> None:
    tc = ToolCall.from_openai({"id": "c", "function": {"name": "case_open", "arguments": ""}})
    assert tc.arguments == {}


def test_provider_response_tool_use_stop_reason() -> None:
    resp = ProviderResponse(
        text="",
        tool_calls=[ToolCall(id="c", name="case_open", arguments={})],
        stop_reason="tool_use",
    )
    assert resp.stop_reason == "tool_use"
    assert resp.tool_calls[0].name == "case_open"


def test_a_fake_provider_satisfies_the_protocol() -> None:
    class FakeProvider:
        def complete(
            self, messages: list[dict], tools: list[dict], **kwargs: object
        ) -> ProviderResponse:
            return ProviderResponse(text="done", tool_calls=[], stop_reason="end_turn")

    provider: ChatProvider = FakeProvider()
    out = provider.complete([{"role": "user", "content": "hi"}], [])
    assert out.text == "done" and out.stop_reason == "end_turn"
