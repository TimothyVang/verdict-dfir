"""Increment 8a: ClaudeCliProvider — route inference through `claude -p` (headless).

The Claude Code CLI authenticates with the subscription entitlement, so it has
inference headroom the raw Messages API (rate-limited OAuth) does not. Since the CLI
is itself an agent (it executes tools), this provider does NOT hand it the real tools;
instead it renders system+tools+conversation into one prompt with a strict JSON
tool-call protocol and parses the model's decision back into a ProviderResponse. The
host loop still dispatches tool calls to the real MCP via the bridge (custody intact).

The subprocess is an injected ``runner`` (prompt -> parsed `claude -p` JSON), so the
prompt building and response parsing are tested with no process spawn.
"""

from __future__ import annotations

from findevil_agent.agentloop.claude_cli import (
    ClaudeCliProvider,
    build_cli_prompt,
    parse_cli_result,
)

_TOOLS = [
    {
        "type": "function",
        "function": {"name": "evtx_query", "description": "Parse EVTX.", "parameters": {}},
    },
    {
        "type": "function",
        "function": {"name": "record_finding", "description": "Record.", "parameters": {}},
    },
]


def test_parse_tool_call_decision() -> None:
    resp = parse_cli_result('{"tool_calls": [{"name": "evtx_query", "arguments": {"path": "/e"}}]}')
    assert resp.stop_reason == "tool_use"
    assert len(resp.tool_calls) == 1
    assert resp.tool_calls[0].name == "evtx_query"
    assert resp.tool_calls[0].arguments == {"path": "/e"}
    assert resp.tool_calls[0].id  # a synthesized, non-empty id


def test_parse_final_decision() -> None:
    resp = parse_cli_result('{"final": "no reportable evidence"}')
    assert resp.stop_reason == "end_turn"
    assert resp.text == "no reportable evidence"
    assert resp.tool_calls == []


def test_parse_strips_code_fences_and_prose() -> None:
    text = 'Here is my decision:\n```json\n{"tool_calls": [{"name": "registry_query", "arguments": {}}]}\n```\n'
    resp = parse_cli_result(text)
    assert resp.stop_reason == "tool_use"
    assert resp.tool_calls[0].name == "registry_query"


def test_parse_handles_brace_inside_string_value() -> None:
    # a JSON string value containing `}` (e.g. a path) must not truncate the object
    resp = parse_cli_result('thinking… {"final": "path C:/a}b done"} trailing')
    assert resp.stop_reason == "end_turn"
    assert "C:/a}b" in resp.text


def test_parse_unparseable_is_end_turn_with_text() -> None:
    resp = parse_cli_result("I could not produce JSON.")
    assert resp.stop_reason == "end_turn"
    assert "could not" in resp.text


def test_build_prompt_includes_system_tools_and_protocol() -> None:
    prompt = build_cli_prompt(
        system="you are pool A",
        messages=[{"role": "user", "content": "investigate /e"}],
        tools=_TOOLS,
    )
    assert "you are pool A" in prompt
    assert "evtx_query" in prompt and "record_finding" in prompt
    assert "investigate /e" in prompt
    # the strict-protocol contract is stated
    assert "tool_calls" in prompt and "final" in prompt


def test_build_prompt_renders_tool_results() -> None:
    prompt = build_cli_prompt(
        system="s",
        messages=[
            {"role": "user", "content": "go"},
            {
                "role": "assistant",
                "content": "looking",
                "tool_calls": [{"id": "cli-0", "name": "evtx_query", "arguments": {"path": "/e"}}],
            },
            {"role": "tool", "tool_call_id": "cli-0", "content": "tool_call_id: tc-1\n{...}"},
        ],
        tools=_TOOLS,
    )
    assert "tc-1" in prompt  # the tool result (with its real citation handle) is in context


def test_provider_uses_injected_runner() -> None:
    seen: dict[str, str] = {}

    def runner(prompt: str) -> dict:
        seen["prompt"] = prompt
        return {"result": '{"final": "done"}', "is_error": False}

    p = ClaudeCliProvider(model="claude-opus-4-8", runner=runner)
    resp = p.complete([{"role": "user", "content": "hi"}], _TOOLS, system="s")
    assert resp.stop_reason == "end_turn"
    assert resp.text == "done"
    assert "hi" in seen["prompt"]
