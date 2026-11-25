"""Increment 1: MCP tools/list output -> OpenAI-shape tool specs (the canonical
provider-shim contract). Pure function, no network."""

from __future__ import annotations

from findevil_agent.agentloop.mcp_tools import mcp_tools_to_openai


def test_converts_mcp_tool_to_openai_function_spec() -> None:
    mcp = [
        {
            "name": "evtx_query",
            "description": "Parse a Windows EVTX log.",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        }
    ]
    assert mcp_tools_to_openai(mcp) == [
        {
            "type": "function",
            "function": {
                "name": "evtx_query",
                "description": "Parse a Windows EVTX log.",
                "parameters": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
        }
    ]


def test_missing_input_schema_defaults_to_empty_object() -> None:
    out = mcp_tools_to_openai([{"name": "case_open", "description": "Open a case."}])
    assert out[0]["function"]["parameters"] == {"type": "object", "properties": {}}


def test_missing_description_is_empty_string() -> None:
    out = mcp_tools_to_openai([{"name": "x", "inputSchema": {"type": "object"}}])
    assert out[0]["function"]["description"] == ""


def test_empty_list_returns_empty() -> None:
    assert mcp_tools_to_openai([]) == []
