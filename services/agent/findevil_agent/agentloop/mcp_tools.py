"""Convert an MCP server's ``tools/list`` output into OpenAI-shape tool specs.

The OpenAI ``/v1/chat/completions`` ``tools`` array is the canonical provider-shim
contract (OpenAI, OpenRouter, vLLM/Ollama, DGX Spark all consume it; the Anthropic
adapter maps from it). This conversion is pure — no network, no model — so the same
typed MCP surface (findevil-mcp / findevil-agent-mcp) is exposed to any provider.
"""

from __future__ import annotations

from typing import Any

_EMPTY_OBJECT_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}}


def mcp_tools_to_openai(mcp_tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map MCP tool descriptors to OpenAI ``tools`` function specs.

    Each MCP tool ``{name, description?, inputSchema?}`` becomes
    ``{type: "function", function: {name, description, parameters}}``. A missing
    ``inputSchema`` defaults to an empty object schema (no parameters); a missing
    description becomes an empty string. The JSON Schema is passed through verbatim.
    """
    specs: list[dict[str, Any]] = []
    for tool in mcp_tools:
        parameters = tool.get("inputSchema") or dict(_EMPTY_OBJECT_SCHEMA)
        specs.append(
            {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": parameters,
                },
            }
        )
    return specs
