"""Canonical provider types + the ChatProvider contract.

The loop speaks ONE shape regardless of backend. A provider shim (Anthropic first,
then any OpenAI-compatible backend) maps that shape to/from its wire API. Keeping
the canonical ToolCall arguments as a parsed ``dict`` means the loop never branches
on provider details when dispatching to MCP.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

StopReason = Literal["end_turn", "tool_use"]


@dataclass(frozen=True)
class ToolCall:
    """A model's request to call one tool, normalized across providers."""

    id: str
    name: str
    arguments: dict[str, Any]

    @classmethod
    def from_openai(cls, raw: dict[str, Any]) -> ToolCall:
        """Build from an OpenAI ``tool_calls[]`` entry (arguments is a JSON string)."""
        fn = raw.get("function", {})
        raw_args = fn.get("arguments") or ""
        arguments = json.loads(raw_args) if raw_args.strip() else {}
        return cls(id=raw["id"], name=fn["name"], arguments=arguments)


@dataclass(frozen=True)
class ProviderResponse:
    """One model turn: free text, any tool calls, and why the turn stopped."""

    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: StopReason = "end_turn"


@runtime_checkable
class ChatProvider(Protocol):
    """The pluggable backend contract: messages + tool specs -> a ProviderResponse.

    ``messages`` are role/content dicts (user/assistant/tool); ``tools`` are
    OpenAI-shape function specs (see ``mcp_tools.mcp_tools_to_openai``). Concrete
    providers (AnthropicProvider, the OpenAI-compatible shim) implement this.
    """

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        **kwargs: Any,
    ) -> ProviderResponse: ...
