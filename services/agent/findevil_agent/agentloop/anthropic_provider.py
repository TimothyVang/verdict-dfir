"""Anthropic (Claude Messages API) adapter for the canonical ChatProvider contract.

Maps the loop's canonical messages + OpenAI-shape tool specs onto the Claude
Messages API (``tool_use`` / ``tool_result`` content blocks), then normalizes the
response back to a ``ProviderResponse`` with parsed ``ToolCall``s. The HTTP call is
an injected ``transport`` (request dict -> response dict) so mapping and
normalization are unit-tested with no network; the default transport posts to the
Anthropic API and is exercised only by the live run.

This is a thin shim — no langgraph/fastapi (Amendment A2 content rule). The MCP
client stays in our loop, so the read-only custody boundary is preserved.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from .anthropic_auth import RETRYABLE_STATUSES, RetryableError, resolve_anthropic_auth, retry
from .types import ProviderResponse, ToolCall

Transport = Callable[[dict[str, Any]], dict[str, Any]]

_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"
_DEFAULT_MAX_TOKENS = 4096


def _openai_tools_to_anthropic(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """``{type:function, function:{name, description, parameters}}`` -> Anthropic tool."""
    out: list[dict[str, Any]] = []
    for tool in tools:
        fn = tool.get("function", tool)
        out.append(
            {
                "name": fn["name"],
                "description": fn.get("description", ""),
                "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
            }
        )
    return out


def _canonical_messages_to_anthropic(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map canonical role/content messages to Anthropic content-block messages.

    - user/assistant with plain ``content`` -> same role, string content.
    - assistant with ``tool_calls`` -> assistant turn of ``tool_use`` blocks.
    - role ``tool`` (a tool result) -> user turn with a ``tool_result`` block.
    """
    out: list[dict[str, Any]] = []
    for msg in messages:
        role = msg["role"]
        if role == "tool":
            out.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": msg["tool_call_id"],
                            "content": msg.get("content", ""),
                        }
                    ],
                }
            )
        elif role == "assistant" and msg.get("tool_calls"):
            blocks = [
                {
                    "type": "tool_use",
                    "id": tc["id"],
                    "name": tc["name"],
                    "input": tc.get("arguments", {}),
                }
                for tc in msg["tool_calls"]
            ]
            out.append({"role": "assistant", "content": blocks})
        else:
            out.append({"role": role, "content": msg.get("content", "")})
    return out


def _default_transport(auth_headers: dict[str, str], *, max_retries: int = 6) -> Transport:
    """POST to the Messages API with resolved auth headers and 429/529 backoff."""
    headers = {
        "content-type": "application/json",
        "anthropic-version": _ANTHROPIC_VERSION,
        **auth_headers,
    }

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(request).encode("utf-8")

        def _once() -> dict[str, Any]:
            req = urllib.request.Request(_ANTHROPIC_URL, data=body, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=600) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                if exc.code in RETRYABLE_STATUSES:
                    raise RetryableError(exc.code) from exc
                raise

        return retry(_once, max_retries=max_retries)

    return transport


class AnthropicProvider:
    """Concrete ``ChatProvider`` backed by the Claude Messages API."""

    def __init__(
        self,
        model: str,
        *,
        transport: Transport | None = None,
        api_key: str | None = None,
        max_tokens: int = _DEFAULT_MAX_TOKENS,
    ) -> None:
        self.model = model
        self.max_tokens = max_tokens
        if transport is not None:
            self._transport = transport
        else:
            # Resolve x-api-key, else the Claude Code OAuth token. Raises if neither
            # exists, so construction fails fast rather than at first request.
            self._transport = _default_transport(resolve_anthropic_auth(api_key))

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        system: str | None = None,
        **_kwargs: Any,
    ) -> ProviderResponse:
        request: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": _canonical_messages_to_anthropic(messages),
            "tools": _openai_tools_to_anthropic(tools),
        }
        if system is not None:
            request["system"] = system

        raw = self._transport(request)
        return _normalize_response(raw)


def _normalize_response(raw: dict[str, Any]) -> ProviderResponse:
    """Anthropic response (content blocks + stop_reason) -> ProviderResponse."""
    texts: list[str] = []
    tool_calls: list[ToolCall] = []
    for block in raw.get("content", []):
        if block.get("type") == "text":
            texts.append(block.get("text", ""))
        elif block.get("type") == "tool_use":
            tool_calls.append(
                ToolCall(id=block["id"], name=block["name"], arguments=block.get("input", {}))
            )
    stop_reason = "tool_use" if raw.get("stop_reason") == "tool_use" else "end_turn"
    return ProviderResponse(
        text="".join(texts),
        tool_calls=tool_calls,
        stop_reason=stop_reason,
    )
