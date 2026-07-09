"""OpenAI-compatible ChatProvider — one adapter for OpenAI / OpenRouter / local / DGX.

The OpenAI ``/v1/chat/completions`` shape is the universal inference contract: native
tool-calling (structured ``tool_calls``, not JSON-in-prose), automatic prefix caching,
and a stateless-but-efficient endpoint with no per-call agent boot (the reason this
scales to large investigations where the ``claude -p`` provider does not). Only
``base_url`` + ``api_key`` + ``model`` change between backends, so OpenRouter, a local
vLLM/Ollama server, and a DGX Spark all run through this one class. The HTTP call is an
injected ``transport`` so mapping and parsing are unit-tested with no network.

No langgraph/fastapi (Amendment A2 content rule).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from .anthropic_auth import RETRYABLE_STATUSES, RetryableError, retry
from .types import ProviderResponse, ToolCall

Transport = Callable[[dict[str, Any]], dict[str, Any]]

_DEFAULT_BASE_URL = "https://api.openai.com/v1"
_DEFAULT_MAX_TOKENS = 4096


def _to_openai_messages(system: str | None, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Canonical messages -> OpenAI chat messages (system prepended; tool round-trip)."""
    out: list[dict[str, Any]] = []
    if system:
        out.append({"role": "system", "content": system})
    for msg in messages:
        role = msg["role"]
        if role == "tool":
            out.append(
                {
                    "role": "tool",
                    "tool_call_id": msg["tool_call_id"],
                    "content": msg.get("content", ""),
                }
            )
        elif role == "assistant" and msg.get("tool_calls"):
            out.append(
                {
                    "role": "assistant",
                    "content": msg.get("content") or "",
                    "tool_calls": [
                        {
                            "id": tc["id"],
                            "type": "function",
                            "function": {
                                "name": tc["name"],
                                "arguments": json.dumps(tc.get("arguments", {})),
                            },
                        }
                        for tc in msg["tool_calls"]
                    ],
                }
            )
        else:
            out.append({"role": role, "content": msg.get("content", "")})
    return out


def _parse_openai_response(raw: dict[str, Any]) -> ProviderResponse:
    """OpenAI chat completion -> ProviderResponse (tool_calls via ToolCall.from_openai)."""
    choice = (raw.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    text = message.get("content") or ""
    tool_calls = [ToolCall.from_openai(tc) for tc in message.get("tool_calls") or []]
    finish = choice.get("finish_reason")
    stop_reason = "tool_use" if tool_calls or finish == "tool_calls" else "end_turn"
    return ProviderResponse(text=text, tool_calls=tool_calls, stop_reason=stop_reason)


def _default_transport(base_url: str, api_key: str | None, *, max_retries: int = 6) -> Transport:
    url = f"{base_url.rstrip('/')}/chat/completions"
    headers = {"content-type": "application/json"}
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(request).encode("utf-8")

        def _once() -> dict[str, Any]:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=600) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                if exc.code in RETRYABLE_STATUSES:
                    raise RetryableError(exc.code) from exc
                raise

        return retry(_once, max_retries=max_retries)

    return transport


class OpenAIProvider:
    """ChatProvider over any OpenAI-compatible ``/v1/chat/completions`` endpoint."""

    def __init__(
        self,
        model: str,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        transport: Transport | None = None,
        max_tokens: int = _DEFAULT_MAX_TOKENS,
    ) -> None:
        self.model = model
        self.base_url = base_url or _DEFAULT_BASE_URL
        # SSRF guard: base_url (esp. operator FINDEVIL_AGENT_BASE_URL for local/dgx) must
        # be http(s) — not file://, gopher://, etc. — before any evidence text is POSTed.
        if urllib.parse.urlparse(self.base_url).scheme not in ("http", "https"):
            raise ValueError(f"base_url must be http(s), got: {self.base_url!r}")
        self.max_tokens = max_tokens
        if transport is not None:
            self._transport = transport
        else:
            self._transport = _default_transport(self.base_url, api_key)

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
            "messages": _to_openai_messages(system, messages),
            "max_tokens": self.max_tokens,
        }
        if tools:
            request["tools"] = tools
            request["tool_choice"] = "auto"

        raw = self._transport(request)
        return _parse_openai_response(raw)
