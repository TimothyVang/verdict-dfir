"""ClaudeCliProvider — drive inference through the headless Claude Code CLI (`claude -p`).

The CLI authenticates with the Claude subscription entitlement, so it has inference
headroom the raw Messages API (rate-limited OAuth token) lacks. The CLI is itself an
agent, so this provider does NOT give it the real MCP tools; it renders the
system+tools+conversation into one prompt under a strict JSON tool-call protocol and
parses the model's decision back into the canonical ``ProviderResponse``. The host loop
still dispatches any tool call to the real MCP servers via the bridge, so custody (the
audit chain + the fact-fidelity gate) is unchanged.

Each ``complete`` is a fresh ``claude -p`` invocation (stateless; the full conversation
is re-sent), so a long investigation pays per-turn context cost — fine for a bounded
run, but the OpenAI-compatible shim is the cheaper long-haul backend.
No langgraph/fastapi (Amendment A2 content rule).
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from typing import Any

from .types import ProviderResponse, ToolCall

CliRunner = Callable[[str], dict[str, Any]]

_DEFAULT_MODEL = "claude-opus-4-8"

_PROTOCOL = (
    "You are driving a forensic tool loop. You do NOT have direct tool access; instead, "
    "respond with ONE JSON object and nothing else.\n"
    'To call tools, respond: {"tool_calls": [{"name": "<tool>", "arguments": {...}}]} '
    "(one or more calls).\n"
    'When you have no further leads, respond: {"final": "<short summary>"}.\n'
    "Output ONLY the JSON object — no prose, no markdown fences."
)


def _render_messages(messages: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for msg in messages:
        role = msg.get("role")
        if role == "tool":
            lines.append(f"[tool result for {msg.get('tool_call_id')}]\n{msg.get('content', '')}")
        elif role == "assistant" and msg.get("tool_calls"):
            calls = json.dumps(
                [
                    {"name": c["name"], "arguments": c.get("arguments", {})}
                    for c in msg["tool_calls"]
                ]
            )
            text = msg.get("content") or ""
            lines.append(f"[assistant]{(' ' + text) if text else ''}\n[tool_calls] {calls}")
        else:
            lines.append(f"[{role}] {msg.get('content', '')}")
    return "\n\n".join(lines)


def build_cli_prompt(
    *, system: str | None, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
) -> str:
    """Render system + available tools + conversation + the JSON protocol into one prompt."""
    tool_specs = [t.get("function", t) for t in tools]
    parts = []
    if system:
        parts.append(f"=== SYSTEM ===\n{system}")
    parts.append(f"=== AVAILABLE TOOLS (JSON Schema) ===\n{json.dumps(tool_specs, indent=2)}")
    parts.append(f"=== PROTOCOL ===\n{_PROTOCOL}")
    parts.append(f"=== CONVERSATION ===\n{_render_messages(messages)}")
    parts.append("=== YOUR JSON RESPONSE ===")
    return "\n\n".join(parts)


def _extract_json_object(text: str) -> dict[str, Any] | None:
    """Parse the first JSON object in ``text``, tolerating leading/trailing prose.

    Uses ``JSONDecoder.raw_decode`` (stdlib) so braces inside string values don't
    truncate the object — a hand-rolled brace counter gets this wrong.
    """
    decoder = json.JSONDecoder()
    start = text.find("{")
    while start != -1:
        try:
            obj, _end = decoder.raw_decode(text, start)
        except json.JSONDecodeError:
            start = text.find("{", start + 1)
            continue
        return obj if isinstance(obj, dict) else None
    return None


def parse_cli_result(text: str) -> ProviderResponse:
    """Parse the CLI's result text (tool-call decision or final) into a ProviderResponse."""
    obj = _extract_json_object(text)
    if obj is None:
        # The model did not emit the protocol JSON; treat its prose as a final answer
        # rather than looping forever on a malformed turn.
        return ProviderResponse(text=text.strip(), stop_reason="end_turn")

    raw_calls = obj.get("tool_calls")
    if isinstance(raw_calls, list) and raw_calls:
        tool_calls = [
            ToolCall(
                id=f"cli-{i}",
                name=str(call.get("name", "")),
                arguments=call.get("arguments") or {},
            )
            for i, call in enumerate(raw_calls)
            if call.get("name")
        ]
        if tool_calls:
            return ProviderResponse(text="", tool_calls=tool_calls, stop_reason="tool_use")

    final = obj.get("final") or obj.get("answer") or obj.get("text") or ""
    return ProviderResponse(text=str(final), stop_reason="end_turn")


def _default_cli_runner(model: str) -> CliRunner:
    def runner(prompt: str) -> dict[str, Any]:
        # The prompt (system + all tool schemas + conversation) is large and grows each
        # turn, so it is fed on STDIN — passing it as an argv arg overruns ARG_MAX.
        proc = subprocess.run(
            ["claude", "-p", "--output-format", "json", "--model", model],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"claude -p failed (rc={proc.returncode}): {proc.stderr[:400]}")
        return json.loads(proc.stdout)

    return runner


class ClaudeCliProvider:
    """ChatProvider backed by the headless Claude Code CLI."""

    def __init__(
        self,
        model: str | None = None,
        *,
        runner: CliRunner | None = None,
    ) -> None:
        self.model = model or _DEFAULT_MODEL
        self._runner = runner or _default_cli_runner(self.model)

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        system: str | None = None,
        **_kwargs: Any,
    ) -> ProviderResponse:
        prompt = build_cli_prompt(system=system, messages=messages, tools=tools)
        raw = self._runner(prompt)
        if raw.get("is_error"):
            raise RuntimeError(f"claude -p returned an error: {raw.get('result', '')[:400]}")
        return parse_cli_result(str(raw.get("result", "")))
