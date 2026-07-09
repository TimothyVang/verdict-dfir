"""The thin agent loop: drive a ChatProvider against MCP tools until it stops.

One investigation turn = ask the provider, dispatch any tool calls back to the MCP
servers, feed the results in as ``tool`` messages, repeat. The loop is provider- and
transport-agnostic: ``dispatch(name, arguments) -> str`` is the only seam to the MCP
client, so the read-only custody boundary lives in whoever builds ``dispatch`` (the
local stdio MCP client), never in this control flow.

Synchronous and bounded by design: a hard ``max_steps`` guard means a model that
never emits ``end_turn`` still terminates, and pods run sequentially so the audit
chain stays deterministically ordered. No langgraph/fastapi (Amendment A2 content
rule).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from .types import ProviderResponse

DispatchFn = Callable[[str, dict[str, Any]], str]

_DEFAULT_MAX_STEPS = 40


class _SupportsComplete(Protocol):
    def complete(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], **kwargs: Any
    ) -> ProviderResponse: ...


@dataclass(frozen=True)
class ToolInvocation:
    """One executed tool call and its raw result, kept for the audit transcript."""

    id: str
    name: str
    arguments: dict[str, Any]
    result: str


@dataclass
class LoopResult:
    """Outcome of a loop run: final text, why it stopped, and the full transcript."""

    final_text: str
    stop: str  # "end_turn" | "max_steps"
    steps: int
    messages: list[dict[str, Any]]
    tool_invocations: list[ToolInvocation] = field(default_factory=list)


def run_agent_loop(
    provider: _SupportsComplete,
    *,
    tools: list[dict[str, Any]],
    dispatch: DispatchFn,
    system: str,
    user_task: str,
    max_steps: int = _DEFAULT_MAX_STEPS,
) -> LoopResult:
    """Run the provider until ``end_turn`` or ``max_steps`` tool-dispatch rounds."""
    messages: list[dict[str, Any]] = [{"role": "user", "content": user_task}]
    invocations: list[ToolInvocation] = []

    for step in range(1, max_steps + 1):
        resp = provider.complete(messages, tools, system=system)

        if resp.stop_reason != "tool_use" or not resp.tool_calls:
            return LoopResult(
                final_text=resp.text,
                stop="end_turn",
                steps=step,
                messages=messages,
                tool_invocations=invocations,
            )

        messages.append(_assistant_turn(resp))
        for call in resp.tool_calls:
            result = dispatch(call.name, call.arguments)
            invocations.append(
                ToolInvocation(id=call.id, name=call.name, arguments=call.arguments, result=result)
            )
            messages.append({"role": "tool", "tool_call_id": call.id, "content": result})

    return LoopResult(
        final_text="",
        stop="max_steps",
        steps=max_steps,
        messages=messages,
        tool_invocations=invocations,
    )


def _assistant_turn(resp: ProviderResponse) -> dict[str, Any]:
    """Canonical assistant message carrying the model's text + requested tool calls."""
    return {
        "role": "assistant",
        "content": resp.text,
        "tool_calls": [
            {"id": c.id, "name": c.name, "arguments": c.arguments} for c in resp.tool_calls
        ],
    }
