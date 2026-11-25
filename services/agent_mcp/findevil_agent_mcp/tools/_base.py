"""Tool registration primitives.

Each MCP tool exports a single :class:`ToolSpec` instance named
``SPEC``. The server iterates ``tools.all_specs()`` at startup to
build the JSON Schema list returned by ``list_tools``.

A handler is a coroutine that takes the validated input model and
returns the output model. Validation happens in the server boundary
so handlers can assume their argument is already-typed.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

Handler = Callable[[BaseModel], Awaitable[BaseModel]]


@dataclass(frozen=True)
class ToolSpec:
    """Static metadata + handler for one MCP tool."""

    name: str
    """Tool name as exposed to the MCP client. Snake-case."""

    description: str
    """Human-readable summary. Shown to Claude Code at tool-pick time."""

    input_model: type[BaseModel]
    """Pydantic v2 model the server validates incoming arguments against.

    Must use ``model_config = ConfigDict(extra="forbid")`` so unknown
    fields surface as errors, not silent drops.
    """

    output_model: type[BaseModel]
    """Pydantic v2 model the handler must return."""

    handler: Handler
    """Async coroutine. Takes the validated input model, returns the output model."""

    def input_schema(self) -> dict[str, Any]:
        """JSON Schema for the input model — emitted to the MCP client."""
        return self.input_model.model_json_schema()


__all__ = ["Handler", "ToolSpec"]
