"""findevil-agent-mcp stdio server.

Spec #2 + Amendment A2. Boots the MCP Python SDK low-level
``Server`` over stdio, registers every tool exposed by
:mod:`findevil_agent_mcp.tools`, and returns each handler's output
as a single ``TextContent`` payload containing canonical JSON.

Boot:
    uv run --directory services/agent_mcp \\
        python -m findevil_agent_mcp.server

In normal operation the launcher is the repo-root ``.mcp.json`` —
Claude Code spawns this server alongside ``findevil-mcp`` (Rust)
when the user opens an investigation against a case directory.

Logging note: stdio is the wire; we MUST NOT print to stdout.
``structlog`` is configured to write to stderr only.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from typing import Any

import structlog
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool
from pydantic import ValidationError

from findevil_agent_mcp.sanitize import sanitize_value
from findevil_agent_mcp.tools import all_specs
from findevil_agent_mcp.tools._base import ToolSpec

SERVER_NAME = "findevil-agent-mcp"
SERVER_VERSION = "0.1.0"


def _configure_logging() -> structlog.BoundLogger:
    """Send logs to stderr — stdio is the JSON-RPC channel.

    Stdout pollution corrupts the protocol stream; this function is
    the single place that controls log destination. Tests can
    monkeypatch the returned logger.
    """
    level_name = os.environ.get("FINDEVIL_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(stream=sys.stderr, level=level, format="%(message)s")
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.WriteLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )
    return structlog.get_logger(SERVER_NAME)


def _build_specs_index() -> dict[str, ToolSpec]:
    """Materialize the registry once at startup.

    Importing the tool modules can be slow (sigstore is lazy but
    pydantic schema generation isn't); we pay that cost once before
    list_tools is first called.
    """
    return {spec.name: spec for spec in all_specs()}


def _to_text_content(payload: Any) -> list[TextContent]:
    """Wrap a Pydantic model (or dict) as a single MCP ``TextContent``.

    The MCP wire format expects ``content[0].text`` to be a string;
    we always emit canonical JSON so downstream agents can ``json.loads``
    deterministically.
    """
    if hasattr(payload, "model_dump"):
        body = payload.model_dump()
    elif isinstance(payload, dict):
        body = payload
    else:
        body = {"value": payload}
    # Neutralize attacker-controlled evidence text (chat/role tokens, invisible
    # Unicode) before it crosses the boundary to the model -- the Python half of
    # the MCP-output->LLM sanitizer (mirrors services/mcp/src/sanitize.rs). Log
    # what was neutralized as counts only, never the payload.
    body, sanitized = sanitize_value(body)
    if sanitized:
        structlog.get_logger(SERVER_NAME).warning(
            "agent_mcp_sanitized_tool_output",
            patterns=sanitized,
            total=sum(sanitized.values()),
        )
    text = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return [TextContent(type="text", text=text)]


def _error_content(message: str, *, kind: str) -> list[TextContent]:
    """Stable error shape returned to the MCP client.

    ``kind`` is one of:
      - ``"validation"``: input failed pydantic validation.
      - ``"unknown_tool"``: name not in the registry.
      - ``"handler"``: the handler raised an unexpected exception.
    """
    payload = {"error": {"kind": kind, "message": message}}
    return [
        TextContent(
            type="text",
            text=json.dumps(payload, sort_keys=True, separators=(",", ":")),
        )
    ]


def build_server() -> tuple[Server, dict[str, ToolSpec]]:
    """Construct the Server + registered handlers without booting stdio.

    Tests use this entry point to drive the server in-process. The
    ``run`` coroutine is the production entry point; it calls this
    function then wires stdio.
    """
    server: Server = Server(SERVER_NAME)
    specs = _build_specs_index()
    log = _configure_logging()
    log.info(
        "agent_mcp_boot",
        server_name=SERVER_NAME,
        server_version=SERVER_VERSION,
        tool_count=len(specs),
        tools=sorted(specs.keys()),
    )

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name=spec.name,
                description=spec.description,
                inputSchema=spec.input_schema(),
            )
            for spec in specs.values()
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        spec = specs.get(name)
        if spec is None:
            log.warning("agent_mcp_unknown_tool", tool=name)
            return _error_content(f"unknown tool: {name!r}", kind="unknown_tool")

        try:
            validated = spec.input_model.model_validate(arguments)
        except ValidationError as exc:
            log.warning(
                "agent_mcp_validation_error",
                tool=name,
                errors=exc.errors(include_url=False),
            )
            return _error_content(f"input validation failed: {exc}", kind="validation")

        try:
            result = await spec.handler(validated)
        except Exception as exc:
            log.error(
                "agent_mcp_handler_exception",
                tool=name,
                exc_type=type(exc).__name__,
                exc=str(exc),
            )
            return _error_content(f"{type(exc).__name__}: {exc}", kind="handler")

        return _to_text_content(result)

    return server, specs


async def _async_main() -> None:
    """Production entry point — wires stdio to the Server."""
    server, _ = build_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def run() -> None:
    """Synchronous wrapper for ``project.scripts`` entry point."""
    asyncio.run(_async_main())


if __name__ == "__main__":
    run()


__all__ = [
    "SERVER_NAME",
    "SERVER_VERSION",
    "build_server",
    "run",
]
